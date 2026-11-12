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

/// The cell schema revision this build ships (CR-038). Migration 0032's
/// `cell_schema_revision_v1()` returns it; write-behind refuses to start on any other value.
pub const CELL_SCHEMA_REVISION: i32 = 32;

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

/// Declares [`DrainFailureCause`], its [`DrainFailureCause::ALL`] and its
/// [`DrainFailureCause::label`] from one list, so a variant cannot be declared without its label
/// and its place in `ALL`.
macro_rules! drain_failure_causes {
    ($($(#[$doc:meta])* $variant:ident => $label:literal,)+) => {
        /// Why one drain authority call failed, finer than [`DrainError`].
        ///
        /// Observation only. [`DrainError`] stays the contract every caller matches on; this closed
        /// set is recorded on `lore.object_dispatch.drain_authority_failures{procedure, cause}` at
        /// the one place the SQLSTATE, the raised message and the failing step are still known
        /// ([`DrainClient::query_at`]). Every label is a static string from this enum, never SQL
        /// text, a message, or an identifier.
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum DrainFailureCause {
            $($(#[$doc])* $variant,)+
        }

        impl DrainFailureCause {
            /// Every variant once, in declaration order. Built by the same macro as the enum, so
            /// it is complete by construction.
            pub const ALL: [Self; [$(DrainFailureCause::$variant),+].len()] =
                [$(Self::$variant),+];

            pub const fn label(self) -> &'static str {
                match self {
                    $(Self::$variant => $label,)+
                }
            }
        }
    };
}

drain_failure_causes! {
    /// The dispatch pool gave no connection. Reaches the caller as `Unavailable`.
    PoolAcquire => "unavailable_pool",
    /// The leased session failed before the statement: client, `BEGIN`, the timeout preamble, or
    /// a hot-row lock step that failed other than by contention. Reaches the caller as
    /// `Unavailable`.
    Session => "unavailable_session",
    /// The whole bounded operation outlived the pool's operation timeout. `Unavailable`.
    OperationTimeout => "unavailable_timeout",
    /// The statement lost a race (40001, 55P03, 40P01). `Contended`.
    Contended => "contended",
    /// SQLSTATE 53000 raised as `DISPATCH_RESERVE_PUT_CAPACITY_EXHAUSTED` (migration 0013). `Refused`.
    RefusedPutCapacity => "refused_put_capacity",
    /// SQLSTATE 53000 raised as `DRAIN_METADATA_CAPACITY` (migrations 0026/0030). `Refused`.
    RefusedMetadataCapacity => "refused_metadata_capacity",
    /// SQLSTATE 53000 under any other message. `Refused`.
    RefusedCapacityOther => "refused_capacity_other",
    /// SQLSTATE 57014: the `SET LOCAL statement_timeout` fired. `Refused`.
    RefusedStatementTimeout => "refused_statement_timeout",
    /// Any other SQLSTATE, a raised authority refusal included. `Refused`.
    RefusedOther => "refused_other",
    /// `DRAIN_METADATA_UNDERFLOW`. `MetadataUnderflow`.
    MetadataUnderflow => "metadata_underflow",
    /// SQLSTATE 55000 raised as `DRAIN_ATTEMPT_RETIRED` (migration 0032): a first-seen attempt older
    /// than the cell's retired floor, which a replica whose clock lags the database produces.
    /// `Refused`.
    RefusedAttemptRetired => "refused_attempt_retired",
    /// The statement failed with no SQLSTATE, so its outcome is unknown. `Unavailable`.
    StatementUnknown => "unavailable_statement",
    /// `COMMIT` lost a race and rolled back. `Contended`.
    CommitContended => "commit_contended",
    /// `COMMIT` failed otherwise and may have committed. `Unavailable`.
    CommitUnknown => "commit_unknown",
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
    if message == Some("DRAIN_ATTEMPT_RETIRED") {
        return DrainFailureCause::RefusedAttemptRetired;
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
    const PROCEDURES: [(&str, &str); 15] = [
        ("drain_reserve_v1", "reserve"),
        ("drain_policy_read_v1", "policy_read"),
        ("drain_check_ready_v2", "check_ready"),
        ("drain_observe_v1", "observe"),
        ("drain_cleanup_candidates_v1", "cleanup_candidates"),
        ("drain_cleanup_claim_v2", "cleanup_claim"),
        ("drain_cleanup_unlease_v1", "cleanup_unlease"),
        ("drain_cleanup_release_v1", "cleanup_release"),
        ("drain_cleanup_compact_v3", "cleanup_compact"),
        ("drain_retired_floor_advance_v1", "retired_floor_advance"),
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

/// drain-tput2: the session advisory lock that orders the transactions writing the cell's hot
/// rows (the three quota counters and the drain policy row every reservation, release and
/// compaction writes).
///
/// Under `SERIALIZABLE` two such transactions never wait for each other: the later writer of a
/// row aborts (40001, "concurrent update"), and measured load lost about 14,000 of them in five
/// minutes. This lock is taken in its own short transaction BEFORE the `SERIALIZABLE` one begins,
/// so that transaction's snapshot already sees the previous holder's commit, and is released
/// after it ends. It only orders the writers; every check stays in the database and a writer
/// that skips the lock is still serialized there, as before. The wait is bounded by the pool's
/// `lock_timeout`, and a session that fails is poisoned, which releases its lock.
///
/// The pool's `statement_timeout` must be greater than its `lock_timeout`. The lock wait is one
/// statement, so with `statement_timeout <= lock_timeout` the statement timeout ends the wait
/// first (57014, not 55P03): the call reads `Unavailable` instead of `Contended`, and the
/// lock-wait timeout counter and the stuck-holder warning never fire. The deployed values are
/// 5,000 ms and 1,000 ms.
///
/// Why not `pg_advisory_xact_lock` inside the `SERIALIZABLE` transaction: that call is itself a
/// `SELECT`, and a serializable transaction's snapshot is taken when its first `SELECT` begins,
/// before the call waits (`PostgreSQL` `LOCK` reference: "A REPEATABLE READ or SERIALIZABLE
/// transaction's view of data will be frozen when its first SELECT or data modification statement
/// begins"; `LOCK TABLE` escapes this only because it takes no snapshot). The snapshot would
/// predate the previous holder's commit, so that commit would still abort this transaction.
/// Measured: the live race `live_r32_racing_reserves_wait_in_turn_under_the_hot_row_lock` with an
/// xact lock inside the transaction lost 6 of 120 racing reserves to contention (4 clients); with
/// this session lock it lost none.
///
/// A session lock must never return to the pool held. Every path that does not reach a clean
/// unlock closes the connection instead (`DispatchLease`'s drop closes, `poison` closes), and the
/// backend gives the lock back when it ends: a dropped or cancelled future, a panic, the
/// operation timeout, a failed statement or commit, and a failed unlock.
///
/// A closed socket is not enough when the holder stops without closing it (a frozen process, a
/// lost network). So while the lock is held the session also carries `idle_session_timeout` and
/// `idle_in_transaction_session_timeout` of one operation timeout, and the server ends a holder
/// that goes idle for that long. With every statement bounded by `statement_timeout`, the server
/// holds the lock at most about `statement_timeout` per statement plus one operation timeout of
/// idle; the unlock resets both settings before the session goes back to the pool. Both settings
/// need `PostgreSQL` 14 or later (`idle_session_timeout` is new in 14).
///
/// One operation timeout covers the lock wait and the transaction together; the lock wait is not
/// added to the budget. So a slow commit can leave too little time for the unlock: the call then
/// reads `Unavailable` although the transaction committed, and the session is closed (which frees
/// the lock). That is safe: `Unavailable` already means "may have committed", and every hot-row
/// procedure is idempotent on replay (a reserve replay is pinned to its descriptor digest; a
/// release, compaction or floor advance that already ran changes nothing). Adding `lock_timeout`
/// to the hot budget instead would lengthen the idle bound, and with it how long a stopped holder
/// stalls the cell.
///
/// The key is per database: `PostgreSQL` advisory locks are scoped to the current database. Two
/// cells that shared one database would serialize each other's hot-row writers. They do not
/// today: every dev cell has its own `PostgreSQL` service and every staging cell its own database.
///
/// Operators: never take this key by hand (for example `SELECT pg_advisory_lock(...)` from
/// `psql`). A session outside loreserver has no idle bound, so while it holds the key every
/// reservation and cleanup release of the cell waits and times out; promotions stop and, under
/// load, pushes fail with `SlowDown` while `/lb_health` stays 200. Lock-wait timeouts are counted
/// on `lore.object_dispatch.drain_hot_row_lock_wait_timeouts`, and while they continue a
/// rate-limited warning names the holder's pid from `pg_locks`.
pub const DRAIN_HOT_ROW_LOCK_KEY: i64 = 0x6c6f_7265_6472_6e31;

/// Why a hot-row session was closed instead of going back to the pool. A closed label set for
/// `lore.object_dispatch.drain_hot_row_sessions_closed{reason}`. A dropped or cancelled call also
/// closes its session; nothing is left to count it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HotRowSessionClose {
    /// The lock wait passed `lock_timeout` (55P03). The call reads `Contended`.
    LockTimeout,
    /// The lock step failed otherwise.
    LockFailed,
    /// The transaction, statement or commit failed.
    Failed,
    /// The transaction ended but the unlock or the reset of the idle bounds failed.
    UnlockFailed,
    /// The whole call outlived the operation timeout.
    OperationTimeout,
}

impl HotRowSessionClose {
    pub const ALL: [Self; 5] = [
        Self::LockTimeout,
        Self::LockFailed,
        Self::Failed,
        Self::UnlockFailed,
        Self::OperationTimeout,
    ];

    pub const fn label(self) -> &'static str {
        match self {
            Self::LockTimeout => "lock_timeout",
            Self::LockFailed => "lock_failed",
            Self::Failed => "failed",
            Self::UnlockFailed => "unlock_failed",
            Self::OperationTimeout => "operation_timeout",
        }
    }
}

/// Shortest time between two stuck-holder warnings of one process. Also the window in which
/// [`HOT_ROW_STALL_LOG_MIN_TIMEOUTS`] timeouts must fall to warn.
pub const HOT_ROW_STALL_LOG_PERIOD: std::time::Duration = std::time::Duration::from_secs(30);

/// Lock-wait timeouts needed inside one [`HOT_ROW_STALL_LOG_PERIOD`] before a warning: one timeout
/// is a busy moment, more in a short time is a holder that does not let go.
pub const HOT_ROW_STALL_LOG_MIN_TIMEOUTS: u64 = 3;

/// Rate limit for the stuck-holder warning (see [`DRAIN_HOT_ROW_LOCK_KEY`]).
#[derive(Debug)]
pub struct HotRowStallLog {
    last: Option<std::time::Instant>,
    /// Timeouts since the last warning; the warning reports it.
    since_warning: u64,
    /// The times of the latest timeouts, at most [`HOT_ROW_STALL_LOG_MIN_TIMEOUTS`] of them.
    recent: std::collections::VecDeque<std::time::Instant>,
}

impl HotRowStallLog {
    pub const fn new() -> Self {
        Self {
            last: None,
            since_warning: 0,
            recent: std::collections::VecDeque::new(),
        }
    }

    /// Count one lock-wait timeout at `now`. `Some(timeouts)` when a warning is due: the latest
    /// [`HOT_ROW_STALL_LOG_MIN_TIMEOUTS`] timeouts all fell inside one
    /// [`HOT_ROW_STALL_LOG_PERIOD`], and at least that period has passed since the last warning.
    /// Older timeouts decay: three timeouts spread over hours do not warn. `timeouts` is the count
    /// since the last warning.
    pub fn on_timeout(&mut self, now: std::time::Instant) -> Option<u64> {
        self.since_warning = self.since_warning.saturating_add(1);
        self.recent.push_back(now);
        while self.recent.len() as u64 > HOT_ROW_STALL_LOG_MIN_TIMEOUTS {
            self.recent.pop_front();
        }
        let repeated = self.recent.len() as u64 >= HOT_ROW_STALL_LOG_MIN_TIMEOUTS
            && self.recent.front().is_some_and(|first| {
                now.saturating_duration_since(*first) <= HOT_ROW_STALL_LOG_PERIOD
            });
        let quiet_long_enough = self
            .last
            .is_none_or(|last| now.saturating_duration_since(last) >= HOT_ROW_STALL_LOG_PERIOD);
        if !repeated || !quiet_long_enough {
            return None;
        }
        self.last = Some(now);
        Some(std::mem::take(&mut self.since_warning))
    }
}

impl Default for HotRowStallLog {
    fn default() -> Self {
        Self::new()
    }
}

/// Process-global on purpose (one warning stream per loreserver). A test that counts warnings
/// therefore depends on every earlier timeout in its process; the live runners run each case in
/// its own process for that reason.
static HOT_ROW_STALL_LOG: std::sync::Mutex<HotRowStallLog> =
    std::sync::Mutex::new(HotRowStallLog::new());

/// The sessions that hold [`DRAIN_HOT_ROW_LOCK_KEY`] now. `pg_locks` is readable by every role.
/// For another role's session, `pg_stat_activity` still shows `usename` and `application_name`,
/// but `client_addr`, `state` and `state_change` read NULL unless the runtime role has
/// `pg_read_all_stats`. `client_addr` is also NULL for a Unix-socket client.
const HOT_ROW_HOLDER_SQL: &str = "SELECT l.pid, a.usename::text, a.application_name, \
       host(a.client_addr), a.state, \
       (EXTRACT(EPOCH FROM (clock_timestamp() - a.state_change)) * 1000)::bigint \
  FROM pg_catalog.pg_locks l LEFT JOIN pg_catalog.pg_stat_activity a ON a.pid = l.pid \
 WHERE l.locktype = 'advisory' AND l.granted AND l.objsubid = 1 \
   AND ((l.classid::bigint << 32) | l.objid::bigint) = $1";

/// One session that holds [`DRAIN_HOT_ROW_LOCK_KEY`], as `pg_locks` and `pg_stat_activity` show
/// it. Every field but `pid` can be `None` (see [`hot_row_lock_holders`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HotRowLockHolder {
    pub pid: i32,
    pub role: Option<String>,
    pub application: Option<String>,
    pub client_address: Option<String>,
    pub state: Option<String>,
    pub state_age_ms: Option<i64>,
}

/// The fields of one holder as the stuck-holder warning prints them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HotRowHolderLogFields {
    pub role: String,
    pub application: String,
    pub client: String,
    pub state: String,
    pub state_age_ms: String,
}

impl HotRowLockHolder {
    /// The holder as the warning prints it. A NULL reads as what it means: with no
    /// `pg_stat_activity` row (the session just ended) every field is unknown; when the role
    /// shows but the state does not, another role's session hid it
    /// ([`HOT_ROW_HOLDER_HIDDEN`]); a NULL client of a visible session is a Unix socket.
    pub fn log_fields(&self) -> HotRowHolderLogFields {
        const ENDED: &str = "unknown (no pg_stat_activity row)";
        let seen = self.role.is_some();
        let hidden_or_ended = if seen { HOT_ROW_HOLDER_HIDDEN } else { ENDED };
        HotRowHolderLogFields {
            role: self.role.clone().unwrap_or_else(|| ENDED.to_owned()),
            application: self.application.clone().unwrap_or_else(|| ENDED.to_owned()),
            client: match (&self.client_address, &self.state) {
                (Some(address), _) => address.clone(),
                (None, Some(_)) => "local (Unix socket)".to_owned(),
                (None, None) => hidden_or_ended.to_owned(),
            },
            state: self
                .state
                .clone()
                .unwrap_or_else(|| hidden_or_ended.to_owned()),
            state_age_ms: self
                .state_age_ms
                .map_or_else(|| hidden_or_ended.to_owned(), |age| age.to_string()),
        }
    }
}

/// The server-side bound on the holder read. The read runs in its own transaction, so a
/// `ROLLBACK` before it has dropped the operation's `SET LOCAL` preamble; without its own bound the
/// read would run with the role's default `statement_timeout` (often none).
pub const HOT_ROW_HOLDER_READ_TIMEOUT_MS: u64 = 1_000;

/// What the holder read prints for a `pg_stat_activity` field another role's session hides.
pub const HOT_ROW_HOLDER_HIDDEN: &str = "hidden (needs pg_read_all_stats)";

/// The sessions that hold [`DRAIN_HOT_ROW_LOCK_KEY`] now, read on `client`'s database. A stuck
/// holder's pid is what an operator passes to `pg_terminate_backend`. The read runs in its own
/// transaction with [`HOT_ROW_HOLDER_READ_TIMEOUT_MS`] as its statement and lock timeout, and
/// rolls back. `client` must not be inside a transaction.
pub async fn hot_row_lock_holders(
    client: &mut tokio_postgres::Client,
) -> Result<Vec<HotRowLockHolder>, tokio_postgres::Error> {
    let tx = client.transaction().await?;
    tx.batch_execute(&format!(
        "SET LOCAL statement_timeout = '{HOT_ROW_HOLDER_READ_TIMEOUT_MS}ms'; \
         SET LOCAL lock_timeout = '{HOT_ROW_HOLDER_READ_TIMEOUT_MS}ms';"
    ))
    .await?;
    let rows = tx
        .query(HOT_ROW_HOLDER_SQL, &[&DRAIN_HOT_ROW_LOCK_KEY])
        .await?;
    tx.rollback().await?;
    rows.iter()
        .map(|row| {
            Ok(HotRowLockHolder {
                pid: row.try_get(0)?,
                role: row.try_get(1)?,
                application: row.try_get(2)?,
                client_address: row.try_get(3)?,
                state: row.try_get(4)?,
                state_age_ms: row.try_get(5)?,
            })
        })
        .collect()
}

/// Warn, naming the holder, that this process's waits for [`DRAIN_HOT_ROW_LOCK_KEY`] keep timing
/// out. Runs on the session whose wait just timed out; the caller closes that session after.
async fn log_hot_row_holder(
    client: &mut tokio_postgres::Client,
    procedure: &'static str,
    timeouts: u64,
) {
    // The failed lock step left its transaction aborted. The ROLLBACK also drops that
    // transaction's SET LOCAL bounds, so the holder read sets its own.
    let holders = match client.batch_execute("ROLLBACK").await {
        Ok(()) => hot_row_lock_holders(client)
            .await
            .map_err(|error| error.to_string()),
        Err(error) => Err(error.to_string()),
    };
    match holders {
        Ok(holders) if holders.is_empty() => tracing::warn!(
            procedure,
            timeouts,
            "drain hot-row lock waits keep timing out; no session holds the lock now"
        ),
        Ok(holders) => {
            crate::metrics::record_drain_hot_row_holder_named();
            for holder in holders {
                let fields = holder.log_fields();
                tracing::warn!(
                    procedure,
                    timeouts,
                    holder_pid = holder.pid,
                    holder_role = %fields.role,
                    holder_application = %fields.application,
                    holder_client = %fields.client,
                    holder_state = %fields.state,
                    holder_state_age_ms = %fields.state_age_ms,
                    "drain hot-row lock waits keep timing out; this session holds the lock \
                     (end it with pg_terminate_backend if it is not a loreserver)"
                );
            }
        }
        Err(error) => tracing::warn!(
            procedure,
            timeouts,
            %error,
            "drain hot-row lock waits keep timing out; the holder could not be read"
        ),
    }
}

/// Take [`DRAIN_HOT_ROW_LOCK_KEY`] for this session, waiting at most the preamble's lock timeout,
/// and arm the idle bounds that end a holder which stops (see the key's documentation).
async fn lock_hot_rows(
    client: &mut tokio_postgres::Client,
    preamble: &str,
    idle_bound: std::time::Duration,
) -> Result<(), tokio_postgres::Error> {
    let idle = idle_bound.as_millis().max(1);
    client
        .batch_execute(&format!(
            "BEGIN; {preamble} SELECT pg_advisory_lock({DRAIN_HOT_ROW_LOCK_KEY}); \
             SET idle_session_timeout = '{idle}ms'; \
             SET idle_in_transaction_session_timeout = '{idle}ms'; COMMIT;"
        ))
        .await
}

/// How a failed [`lock_hot_rows`] reads. Nothing reached the authority yet, so a lost race is
/// `Contended` and anything else is the session's failure (`Unavailable`), never an authority
/// refusal.
fn lock_step_failure(
    code: Option<&SqlState>,
) -> (DrainFailureCause, DrainError, HotRowSessionClose) {
    match code {
        Some(code) if *code == SqlState::LOCK_NOT_AVAILABLE => (
            DrainFailureCause::Contended,
            DrainError::Contended,
            HotRowSessionClose::LockTimeout,
        ),
        Some(code) if is_contention(code) => (
            DrainFailureCause::Contended,
            DrainError::Contended,
            HotRowSessionClose::LockFailed,
        ),
        _ => (
            DrainFailureCause::Session,
            DrainError::Unavailable,
            HotRowSessionClose::LockFailed,
        ),
    }
}

/// Release [`DRAIN_HOT_ROW_LOCK_KEY`] and reset the idle bounds. False when any of it failed or
/// the lock was not held; the caller then closes the session.
async fn unlock_hot_rows(client: &mut tokio_postgres::Client) -> bool {
    let Ok(messages) = client
        .simple_query(&format!(
            "SELECT pg_advisory_unlock({DRAIN_HOT_ROW_LOCK_KEY}); \
             RESET idle_session_timeout; RESET idle_in_transaction_session_timeout;"
        ))
        .await
    else {
        return false;
    };
    messages.iter().any(|message| {
        matches!(message, tokio_postgres::SimpleQueryMessage::Row(row) if row.get(0) == Some("t"))
    })
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
        self.query_with(isolation, false, sql, values).await
    }

    /// [`DrainClient::query`] under the cell's hot-row lock ([`DRAIN_HOT_ROW_LOCK_KEY`]): for a
    /// procedure that writes the quota or policy counters every reservation writes.
    pub(crate) async fn query_hot(
        &self,
        sql: &str,
        values: &[&(dyn tokio_postgres::types::ToSql + Sync)],
    ) -> Result<Vec<Row>, DrainError> {
        self.query_with(IsolationLevel::Serializable, true, sql, values)
            .await
    }

    async fn query_with(
        &self,
        isolation: IsolationLevel,
        hot: bool,
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
        // Why a hot-row session is closed, when the call fails (see `HotRowSessionClose`).
        let mut close = HotRowSessionClose::Failed;
        // One operation timeout covers the lock wait and the transaction; see the note on
        // `DRAIN_HOT_ROW_LOCK_KEY` about a commit that reads `Unavailable`.
        let operation = tokio::time::timeout(self.pool.operation_timeout(), async {
            let session = || failed(DrainFailureCause::Session, DrainError::Unavailable);
            let client = lease.client().map_err(|_error| session())?;
            if hot
                && let Err(e) = lock_hot_rows(
                    client,
                    &self.pool.bounded_execution_preamble(),
                    self.pool.operation_timeout(),
                )
                .await
            {
                let (cause, error, reason) = lock_step_failure(e.code());
                close = reason;
                if reason == HotRowSessionClose::LockTimeout {
                    let procedure = drain_procedure_label(sql);
                    crate::metrics::record_drain_hot_row_lock_wait_timeout(procedure);
                    let due = HOT_ROW_STALL_LOG
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .on_timeout(std::time::Instant::now());
                    if let Some(timeouts) = due {
                        log_hot_row_holder(client, procedure, timeouts).await;
                    }
                }
                return Err(failed(cause, error));
            }
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
            // The commit stands either way; a lock that did not unlock goes with its session.
            let unlocked = !hot || unlock_hot_rows(client).await;
            Ok((rows, unlocked))
        })
        .await;
        match operation {
            Ok(Ok((rows, true))) => {
                lease.release().await;
                Ok(rows)
            }
            Ok(Ok((rows, false))) => {
                crate::metrics::record_drain_hot_row_session_closed(
                    HotRowSessionClose::UnlockFailed,
                );
                lease.poison();
                Ok(rows)
            }
            Ok(Err(error)) => {
                if hot {
                    crate::metrics::record_drain_hot_row_session_closed(close);
                }
                lease.poison();
                Err(error)
            }
            Err(_) => {
                if hot {
                    crate::metrics::record_drain_hot_row_session_closed(
                        HotRowSessionClose::OperationTimeout,
                    );
                }
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

    /// One descriptor, one `SERIALIZABLE` transaction, under the hot-row lock
    /// ([`DRAIN_HOT_ROW_LOCK_KEY`]).
    pub async fn reserve(&self, descriptor: &DrainDescriptor) -> Result<(), DrainError> {
        let json = serde_json::to_string(descriptor).map_err(|_error| DrainError::Invalid)?;
        let canonical = descriptor.canonical_bytes()?;
        self.query_hot(
            "SELECT object_store_retention.drain_reserve_v1($1::text::jsonb,$2,$3)",
            &[&json, &canonical, &&blake3::hash(&canonical).as_bytes()[..]],
        )
        .await?;
        Ok(())
    }

    /// CAS-check a ready spool row before its provider send (cell schema R31).
    ///
    /// The token is the row's `(spool_revision, ready_at_unix_ms)` from its spool-ready outcome:
    /// within one row `spool_revision` only grows and a ready row is frozen, and `ready_at` is the
    /// database clock, so the pair names exactly one ready incarnation. It replaced the
    /// database-built record digest when BLAKE3 left `PostgreSQL`.
    pub async fn check_ready(
        &self,
        spool: Uuid,
        attempt: Uuid,
        spool_revision: u64,
        ready_at_unix_ms: i64,
        key: &str,
        deadline: i64,
    ) -> Result<(i64, u64), DrainError> {
        let spool_revision = spool_revision.to_string();
        let rows = self
            .query(
                "SELECT * FROM object_store_retention.drain_check_ready_v2($1,$2,$3::text::object_store_retention.uint64,$4,$5,$6)",
                &[
                    &spool,
                    &attempt,
                    &spool_revision,
                    &ready_at_unix_ms,
                    &key,
                    &deadline,
                ],
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

    /// drain-tput4: a failed hot-row lock step never reached the authority. A lock timeout and a
    /// lost race read `Contended`; anything else, a statement timeout or a SQLSTATE-less I/O
    /// failure included, reads `Unavailable`, never `Refused`.
    #[test]
    fn a_failed_hot_row_lock_step_is_contention_or_unavailable_never_a_refusal() {
        use DrainFailureCause as C;
        use HotRowSessionClose as R;
        assert_eq!(
            lock_step_failure(Some(&SqlState::LOCK_NOT_AVAILABLE)),
            (C::Contended, DrainError::Contended, R::LockTimeout)
        );
        for code in [
            SqlState::T_R_SERIALIZATION_FAILURE,
            SqlState::T_R_DEADLOCK_DETECTED,
        ] {
            assert_eq!(
                lock_step_failure(Some(&code)),
                (C::Contended, DrainError::Contended, R::LockFailed)
            );
        }
        for code in [
            Some(SqlState::QUERY_CANCELED),
            Some(SqlState::RAISE_EXCEPTION),
            Some(SqlState::ADMIN_SHUTDOWN),
            None,
        ] {
            assert_eq!(
                lock_step_failure(code.as_ref()),
                (C::Session, DrainError::Unavailable, R::LockFailed),
                "{code:?}"
            );
        }
    }

    /// drain-tput4: the stuck-holder warning needs repeated timeouts and is rate-limited.
    #[test]
    fn the_stuck_holder_warning_needs_repeated_timeouts_and_waits_a_period() {
        let start = std::time::Instant::now();
        let at = |seconds: u64| start + std::time::Duration::from_secs(seconds);
        let mut log = HotRowStallLog::new();
        // One or two timeouts are a busy moment.
        assert_eq!(log.on_timeout(at(0)), None);
        assert_eq!(log.on_timeout(at(1)), None);
        // The third is a holder that does not let go.
        assert_eq!(log.on_timeout(at(2)), Some(3));
        // Within the period, no second warning however many timeouts follow.
        for second in 3..32 {
            assert_eq!(log.on_timeout(at(second)), None, "second {second}");
        }
        // A period after the last warning, the next timeout warns with the count since then.
        assert_eq!(log.on_timeout(at(32)), Some(30));
        // A period has passed, but one timeout alone does not warn.
        assert_eq!(log.on_timeout(at(100)), None);
        assert_eq!(log.on_timeout(at(101)), None);
        assert_eq!(log.on_timeout(at(102)), Some(3));
        // drain-tput5: timeouts decay. Three spread wider than one period do not warn, however
        // long ago the last warning was.
        assert_eq!(log.on_timeout(at(200)), None);
        assert_eq!(log.on_timeout(at(240)), None);
        assert_eq!(log.on_timeout(at(280)), None);
        assert_eq!(log.on_timeout(at(400)), None);
        // Three inside one period do, and the warning counts every timeout since the last one.
        assert_eq!(log.on_timeout(at(401)), None);
        assert_eq!(log.on_timeout(at(430)), Some(6));
        assert_eq!(
            HotRowSessionClose::ALL.map(HotRowSessionClose::label),
            [
                "lock_timeout",
                "lock_failed",
                "failed",
                "unlock_failed",
                "operation_timeout"
            ]
        );
        // The local counts index by discriminant, so `ALL` must list the variants in order.
        for (index, reason) in HotRowSessionClose::ALL.into_iter().enumerate() {
            assert_eq!(reason as usize, index);
        }
    }

    /// drain-tput5: a NULL `pg_stat_activity` field reads as what it means, never as a bare
    /// `None`. Another role's session shows its role and application but hides the rest.
    #[test]
    fn the_holder_warning_names_hidden_fields_as_hidden() {
        let holder = |role: Option<&str>, client: Option<&str>, state: Option<&str>| {
            HotRowLockHolder {
                pid: 7,
                role: role.map(str::to_owned),
                application: role.map(|_| "psql".to_owned()),
                client_address: client.map(str::to_owned),
                state: state.map(str::to_owned),
                state_age_ms: state.map(|_| 1_500),
            }
            .log_fields()
        };
        // Another role's session, read without pg_read_all_stats.
        let hidden = holder(Some("other"), None, None);
        assert_eq!(hidden.role, "other");
        assert_eq!(hidden.application, "psql");
        for field in [&hidden.client, &hidden.state, &hidden.state_age_ms] {
            assert_eq!(field, HOT_ROW_HOLDER_HIDDEN);
        }
        // A visible session.
        let visible = holder(Some("rt"), Some("10.0.0.5"), Some("idle in transaction"));
        assert_eq!(visible.client, "10.0.0.5");
        assert_eq!(visible.state, "idle in transaction");
        assert_eq!(visible.state_age_ms, "1500");
        // A visible session over a Unix socket has no client address.
        assert_eq!(
            holder(Some("rt"), None, Some("active")).client,
            "local (Unix socket)"
        );
        // No pg_stat_activity row: the session just ended; nothing is hidden.
        let ended = holder(None, None, None);
        for field in [
            &ended.role,
            &ended.application,
            &ended.client,
            &ended.state,
            &ended.state_age_ms,
        ] {
            assert_eq!(field, "unknown (no pg_stat_activity row)");
        }
        // The address prints without its /32 netmask.
        assert!(HOT_ROW_HOLDER_SQL.contains("host(a.client_addr)"));
        assert!(!HOT_ROW_HOLDER_SQL.contains("client_addr::text"));
    }

    const PUT_CAPACITY: &str = "DISPATCH_RESERVE_PUT_CAPACITY_EXHAUSTED";
    const METADATA_CAPACITY: &str = "DRAIN_METADATA_CAPACITY";
    const UNDERFLOW: &str = "DRAIN_METADATA_UNDERFLOW";
    const RETIRED: &str = "DRAIN_ATTEMPT_RETIRED";

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
            | C::RefusedAttemptRetired
            | C::RefusedOther => DrainError::Refused,
            C::MetadataUnderflow => DrainError::MetadataUnderflow,
        }
    }

    #[test]
    fn drain_failure_cause_labels_are_fourteen_distinct_exact_literals() {
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
            "refused_attempt_retired",
            "unavailable_statement",
            "commit_contended",
            "commit_unknown",
        ];
        assert_eq!(DrainFailureCause::ALL.len(), 14);
        let labels: Vec<&str> = DrainFailureCause::ALL.iter().map(|c| c.label()).collect();
        assert_eq!(labels, expected, "ALL order and labels are pinned");
        let mut unique = labels.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), 14, "labels must be distinct");
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
        let not_in_state = SqlState::OBJECT_NOT_IN_PREREQUISITE_STATE;
        let table: [(Option<&SqlState>, Option<&str>, DrainFailureCause); 19] = [
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
            // 0032's retired-attempt refusal is 55000 plus its exact message; any other 55000
            // message is an ordinary refusal.
            (Some(&not_in_state), Some(RETIRED), C::RefusedAttemptRetired),
            (
                Some(&not_in_state),
                Some("DRAIN_ATTEMPT_RETIRED2"),
                C::RefusedOther,
            ),
            (Some(&not_in_state), None, C::RefusedOther),
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

    /// The drain client no longer calls the compaction procedure migration 0032 dropped, and it does
    /// call the replacement. Scanned over the SQL call sites (`"SELECT ...` literals), not the label
    /// table, which may keep naming a retired procedure.
    #[test]
    fn the_drain_client_calls_compact_v3_and_not_the_dropped_compact_v2() {
        let mut calls = Vec::new();
        for source in [
            include_str!("drain_policy.rs"),
            include_str!("drain_spool.rs"),
        ] {
            let production = source.split("#[cfg(test)]").next().unwrap_or(source);
            for line in production.lines() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") || !trimmed.contains("\"SELECT ") {
                    continue;
                }
                calls.push(trimmed.to_string());
            }
        }
        assert!(
            calls
                .iter()
                .any(|sql| sql.contains("drain_cleanup_compact_v3($1)")),
            "release_cleanup must call compact_v3 with the spool id only"
        );
        assert!(
            calls
                .iter()
                .all(|sql| !sql.contains("drain_cleanup_compact_v2")),
            "migration 0032 dropped drain_cleanup_compact_v2"
        );
    }

    /// This build's revision is the one migration 0032 installs, and the Rust enum agrees.
    #[test]
    fn the_client_revision_is_the_one_migration_0032_installs() {
        assert_eq!(CELL_SCHEMA_REVISION, 32);
        let migration =
            include_str!("../migrations/0032_object_store_dispatch_drain_retired_floor.sql");
        let flattened: String = migration
            .lines()
            .filter(|line| !line.trim_start().starts_with("--"))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            flattened.contains("SELECT 32"),
            "0032 must return 32 from cell_schema_revision_v1"
        );
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
                "SELECT * FROM object_store_retention.drain_check_ready_v2($1,$2,$3::text::object_store_retention.uint64,$4,$5,$6)",
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
                "SELECT object_store_retention.drain_cleanup_compact_v3($1)",
                "cleanup_compact",
            ),
            (
                "SELECT object_store_retention.drain_retired_floor_advance_v1($1,$2)",
                "retired_floor_advance",
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

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Domain-coordinator errors (CR-029).
//!
//! One per-module `thiserror` enum, translated once at the `lore-server` seam
//! rather than re-mapped in every handler. SQLSTATE and driver classification
//! happens here and nowhere else, so a caller never inspects a
//! `tokio_postgres::Error` itself.
//!
//! **`OutcomeUnknown` is not an error you retry.** A commit whose
//! acknowledgement was lost may or may not have applied. CR-029's rule, as
//! corrected by R-BLOCK-1, is that it maps to a gRPC code whose
//! `From<tonic::Status>` arm is *not* `Disconnected`: `lore-transport`
//! (`src/error.rs:22`) folds `Unavailable` **and** `Unknown` into
//! `ProtocolError::Disconnected`, and `grpc/mod.rs:1177` reissues on exactly
//! that variant. `ABORTED` is the selected code — it already carries "rerun
//! preflight and refetch authoritative state" in this CR, which is precisely the
//! outcome-unknown instruction. Phase 7 pins that with a regression test.

use std::fmt;

/// SQLSTATE class 40: serialization failure / deadlock detected. Bounded retry
/// is correct for these and only these.
const SQLSTATE_SERIALIZATION_FAILURE: &str = "40001";
const SQLSTATE_DEADLOCK_DETECTED: &str = "40P01";

/// Typed failure of a domain-coordinator method.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum DomainError {
    /// A caller-supplied value violates a frozen bound before any database work
    /// happens. Never retryable, never a partial write.
    #[error("invalid domain input: {0}")]
    InvalidInput(String),

    /// The domain schema is present but the cell has not completed backfill and
    /// cutover, so enforcement must stay off. Fails closed.
    #[error("domain enforcement requested before cutover: {0}")]
    NotReady(String),

    /// A generic-store write targeted a domain-owned key while enforcement is
    /// on. Explicit by design: no trait default, no downcast, no silent
    /// fallback.
    #[error("domain-owned key rejected on the generic mutable path: {0}")]
    DomainKeyBypass(String),

    /// A precondition (expected generation, CAS predicate, tombstone fence, name
    /// ownership) did not hold. Decisive: the transaction committed
    /// `NOT_APPLIED` with this reason and made no domain mutation.
    #[error("domain precondition rejected: {reason} (v{reason_version})")]
    PreconditionRejected {
        /// Versioned reason code recorded in the receipt.
        reason: String,
        /// Version of the reason vocabulary.
        reason_version: i32,
    },

    /// Serialization failure or deadlock. Bounded retry is correct.
    #[error("domain transaction contention: {0}")]
    Contention(String),

    /// Pool exhaustion or a transient connection/database failure. The caller
    /// surfaces `SlowDown` so clients back off.
    #[error("domain store transient failure: {0}")]
    Transient(String),

    /// The commit was issued but its acknowledgement was lost. **Never retried
    /// and never inferred from later repository, branch, or tombstone state.**
    #[error("domain commit outcome unknown: {0}")]
    OutcomeUnknown(String),

    /// Anything else, source-preserving.
    #[error("domain store internal error: {0}")]
    Internal(String),
}

impl DomainError {
    /// True only for the two classes a bounded retry may re-drive. Notably
    /// false for [`DomainError::OutcomeUnknown`], which must never be retried.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Contention(_) | Self::Transient(_))
    }

    /// Classify one driver error, in exactly one place.
    pub fn from_pg(context: &str, e: tokio_postgres::Error) -> Self {
        if let Some(sqlstate) = e.code().map(|c| c.code().to_owned())
            && (sqlstate == SQLSTATE_SERIALIZATION_FAILURE
                || sqlstate == SQLSTATE_DEADLOCK_DETECTED)
        {
            return Self::Contention(format!("{context}: {e}"));
        }
        if crate::pool::is_transient_pg(&e) {
            return Self::Transient(format!("{context}: {e}"));
        }
        Self::Internal(format!("{context}: {e}"))
    }

    /// Classify one pool-checkout error.
    pub fn from_pool(context: &str, e: deadpool_postgres::PoolError) -> Self {
        if crate::pool::is_transient_pool(&e) {
            Self::Transient(format!("{context}: {e}"))
        } else {
            Self::Internal(format!("{context}: {e}"))
        }
    }
}

/// Public outcome of one admitted domain operation, as committed into its
/// receipt. Every admitted attempt commits exactly one of these.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DomainOutcome {
    /// The mutation happened.
    Applied,
    /// It decisively did not, with a versioned reason and no domain mutation or
    /// event.
    NotApplied {
        /// Version of the reason vocabulary.
        reason_version: i32,
        /// Frozen reason code, e.g. `UUID_TIME_OUT_OF_RANGE_V1`.
        reason: String,
    },
}

impl fmt::Display for DomainOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Applied => write!(f, "APPLIED"),
            Self::NotApplied {
                reason_version,
                reason,
            } => write!(f, "NOT_APPLIED({reason_version}, {reason})"),
        }
    }
}

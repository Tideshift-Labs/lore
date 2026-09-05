// SPDX-FileCopyrightText: 2026 Tideshift Labs
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT

//! Client-side types for CR-029's domain-operation receipt lookup (WP-120).
//!
//! A caller that dispatched a domain mutation and never saw its answer cannot ask the current
//! state of the repository what happened: a successor mutation reproduces or obscures the same
//! observation. The receipt is the only thing that attributes an outcome to *one attempt*, so
//! this is the read a reconciler makes, and the shapes here exist to keep that read honest.
//!
//! Two properties the types carry rather than document:
//!
//! - the outcome lives *inside* [`DomainReceiptState::Committed`], so no caller can read a
//!   decisive `Applied`/`NotApplied` off a receipt that was merely `Prepared`, expired, or
//!   absent. Those are the states the contract calls non-attributive, and none of them has an
//!   outcome field to misread; and
//! - `authorization_id` is not a field. CR-029 v1 requires it to equal the operation id, and the
//!   server rejects a request where it does not, so the client derives it instead of asking a
//!   caller to restate a value that has exactly one correct answer.

use bytes::Bytes;
use uuid::Uuid;

/// The length of every digest on this rail: the fingerprint, the canonical intent digest, and
/// the consumed-ticket commitment.
pub const RECEIPT_DIGEST_LEN: usize = 32;

/// Everything a receipt lookup restates so the server can match one exact attempt.
///
/// Every field is a durable property of the original attempt, recorded before dispatch. None of
/// it is re-derived at reconciliation time: a fingerprint recomputed from current state would
/// describe the intent the caller has *now*, which is the thing the lookup is supposed to be
/// independent of.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainReceiptQuery {
    /// The verified organization the operation was scoped to.
    pub org_uuid: Uuid,
    /// The authenticated principal's receipt namespace. Selects which namespace is searched; it
    /// is deliberately not part of the canonical fingerprint.
    pub initiating_principal_namespace: Bytes,
    /// The attempt's own UUIDv7. Reused for this lookup and never for a mutation replay.
    pub operation_id: Uuid,
    /// The canonical method name the attempt was dispatched under.
    pub method: String,
    /// The canonical scope bytes for the attempt.
    pub scope: Bytes,
    /// Nonzero version of the fingerprint scheme the attempt used.
    pub fingerprint_version: u32,
    /// The versioned canonical request fingerprint, [`RECEIPT_DIGEST_LEN`] bytes.
    pub fingerprint: Bytes,
    /// The canonical intent digest, [`RECEIPT_DIGEST_LEN`] bytes.
    pub canonical_intent_digest: Bytes,
    /// Nonzero revision of the authorization the attempt was admitted under.
    pub authorization_revision: u64,
    /// The exact commitment persisted once the prepare ticket was consumed,
    /// [`RECEIPT_DIGEST_LEN`] bytes.
    pub consumed_ticket_sha256: Bytes,
}

impl DomainReceiptQuery {
    /// Reject a query that cannot match anything before it costs a round trip.
    ///
    /// Only structural invariants are checked: exact digest lengths, non-empty required bytes,
    /// nonzero versions, and a v7 operation id. The server's *upper* bounds on the method,
    /// scope, and namespace are deliberately not duplicated here. Copying a bound into the
    /// client makes two layers that each pin a literal to themselves and agree only by
    /// coincidence; the server owns those bounds and answers `InvalidArgument` when they are
    /// exceeded, which is a better outcome than a client that silently disagrees with it.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.initiating_principal_namespace.is_empty() {
            return Err("initiating_principal_namespace must not be empty");
        }
        if self.method.is_empty() {
            return Err("method must not be empty");
        }
        if self.scope.is_empty() {
            return Err("scope must not be empty");
        }
        if self.fingerprint_version == 0 {
            return Err("fingerprint_version must be nonzero");
        }
        if self.authorization_revision == 0 {
            return Err("authorization_revision must be nonzero");
        }
        if self.fingerprint.len() != RECEIPT_DIGEST_LEN {
            return Err("fingerprint must be exactly 32 bytes");
        }
        if self.canonical_intent_digest.len() != RECEIPT_DIGEST_LEN {
            return Err("canonical_intent_digest must be exactly 32 bytes");
        }
        if self.consumed_ticket_sha256.len() != RECEIPT_DIGEST_LEN {
            return Err("consumed_ticket_sha256 must be exactly 32 bytes");
        }
        if self.operation_id.get_version_num() != 7 {
            return Err("operation_id must be a UUIDv7");
        }
        Ok(())
    }
}

/// The decisive half of a committed receipt.
///
/// Reachable only from [`DomainReceiptState::Committed`], because only a committed receipt has
/// one. A `NotApplied` carries the versioned reason the server recorded; a reconciler reads the
/// version and code, never the prose.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DomainReceiptOutcome {
    /// The requested effect happened. Finalize as success; do not replay.
    Applied,
    /// The requested effect did not happen, and the server says so about *this* attempt.
    ///
    /// The reason version is required, not optional. WP-120 makes a `NOT_APPLIED` decisive only
    /// when it is *versioned*, and the server always emits a version with one, so an unversioned
    /// `NOT_APPLIED` is a response no honest server sends. Modelling it as `Option` would have
    /// left every caller to re-decide what a missing version means, and the contract has already
    /// decided: it is not something you may act on.
    NotApplied {
        /// Version of the reason vocabulary this reason is drawn from.
        reason_version: u32,
        /// The recorded reason. A caller branches on `reason_version` and this value as data,
        /// never by matching an error message.
        reason: String,
    },
}

/// What the server knows about one exact attempt.
///
/// Everything other than [`Self::Committed`] is non-attributive: it constrains nothing about
/// whether the mutation happened, so a reconciler holds its record open rather than resolving
/// it. The variants are kept distinct anyway, because the *reason* a lookup was inconclusive
/// decides whether asking again later can help.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DomainReceiptState {
    /// The attempt was prepared and never committed. Says nothing about the mutation.
    Prepared {
        /// When the server recorded the prepare.
        prepared_at_unix_millis: i64,
        /// When the prepare stops being honoured.
        hard_expires_at_unix_millis: i64,
    },
    /// The only decisive state.
    Committed {
        /// What the server recorded for this attempt.
        outcome: DomainReceiptOutcome,
        /// Set when the result came from a compact future-rejection marker rather than a full
        /// receipt row. Still a complete result; it does not decay to `Expired` at day 30.
        from_future_marker: bool,
    },
    /// Some part of the restated identity did not match a stored receipt.
    Mismatch,
    /// The full result was retained and has since been pruned to a compact tombstone.
    Expired,
    /// Even the tombstone is gone. The operation id stays permanently stale for mutation.
    ExpiredOrUnknown,
    /// No receipt under this identity. Absence is not proof the mutation did not happen.
    NotFound,
}

impl DomainReceiptState {
    /// Whether this state attributes an outcome to the exact attempt.
    ///
    /// The single predicate a reconciler branches on before it may resolve a durable record.
    /// Everything else stays unresolved, keeps its write latch, and is retried read-only.
    pub fn is_attributive(&self) -> bool {
        matches!(self, Self::Committed { .. })
    }
}

/// A receipt found by the attempt identity this client minted (WP-120).
///
/// The answer to the question a reconciler actually has. [`DomainReceipt`] answers "what happened
/// to the operation whose full intent I can restate", which a client that lost a response cannot
/// ask; this answers "what happened to the attempt I named before I dispatched it", which is the
/// only thing such a client still holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainAttemptReceipt {
    /// What the server knows about the attempt. Read exactly as [`DomainReceipt::state`] is.
    pub state: DomainReceiptState,
    /// The method the receipt was filed under, empty when nothing matched.
    ///
    /// A caller that journalled the method before dispatch can check this against it. Doing so is
    /// worth the trouble: a client reconciling several unresolved attempts at once has no other
    /// way to notice that it asked about one and was answered about another.
    pub method: String,
}

/// A receipt lookup's answer, with the witness the server echoed back.
///
/// The witness fields are evidence a caller persists next to the resolved record. Two of them
/// are genuinely server-derived: `verification_nonce` and `bound_fields_digest` come from what
/// the server verified. The other two are not new information — the server refuses the lookup
/// outright unless `consumed_ticket_sha256` and `authorization_revision` match what the caller
/// sent, so receiving them back is a restatement rather than a disclosure. They are still worth
/// storing beside the outcome, because a later audit reads the answer and the identity it was
/// given under from one record instead of joining two.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DomainReceipt {
    /// What the server knows about the attempt.
    pub state: DomainReceiptState,
    /// The immutable platform-verification witness recorded with the receipt.
    pub verification_nonce: Bytes,
    /// Digest of the fields the verification was bound to.
    pub bound_fields_digest: Bytes,
    /// The commitment the receipt is filed under. A lookup never returns the consume token.
    pub consumed_ticket_sha256: Bytes,
    /// The authorization revision the server verified this lookup under.
    pub authorization_revision: u64,
}

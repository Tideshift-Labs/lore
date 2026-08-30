// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Domain operation receipts: prepare, consume, commit, and lookup (CR-029).
//!
//! **Prepare and the terminal receipt are ONE state machine on ONE row**, not
//! two records. `prepare` inserts or exact-loads the keyed row as `PREPARED`
//! with an opaque 256-bit consume token; the mutation transaction locks that
//! same row, verifies the token and the immutable binding, and atomically
//! replaces `PREPARED` with a terminal `APPLIED` or
//! `NOT_APPLIED(reason_version, reason)`. A terminal row is immutable, and
//! lookup never returns the token.
//!
//! **One `clock_timestamp()` is the sole time authority** for every admission,
//! expiry, and retention decision an operation makes. A process clock is never
//! consulted, because two replicas with opposing skew must agree on whether a
//! given UUIDv7 is stale, in-window, or beyond the horizon. UUIDv7 *syntax* is
//! parsed before database access — that is a wire-format check, not a time
//! decision.
//!
//! **Nothing here manufactures a second ordinary operation row.** Neither
//! mutation admission nor lookup may create one, and a local rejection is
//! decisive without an ordinary receipt only when the future marker proves
//! admission was impossible.

use std::time::Duration;
use std::time::SystemTime;

use tokio_postgres::Transaction;
use uuid::Uuid;

use crate::domain::errors::DomainError;
use crate::domain::errors::DomainOutcome;
use crate::domain::schema;

// --- Frozen constants (CR-029; not tunable at runtime) ---------------------

/// A UUID timestamp at or below `clock + 5 minutes` is ordinary and admissible.
pub const NORMAL_FUTURE_SKEW: Duration = Duration::from_secs(5 * 60);
/// Above `NORMAL_FUTURE_SKEW` and up to this bound, admission commits an
/// attributable `NOT_APPLIED` with a real receipt. Strictly below the retained-
/// marker safety deadline, deliberately.
pub const RECEIPT_BEARING_FUTURE_HORIZON: Duration = Duration::from_secs(24 * 60 * 60);
/// An unconsumed `PREPARED` row becomes terminal at this age, so process loss
/// cannot leave a permanent prepared wedge.
pub const PREPARED_HARD_TTL: Duration = Duration::from_secs(15 * 60);
/// Older than this and first-seen, an operation is non-attributive.
pub const STALE_HORIZON: Duration = Duration::from_secs(365 * 24 * 60 * 60);
/// Extra retention on a compact marker past the stale horizon.
pub const MARKER_SAFETY_EPSILON: Duration = Duration::from_secs(24 * 60 * 60);
/// Maximum replay result retained by the frozen CR-029 receipt schema.
pub const PUBLIC_RESULT_MAX_BYTES: usize = 4096;
/// Full receipts remain for 30 days; compact evidence outlives them.
pub const FULL_RESULT_RETENTION: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Frozen versioned reason codes.
pub const REASON_VERSION: i32 = 1;
/// Above the ordinary skew, within the receipt-bearing horizon.
pub const UUID_TIME_OUT_OF_RANGE_V1: &str = "UUID_TIME_OUT_OF_RANGE_V1";
/// Beyond the receipt-bearing horizon; recorded as a compact marker.
pub const UUID_FUTURE_HORIZON_EXCEEDED_V1: &str = "UUID_FUTURE_HORIZON_EXCEEDED_V1";
/// An unconsumed prepared row that reached its hard TTL.
pub const PREPARED_HARD_TTL_EXPIRED_V1: &str = "PREPARED_HARD_TTL_EXPIRED_V1";

/// The four-part receipt key. The verified issuer, authenticated subject, and
/// tenant scope select the namespace; they are **never** serialized into the
/// fingerprint bytes, so the same canonical intent under another issuer,
/// subject, or scope has the same fingerprint but addresses an independent
/// authorized namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptKey {
    /// Verified token issuer.
    pub verified_issuer: String,
    /// Authenticated subject.
    pub authenticated_subject: String,
    /// Versioned canonical tuple over the **target** resource identity, derived
    /// independently of the token's resource list. `urc-*` never appears in it
    /// (CR-029 R-BLOCK-5).
    pub tenant_scope_key: Vec<u8>,
    /// RFC 9562 UUIDv7, 16 bytes.
    pub operation_id: Uuid,
}

/// The caller-known intent an exact retry must reproduce byte-for-byte.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationBinding {
    /// Governed method name.
    pub method: String,
    /// Canonical scope bytes.
    pub scope: Vec<u8>,
    /// Fingerprint schema version.
    pub fingerprint_version: i32,
    /// BLAKE3 over the canonical caller-controlled fields. Excludes the
    /// authenticated principal, server-assigned timestamps, and every
    /// server-side observation.
    pub fingerprint: Vec<u8>,
    /// Digest of the canonical intent.
    pub canonical_intent_digest: Vec<u8>,
}

/// Result of `domain_operation_prepare`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrepareResult {
    /// Admitted. The token is single-use, non-loggable, and valid only for this
    /// exact namespace/method/scope/fingerprint.
    Prepared {
        /// The opaque 256-bit consume token.
        token: [u8; 32],
        /// When the unconsumed row becomes terminal.
        hard_expires_at: SystemTime,
    },
    /// Already decided. Decisive.
    Committed(DomainOutcome),
    /// First seen and older than the stale horizon. Non-attributive: no row, no
    /// marker, no authorization, no claim, no quota allocation, no dispatch.
    ExpiredOrUnknown,
    /// The key exists under a different binding. Nothing is mutated.
    Mismatch,
    /// Future-marker quota is full. Admission backpressure, never an outcome,
    /// and no identity is written.
    CapacityExhausted,
}

/// Result of `domain_operation_receipt_get`. Read-only; never mutates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptLookup {
    /// Nonterminal. Bounded binding/timing metadata only — never the token and
    /// never a decisive result. Public status maps this to `OutcomeUnknown`.
    Prepared {
        /// When the row was admitted.
        prepared_at: SystemTime,
        /// When it becomes terminal without a consume.
        hard_expires_at: SystemTime,
    },
    /// Decisive, with the authority that produced it.
    Committed {
        /// `APPLIED`, or `NOT_APPLIED` with a versioned reason.
        outcome: DomainOutcome,
        /// True when the authority is an exact compact future marker rather
        /// than an ordinary receipt.
        from_future_marker: bool,
    },
    /// The key exists under a different caller-known intent. Fails closed.
    Mismatch,
    /// An ordinary receipt whose full result aged out at 30 days.
    Expired,
    /// Safely pruned, or never admissible. Non-attributive.
    ExpiredOrUnknown,
    /// No row of any kind.
    NotFound,
}

/// Extract the RFC 9562 UUIDv7 timestamp.
///
/// Syntax and version are parsed before database access on purpose: a malformed
/// or non-v7 key is a wire-format error that must be rejected before prepare,
/// claim, or dispatch, and rejecting it costs no transaction. The *time
/// decision* that follows still uses only the database clock.
pub fn uuid_v7_timestamp(id: &Uuid) -> Result<SystemTime, DomainError> {
    if id.get_version_num() != 7 {
        return Err(DomainError::InvalidInput(format!(
            "operation ID must be a UUIDv7, got version {}",
            id.get_version_num()
        )));
    }
    let ts = id.get_timestamp().ok_or_else(|| {
        DomainError::InvalidInput("UUIDv7 carries no extractable timestamp".to_owned())
    })?;
    let (secs, nanos) = ts.to_unix();
    SystemTime::UNIX_EPOCH
        .checked_add(Duration::new(secs, nanos))
        .ok_or_else(|| DomainError::InvalidInput("UUIDv7 timestamp overflows".to_owned()))
}

/// How one UUID timestamp classifies against the single admission clock.
///
/// Split out as a pure function so the boundaries are testable without a
/// database. The clock value itself must still come from Postgres.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemporalClass {
    /// Older than `clock - 365 days`.
    Stale,
    /// Within `[clock - 365 days, clock + 5 minutes]`.
    Admissible,
    /// In `(clock + 5 minutes, clock + 24 hours]`.
    ReceiptBearingFuture,
    /// Beyond `clock + 24 hours`.
    BeyondHorizon,
}

/// Classify one UUID timestamp against one admission clock.
///
/// Both bounds are inclusive where CR-029 says inclusive: a timestamp exactly at
/// `clock - 365 days` or exactly at `clock + 5 minutes` is admissible, and one
/// exactly at `clock + 24 hours` is still receipt-bearing rather than beyond the
/// horizon.
pub fn classify(uuid_timestamp: SystemTime, admission_clock: SystemTime) -> TemporalClass {
    if let Ok(behind) = admission_clock.duration_since(uuid_timestamp) {
        return if behind > STALE_HORIZON {
            TemporalClass::Stale
        } else {
            TemporalClass::Admissible
        };
    }
    // `duration_since` erred, so the UUID is ahead of the clock.
    let ahead = uuid_timestamp
        .duration_since(admission_clock)
        .unwrap_or(Duration::ZERO);
    if ahead <= NORMAL_FUTURE_SKEW {
        TemporalClass::Admissible
    } else if ahead <= RECEIPT_BEARING_FUTURE_HORIZON {
        TemporalClass::ReceiptBearingFuture
    } else {
        TemporalClass::BeyondHorizon
    }
}

/// Read the transaction's single admission clock.
///
/// Called exactly once per operation. Every downstream comparison uses the
/// returned value rather than calling `clock_timestamp()` again, so an operation
/// cannot straddle two instants.
pub async fn admission_clock(tx: &Transaction<'_>) -> Result<SystemTime, DomainError> {
    let row = tx
        .query_one("SELECT clock_timestamp() AS now", &[])
        .await
        .map_err(|e| DomainError::from_pg("admission clock", e))?;
    Ok(row.get("now"))
}

/// Lock the receipt row for this key.
///
/// **Position 0 in CR-032's F-032-3 lock order**, ahead of repository, branch,
/// lock namespace, fragments, associations, and the outbox insert. Prepare and
/// consume are the admission gate, so a mutation transaction takes this row
/// before it touches any domain state — which is both natural and the only
/// position that avoids a receipt-then-repository versus repository-then-receipt
/// deadlock cycle.
///
/// The future-rejection quota row is deliberately NOT in this chain: it is taken
/// only by rejection admission and by bounded prune/cleanup, which write no
/// receipt, authorization, claim, domain, or outbox row, so it is a disjoint
/// single-row lock.
async fn lock_receipt_row(
    tx: &Transaction<'_>,
    key: &ReceiptKey,
) -> Result<Option<ReceiptRow>, DomainError> {
    let row = tx
        .query_opt(
            "SELECT state, consume_token, outcome, not_applied_reason_version, \
                    not_applied_reason, method, scope, fingerprint_version, fingerprint, \
                    canonical_intent_digest, public_result, \
                    prepared_at, hard_expires_at, committed_at, full_result_expires_at, \
                    compact_expires_at, compacted \
             FROM lore_domain_operation_receipts \
             WHERE verified_issuer = $1 AND authenticated_subject = $2 \
               AND tenant_scope_key = $3 AND operation_id = $4 \
             FOR UPDATE",
            &[
                &key.verified_issuer,
                &key.authenticated_subject,
                &key.tenant_scope_key,
                &key.operation_id.as_bytes().as_slice(),
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("receipt row lock", e))?;

    Ok(row.map(|r| ReceiptRow {
        state: r.get("state"),
        consume_token: r.get("consume_token"),
        outcome: r.get("outcome"),
        not_applied_reason_version: r.get("not_applied_reason_version"),
        not_applied_reason: r.get("not_applied_reason"),
        method: r.get("method"),
        scope: r.get("scope"),
        fingerprint_version: r.get("fingerprint_version"),
        fingerprint: r.get("fingerprint"),
        canonical_intent_digest: r.get("canonical_intent_digest"),
        public_result: r.get("public_result"),
        prepared_at: r.get("prepared_at"),
        hard_expires_at: r.get("hard_expires_at"),
        committed_at: r.get("committed_at"),
        full_result_expires_at: r.get("full_result_expires_at"),
    }))
}

struct ReceiptRow {
    state: i16,
    consume_token: Option<Vec<u8>>,
    outcome: Option<i16>,
    not_applied_reason_version: Option<i32>,
    not_applied_reason: Option<String>,
    method: String,
    scope: Vec<u8>,
    fingerprint_version: i32,
    fingerprint: Vec<u8>,
    canonical_intent_digest: Vec<u8>,
    public_result: Option<Vec<u8>>,
    prepared_at: SystemTime,
    hard_expires_at: SystemTime,
    committed_at: Option<SystemTime>,
    full_result_expires_at: Option<SystemTime>,
}

impl ReceiptRow {
    fn matches(&self, binding: &OperationBinding) -> bool {
        self.method == binding.method
            && self.scope == binding.scope
            && self.fingerprint_version == binding.fingerprint_version
            && self.fingerprint == binding.fingerprint
            && self.canonical_intent_digest == binding.canonical_intent_digest
    }

    fn committed_outcome(&self) -> Result<DomainOutcome, DomainError> {
        match self.outcome {
            Some(schema::RECEIPT_OUTCOME_APPLIED) => Ok(DomainOutcome::Applied),
            Some(schema::RECEIPT_OUTCOME_NOT_APPLIED) => Ok(DomainOutcome::NotApplied {
                reason_version: self.not_applied_reason_version.unwrap_or(REASON_VERSION),
                reason: self
                    .not_applied_reason
                    .clone()
                    .unwrap_or_else(|| "UNKNOWN".to_owned()),
            }),
            other => Err(DomainError::Internal(format!(
                "committed receipt has outcome {other:?}, which the state CHECK should forbid"
            ))),
        }
    }
}

/// Drive an unconsumed `PREPARED` row past its hard TTL, in place.
///
/// Every prepare, get, and consume touch performs this same transition, and so
/// does the bounded sweeper. That redundancy is the point: a process that dies
/// between prepare and consume leaves a row that the next toucher terminalizes,
/// so there is no path to a permanent prepared wedge.
async fn expire_prepared(
    tx: &Transaction<'_>,
    key: &ReceiptKey,
    admission_clock: SystemTime,
) -> Result<DomainOutcome, DomainError> {
    let outcome = DomainOutcome::NotApplied {
        reason_version: REASON_VERSION,
        reason: PREPARED_HARD_TTL_EXPIRED_V1.to_owned(),
    };
    commit_terminal(tx, key, &outcome, None, admission_clock).await?;
    Ok(outcome)
}

/// Transition a locked `PREPARED` row to its immutable terminal state.
///
/// The retention deadlines are derived from the caller's single admission clock
/// rather than from `now()`, so a receipt committed by a replica with skewed
/// process time still expires on the database's schedule.
pub async fn commit_terminal(
    tx: &Transaction<'_>,
    key: &ReceiptKey,
    outcome: &DomainOutcome,
    public_result: Option<&[u8]>,
    admission_clock: SystemTime,
) -> Result<(), DomainError> {
    if public_result.is_some_and(|result| result.len() > PUBLIC_RESULT_MAX_BYTES) {
        return Err(DomainError::InvalidInput(format!(
            "receipt public result exceeds {PUBLIC_RESULT_MAX_BYTES} bytes"
        )));
    }
    let (outcome_code, reason_version, reason) = match outcome {
        DomainOutcome::Applied => (schema::RECEIPT_OUTCOME_APPLIED, None, None),
        DomainOutcome::NotApplied {
            reason_version,
            reason,
        } => (
            schema::RECEIPT_OUTCOME_NOT_APPLIED,
            Some(*reason_version),
            Some(reason.clone()),
        ),
    };

    let full_expiry = admission_clock
        .checked_add(FULL_RESULT_RETENTION)
        .ok_or_else(|| DomainError::Internal("full-result retention overflows".to_owned()))?;
    let compact_expiry = later_of_compact_deadline(admission_clock, key)?;

    let updated = tx
        .execute(
            "UPDATE lore_domain_operation_receipts \
             SET state = $1, consume_token = NULL, outcome = $2, \
                 not_applied_reason_version = $3, not_applied_reason = $4, \
                 public_result = $5, committed_at = $6, \
                 full_result_expires_at = $7, compact_expires_at = $8 \
             WHERE verified_issuer = $9 AND authenticated_subject = $10 \
               AND tenant_scope_key = $11 AND operation_id = $12 \
               AND state = $13",
            &[
                &schema::RECEIPT_STATE_COMMITTED,
                &outcome_code,
                &reason_version,
                &reason,
                &public_result,
                &admission_clock,
                &full_expiry,
                &compact_expiry,
                &key.verified_issuer,
                &key.authenticated_subject,
                &key.tenant_scope_key,
                &key.operation_id.as_bytes().as_slice(),
                &schema::RECEIPT_STATE_PREPARED,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("receipt commit", e))?;

    if updated == 0 {
        return Err(DomainError::Internal(
            "receipt commit matched no PREPARED row; a terminal row is immutable and \
             must never be rewritten"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Compact evidence outlives the full result: the later of
/// `committed_at + 365 days` and `uuid_timestamp + 365 days + 24 hours`.
///
/// The second term is what stops an old-but-not-yet-safe ID from being re-
/// admitted after its receipt aged out — the marker must outlive the window in
/// which the same ID could still arrive.
fn later_of_compact_deadline(
    admission_clock: SystemTime,
    key: &ReceiptKey,
) -> Result<SystemTime, DomainError> {
    let from_commit = admission_clock
        .checked_add(STALE_HORIZON)
        .ok_or_else(|| DomainError::Internal("compact retention overflows".to_owned()))?;
    let uuid_ts = uuid_v7_timestamp(&key.operation_id)?;
    let from_uuid = uuid_ts
        .checked_add(STALE_HORIZON)
        .and_then(|t| t.checked_add(MARKER_SAFETY_EPSILON))
        .ok_or_else(|| DomainError::Internal("compact retention overflows".to_owned()))?;
    Ok(if from_uuid > from_commit {
        from_uuid
    } else {
        from_commit
    })
}

/// A locked, verified `PREPARED` row. Holding one is the proof a mutation is
/// admitted; it is produced only by [`consume`] and only inside the mutation
/// transaction that will commit its terminal receipt.
#[derive(Debug)]
pub struct ConsumedAdmission {
    /// The key whose terminal receipt this transaction owes.
    pub key: ReceiptKey,
    /// The single admission clock for this transaction.
    pub admission_clock: SystemTime,
}

/// Result of locking the admission row for a governed mutation.
pub enum ConsumeResult {
    /// A live PREPARED token was consumed and the transaction may mutate.
    Admitted(ConsumedAdmission),
    /// The operation already has a durable decisive outcome. This includes a
    /// PREPARED row terminalized by the hard-TTL check in this transaction.
    Committed {
        /// Durable terminal outcome.
        outcome: DomainOutcome,
        /// Retained opaque method result, when the operation stored one.
        public_result: Option<Vec<u8>>,
    },
    /// Missing, mismatched, or invalid-token admission. Nothing was mutated.
    Rejected,
}

/// `domain_operation_prepare`.
///
/// Runs in its own transaction, ahead of the mutation transaction. Creates or
/// exact-loads the keyed `PREPARED` row, or commits the frozen temporal
/// `NOT_APPLIED`, or records/loads the compact future marker — before any
/// mutation transaction exists.
///
/// Authorization completes before this is called. No authorization failure ever
/// manufactures a Lore row or a rejection marker.
pub async fn prepare(
    tx: &Transaction<'_>,
    key: &ReceiptKey,
    binding: &OperationBinding,
    witness: Option<&AuthorizationWitness>,
) -> Result<PrepareResult, DomainError> {
    let clock = admission_clock(tx).await?;
    let uuid_ts = uuid_v7_timestamp(&key.operation_id)?;

    // Exact-load first: an existing row, terminal or prepared, is authoritative
    // and no classification can override it.
    if let Some(row) = lock_receipt_row(tx, key).await? {
        if !row.matches(binding) {
            return Ok(PrepareResult::Mismatch);
        }
        if row.state == schema::RECEIPT_STATE_COMMITTED {
            return Ok(PrepareResult::Committed(row.committed_outcome()?));
        }
        if clock >= row.hard_expires_at {
            return Ok(PrepareResult::Committed(
                expire_prepared(tx, key, clock).await?,
            ));
        }
        let token = row.consume_token.ok_or_else(|| {
            DomainError::Internal(
                "a PREPARED row without a consume token; the state CHECK should forbid it"
                    .to_owned(),
            )
        })?;
        let token: [u8; 32] = token.as_slice().try_into().map_err(|_| {
            DomainError::Internal("stored consume token is not 32 bytes".to_owned())
        })?;
        return Ok(PrepareResult::Prepared {
            token,
            hard_expires_at: row.hard_expires_at,
        });
    }

    // No ordinary row. A compact future marker under the same key is itself a
    // complete decisive result and is consulted before classification.
    if let Some(marker) = load_future_marker(tx, key, binding).await? {
        return Ok(match marker {
            FutureMarker::Exact(outcome) => PrepareResult::Committed(outcome),
            FutureMarker::Mismatch => PrepareResult::Mismatch,
        });
    }

    match classify(uuid_ts, clock) {
        // First seen and older than the horizon. Creates nothing at all — not a
        // PREPARED row, receipt, marker, quota allocation, or outcome.
        TemporalClass::Stale => Ok(PrepareResult::ExpiredOrUnknown),

        TemporalClass::Admissible => {
            let token = new_consume_token();
            let hard_expires_at = clock
                .checked_add(PREPARED_HARD_TTL)
                .ok_or_else(|| DomainError::Internal("prepared hard TTL overflows".to_owned()))?;
            insert_prepared(
                tx,
                key,
                binding,
                witness,
                &token,
                uuid_ts,
                clock,
                hard_expires_at,
            )
            .await?;
            Ok(PrepareResult::Prepared {
                token,
                hard_expires_at,
            })
        }

        // Attributable: a real receipt, committed with no domain mutation or
        // event. Distinct from the beyond-horizon case, which gets a marker.
        TemporalClass::ReceiptBearingFuture => {
            let token = new_consume_token();
            let hard_expires_at = clock
                .checked_add(PREPARED_HARD_TTL)
                .ok_or_else(|| DomainError::Internal("prepared hard TTL overflows".to_owned()))?;
            insert_prepared(
                tx,
                key,
                binding,
                witness,
                &token,
                uuid_ts,
                clock,
                hard_expires_at,
            )
            .await?;
            let outcome = DomainOutcome::NotApplied {
                reason_version: REASON_VERSION,
                reason: UUID_TIME_OUT_OF_RANGE_V1.to_owned(),
            };
            commit_terminal(tx, key, &outcome, None, clock).await?;
            Ok(PrepareResult::Committed(outcome))
        }

        // Beyond the receipt-bearing horizon: a compact marker under quota, and
        // no ordinary operation row, platform claim, reservation, mutation,
        // event, or dispatch.
        TemporalClass::BeyondHorizon => {
            insert_future_marker(tx, key, binding, uuid_ts, clock).await
        }
    }
}

/// Server-only authorization/execution evidence recorded beside a receipt.
/// Never a fingerprint input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationWitness {
    /// Platform authorization row identity.
    pub authorization_id: Vec<u8>,
    /// Monotonic authorization revision.
    pub authorization_revision: i64,
    /// Immutable verification nonce from the consume transition.
    pub verification_nonce: Vec<u8>,
    /// Digest over the bound fields.
    pub bound_fields_digest: Vec<u8>,
    /// SHA-256 commitment to the consumed preclaim ticket. The ticket secret is
    /// never persisted anywhere.
    pub consumed_ticket_sha256: Vec<u8>,
    /// Frozen BLAKE3-256 claim-identity digest minted by the platform verify
    /// CAS. Lore stores and exact-matches these bytes; it never derives them.
    pub expected_claim_identity_digest: Vec<u8>,
}

/// Mint a 256-bit consume token from the OS CSPRNG.
fn new_consume_token() -> [u8; 32] {
    rand::random()
}

/// Compare two consume tokens in constant time.
///
/// The token is a bearer secret: whoever holds it may commit the mutation. A
/// short-circuiting `==` leaks a prefix-match oracle to anyone who can measure
/// the response, and an attacker who can retry cheaply can walk a token out
/// byte by byte. The comparison is fixed-width and unconditional.
fn tokens_match(stored: &[u8], presented: &[u8; 32]) -> bool {
    if stored.len() != presented.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in stored.iter().zip(presented.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[allow(clippy::too_many_arguments)]
async fn insert_prepared(
    tx: &Transaction<'_>,
    key: &ReceiptKey,
    binding: &OperationBinding,
    witness: Option<&AuthorizationWitness>,
    token: &[u8; 32],
    uuid_timestamp: SystemTime,
    prepared_at: SystemTime,
    hard_expires_at: SystemTime,
) -> Result<(), DomainError> {
    tx.execute(
        "INSERT INTO lore_domain_operation_receipts ( \
             verified_issuer, authenticated_subject, tenant_scope_key, operation_id, \
             method, scope, fingerprint_version, fingerprint, canonical_intent_digest, \
             state, consume_token, \
             authorization_id, authorization_revision, verification_nonce, \
             bound_fields_digest, consumed_ticket_sha256, \
             uuid_timestamp, prepared_at, hard_expires_at \
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, \
                   $12, $13, $14, $15, $16, $17, $18, $19)",
        &[
            &key.verified_issuer,
            &key.authenticated_subject,
            &key.tenant_scope_key,
            &key.operation_id.as_bytes().as_slice(),
            &binding.method,
            &binding.scope,
            &binding.fingerprint_version,
            &binding.fingerprint,
            &binding.canonical_intent_digest,
            &schema::RECEIPT_STATE_PREPARED,
            &token.as_slice(),
            &witness.map(|w| w.authorization_id.clone()),
            &witness.map(|w| w.authorization_revision),
            &witness.map(|w| w.verification_nonce.clone()),
            &witness.map(|w| w.bound_fields_digest.clone()),
            &witness.map(|w| w.consumed_ticket_sha256.clone()),
            &uuid_timestamp,
            &prepared_at,
            &hard_expires_at,
        ],
    )
    .await
    .map_err(|e| DomainError::from_pg("receipt prepare insert", e))?;

    if let Some(witness) = witness {
        insert_dispatch_possibility_fence(tx, key, binding, witness, prepared_at).await?;
    }
    Ok(())
}

async fn insert_dispatch_possibility_fence(
    tx: &Transaction<'_>,
    key: &ReceiptKey,
    binding: &OperationBinding,
    witness: &AuthorizationWitness,
    created_at: SystemTime,
) -> Result<(), DomainError> {
    if witness.expected_claim_identity_digest.len() != 32 {
        return Err(DomainError::InvalidInput(
            "expected claim identity digest must be exactly 32 bytes".to_owned(),
        ));
    }
    let safe_prune_after = later_of_compact_deadline(created_at, key)?;
    tx.execute(
        "INSERT INTO lore_domain_operation_dispatch_possibility_fences ( \
             verified_issuer, authenticated_subject, tenant_scope_key, operation_id, \
             method, scope, fingerprint_version, fingerprint, canonical_intent_digest, \
             authorization_id, authorization_revision, verification_nonce, \
             bound_fields_digest, consumed_ticket_sha256, expected_claim_identity_digest, \
             created_revision, created_at, safe_prune_after \
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)",
        &[
            &key.verified_issuer,
            &key.authenticated_subject,
            &key.tenant_scope_key,
            &key.operation_id.as_bytes().as_slice(),
            &binding.method,
            &binding.scope,
            &binding.fingerprint_version,
            &binding.fingerprint,
            &binding.canonical_intent_digest,
            &witness.authorization_id,
            &witness.authorization_revision,
            &witness.verification_nonce,
            &witness.bound_fields_digest,
            &witness.consumed_ticket_sha256,
            &witness.expected_claim_identity_digest,
            &witness.authorization_revision,
            &created_at,
            &safe_prune_after,
        ],
    )
    .await
    .map_err(|e| DomainError::from_pg("dispatch possibility fence insert", e))?;
    Ok(())
}

enum FutureMarker {
    Exact(DomainOutcome),
    Mismatch,
}

/// Exact-load a compact future marker, checking the caller-known binding.
///
/// The binding check is not optional. A marker is a decisive
/// `COMMITTED NOT_APPLIED`, so returning one for a *different* caller-known
/// intent that happens to share the operation ID would answer one operation
/// with another operation's outcome. Mismatched reuse fails closed here exactly
/// as it does for an ordinary receipt.
async fn load_future_marker(
    tx: &Transaction<'_>,
    key: &ReceiptKey,
    binding: &OperationBinding,
) -> Result<Option<FutureMarker>, DomainError> {
    let row = tx
        .query_opt(
            "SELECT method, scope, fingerprint_version, fingerprint, \
                    reason_version, reason \
             FROM lore_domain_operation_future_rejections \
             WHERE verified_issuer = $1 AND authenticated_subject = $2 \
               AND tenant_scope_key = $3 AND operation_id = $4",
            &[
                &key.verified_issuer,
                &key.authenticated_subject,
                &key.tenant_scope_key,
                &key.operation_id.as_bytes().as_slice(),
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("future marker lookup", e))?;

    let Some(r) = row else { return Ok(None) };

    let method: String = r.get("method");
    let scope: Vec<u8> = r.get("scope");
    let fingerprint_version: i32 = r.get("fingerprint_version");
    let fingerprint: Vec<u8> = r.get("fingerprint");
    if method != binding.method
        || scope != binding.scope
        || fingerprint_version != binding.fingerprint_version
        || fingerprint != binding.fingerprint
    {
        return Ok(Some(FutureMarker::Mismatch));
    }

    Ok(Some(FutureMarker::Exact(DomainOutcome::NotApplied {
        reason_version: r.get("reason_version"),
        reason: r.get("reason"),
    })))
}

/// Record or exact-load a compact future-rejection marker under quota.
///
/// The quota row is a disjoint single-row lock (F-032-3's amendment says so
/// explicitly), taken under UPSERT. `FUTURE_REJECT_QUOTA_V1` permits 1,024
/// retained markers and 64 newly admitted markers per fixed UTC database-clock
/// hour in one namespace. At either limit this returns
/// [`PrepareResult::CapacityExhausted`] and writes **no** marker, receipt,
/// authorization, claim, or operation identity — it is admission backpressure,
/// never `APPLIED`/`NOT_APPLIED`, and it does not block ordinary in-window
/// operations.
async fn insert_future_marker(
    tx: &Transaction<'_>,
    key: &ReceiptKey,
    binding: &OperationBinding,
    uuid_timestamp: SystemTime,
    clock: SystemTime,
) -> Result<PrepareResult, DomainError> {
    let quota = tx
        .query_one(
            "INSERT INTO lore_domain_operation_future_reject_quotas ( \
                 verified_issuer, authenticated_subject, tenant_scope_key, \
                 quota_version, retained_count, bucket_start, bucket_count, updated_at \
             ) VALUES ($1, $2, $3, $4, 0, \
                       date_trunc('hour', $5::timestamptz AT TIME ZONE 'UTC') AT TIME ZONE 'UTC', \
                       0, $5) \
             ON CONFLICT (verified_issuer, authenticated_subject, tenant_scope_key) DO UPDATE \
             SET bucket_start = CASE \
                     WHEN lore_domain_operation_future_reject_quotas.bucket_start \
                          < date_trunc('hour', $5::timestamptz AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' \
                     THEN date_trunc('hour', $5::timestamptz AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' \
                     ELSE lore_domain_operation_future_reject_quotas.bucket_start END, \
                 bucket_count = CASE \
                     WHEN lore_domain_operation_future_reject_quotas.bucket_start \
                          < date_trunc('hour', $5::timestamptz AT TIME ZONE 'UTC') AT TIME ZONE 'UTC' \
                     THEN 0 ELSE lore_domain_operation_future_reject_quotas.bucket_count END, \
                 updated_at = $5 \
             RETURNING retained_count, bucket_count",
            &[
                &key.verified_issuer,
                &key.authenticated_subject,
                &key.tenant_scope_key,
                &schema::FUTURE_REJECT_QUOTA_VERSION,
                &clock,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("future reject quota upsert", e))?;

    let retained: i64 = quota.get("retained_count");
    let hourly: i64 = quota.get("bucket_count");
    if retained >= schema::FUTURE_REJECT_QUOTA_RETAINED_MAX
        || hourly >= schema::FUTURE_REJECT_QUOTA_HOURLY_MAX
    {
        return Ok(PrepareResult::CapacityExhausted);
    }

    let prune_after = later_of_compact_deadline(clock, key)?;
    // Rows affected decides whether the counters move. `ON CONFLICT DO NOTHING`
    // means a concurrent duplicate inserts nothing, and incrementing regardless
    // would over-count permanently — the namespace would drift toward
    // CapacityExhausted with fewer retained markers than the counter claims,
    // and nothing would ever correct it.
    let inserted = tx
        .execute(
            "INSERT INTO lore_domain_operation_future_rejections ( \
             verified_issuer, authenticated_subject, tenant_scope_key, operation_id, \
             method, scope, fingerprint_version, fingerprint, \
             reason_version, reason, uuid_timestamp, rejected_at, prune_after \
         ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) \
         ON CONFLICT (verified_issuer, authenticated_subject, tenant_scope_key, operation_id) \
         DO NOTHING",
            &[
                &key.verified_issuer,
                &key.authenticated_subject,
                &key.tenant_scope_key,
                &key.operation_id.as_bytes().as_slice(),
                &binding.method,
                &binding.scope,
                &binding.fingerprint_version,
                &binding.fingerprint,
                &REASON_VERSION,
                &UUID_FUTURE_HORIZON_EXCEEDED_V1,
                &uuid_timestamp,
                &clock,
                &prune_after,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("future marker insert", e))?;

    if inserted == 1 {
        tx.execute(
            "UPDATE lore_domain_operation_future_reject_quotas \
             SET retained_count = retained_count + 1, bucket_count = bucket_count + 1, \
                 updated_at = $4 \
             WHERE verified_issuer = $1 AND authenticated_subject = $2 AND tenant_scope_key = $3",
            &[
                &key.verified_issuer,
                &key.authenticated_subject,
                &key.tenant_scope_key,
                &clock,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("future reject quota increment", e))?;
    }

    Ok(PrepareResult::Committed(DomainOutcome::NotApplied {
        reason_version: REASON_VERSION,
        reason: UUID_FUTURE_HORIZON_EXCEEDED_V1.to_owned(),
    }))
}

/// Lock and consume the `PREPARED` row inside the mutation transaction.
///
/// This is the first lock the mutation takes (F-032-3 position 0) and the last
/// point at which the operation can still be refused without a domain effect.
/// A token is single-use and cannot be supplied for another namespace,
/// operation, method, scope, or fingerprint: every one of those is in the
/// predicate, and a miss returns `Ok(None)` rather than distinguishing which
/// part failed.
pub async fn consume(
    tx: &Transaction<'_>,
    key: &ReceiptKey,
    binding: &OperationBinding,
    token: &[u8; 32],
) -> Result<ConsumeResult, DomainError> {
    let clock = admission_clock(tx).await?;
    let Some(row) = lock_receipt_row(tx, key).await? else {
        return Ok(ConsumeResult::Rejected);
    };
    if !row.matches(binding) {
        return Ok(ConsumeResult::Rejected);
    }
    if row.state == schema::RECEIPT_STATE_COMMITTED {
        return Ok(ConsumeResult::Committed {
            outcome: row.committed_outcome()?,
            public_result: row.public_result,
        });
    }
    if row.state != schema::RECEIPT_STATE_PREPARED {
        return Ok(ConsumeResult::Rejected);
    }
    let Some(stored) = row.consume_token.as_deref() else {
        return Ok(ConsumeResult::Rejected);
    };
    if !tokens_match(stored, token) {
        return Ok(ConsumeResult::Rejected);
    }
    if clock >= row.hard_expires_at {
        // Expiry performs the same terminal transition with no domain effect.
        return Ok(ConsumeResult::Committed {
            outcome: expire_prepared(tx, key, clock).await?,
            public_result: None,
        });
    }
    Ok(ConsumeResult::Admitted(ConsumedAdmission {
        key: key.clone(),
        admission_clock: clock,
    }))
}

/// `domain_operation_receipt_get`.
///
/// **Performs no domain mutation** — but it is not literally read-only. A
/// PREPARED row past its hard TTL is terminalized here, exactly as prepare and
/// consume do it, because an operation whose caller only polls for status must
/// still reach a terminal answer rather than reporting PREPARED forever.
///
/// Requires the operation ID, expected method, canonical scope, and versioned
/// fingerprint, so it answers only within the authenticated principal's own
/// receipt namespace and a mismatched reuse fails closed. It never returns the
/// consume token and never performs a domain mutation; a later metadata update,
/// branch advance, delete, obliteration, repair, or re-store cannot erase or
/// rewrite the receipt it reads.
pub async fn receipt_get(
    tx: &Transaction<'_>,
    key: &ReceiptKey,
    binding: &OperationBinding,
) -> Result<ReceiptLookup, DomainError> {
    let clock = admission_clock(tx).await?;

    // Locks the row, because a past-TTL PREPARED row is terminalized here as
    // well as in prepare and consume. That is what "every prepare, get, and
    // consume touch performs this same transition" means: an operation whose
    // caller only ever polls for status must still reach a terminal answer.
    let row = lock_receipt_row(tx, key).await?;

    if let Some(row) = row {
        if !row.matches(binding) {
            return Ok(ReceiptLookup::Mismatch);
        }
        if row.state == schema::RECEIPT_STATE_PREPARED {
            if clock >= row.hard_expires_at {
                return Ok(ReceiptLookup::Committed {
                    outcome: expire_prepared(tx, key, clock).await?,
                    from_future_marker: false,
                });
            }
            // PREPARED is nonterminal, not a decisive payload: bounded metadata
            // only, no token, no result. Public status maps it to
            // OutcomeUnknown/StillUnknown.
            return Ok(ReceiptLookup::Prepared {
                prepared_at: row.prepared_at,
                hard_expires_at: row.hard_expires_at,
            });
        }
        if let Some(expiry) = row.full_result_expires_at
            && clock >= expiry
        {
            return Ok(ReceiptLookup::Expired);
        }
        let _ = row.committed_at;
        return Ok(ReceiptLookup::Committed {
            outcome: row.committed_outcome()?,
            from_future_marker: false,
        });
    }

    // A future marker is already a compact complete result: it keeps returning
    // COMMITTED NOT_APPLIED through its prune deadline rather than degrading to
    // EXPIRED at day 30.
    if let Some(marker) = load_future_marker(tx, key, binding).await? {
        return Ok(match marker {
            FutureMarker::Exact(outcome) => ReceiptLookup::Committed {
                outcome,
                from_future_marker: true,
            },
            FutureMarker::Mismatch => ReceiptLookup::Mismatch,
        });
    }

    // Nothing retained. A safely pruned old ID and one that was never admitted
    // are deliberately indistinguishable.
    let uuid_ts = uuid_v7_timestamp(&key.operation_id)?;
    Ok(match classify(uuid_ts, clock) {
        TemporalClass::Stale => ReceiptLookup::ExpiredOrUnknown,
        _ => ReceiptLookup::NotFound,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(offset_secs: i64) -> SystemTime {
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000);
        if offset_secs >= 0 {
            base + Duration::from_secs(offset_secs as u64)
        } else {
            base - Duration::from_secs(offset_secs.unsigned_abs())
        }
    }

    #[test]
    fn exactly_at_the_skew_bound_is_admissible() {
        let clock = at(0);
        let uuid_ts = clock + NORMAL_FUTURE_SKEW;
        assert_eq!(classify(uuid_ts, clock), TemporalClass::Admissible);
    }

    #[test]
    fn one_second_past_the_skew_bound_is_receipt_bearing() {
        let clock = at(0);
        let uuid_ts = clock + NORMAL_FUTURE_SKEW + Duration::from_secs(1);
        assert_eq!(
            classify(uuid_ts, clock),
            TemporalClass::ReceiptBearingFuture
        );
    }

    #[test]
    fn exactly_at_the_horizon_is_still_receipt_bearing() {
        let clock = at(0);
        let uuid_ts = clock + RECEIPT_BEARING_FUTURE_HORIZON;
        assert_eq!(
            classify(uuid_ts, clock),
            TemporalClass::ReceiptBearingFuture
        );
    }

    #[test]
    fn one_second_past_the_horizon_is_beyond() {
        let clock = at(0);
        let uuid_ts = clock + RECEIPT_BEARING_FUTURE_HORIZON + Duration::from_secs(1);
        assert_eq!(classify(uuid_ts, clock), TemporalClass::BeyondHorizon);
    }

    #[test]
    fn exactly_at_the_stale_bound_is_admissible() {
        let clock = at(0);
        let uuid_ts = clock - STALE_HORIZON;
        assert_eq!(classify(uuid_ts, clock), TemporalClass::Admissible);
    }

    #[test]
    fn one_second_past_the_stale_bound_is_stale() {
        let clock = at(0);
        let uuid_ts = clock - STALE_HORIZON - Duration::from_secs(1);
        assert_eq!(classify(uuid_ts, clock), TemporalClass::Stale);
    }

    #[test]
    fn the_receipt_bearing_horizon_is_strictly_below_marker_retention() {
        // CR-029: "The 24-hour receipt-bearing future horizon is strictly below
        // retained-marker safety." A marker is retained for
        // STALE_HORIZON + MARKER_SAFETY_EPSILON, so an ID that was rejected
        // beyond the horizon still has its marker when the same ID could next
        // arrive. If these two were ever reordered, a beyond-horizon rejection
        // could be pruned while still re-admissible and silently become a
        // second attempt.
        assert!(RECEIPT_BEARING_FUTURE_HORIZON < STALE_HORIZON + MARKER_SAFETY_EPSILON);
    }

    #[test]
    fn a_prepared_row_expires_well_inside_the_admissible_window() {
        // The hard TTL exists so process loss cannot wedge a prepared row. It
        // has to be short relative to the stale horizon, or an abandoned row
        // would outlive the window in which its ID is still admissible and the
        // caller could never retry.
        assert!(PREPARED_HARD_TTL < STALE_HORIZON);
        assert!(PREPARED_HARD_TTL < FULL_RESULT_RETENTION);
    }

    #[test]
    fn a_non_v7_uuid_is_rejected_before_any_database_access() {
        let v4 = Uuid::new_v4();
        assert!(matches!(
            uuid_v7_timestamp(&v4),
            Err(DomainError::InvalidInput(_))
        ));
    }

    #[test]
    fn a_v7_uuid_yields_its_embedded_timestamp() {
        let id = Uuid::now_v7();
        let ts = uuid_v7_timestamp(&id).expect("v7 carries a timestamp");
        let drift = SystemTime::now()
            .duration_since(ts)
            .unwrap_or(Duration::ZERO);
        assert!(drift < Duration::from_secs(60), "drift was {drift:?}");
    }
}

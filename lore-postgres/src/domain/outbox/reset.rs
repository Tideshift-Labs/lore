// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The Postgres half of the stream-reset receipt (WP-119 Step C).
//!
//! WP-110 detects a broker reset and emits the frozen report. WP-119 owns the
//! service, the authentication, and everything here: the durable evidence, the
//! stored acknowledgement, the fence, and the retirement. The gRPC service in
//! `lore-server` does derivation and authentication; this module does the one
//! transaction that makes a reset a fact.
//!
//! # Lookup before validation, and why that order is the security property
//!
//! [`accept_reset`] looks up the durable detection keys **before** it validates
//! current placement or the current old stream. That is not an optimisation. A
//! commit whose acknowledgement was lost is retried later, possibly after the
//! cell's placement has moved again — and the retry must receive the identical
//! stored ack rather than `PLACEMENT_MISMATCH`. Validating placement first
//! would make a correct emitter's retry fail forever with no path to the answer
//! its own accepted reset already produced.
//!
//! The converse ordering matters too, and belongs to the caller: authentication
//! and authorization run **before** the stored-record comparison, so a caller
//! probing detection keys cannot distinguish an existing detection from an
//! absent one.
//!
//! # Byte-identity is a storage rule
//!
//! The serialized `StreamResetAckV1` is persisted in the receipt transaction and
//! replayed verbatim. It is not re-encoded from the stored fields, because
//! protobuf serialization is not canonical and re-encoding across library
//! versions can differ — which would break the byte-identity the contract
//! requires for equivalent retries.
//!
//! # One transaction, or nothing
//!
//! Generation allocation, evidence, stored ack, fence, replacement placeholder,
//! readiness invalidation, and retirement are one transaction. A caller
//! acknowledges only after it commits. Every rejection path — mismatch, stale,
//! invalid successor, unknown cell — mutates nothing at all.

use std::time::SystemTime;

use tokio_postgres::GenericClient;
use tokio_postgres::Row;

use crate::domain::errors::DomainError;
use crate::domain::outbox::membership::install_required_placeholder;
use crate::domain::outbox::membership::retire_all_for_reset;
use crate::domain::outbox::membership::validate_cell_id;
use crate::domain::outbox::membership::validate_stream;
use crate::domain::outbox::schema::MAX_BROKER_RESET_IDENTITY_BYTES;
use crate::domain::outbox::schema::MAX_DETECTION_ID_BYTES;
use crate::domain::outbox::schema::MAX_EMITTER_IDENTITY_BYTES;
use crate::domain::outbox::schema::MAX_RESET_ACK_BYTES;
use crate::domain::outbox::schema::RESET_STATE_IN_PROGRESS;
use crate::domain::retry::classify_commit;

// ---------------------------------------------------------------------------
// The frozen reason vocabulary
// ---------------------------------------------------------------------------
//
// `ResetReasonV1`, from the notification-plane contract. Declared here as well
// as in `lore-server`'s wire transcription because this crate persists and
// validates them and must not depend on the server crate; `lore-server`'s
// `event_relay::reset_wire` asserts the two agree, so a renumbering on either
// side fails a test rather than silently storing a reason under another name.
//
// `RESET_REASON_V1_UNSPECIFIED = 0` is deliberately absent: proto3 requires a
// zero value, it never appears in a valid report, and a constant for it here
// would invite a comparison that treats it as a reason rather than as
// malformed input.

/// The stream identity changed. Every reason except the two below requires it.
pub const RESET_REASON_STREAM_IDENTITY_CHANGED: i32 = 1;
/// The identity is unchanged and the epoch advanced.
pub const RESET_REASON_STREAM_EPOCH_ADVANCED: i32 = 2;
/// A sequence rollback. A restored stream may keep its identity, so either a
/// changed identity or a greater epoch is a valid successor.
pub const RESET_REASON_SEQUENCE_ROLLBACK: i32 = 3;
/// The broker was restored from a backup.
pub const RESET_REASON_BROKER_RESTORE: i32 = 4;
/// An operator moved the stream deliberately.
pub const RESET_REASON_OPERATOR_RESET: i32 = 5;

/// Every reason a valid report may carry, in wire order.
pub const RESET_REASONS: [i32; 5] = [
    RESET_REASON_STREAM_IDENTITY_CHANGED,
    RESET_REASON_STREAM_EPOCH_ADVANCED,
    RESET_REASON_SEQUENCE_ROLLBACK,
    RESET_REASON_BROKER_RESTORE,
    RESET_REASON_OPERATOR_RESET,
];

// ---------------------------------------------------------------------------
// Value types
// ---------------------------------------------------------------------------

/// One authenticated reset report, after the service has validated its
/// canonical derivation.
///
/// It carries no reset generation: WP-119 assigns that, and a caller-supplied
/// one would let a detector choose which fence it installs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResetReport {
    /// UUIDv5 of the lowercase hexadecimal fingerprint.
    pub detection_id: String,
    /// SHA-256 over the contract's canonical preimage.
    pub reset_fingerprint: [u8; 32],
    /// Authoritative broker reset identity.
    pub broker_reset_identity: String,
    /// The cell this reset belongs to.
    pub cell_id: String,
    /// Placement revision the emitter believed was current.
    pub placement_revision: i64,
    /// Stream identity before the reset.
    pub old_stream_identity: String,
    /// Stream epoch before the reset.
    pub old_stream_epoch: i64,
    /// Stream identity after the reset.
    pub new_stream_identity: String,
    /// Stream epoch after the reset.
    pub new_stream_epoch: i64,
    /// `ResetReasonV1`, 1..=5.
    pub reason_code: i32,
    /// Detection timestamp. Evidence only: excluded from the fingerprint and
    /// from duplicate equality, so two reports of one physical reset differing
    /// only here are the same detection.
    pub detected_at_unix_ms: i64,
}

/// The evidence and stored acknowledgement of one accepted reset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredReset {
    /// The generation WP-119 assigned.
    pub reset_generation: i64,
    /// The stream identity this reset voided.
    ///
    /// Carried on the **replay** path as well as the accept path, and that is
    /// load-bearing rather than informational: a receipt that commits and whose
    /// requeue then fails is retried by the emitter, and the retry must be able
    /// to re-drive the requeue for the same old epoch. Without the old tuple
    /// here it could only return the stored ack, and every retained unsafe row
    /// for the void epoch would stay `broker_accepted` forever.
    pub old_stream_identity: String,
    /// The epoch this reset voided, for the same reason.
    pub old_stream_epoch: i64,
    /// The bounded evidence identity carried in the ack.
    pub evidence_id: String,
    /// The serialized `StreamResetAckV1`, replayed verbatim.
    pub ack_bytes: Vec<u8>,
    /// `reset_in_progress` or `cleared`.
    pub state: String,
    /// When the receipt transaction committed the row.
    pub persisted_at: SystemTime,
}

/// What the service needs in order to build the ack it will store.
///
/// Handed to the caller's encoder inside the receipt transaction, because the
/// generation and the persisted timestamp are only known there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AckInputs {
    /// The cell.
    pub cell_id: String,
    /// Echoed detection identity.
    pub detection_id: String,
    /// Echoed fingerprint.
    pub reset_fingerprint: [u8; 32],
    /// The assigned generation.
    pub reset_generation: i64,
    /// The assigned evidence identity.
    pub evidence_id: String,
    /// The database clock at persistence, in milliseconds.
    pub persisted_at_unix_ms: i64,
}

/// The outcome of one reset receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResetAcceptance {
    /// A previously unseen detection was accepted. The fence stands.
    Accepted {
        /// The evidence and ack now stored.
        stored: StoredReset,
        /// The cell's snapshot version after the transaction.
        membership_version: i64,
        /// Receiver generations retired by this reset.
        retired_generations: u64,
        /// The old stream identity whose retained unsafe rows the caller must
        /// now requeue.
        old_stream_identity: String,
        /// The old epoch, likewise.
        old_stream_epoch: i64,
    },
    /// An exact retry of an already-accepted detection from the same emitter
    /// and cell. The stored ack is replayed byte-identically and nothing was
    /// mutated. Still valid after the cell's placement has moved on.
    Replayed {
        /// The stored evidence and ack.
        stored: StoredReset,
    },
    /// A detection key resolved to a record whose correctness fields, original
    /// placement revision, reason, emitter identity, or cell differ. Nothing
    /// was mutated and no ack is disclosed.
    DetectionMismatch,
    /// This cell has no membership state row, so it has never been through
    /// cutover and cannot hold a reset.
    CellUnknown,
    /// A previously unseen report whose placement revision is not the cell's
    /// current one.
    PlacementMismatch {
        /// The cell's current placement revision.
        current_placement_revision: i64,
    },
    /// A previously unseen, otherwise authorized report whose old identity and
    /// epoch are no longer current. No fence, readiness, counter, or evidence
    /// mutation.
    StaleOldStream {
        /// The cell's authoritative identity now.
        current_stream_identity: Option<String>,
        /// The cell's authoritative epoch now.
        current_stream_epoch: Option<i64>,
    },
    /// The successor transition is not valid for this reason and old tuple.
    InvalidSuccessor {
        /// Which rule it failed. A fixed, low-cardinality string.
        rule: &'static str,
    },
}

/// The successor rules, as fixed strings so a rejection is classifiable without
/// parsing prose.
pub const SUCCESSOR_RULE_EMPTY_BROKER_IDENTITY: &str = "empty_broker_reset_identity";
pub const SUCCESSOR_RULE_UNCHANGED_TUPLE: &str = "successor_equals_predecessor";
pub const SUCCESSOR_RULE_EPOCH_NOT_ADVANCED: &str = "epoch_advanced_requires_greater_epoch";
pub const SUCCESSOR_RULE_IDENTITY_CHANGED_FOR_EPOCH_ADVANCE: &str =
    "epoch_advanced_requires_unchanged_identity";
pub const SUCCESSOR_RULE_ROLLBACK_NEEDS_CHANGE: &str =
    "sequence_rollback_requires_changed_identity_or_greater_epoch";
pub const SUCCESSOR_RULE_IDENTITY_UNCHANGED: &str = "reason_requires_changed_stream_identity";
pub const SUCCESSOR_RULE_RETIRED_PREDECESSOR: &str = "successor_is_a_retired_predecessor";
pub const SUCCESSOR_RULE_CONFLICTING_TRANSITION: &str =
    "old_tuple_already_transitioned_to_another_successor";

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn bounded(label: &str, value: &str, max: usize) -> Result<(), DomainError> {
    if value.is_empty() {
        return Err(DomainError::InvalidInput(format!(
            "outbox reset {label} is empty"
        )));
    }
    bounded_width(label, value, max)
}

/// Width only, emptiness allowed.
///
/// Used for `broker_reset_identity`, and the distinction is a classification
/// rather than a style choice. The contract makes a nonempty broker reset
/// identity a **successor validity** rule, so an empty one is
/// `INVALID_SUCCESSOR_STREAM_V1` and not `MALFORMED_REPORT_V1`. Rejecting it as
/// a bounds violation here would return the wrong error class and make
/// [`SUCCESSOR_RULE_EMPTY_BROKER_IDENTITY`] unreachable. The column's own
/// `BETWEEN 1 AND 256` CHECK remains the backstop: an empty value never reaches
/// an insert, because successor validation refuses it first.
fn bounded_width(label: &str, value: &str, max: usize) -> Result<(), DomainError> {
    if value.len() > max {
        return Err(DomainError::InvalidInput(format!(
            "outbox reset {label} exceeds {max} bytes: {}",
            value.len()
        )));
    }
    Ok(())
}

/// Bounds only. Canonical derivation, authentication, and authorization all
/// happen in the service before a report reaches this module.
pub fn validate_report(report: &ResetReport) -> Result<(), DomainError> {
    validate_cell_id(&report.cell_id)?;
    bounded("detection_id", &report.detection_id, MAX_DETECTION_ID_BYTES)?;
    // Width only. An EMPTY broker reset identity is a successor-validity
    // failure, not a malformed report; see [`bounded_width`].
    bounded_width(
        "broker_reset_identity",
        &report.broker_reset_identity,
        MAX_BROKER_RESET_IDENTITY_BYTES,
    )?;
    validate_stream(&report.old_stream_identity, report.old_stream_epoch)?;
    validate_stream(&report.new_stream_identity, report.new_stream_epoch)?;
    if !RESET_REASONS.contains(&report.reason_code) {
        return Err(DomainError::InvalidInput(format!(
            "outbox reset reason_code must be one of {RESET_REASONS:?}, got {}",
            report.reason_code
        )));
    }
    if report.placement_revision < 0 {
        return Err(DomainError::InvalidInput(format!(
            "outbox reset placement_revision must be >= 0, got {}",
            report.placement_revision
        )));
    }
    Ok(())
}

/// The successor rules that need only the report itself.
///
/// The two that need the database — a successor that is a retired predecessor,
/// and an old tuple that already transitioned elsewhere — are checked in
/// [`accept_reset`] against `lore_outbox_reset_generations`.
pub fn successor_shape_rule(report: &ResetReport) -> Option<&'static str> {
    if report.broker_reset_identity.is_empty() {
        return Some(SUCCESSOR_RULE_EMPTY_BROKER_IDENTITY);
    }
    let identity_changed = report.new_stream_identity != report.old_stream_identity;
    let epoch_greater = report.new_stream_epoch > report.old_stream_epoch;
    if !identity_changed && report.new_stream_epoch == report.old_stream_epoch {
        // An in-place rollback is indistinguishable from a replay of an
        // already-accepted detection, so the contract refuses to express it
        // rather than synthesizing a successor that would either collide with a
        // stored record or fabricate broker state.
        return Some(SUCCESSOR_RULE_UNCHANGED_TUPLE);
    }
    match report.reason_code {
        RESET_REASON_STREAM_EPOCH_ADVANCED => {
            if identity_changed {
                return Some(SUCCESSOR_RULE_IDENTITY_CHANGED_FOR_EPOCH_ADVANCE);
            }
            if !epoch_greater {
                return Some(SUCCESSOR_RULE_EPOCH_NOT_ADVANCED);
            }
        }
        RESET_REASON_SEQUENCE_ROLLBACK => {
            // A restored stream may keep its identity, so either half suffices.
            if !identity_changed && !epoch_greater {
                return Some(SUCCESSOR_RULE_ROLLBACK_NEEDS_CHANGE);
            }
        }
        _ => {
            // Every other reason describes a stream that was replaced, so the
            // identity must move. A new epoch under the same identity would be
            // `STREAM_EPOCH_ADVANCED` and is a different classification.
            if !identity_changed {
                return Some(SUCCESSOR_RULE_IDENTITY_UNCHANGED);
            }
        }
    }
    None
}

/// The bounded evidence identity for an assigned generation.
///
/// Deterministic in the generation and the fingerprint, so a service restarted
/// mid-flight re-derives the same value rather than minting a second identity
/// for one reset. Well inside the contract's 64-character bound: the generation
/// is a `u64` at most twenty digits and the digest prefix is sixteen.
fn evidence_id(reset_generation: i64, reset_fingerprint: &[u8; 32]) -> String {
    use std::fmt::Write as _;

    let mut id = String::with_capacity(64);
    id.push_str("rst-");
    // `write!` into a `String` is infallible, and the only `Err` the trait can
    // produce here would come from the formatter itself. Discarded rather than
    // propagated: an allocation failure has already aborted.
    let _ = write!(id, "{reset_generation}-");
    for byte in &reset_fingerprint[..8] {
        let _ = write!(id, "{byte:02x}");
    }
    id
}

// ---------------------------------------------------------------------------
// Row decoding
// ---------------------------------------------------------------------------

const RESET_COLUMNS: &str = "cell_id, reset_generation, detection_id, reset_fingerprint, \
     broker_reset_identity, old_stream_identity, old_stream_epoch, \
     new_stream_identity, new_stream_epoch, reason_code, placement_revision, \
     detected_at_unix_ms, emitter_identity, evidence_id, ack_bytes, state, persisted_at";

/// One persisted reset row, in full, for the duplicate comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ResetRecord {
    cell_id: String,
    detection_id: String,
    reset_fingerprint: Vec<u8>,
    broker_reset_identity: String,
    old_stream_identity: String,
    old_stream_epoch: i64,
    new_stream_identity: String,
    new_stream_epoch: i64,
    reason_code: i32,
    placement_revision: i64,
    emitter_identity: String,
    stored: StoredReset,
}

fn record_from(row: &Row) -> ResetRecord {
    ResetRecord {
        cell_id: row.get("cell_id"),
        detection_id: row.get("detection_id"),
        reset_fingerprint: row.get("reset_fingerprint"),
        broker_reset_identity: row.get("broker_reset_identity"),
        old_stream_identity: row.get("old_stream_identity"),
        old_stream_epoch: row.get("old_stream_epoch"),
        new_stream_identity: row.get("new_stream_identity"),
        new_stream_epoch: row.get("new_stream_epoch"),
        reason_code: row.get("reason_code"),
        placement_revision: row.get("placement_revision"),
        emitter_identity: row.get("emitter_identity"),
        stored: StoredReset {
            reset_generation: row.get("reset_generation"),
            old_stream_identity: row.get("old_stream_identity"),
            old_stream_epoch: row.get("old_stream_epoch"),
            evidence_id: row.get("evidence_id"),
            ack_bytes: row.get("ack_bytes"),
            state: row.get("state"),
            persisted_at: row.get("persisted_at"),
        },
    }
}

/// Whether a stored record is the same detection as this report from this
/// emitter.
///
/// `detected_at_unix_ms` is excluded, because the contract excludes it from the
/// fingerprint *and* from duplicate equality: two reports of one physical reset
/// differ there and are one detection. `placement_revision` and `reason_code`
/// are **included**, because they are excluded from the fingerprint but retained
/// in duplicate equality — the reason selects which successor shapes are valid,
/// so two reports disagreeing on it are not the same report.
fn is_exact_duplicate(record: &ResetRecord, report: &ResetReport, emitter_identity: &str) -> bool {
    record.cell_id == report.cell_id
        && record.detection_id == report.detection_id
        && record.reset_fingerprint.as_slice() == report.reset_fingerprint.as_slice()
        && record.broker_reset_identity == report.broker_reset_identity
        && record.old_stream_identity == report.old_stream_identity
        && record.old_stream_epoch == report.old_stream_epoch
        && record.new_stream_identity == report.new_stream_identity
        && record.new_stream_epoch == report.new_stream_epoch
        && record.reason_code == report.reason_code
        && record.placement_revision == report.placement_revision
        && record.emitter_identity == emitter_identity
}

// ---------------------------------------------------------------------------
// The receipt transaction
// ---------------------------------------------------------------------------

/// Accept, replay, or reject one reset report.
///
/// `build_ack` is called inside the transaction, after the generation and the
/// persisted timestamp are known and before anything is written, and its bytes
/// are stored verbatim.
///
/// On [`ResetAcceptance::Accepted`] the caller must then requeue every retained
/// unsafe row for the old epoch through
/// [`super::relay::requeue_unsafe_for_epoch_reset`] and only then acknowledge.
/// That step is deliberately outside this transaction: it is a multi-batch
/// sweep bounded at a thousand rows apiece, and folding it in would make the
/// receipt transaction unbounded.
pub async fn accept_reset<F>(
    client: &mut deadpool_postgres::Client,
    report: &ResetReport,
    emitter_identity: &str,
    build_ack: F,
) -> Result<ResetAcceptance, DomainError>
where
    F: FnOnce(&AckInputs) -> Vec<u8>,
{
    validate_report(report)?;
    bounded(
        "emitter_identity",
        emitter_identity,
        MAX_EMITTER_IDENTITY_BYTES,
    )?;

    let tx = client
        .transaction()
        .await
        .map_err(|e| DomainError::from_pg("outbox reset begin", e))?;

    // `FOR UPDATE` on the counters row before anything else. Same lock order as
    // every membership writer, and it is what makes two equivalent detectors
    // serialise: the loser blocks here, then rereads below and finds the
    // winner's stored record rather than racing on the unique indexes.
    let Some(state) = tx
        .query_opt(
            "SELECT membership_version, reset_generation, current_stream_identity, \
                    current_stream_epoch, current_placement_revision \
             FROM lore_outbox_membership_state WHERE cell_id = $1 FOR UPDATE",
            &[&report.cell_id],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox reset state select", e))?
    else {
        drop(tx);
        return Ok(ResetAcceptance::CellUnknown);
    };
    let membership_version: i64 = state.get("membership_version");
    let current_reset_generation: i64 = state.get("reset_generation");
    let current_stream_identity: Option<String> = state.get("current_stream_identity");
    let current_stream_epoch: Option<i64> = state.get("current_stream_epoch");
    let current_placement_revision: i64 = state.get("current_placement_revision");

    // Durable lookup FIRST, on both keys. Derivation already passed in the
    // service, so the two keys cannot disagree about which record they name;
    // querying both is defence against a record written by an earlier or
    // defective service version, not a second derivation check.
    let fingerprint = report.reset_fingerprint.as_slice();
    let existing = tx
        .query(
            &format!(
                "SELECT {RESET_COLUMNS} FROM lore_outbox_reset_generations \
                 WHERE cell_id = $1 AND (detection_id = $2 OR reset_fingerprint = $3)"
            ),
            &[&report.cell_id, &report.detection_id, &fingerprint],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox reset detection lookup", e))?;

    if !existing.is_empty() {
        drop(tx);
        // Two rows means the two keys resolved to different records, which is a
        // mismatch by construction: one of them was written under a different
        // payload.
        if existing.len() != 1 {
            return Ok(ResetAcceptance::DetectionMismatch);
        }
        let record = record_from(&existing[0]);
        if is_exact_duplicate(&record, report, emitter_identity) {
            return Ok(ResetAcceptance::Replayed {
                stored: record.stored,
            });
        }
        return Ok(ResetAcceptance::DetectionMismatch);
    }

    // Only an absent detection validates current placement and current old
    // stream.
    if report.placement_revision != current_placement_revision {
        drop(tx);
        return Ok(ResetAcceptance::PlacementMismatch {
            current_placement_revision,
        });
    }
    if current_stream_identity.as_deref() != Some(report.old_stream_identity.as_str())
        || current_stream_epoch != Some(report.old_stream_epoch)
    {
        drop(tx);
        return Ok(ResetAcceptance::StaleOldStream {
            current_stream_identity,
            current_stream_epoch,
        });
    }
    if let Some(rule) = successor_shape_rule(report) {
        drop(tx);
        return Ok(ResetAcceptance::InvalidSuccessor { rule });
    }

    // A successor that this cell has already retired as a predecessor would
    // move the stream backward into a tuple whose checkpoint vector is void.
    let retired_predecessor: bool = tx
        .query_one(
            "SELECT EXISTS ( \
                 SELECT 1 FROM lore_outbox_reset_generations \
                 WHERE cell_id = $1 AND old_stream_identity = $2 AND old_stream_epoch = $3 \
             ) AS present",
            &[
                &report.cell_id,
                &report.new_stream_identity,
                &report.new_stream_epoch,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox reset retired predecessor probe", e))?
        .get("present");
    if retired_predecessor {
        drop(tx);
        return Ok(ResetAcceptance::InvalidSuccessor {
            rule: SUCCESSOR_RULE_RETIRED_PREDECESSOR,
        });
    }

    // No accepted transition from this old tuple may name a different
    // successor. Unreachable while the old tuple must equal the current
    // placement, which every accept advances — kept because "unreachable given
    // another check" is exactly the invariant a later change breaks silently.
    let conflicting: bool = tx
        .query_one(
            "SELECT EXISTS ( \
                 SELECT 1 FROM lore_outbox_reset_generations \
                 WHERE cell_id = $1 AND old_stream_identity = $2 AND old_stream_epoch = $3 \
                   AND (new_stream_identity <> $4 OR new_stream_epoch <> $5) \
             ) AS present",
            &[
                &report.cell_id,
                &report.old_stream_identity,
                &report.old_stream_epoch,
                &report.new_stream_identity,
                &report.new_stream_epoch,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox reset transition probe", e))?
        .get("present");
    if conflicting {
        drop(tx);
        return Ok(ResetAcceptance::InvalidSuccessor {
            rule: SUCCESSOR_RULE_CONFLICTING_TRANSITION,
        });
    }

    let reset_generation = current_reset_generation
        .checked_add(1)
        .ok_or_else(|| DomainError::Internal("outbox reset generation overflowed i64".into()))?;
    let evidence_id = evidence_id(reset_generation, &report.reset_fingerprint);

    // One materialised clock read, used for both the stored timestamp and the
    // ack's own field. `clock_timestamp()` is volatile, so two calls in one
    // statement may return two instants; `MATERIALIZED` forces exactly one.
    let clock = tx
        .query_one(
            "WITH reading AS MATERIALIZED (SELECT clock_timestamp() AS at) \
             SELECT at, (EXTRACT(EPOCH FROM at) * 1000)::bigint AS at_ms FROM reading",
            &[],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox reset clock read", e))?;
    let persisted_at: SystemTime = clock.get("at");
    let persisted_at_unix_ms: i64 = clock.get("at_ms");

    let ack_bytes = build_ack(&AckInputs {
        cell_id: report.cell_id.clone(),
        detection_id: report.detection_id.clone(),
        reset_fingerprint: report.reset_fingerprint,
        reset_generation,
        evidence_id: evidence_id.clone(),
        persisted_at_unix_ms,
    });
    if ack_bytes.is_empty() || ack_bytes.len() > MAX_RESET_ACK_BYTES {
        return Err(DomainError::InvalidInput(format!(
            "outbox reset ack must be 1..={MAX_RESET_ACK_BYTES} bytes, got {}",
            ack_bytes.len()
        )));
    }

    tx.execute(
        "INSERT INTO lore_outbox_reset_generations \
             (cell_id, reset_generation, detection_id, reset_fingerprint, \
              broker_reset_identity, old_stream_identity, old_stream_epoch, \
              new_stream_identity, new_stream_epoch, reason_code, placement_revision, \
              detected_at_unix_ms, emitter_identity, evidence_id, ack_bytes, state, \
              persisted_at) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17)",
        &[
            &report.cell_id,
            &reset_generation,
            &report.detection_id,
            &fingerprint,
            &report.broker_reset_identity,
            &report.old_stream_identity,
            &report.old_stream_epoch,
            &report.new_stream_identity,
            &report.new_stream_epoch,
            &report.reason_code,
            &report.placement_revision,
            &report.detected_at_unix_ms,
            &emitter_identity,
            &evidence_id,
            &ack_bytes,
            &RESET_STATE_IN_PROGRESS,
            &persisted_at,
        ],
    )
    .await
    .map_err(|e| DomainError::from_pg("outbox reset evidence insert", e))?;

    // The cell moves to the new placement in the same transaction that fences
    // it. Anything else would leave a window where the fence stands but the
    // authoritative placement still names the void epoch, and a readiness CAS
    // in that window would succeed against a stream that no longer exists.
    let new_membership_version = membership_version
        .checked_add(1)
        .ok_or_else(|| DomainError::Internal("outbox membership version overflowed i64".into()))?;
    tx.execute(
        "UPDATE lore_outbox_membership_state SET \
             reset_generation = $2, \
             current_stream_identity = $3, \
             current_stream_epoch = $4, \
             membership_version = $5, \
             updated_at = clock_timestamp() \
         WHERE cell_id = $1",
        &[
            &report.cell_id,
            &reset_generation,
            &report.new_stream_identity,
            &report.new_stream_epoch,
            &new_membership_version,
        ],
    )
    .await
    .map_err(|e| DomainError::from_pg("outbox reset placement advance", e))?;

    // Readiness invalidation is exactly this: every generation retires, and the
    // required-replacement placeholder takes their place so the required set is
    // never empty while the fence stands.
    let retired_generations =
        retire_all_for_reset(&*tx, &report.cell_id, new_membership_version).await?;
    install_required_placeholder(&*tx, &report.cell_id, new_membership_version).await?;

    classify_commit(tx.commit().await, "outbox reset commit")?;
    Ok(ResetAcceptance::Accepted {
        stored: StoredReset {
            reset_generation,
            old_stream_identity: report.old_stream_identity.clone(),
            old_stream_epoch: report.old_stream_epoch,
            evidence_id,
            ack_bytes,
            state: RESET_STATE_IN_PROGRESS.to_string(),
            persisted_at,
        },
        membership_version: new_membership_version,
        retired_generations,
        old_stream_identity: report.old_stream_identity.clone(),
        old_stream_epoch: report.old_stream_epoch,
    })
}

/// Read one cell's reset generations, newest first.
pub async fn read_reset_generations(
    client: &impl GenericClient,
    cell_id: &str,
    limit: i64,
) -> Result<Vec<StoredReset>, DomainError> {
    validate_cell_id(cell_id)?;
    let rows = client
        .query(
            &format!(
                "SELECT {RESET_COLUMNS} FROM lore_outbox_reset_generations \
                 WHERE cell_id = $1 ORDER BY reset_generation DESC LIMIT $2"
            ),
            &[&cell_id, &limit.clamp(1, 1_000)],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox reset generations select", e))?;
    Ok(rows.iter().map(|row| record_from(row).stored).collect())
}

/// Whether a reset fence currently stands for this cell.
///
/// The same probe [`super::membership::read_membership_snapshot`] folds into a
/// snapshot, exposed on its own for the readiness surface, which needs the fact
/// without the membership.
pub async fn reset_in_progress(
    client: &impl GenericClient,
    cell_id: &str,
) -> Result<bool, DomainError> {
    validate_cell_id(cell_id)?;
    Ok(client
        .query_one(
            "SELECT EXISTS ( \
                 SELECT 1 FROM lore_outbox_reset_generations \
                 WHERE cell_id = $1 AND state = 'reset_in_progress' \
             ) AS fenced",
            &[&cell_id],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox reset fence probe", e))?
        .get("fenced"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> ResetReport {
        ResetReport {
            detection_id: "efaa31a7-a8db-5666-a6fe-3eb00881fd27".to_string(),
            reset_fingerprint: [0x11; 32],
            broker_reset_identity: "sfo3-01:JS-9Q2F7K3M1X".to_string(),
            cell_id: "sfo3-cell-a".to_string(),
            placement_revision: 4,
            old_stream_identity: "DURABLE-sfo3-cell-a".to_string(),
            old_stream_epoch: 7,
            new_stream_identity: "DURABLE-sfo3-cell-a".to_string(),
            new_stream_epoch: 8,
            reason_code: RESET_REASON_STREAM_EPOCH_ADVANCED,
            detected_at_unix_ms: 1_787_000_000_000,
        }
    }

    #[test]
    fn the_epoch_advanced_vector_is_a_valid_successor() {
        assert_eq!(successor_shape_rule(&report()), None);
    }

    #[test]
    fn epoch_advanced_requires_an_unchanged_identity_and_a_greater_epoch() {
        let mut r = report();
        r.new_stream_identity = "DURABLE-sfo3-cell-a-r2".to_string();
        assert_eq!(
            successor_shape_rule(&r),
            Some(SUCCESSOR_RULE_IDENTITY_CHANGED_FOR_EPOCH_ADVANCE)
        );

        let mut r = report();
        r.new_stream_epoch = 6;
        assert_eq!(
            successor_shape_rule(&r),
            Some(SUCCESSOR_RULE_EPOCH_NOT_ADVANCED)
        );
    }

    /// The fixture's `broker-restore-identity-changed` vector: the identity
    /// changes and the new epoch restarts BELOW the old one, proving epoch
    /// ordering is not a validity input once the identity moves.
    #[test]
    fn broker_restore_accepts_an_epoch_that_restarts_below_the_old_one() {
        let mut r = report();
        r.reason_code = RESET_REASON_BROKER_RESTORE;
        r.old_stream_identity = "DURABLE-sfo3-cell-a".to_string();
        r.old_stream_epoch = 8;
        r.new_stream_identity = "DURABLE-sfo3-cell-a-r2".to_string();
        r.new_stream_epoch = 1;
        assert_eq!(successor_shape_rule(&r), None);
    }

    #[test]
    fn broker_restore_requires_a_changed_identity() {
        let mut r = report();
        r.reason_code = RESET_REASON_BROKER_RESTORE;
        assert_eq!(
            successor_shape_rule(&r),
            Some(SUCCESSOR_RULE_IDENTITY_UNCHANGED)
        );
    }

    /// A restored stream may keep its identity, so a rollback accepts either a
    /// changed identity or a greater epoch — but not neither.
    #[test]
    fn sequence_rollback_accepts_either_half_but_not_neither() {
        let mut r = report();
        r.reason_code = RESET_REASON_SEQUENCE_ROLLBACK;
        assert_eq!(successor_shape_rule(&r), None, "greater epoch alone");

        let mut r = report();
        r.reason_code = RESET_REASON_SEQUENCE_ROLLBACK;
        r.new_stream_identity = "DURABLE-sfo3-cell-a-r2".to_string();
        r.new_stream_epoch = 1;
        assert_eq!(successor_shape_rule(&r), None, "changed identity alone");
    }

    /// An in-place rollback is not expressible in this transport: an identical
    /// tuple cannot be told apart from a replay of an accepted detection.
    #[test]
    fn an_unchanged_tuple_is_never_a_successor() {
        for reason in RESET_REASONS {
            let mut r = report();
            r.reason_code = reason;
            r.new_stream_identity = r.old_stream_identity.clone();
            r.new_stream_epoch = r.old_stream_epoch;
            assert_eq!(
                successor_shape_rule(&r),
                Some(SUCCESSOR_RULE_UNCHANGED_TUPLE),
                "reason {reason} accepted an identical tuple"
            );
        }
    }

    /// The fixture's `empty-broker-reset-identity` case pins
    /// `INVALID_SUCCESSOR_STREAM_V1`, not `MALFORMED_REPORT_V1`. That means the
    /// bounds check must let an empty value THROUGH so successor validation is
    /// the thing that refuses it — asserting `successor_shape_rule` alone would
    /// pass even if `validate_report` rejected it first and made this rule
    /// unreachable.
    #[test]
    fn an_empty_broker_identity_reaches_successor_validation() {
        let mut r = report();
        r.broker_reset_identity = String::new();
        assert!(
            validate_report(&r).is_ok(),
            "bounds validation must not classify an empty broker identity as malformed"
        );
        assert_eq!(
            successor_shape_rule(&r),
            Some(SUCCESSOR_RULE_EMPTY_BROKER_IDENTITY)
        );
    }

    /// The width bound still applies, and that half IS malformed input.
    #[test]
    fn an_over_long_broker_identity_is_still_a_bounds_failure() {
        let mut r = report();
        r.broker_reset_identity = "x".repeat(MAX_BROKER_RESET_IDENTITY_BYTES + 1);
        assert!(validate_report(&r).is_err());
    }

    #[test]
    fn the_unspecified_reason_is_not_a_reason() {
        let mut r = report();
        r.reason_code = 0;
        assert!(validate_report(&r).is_err());
        assert!(!RESET_REASONS.contains(&0));
    }

    #[test]
    fn an_unknown_reason_is_refused() {
        let mut r = report();
        r.reason_code = 6;
        assert!(validate_report(&r).is_err());
    }

    #[test]
    fn an_evidence_id_is_deterministic_and_bounded() {
        let first = evidence_id(1, &[0xab; 32]);
        assert_eq!(first, evidence_id(1, &[0xab; 32]));
        assert_ne!(first, evidence_id(2, &[0xab; 32]));
        assert_ne!(first, evidence_id(1, &[0xcd; 32]));
        assert!(first.len() <= MAX_DETECTION_ID_BYTES);
        assert!(evidence_id(i64::MAX, &[0xff; 32]).len() <= MAX_DETECTION_ID_BYTES);
    }

    fn record(report: &ResetReport, emitter: &str) -> ResetRecord {
        ResetRecord {
            cell_id: report.cell_id.clone(),
            detection_id: report.detection_id.clone(),
            reset_fingerprint: report.reset_fingerprint.to_vec(),
            broker_reset_identity: report.broker_reset_identity.clone(),
            old_stream_identity: report.old_stream_identity.clone(),
            old_stream_epoch: report.old_stream_epoch,
            new_stream_identity: report.new_stream_identity.clone(),
            new_stream_epoch: report.new_stream_epoch,
            reason_code: report.reason_code,
            placement_revision: report.placement_revision,
            emitter_identity: emitter.to_string(),
            stored: StoredReset {
                reset_generation: 3,
                old_stream_identity: report.old_stream_identity.clone(),
                old_stream_epoch: report.old_stream_epoch,
                evidence_id: "rst-3-1111111111111111".to_string(),
                ack_bytes: vec![1, 2, 3],
                state: RESET_STATE_IN_PROGRESS.to_string(),
                persisted_at: SystemTime::UNIX_EPOCH,
            },
        }
    }

    /// The timestamp-exclusion case: two reports differing only in
    /// `detected_at_unix_ms` are one detection.
    #[test]
    fn a_differing_detected_at_still_matches() {
        let stored = record(&report(), "spiffe://cell/sfo3-cell-a/wp110");
        let mut retry = report();
        retry.detected_at_unix_ms = 1_787_000_450_000;
        assert!(is_exact_duplicate(
            &stored,
            &retry,
            "spiffe://cell/sfo3-cell-a/wp110"
        ));
    }

    /// `reason_code` is outside the fingerprint but inside duplicate equality,
    /// so reusing a stored fingerprint with a different reason is a mismatch
    /// rather than a duplicate — even when both reasons are independently valid
    /// for the successor tuple.
    #[test]
    fn a_differing_reason_is_a_mismatch_not_a_duplicate() {
        let stored = record(&report(), "spiffe://cell/sfo3-cell-a/wp110");
        let mut retry = report();
        retry.reason_code = RESET_REASON_SEQUENCE_ROLLBACK;
        assert!(!is_exact_duplicate(
            &stored,
            &retry,
            "spiffe://cell/sfo3-cell-a/wp110"
        ));
        // Both reasons ARE valid for this tuple, so the rejection can only come
        // from the payload comparison.
        assert_eq!(successor_shape_rule(&retry), None);
    }

    #[test]
    fn placement_revision_is_inside_duplicate_equality() {
        let stored = record(&report(), "spiffe://cell/sfo3-cell-a/wp110");
        let mut retry = report();
        retry.placement_revision = 5;
        assert!(!is_exact_duplicate(
            &stored,
            &retry,
            "spiffe://cell/sfo3-cell-a/wp110"
        ));
    }

    #[test]
    fn a_different_emitter_is_never_a_duplicate() {
        let stored = record(&report(), "spiffe://cell/sfo3-cell-a/wp110");
        assert!(!is_exact_duplicate(
            &stored,
            &report(),
            "spiffe://cell/sfo3-cell-b/wp110"
        ));
    }

    #[test]
    fn a_bounds_violation_is_refused_before_any_database_work() {
        let mut r = report();
        r.detection_id = "x".repeat(MAX_DETECTION_ID_BYTES + 1);
        assert!(validate_report(&r).is_err());

        let mut r = report();
        r.cell_id = "Not-A-Cell".to_string();
        assert!(validate_report(&r).is_err());

        let mut r = report();
        r.old_stream_epoch = 0;
        assert!(validate_report(&r).is_err());
    }
}

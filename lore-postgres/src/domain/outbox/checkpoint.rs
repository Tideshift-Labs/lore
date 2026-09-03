// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-032's receiver checkpoint vector (WP-119 Step C).
//!
//! One row per `(stream_identity, stream_epoch, receiver_identity,
//! membership_generation)`, exactly as the notification-plane contract keys it.
//! The epoch is in the key rather than beside it because a frontier from a
//! prior epoch says nothing about the current one: after a reset the whole
//! vector is void, and keying it this way makes that a fact about the data
//! rather than a sweep someone has to remember to run.
//!
//! # What a frontier is, and the one rule that matters
//!
//! `contiguous_frontier` is the highest broker sequence at or below which every
//! event has been applied or refetched. **It never advances across an
//! unresolved gap.** A receiver that acknowledged 900-916 and 919-930 with
//! 917-918 unresolved has a frontier of 916, not 930 — and
//! [`report_checkpoint`] refuses the report that says otherwise rather than
//! trusting the reporter to have computed it correctly. That single rule is
//! what keeps a later acknowledgement from releasing a row nobody consumed.
//!
//! # Three fences, all compare-and-set
//!
//! A report is accepted only from the authenticated **current** generation, at
//! the cell's **current** placement, under the **current** membership snapshot
//! version. A stale generation therefore cannot advance its successor's
//! frontier or clear a blocker it did not resolve, and a report built on a
//! membership snapshot that has since changed fails rather than mixing
//! generations into one safety decision.
//!
//! All three are read under a share lock on the cell's counters row, which is
//! what makes them a fence rather than three observations: every membership
//! writer takes `FOR UPDATE` on that row first, so a retirement or an accepted
//! reset cannot land between the checks and the write.
//!
//! The frontier is additionally monotonic per row: an out-of-order report that
//! would move it backward is refused, not applied.

use std::time::SystemTime;

use tokio_postgres::GenericClient;
use tokio_postgres::Row;

use crate::domain::errors::DomainError;
use crate::domain::outbox::membership::validate_cell_id;
use crate::domain::outbox::membership::validate_receiver_identity;
use crate::domain::outbox::membership::validate_stream;
use crate::domain::outbox::schema::MAX_CHECKPOINT_BLOCKERS;
use crate::domain::outbox::schema::MEMBERSHIP_STATE_RETIRED;
use crate::domain::retry::classify_commit;

/// Longest permitted poison class. A bounded classification, not a message.
pub const MAX_POISON_CLASS_BYTES: usize = 64;

// ---------------------------------------------------------------------------
// Value types
// ---------------------------------------------------------------------------

/// One unresolved sequence range, inclusive at both ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SequenceGap {
    /// First unresolved sequence.
    pub from: i64,
    /// Last unresolved sequence.
    pub to: i64,
}

/// One parked poison disposition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoisonEntry {
    /// The sequence that could not be applied.
    pub broker_sequence: i64,
    /// Bounded classification: `UNSUPPORTED_SCHEMA`, `INVALID_SCOPE`, and the
    /// like. Never a message, never operator prose, never an identifier.
    pub class: String,
}

/// One authenticated checkpoint report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointReport {
    /// Stream the receiver is consuming.
    pub stream_identity: String,
    /// Epoch of that stream.
    pub stream_epoch: i64,
    /// Reporting receiver.
    pub receiver_identity: String,
    /// Reporting generation. Only the current one is accepted.
    pub membership_generation: i64,
    /// The membership snapshot version the report was computed under.
    pub membership_version: i64,
    /// The contiguous acknowledgement frontier.
    pub contiguous_frontier: i64,
    /// Explicit unresolved ranges.
    pub gaps: Vec<SequenceGap>,
    /// Explicit unresolved poison dispositions.
    pub poison: Vec<PoisonEntry>,
}

/// One row of the persisted vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointRecord {
    /// Cell that owns the row.
    pub cell_id: String,
    /// Stream identity.
    pub stream_identity: String,
    /// Stream epoch.
    pub stream_epoch: i64,
    /// Receiver identity.
    pub receiver_identity: String,
    /// Receiver generation.
    pub membership_generation: i64,
    /// Membership snapshot version of the last accepted report.
    pub membership_version: i64,
    /// The contiguous acknowledgement frontier.
    pub contiguous_frontier: i64,
    /// Unresolved ranges.
    pub gaps: Vec<SequenceGap>,
    /// Unresolved poison dispositions.
    pub poison: Vec<PoisonEntry>,
    /// When the receiver said it reported.
    pub reported_at: SystemTime,
    /// When this projection accepted it.
    pub projection_at: SystemTime,
}

impl CheckpointRecord {
    /// Whether this row carries any unresolved blocker.
    ///
    /// A blocker never sits below the frontier — [`report_checkpoint`] refuses a
    /// report where it would — so this is "is this receiver parked", not "is
    /// this row inconsistent".
    pub fn has_blockers(&self) -> bool {
        !self.gaps.is_empty() || !self.poison.is_empty()
    }
}

/// The outcome of one checkpoint report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckpointOutcome {
    /// The report was accepted and the projection now carries it.
    Applied {
        /// The frontier now on the row.
        contiguous_frontier: i64,
    },
    /// No `lore_outbox_membership_state` row for this cell.
    CellUnknown,
    /// The membership snapshot moved under the reporter. Reread and recompute;
    /// the projection is unchanged.
    MembershipVersionConflict {
        /// The version now current.
        current_membership_version: i64,
    },
    /// The report names a stream identity or epoch that is not the cell's
    /// current placement. Old-epoch checkpoint advancement is denied.
    EpochMismatch {
        /// Authoritative identity now.
        current_stream_identity: Option<String>,
        /// Authoritative epoch now.
        current_stream_epoch: Option<i64>,
    },
    /// No such receiver generation.
    GenerationNotFound,
    /// The reporting generation has been replaced. It cannot advance its
    /// successor's frontier, and the projection is unchanged.
    StaleGeneration {
        /// The generation that is current for this receiver.
        current_membership_generation: i64,
    },
    /// The reporting generation is retired.
    RetiredGeneration,
    /// The report would move the frontier backward. Refused; the projection is
    /// unchanged.
    FrontierRegressed {
        /// The frontier still on the row.
        current_contiguous_frontier: i64,
    },
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn validate_poison_class(class: &str) -> Result<(), DomainError> {
    if class.is_empty() || class.len() > MAX_POISON_CLASS_BYTES {
        return Err(DomainError::InvalidInput(format!(
            "outbox poison class must be 1..={MAX_POISON_CLASS_BYTES} bytes, got {}",
            class.len()
        )));
    }
    // Deliberately narrow: this value is read back into operator tooling and
    // into a low-cardinality readiness reason, and a class carrying arbitrary
    // text would be a message with a different name. ASCII-only by
    // construction, so a multi-byte character fails rather than slipping
    // through a char/byte mismatch.
    if !class
        .bytes()
        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err(DomainError::InvalidInput(format!(
            "outbox poison class must match ^[A-Z0-9_]+$, got {class:?}"
        )));
    }
    Ok(())
}

/// Check the report's internal consistency before any database work.
///
/// The frontier-versus-blocker rule is the load-bearing one: the contract makes
/// the frontier contiguous *by definition*, so a report claiming a frontier at
/// or above one of its own unresolved blockers is not a stale report or a
/// conflict — it is a report that contradicts itself, and accepting it would
/// release exactly the events the blocker exists to hold.
fn validate_report(report: &CheckpointReport) -> Result<(), DomainError> {
    validate_receiver_identity(&report.receiver_identity)?;
    validate_stream(&report.stream_identity, report.stream_epoch)?;
    if report.membership_generation < 1 {
        return Err(DomainError::InvalidInput(format!(
            "outbox checkpoint membership_generation must be >= 1, got {}",
            report.membership_generation
        )));
    }
    if report.membership_version < 1 {
        return Err(DomainError::InvalidInput(format!(
            "outbox checkpoint membership_version must be >= 1, got {}",
            report.membership_version
        )));
    }
    if report.contiguous_frontier < 0 {
        return Err(DomainError::InvalidInput(format!(
            "outbox contiguous_frontier must be >= 0, got {}",
            report.contiguous_frontier
        )));
    }
    if report.gaps.len() > MAX_CHECKPOINT_BLOCKERS || report.poison.len() > MAX_CHECKPOINT_BLOCKERS
    {
        return Err(DomainError::InvalidInput(format!(
            "outbox checkpoint carries {} gaps and {} poison entries; at most \
             {MAX_CHECKPOINT_BLOCKERS} of each are accepted",
            report.gaps.len(),
            report.poison.len()
        )));
    }
    for gap in &report.gaps {
        if gap.from < 0 || gap.to < gap.from {
            return Err(DomainError::InvalidInput(format!(
                "outbox checkpoint gap {}..={} is not a non-negative ascending range",
                gap.from, gap.to
            )));
        }
        if gap.from <= report.contiguous_frontier {
            return Err(DomainError::InvalidInput(format!(
                "outbox checkpoint frontier {} is at or above its own unresolved gap {}..={}; a \
                 contiguous frontier never advances across a gap",
                report.contiguous_frontier, gap.from, gap.to
            )));
        }
    }
    for entry in &report.poison {
        validate_poison_class(&entry.class)?;
        if entry.broker_sequence < 0 {
            return Err(DomainError::InvalidInput(format!(
                "outbox poison broker_sequence must be >= 0, got {}",
                entry.broker_sequence
            )));
        }
        if entry.broker_sequence <= report.contiguous_frontier {
            return Err(DomainError::InvalidInput(format!(
                "outbox checkpoint frontier {} is at or above its own unresolved poison entry at \
                 sequence {}; a contiguous frontier never advances across a blocker",
                report.contiguous_frontier, entry.broker_sequence
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Row decoding
// ---------------------------------------------------------------------------

const CHECKPOINT_COLUMNS: &str = "cell_id, stream_identity, stream_epoch, receiver_identity, \
     membership_generation, membership_version, contiguous_frontier, \
     gap_starts, gap_ends, poison_sequences, poison_classes, reported_at, projection_at";

fn record_from(row: &Row) -> Result<CheckpointRecord, DomainError> {
    let starts: Vec<i64> = row.get("gap_starts");
    let ends: Vec<i64> = row.get("gap_ends");
    if starts.len() != ends.len() {
        // The `blocker_bounds` CHECK pairs these, so this is unreachable while
        // the schema holds. An explicit error rather than a zip that silently
        // truncates: a dropped gap is a released row.
        return Err(DomainError::Internal(format!(
            "outbox checkpoint gap arrays are unpaired ({} starts, {} ends); the column CHECK has \
             drifted",
            starts.len(),
            ends.len()
        )));
    }
    let sequences: Vec<i64> = row.get("poison_sequences");
    let classes: Vec<String> = row.get("poison_classes");
    if sequences.len() != classes.len() {
        return Err(DomainError::Internal(format!(
            "outbox checkpoint poison arrays are unpaired ({} sequences, {} classes); the column \
             CHECK has drifted",
            sequences.len(),
            classes.len()
        )));
    }
    Ok(CheckpointRecord {
        cell_id: row.get("cell_id"),
        stream_identity: row.get("stream_identity"),
        stream_epoch: row.get("stream_epoch"),
        receiver_identity: row.get("receiver_identity"),
        membership_generation: row.get("membership_generation"),
        membership_version: row.get("membership_version"),
        contiguous_frontier: row.get("contiguous_frontier"),
        gaps: starts
            .into_iter()
            .zip(ends)
            .map(|(from, to)| SequenceGap { from, to })
            .collect(),
        poison: sequences
            .into_iter()
            .zip(classes)
            .map(|(broker_sequence, class)| PoisonEntry {
                broker_sequence,
                class,
            })
            .collect(),
        reported_at: row.get("reported_at"),
        projection_at: row.get("projection_at"),
    })
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

/// Persist one authenticated checkpoint report.
///
/// The caller has already authenticated the reporter; this is the projection's
/// own set of fences, and each of them is a reason a correct receiver can hit
/// legitimately rather than an error class:
///
/// * the membership snapshot version must still be current, so one safety
///   evaluation never mixes two memberships;
/// * the report's stream identity and epoch must equal the cell's authoritative
///   current placement, which is what denies old-epoch advancement after a
///   reset;
/// * the reporting generation must be the current one for that receiver and not
///   retired, so a replaced generation cannot advance its successor; and
/// * the frontier must not move backward.
pub async fn report_checkpoint(
    client: &mut deadpool_postgres::Client,
    cell_id: &str,
    report: &CheckpointReport,
) -> Result<CheckpointOutcome, DomainError> {
    validate_cell_id(cell_id)?;
    validate_report(report)?;

    let tx = client
        .transaction()
        .await
        .map_err(|e| DomainError::from_pg("outbox checkpoint begin", e))?;

    // `FOR SHARE`, not a bare read. Without it the three comparisons below are
    // observations rather than a fence: a retirement or an accepted reset
    // committing between this read and the upsert would let the write land on a
    // generation that is no longer current, under a membership version that is
    // no longer current. Every membership writer takes `FOR UPDATE` on this row
    // first, so the share lock blocks them until this bounded transaction
    // commits — and it does not block the evaluator, which takes the same share
    // lock.
    let Some(state) = tx
        .query_opt(
            "SELECT membership_version, current_stream_identity, current_stream_epoch \
             FROM lore_outbox_membership_state WHERE cell_id = $1 FOR SHARE",
            &[&cell_id],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox checkpoint state select", e))?
    else {
        drop(tx);
        return Ok(CheckpointOutcome::CellUnknown);
    };
    let current_membership_version: i64 = state.get("membership_version");
    let current_stream_identity: Option<String> = state.get("current_stream_identity");
    let current_stream_epoch: Option<i64> = state.get("current_stream_epoch");

    if current_membership_version != report.membership_version {
        drop(tx);
        return Ok(CheckpointOutcome::MembershipVersionConflict {
            current_membership_version,
        });
    }
    if current_stream_identity.as_deref() != Some(report.stream_identity.as_str())
        || current_stream_epoch != Some(report.stream_epoch)
    {
        drop(tx);
        return Ok(CheckpointOutcome::EpochMismatch {
            current_stream_identity,
            current_stream_epoch,
        });
    }

    // The reporting generation must be this receiver's current one. Read the
    // greatest generation it has in the same transaction rather than trusting
    // the report's own claim to be current.
    let Some(current) = tx
        .query_opt(
            "SELECT membership_generation, state FROM lore_outbox_receiver_membership \
             WHERE cell_id = $1 AND receiver_identity = $2 \
             ORDER BY membership_generation DESC LIMIT 1",
            &[&cell_id, &report.receiver_identity],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox checkpoint generation select", e))?
    else {
        drop(tx);
        return Ok(CheckpointOutcome::GenerationNotFound);
    };
    let current_membership_generation: i64 = current.get("membership_generation");
    let current_state: String = current.get("state");
    if current_membership_generation != report.membership_generation {
        drop(tx);
        return Ok(CheckpointOutcome::StaleGeneration {
            current_membership_generation,
        });
    }
    if current_state == MEMBERSHIP_STATE_RETIRED {
        drop(tx);
        return Ok(CheckpointOutcome::RetiredGeneration);
    }

    let gap_starts: Vec<i64> = report.gaps.iter().map(|gap| gap.from).collect();
    let gap_ends: Vec<i64> = report.gaps.iter().map(|gap| gap.to).collect();
    let poison_sequences: Vec<i64> = report
        .poison
        .iter()
        .map(|entry| entry.broker_sequence)
        .collect();
    let poison_classes: Vec<String> = report
        .poison
        .iter()
        .map(|entry| entry.class.clone())
        .collect();

    // The frontier's monotonicity lives in the `ON CONFLICT ... WHERE`, not in
    // a read-then-write: two concurrent reports for one generation would both
    // pass a prior read and the later writer would win regardless of which
    // frontier was higher.
    let applied = tx
        .query_opt(
            "INSERT INTO lore_outbox_checkpoints \
                 (stream_identity, stream_epoch, receiver_identity, membership_generation, \
                  cell_id, membership_version, contiguous_frontier, \
                  gap_starts, gap_ends, poison_sequences, poison_classes, \
                  reported_at, projection_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, \
                     clock_timestamp(), clock_timestamp()) \
             ON CONFLICT (stream_identity, stream_epoch, receiver_identity, \
                          membership_generation) \
             DO UPDATE SET \
                 membership_version = EXCLUDED.membership_version, \
                 contiguous_frontier = EXCLUDED.contiguous_frontier, \
                 gap_starts = EXCLUDED.gap_starts, \
                 gap_ends = EXCLUDED.gap_ends, \
                 poison_sequences = EXCLUDED.poison_sequences, \
                 poison_classes = EXCLUDED.poison_classes, \
                 reported_at = EXCLUDED.reported_at, \
                 projection_at = clock_timestamp() \
             WHERE lore_outbox_checkpoints.contiguous_frontier <= EXCLUDED.contiguous_frontier \
             RETURNING contiguous_frontier",
            &[
                &report.stream_identity,
                &report.stream_epoch,
                &report.receiver_identity,
                &report.membership_generation,
                &cell_id,
                &report.membership_version,
                &report.contiguous_frontier,
                &gap_starts,
                &gap_ends,
                &poison_sequences,
                &poison_classes,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox checkpoint upsert", e))?;

    let Some(row) = applied else {
        // The conflict target matched and the monotonicity predicate refused
        // it, so a row exists and carries a higher frontier. Read it inside the
        // same transaction so the reported value is the one that won.
        let current = tx
            .query_opt(
                "SELECT contiguous_frontier FROM lore_outbox_checkpoints \
                 WHERE stream_identity = $1 AND stream_epoch = $2 \
                   AND receiver_identity = $3 AND membership_generation = $4",
                &[
                    &report.stream_identity,
                    &report.stream_epoch,
                    &report.receiver_identity,
                    &report.membership_generation,
                ],
            )
            .await
            .map_err(|e| DomainError::from_pg("outbox checkpoint regression read", e))?;
        let current_contiguous_frontier =
            current.as_ref().map_or(report.contiguous_frontier, |row| {
                row.get("contiguous_frontier")
            });
        drop(tx);
        return Ok(CheckpointOutcome::FrontierRegressed {
            current_contiguous_frontier,
        });
    };
    let contiguous_frontier: i64 = row.get("contiguous_frontier");

    classify_commit(tx.commit().await, "outbox checkpoint commit")?;
    Ok(CheckpointOutcome::Applied {
        contiguous_frontier,
    })
}

/// Read the whole vector for one stream and epoch.
///
/// Ordered by receiver and generation so an operator listing and a test
/// assertion see the same sequence.
pub async fn read_checkpoints(
    client: &impl GenericClient,
    cell_id: &str,
    stream_identity: &str,
    stream_epoch: i64,
) -> Result<Vec<CheckpointRecord>, DomainError> {
    validate_cell_id(cell_id)?;
    validate_stream(stream_identity, stream_epoch)?;
    let rows = client
        .query(
            &format!(
                "SELECT {CHECKPOINT_COLUMNS} FROM lore_outbox_checkpoints \
                 WHERE cell_id = $1 AND stream_identity = $2 AND stream_epoch = $3 \
                 ORDER BY receiver_identity, membership_generation"
            ),
            &[&cell_id, &stream_identity, &stream_epoch],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox checkpoint select", e))?;
    rows.iter().map(record_from).collect()
}

/// Read one receiver generation's checkpoint.
pub async fn read_checkpoint(
    client: &impl GenericClient,
    stream_identity: &str,
    stream_epoch: i64,
    receiver_identity: &str,
    membership_generation: i64,
) -> Result<Option<CheckpointRecord>, DomainError> {
    validate_stream(stream_identity, stream_epoch)?;
    validate_receiver_identity(receiver_identity)?;
    let row = client
        .query_opt(
            &format!(
                "SELECT {CHECKPOINT_COLUMNS} FROM lore_outbox_checkpoints \
                 WHERE stream_identity = $1 AND stream_epoch = $2 \
                   AND receiver_identity = $3 AND membership_generation = $4"
            ),
            &[
                &stream_identity,
                &stream_epoch,
                &receiver_identity,
                &membership_generation,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("outbox checkpoint row select", e))?;
    row.as_ref().map(record_from).transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> CheckpointReport {
        CheckpointReport {
            stream_identity: "DURABLE-sfo3-cell-a".to_string(),
            stream_epoch: 8,
            receiver_identity: "loreserver-sfo3-cell-a-1".to_string(),
            membership_generation: 4,
            membership_version: 31,
            contiguous_frontier: 930,
            gaps: Vec::new(),
            poison: Vec::new(),
        }
    }

    #[test]
    fn a_clean_report_validates() {
        assert!(validate_report(&report()).is_ok());
    }

    /// The contract's single most important frontier rule, enforced against the
    /// report itself rather than trusted: acknowledging 919-930 above an
    /// unresolved 917-918 leaves the frontier at 916.
    #[test]
    fn a_frontier_above_its_own_gap_is_refused() {
        let mut r = report();
        r.contiguous_frontier = 930;
        r.gaps = vec![SequenceGap { from: 917, to: 918 }];
        let error = validate_report(&r).expect_err("a frontier above its own gap must be refused");
        assert!(
            error.to_string().contains("never advances across a gap"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_frontier_below_its_gap_is_accepted() {
        let mut r = report();
        r.contiguous_frontier = 916;
        r.gaps = vec![SequenceGap { from: 917, to: 918 }];
        assert!(validate_report(&r).is_ok());
    }

    /// A frontier exactly AT the first unresolved sequence is refused too. The
    /// gap is inclusive, so `from` is itself unresolved and a frontier of
    /// `from` would claim it applied.
    #[test]
    fn a_frontier_at_the_first_unresolved_sequence_is_refused() {
        let mut r = report();
        r.contiguous_frontier = 917;
        r.gaps = vec![SequenceGap { from: 917, to: 918 }];
        assert!(validate_report(&r).is_err());
    }

    #[test]
    fn a_frontier_above_its_own_poison_entry_is_refused() {
        let mut r = report();
        r.contiguous_frontier = 918;
        r.poison = vec![PoisonEntry {
            broker_sequence: 917,
            class: "UNSUPPORTED_SCHEMA".to_string(),
        }];
        let error =
            validate_report(&r).expect_err("a frontier above its own poison must be refused");
        assert!(
            error
                .to_string()
                .contains("never advances across a blocker"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_frontier_below_its_poison_entry_is_accepted() {
        let mut r = report();
        r.contiguous_frontier = 916;
        r.poison = vec![PoisonEntry {
            broker_sequence: 917,
            class: "UNSUPPORTED_SCHEMA".to_string(),
        }];
        assert!(validate_report(&r).is_ok());
    }

    #[test]
    fn a_descending_gap_range_is_refused() {
        let mut r = report();
        r.contiguous_frontier = 900;
        r.gaps = vec![SequenceGap { from: 918, to: 917 }];
        assert!(validate_report(&r).is_err());
    }

    #[test]
    fn a_poison_class_is_a_bounded_classification_not_a_message() {
        assert!(validate_poison_class("UNSUPPORTED_SCHEMA").is_ok());
        assert!(validate_poison_class("INVALID_SCOPE_2").is_ok());
        assert!(validate_poison_class("").is_err());
        assert!(validate_poison_class("unsupported_schema").is_err());
        assert!(validate_poison_class("could not apply event 12").is_err());
        assert!(validate_poison_class(&"A".repeat(65)).is_err());
        // ASCII-only by construction: a multi-byte character is not an
        // uppercase ASCII byte, so it fails rather than passing a char check.
        assert!(validate_poison_class("CAFÉ").is_err());
    }

    #[test]
    fn too_many_blockers_are_refused() {
        let mut r = report();
        r.contiguous_frontier = 0;
        r.gaps = (1..=(MAX_CHECKPOINT_BLOCKERS as i64 + 1))
            .map(|n| SequenceGap {
                from: n * 10,
                to: n * 10,
            })
            .collect();
        assert!(validate_report(&r).is_err());
    }

    #[test]
    fn a_stale_generation_or_version_is_refused_before_any_write() {
        // Both are database-side fences, so what is provable here is the
        // shape: a report never carries generation 0 or version 0, which is
        // what would let it match a placeholder or an unseeded counter.
        let mut r = report();
        r.membership_generation = 0;
        assert!(validate_report(&r).is_err());
        let mut r = report();
        r.membership_version = 0;
        assert!(validate_report(&r).is_err());
    }

    #[test]
    fn a_record_reports_its_blockers() {
        let clean = CheckpointRecord {
            cell_id: "sfo3-cell-a".to_string(),
            stream_identity: "DURABLE-sfo3-cell-a".to_string(),
            stream_epoch: 8,
            receiver_identity: "loreserver-sfo3-cell-a-1".to_string(),
            membership_generation: 4,
            membership_version: 31,
            contiguous_frontier: 930,
            gaps: Vec::new(),
            poison: Vec::new(),
            reported_at: SystemTime::UNIX_EPOCH,
            projection_at: SystemTime::UNIX_EPOCH,
        };
        assert!(!clean.has_blockers());
        let mut gapped = clean.clone();
        gapped.gaps = vec![SequenceGap { from: 931, to: 932 }];
        assert!(gapped.has_blockers());
        let mut poisoned = clean;
        poisoned.poison = vec![PoisonEntry {
            broker_sequence: 931,
            class: "UNSUPPORTED_SCHEMA".to_string(),
        }];
        assert!(poisoned.has_blockers());
    }
}

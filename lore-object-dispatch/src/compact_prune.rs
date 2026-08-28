// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Pure compact-receipt final-prune and contiguous-watermark planner.
//!
//! This module performs no database, backup, filesystem, clock, provider, or runtime I/O. It
//! returns the exact compare-and-swap projection for a later serializable transaction.

use thiserror::Error;

use crate::CanonicalObjectStoreCompactReceipt;
use crate::OBJECT_STORE_FULL_TO_COMPACT_GLOBAL_SCOPE_ID;
use crate::ObjectStoreFullToCompactExpectedRevisions;
use crate::ObjectStoreFullToCompactNextCounters;
use crate::ObjectStoreFullToCompactScope;
use crate::ObjectStoreRecordStorageCounter;
use crate::contract::BoundedCanonicalWriter;
use crate::contract::validate_canonical_text;

const INTENT_DOMAIN: &[u8] = b"object-store-compact-prune-intent-v1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectStoreCompactPruneWatermark {
    pub pruned_through_compact_sequence: u64,
    pub watermark_revision: u64,
    pub last_prune_fingerprint: Option<[u8; 32]>,
    pub last_compact_blake3: Option<[u8; 32]>,
    pub last_pruned_at_unix_ms: Option<i64>,
    pub last_backup_revision: Option<String>,
    pub last_backup_manifest_blake3: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectStoreCompactPruneBackupCoverage {
    pub backup_revision: String,
    pub backup_manifest_blake3: [u8; 32],
    pub durable_covered_through_compact_sequence: u64,
    pub restore_verified_through_compact_sequence: u64,
    pub observed_at_unix_ms: i64,
}

pub enum ObjectStoreCompactPruneCandidate<'a> {
    CompactInstalled {
        compact_sequence: u64,
        compact: &'a CanonicalObjectStoreCompactReceipt,
    },
    CompactAbsent {
        compact_sequence: u64,
        compact_blake3: [u8; 32],
    },
    Conflict,
}

pub struct ObjectStoreCompactPruneInput<'a> {
    pub candidate: ObjectStoreCompactPruneCandidate<'a>,
    pub watermark: &'a ObjectStoreCompactPruneWatermark,
    pub backup_coverage: &'a ObjectStoreCompactPruneBackupCoverage,
    pub database_now_unix_ms: i64,
    pub global_counter: &'a ObjectStoreRecordStorageCounter,
    pub cell_counter: &'a ObjectStoreRecordStorageCounter,
    pub tenant_counter: &'a ObjectStoreRecordStorageCounter,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectStoreCompactPruneBackupMissing {
    DurableBackup,
    RestoreVerification,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObjectStoreCompactPruneDecision {
    ApplyCompactPrune {
        prune_fingerprint: [u8; 32],
        expected_compact_blake3: [u8; 32],
        expected_watermark_revision: u64,
        expected_counter_revisions: ObjectStoreFullToCompactExpectedRevisions,
        next_watermark: Box<ObjectStoreCompactPruneWatermark>,
        next_counters: Box<ObjectStoreFullToCompactNextCounters>,
    },
    ReplayPruned {
        pruned_through_compact_sequence: u64,
    },
    WaitPruneGap {
        expected_compact_sequence: u64,
    },
    WaitPruneFloor {
        eligible_at_unix_ms: i64,
    },
    WaitBackupCoverage {
        missing: ObjectStoreCompactPruneBackupMissing,
    },
    PruneConflict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum CompactPruneError {
    #[error("compact prune watermark is invalid")]
    InvalidWatermark,
    #[error("compact prune sequence is invalid")]
    InvalidSequence,
    #[error("compact prune backup coverage is invalid")]
    InvalidBackupCoverage,
    #[error("compact prune database time is invalid")]
    InvalidTime,
    #[error("compact prune counter scope or revision is invalid")]
    InvalidCounter,
    #[error("compact prune counter subtraction underflows")]
    CounterUnderflow,
    #[error("compact prune counter or revision overflows")]
    CounterOverflow,
    #[error("child compact prune counter exceeds the global counter")]
    ChildExceedsGlobal,
    #[error("compact prune canonical intent exceeds its bound")]
    CanonicalTooLarge,
}

fn validate_identity(value: &str) -> Result<(), CompactPruneError> {
    validate_canonical_text(value, u32::MAX).map_err(|_| CompactPruneError::InvalidBackupCoverage)
}

fn validate_watermark(value: &ObjectStoreCompactPruneWatermark) -> Result<(), CompactPruneError> {
    if value.watermark_revision == 0 {
        return Err(CompactPruneError::InvalidWatermark);
    }
    let present = [
        value.last_prune_fingerprint.is_some(),
        value.last_compact_blake3.is_some(),
        value.last_pruned_at_unix_ms.is_some(),
        value.last_backup_revision.is_some(),
        value.last_backup_manifest_blake3.is_some(),
    ];
    if value.pruned_through_compact_sequence == 0 {
        if present.into_iter().any(|field| field) {
            return Err(CompactPruneError::InvalidWatermark);
        }
    } else if present.into_iter().any(|field| !field)
        || value.last_pruned_at_unix_ms.is_some_and(|time| time < 0)
        || value
            .last_backup_revision
            .as_deref()
            .is_some_and(|revision| validate_identity(revision).is_err())
    {
        return Err(CompactPruneError::InvalidWatermark);
    }
    Ok(())
}

fn validate_backup(value: &ObjectStoreCompactPruneBackupCoverage) -> Result<(), CompactPruneError> {
    validate_identity(&value.backup_revision)?;
    if value.observed_at_unix_ms < 0
        || value.restore_verified_through_compact_sequence
            > value.durable_covered_through_compact_sequence
    {
        return Err(CompactPruneError::InvalidBackupCoverage);
    }
    Ok(())
}

fn validate_counter(
    value: &ObjectStoreRecordStorageCounter,
    expected_scope: ObjectStoreFullToCompactScope,
    expected_scope_id: &str,
) -> Result<(), CompactPruneError> {
    validate_canonical_text(&value.scope_id, u32::MAX)
        .map_err(|_| CompactPruneError::InvalidCounter)?;
    if value.scope != expected_scope
        || value.scope_id != expected_scope_id
        || value.counter_revision == 0
    {
        return Err(CompactPruneError::InvalidCounter);
    }
    Ok(())
}

fn children_within_global(
    global: &ObjectStoreRecordStorageCounter,
    children: [&ObjectStoreRecordStorageCounter; 2],
) -> bool {
    children.iter().all(|child| {
        child.full_record_rows <= global.full_record_rows
            && child.full_record_bytes <= global.full_record_bytes
            && child.compact_rows <= global.compact_rows
            && child.compact_bytes <= global.compact_bytes
    })
}

fn next_counter(
    value: &ObjectStoreRecordStorageCounter,
    compact_bytes: u64,
) -> Result<ObjectStoreRecordStorageCounter, CompactPruneError> {
    Ok(ObjectStoreRecordStorageCounter {
        scope: value.scope,
        scope_id: value.scope_id.clone(),
        full_record_rows: value.full_record_rows,
        full_record_bytes: value.full_record_bytes,
        compact_rows: value
            .compact_rows
            .checked_sub(1)
            .ok_or(CompactPruneError::CounterUnderflow)?,
        compact_bytes: value
            .compact_bytes
            .checked_sub(compact_bytes)
            .ok_or(CompactPruneError::CounterUnderflow)?,
        counter_revision: value
            .counter_revision
            .checked_add(1)
            .ok_or(CompactPruneError::CounterOverflow)?,
    })
}

fn prune_fingerprint(
    compact_sequence: u64,
    compact_blake3: &[u8; 32],
    compact_bytes: u64,
) -> Result<[u8; 32], CompactPruneError> {
    let mut output =
        BoundedCanonicalWriter::new(u32::MAX).map_err(|_| CompactPruneError::CanonicalTooLarge)?;
    output
        .raw(INTENT_DOMAIN)
        .and_then(|()| output.u64(compact_sequence))
        .and_then(|()| output.raw(compact_blake3))
        .and_then(|()| output.u64(1))
        .and_then(|()| output.u64(compact_bytes))
        .and_then(|()| output.u64(0))
        .map_err(|_| CompactPruneError::CanonicalTooLarge)?;
    Ok(*blake3::hash(&output.finish()).as_bytes())
}

pub fn decide_object_store_compact_prune(
    input: &ObjectStoreCompactPruneInput<'_>,
) -> Result<ObjectStoreCompactPruneDecision, CompactPruneError> {
    validate_watermark(input.watermark)?;
    let (compact_sequence, compact) = match &input.candidate {
        ObjectStoreCompactPruneCandidate::Conflict => {
            return Ok(ObjectStoreCompactPruneDecision::PruneConflict);
        }
        ObjectStoreCompactPruneCandidate::CompactAbsent {
            compact_sequence,
            compact_blake3,
        } => {
            if *compact_sequence == 0 {
                return Err(CompactPruneError::InvalidSequence);
            }
            if *compact_sequence <= input.watermark.pruned_through_compact_sequence {
                if *compact_sequence == input.watermark.pruned_through_compact_sequence
                    && input.watermark.last_compact_blake3.as_ref() != Some(compact_blake3)
                {
                    return Ok(ObjectStoreCompactPruneDecision::PruneConflict);
                }
                return Ok(ObjectStoreCompactPruneDecision::ReplayPruned {
                    pruned_through_compact_sequence: input
                        .watermark
                        .pruned_through_compact_sequence,
                });
            }
            return Ok(ObjectStoreCompactPruneDecision::PruneConflict);
        }
        ObjectStoreCompactPruneCandidate::CompactInstalled {
            compact_sequence,
            compact,
        } => (*compact_sequence, *compact),
    };
    if compact_sequence == 0 {
        return Err(CompactPruneError::InvalidSequence);
    }
    if compact_sequence <= input.watermark.pruned_through_compact_sequence {
        return Ok(ObjectStoreCompactPruneDecision::PruneConflict);
    }
    let expected_sequence = input
        .watermark
        .pruned_through_compact_sequence
        .checked_add(1)
        .ok_or(CompactPruneError::CounterOverflow)?;
    if compact_sequence != expected_sequence {
        return Ok(ObjectStoreCompactPruneDecision::WaitPruneGap {
            expected_compact_sequence: expected_sequence,
        });
    }
    if input.database_now_unix_ms < 0 {
        return Err(CompactPruneError::InvalidTime);
    }
    if input
        .watermark
        .last_pruned_at_unix_ms
        .is_some_and(|last| input.database_now_unix_ms < last)
    {
        return Err(CompactPruneError::InvalidTime);
    }
    if input.database_now_unix_ms < compact.value().compact_prune_after_unix_ms {
        return Ok(ObjectStoreCompactPruneDecision::WaitPruneFloor {
            eligible_at_unix_ms: compact.value().compact_prune_after_unix_ms,
        });
    }
    validate_backup(input.backup_coverage)?;
    if input.backup_coverage.observed_at_unix_ms > input.database_now_unix_ms {
        return Err(CompactPruneError::InvalidBackupCoverage);
    }
    if input
        .backup_coverage
        .durable_covered_through_compact_sequence
        < compact_sequence
    {
        return Ok(ObjectStoreCompactPruneDecision::WaitBackupCoverage {
            missing: ObjectStoreCompactPruneBackupMissing::DurableBackup,
        });
    }
    if input
        .backup_coverage
        .restore_verified_through_compact_sequence
        < compact_sequence
    {
        return Ok(ObjectStoreCompactPruneDecision::WaitBackupCoverage {
            missing: ObjectStoreCompactPruneBackupMissing::RestoreVerification,
        });
    }
    if input.backup_coverage.observed_at_unix_ms < compact.value().compacted_at_unix_ms {
        return Err(CompactPruneError::InvalidBackupCoverage);
    }

    validate_counter(
        input.global_counter,
        ObjectStoreFullToCompactScope::Global,
        OBJECT_STORE_FULL_TO_COMPACT_GLOBAL_SCOPE_ID,
    )?;
    validate_counter(
        input.cell_counter,
        ObjectStoreFullToCompactScope::Cell,
        &compact.value().authenticated_cell_id,
    )?;
    validate_counter(
        input.tenant_counter,
        ObjectStoreFullToCompactScope::Tenant,
        &compact.value().authenticated_tenant_id,
    )?;
    if !children_within_global(
        input.global_counter,
        [input.cell_counter, input.tenant_counter],
    ) {
        return Err(CompactPruneError::ChildExceedsGlobal);
    }
    let compact_bytes = u64::try_from(compact.canonical_bytes().len())
        .map_err(|_| CompactPruneError::CounterOverflow)?;
    let next_counters = ObjectStoreFullToCompactNextCounters {
        global: next_counter(input.global_counter, compact_bytes)?,
        cell: next_counter(input.cell_counter, compact_bytes)?,
        tenant: next_counter(input.tenant_counter, compact_bytes)?,
    };
    if !children_within_global(
        &next_counters.global,
        [&next_counters.cell, &next_counters.tenant],
    ) {
        return Err(CompactPruneError::ChildExceedsGlobal);
    }
    let fingerprint = prune_fingerprint(compact_sequence, compact.compact_blake3(), compact_bytes)?;
    let next_watermark = ObjectStoreCompactPruneWatermark {
        pruned_through_compact_sequence: compact_sequence,
        watermark_revision: input
            .watermark
            .watermark_revision
            .checked_add(1)
            .ok_or(CompactPruneError::CounterOverflow)?,
        last_prune_fingerprint: Some(fingerprint),
        last_compact_blake3: Some(*compact.compact_blake3()),
        last_pruned_at_unix_ms: Some(input.database_now_unix_ms),
        last_backup_revision: Some(input.backup_coverage.backup_revision.clone()),
        last_backup_manifest_blake3: Some(input.backup_coverage.backup_manifest_blake3),
    };
    Ok(ObjectStoreCompactPruneDecision::ApplyCompactPrune {
        prune_fingerprint: fingerprint,
        expected_compact_blake3: *compact.compact_blake3(),
        expected_watermark_revision: input.watermark.watermark_revision,
        expected_counter_revisions: ObjectStoreFullToCompactExpectedRevisions {
            global: input.global_counter.counter_revision,
            cell: input.cell_counter.counter_revision,
            tenant: input.tenant_counter.counter_revision,
        },
        next_watermark: Box::new(next_watermark),
        next_counters: Box::new(next_counters),
    })
}

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Pure full-record to compact-receipt storage transfer planner.
//!
//! This module performs no database, provider, filesystem, clock, or runtime I/O. It returns the
//! exact compare-and-swap counter projection that a later serializable persistence transaction may
//! apply together with compact insertion and heavy-row deletion.

use thiserror::Error;

use crate::CanonicalObjectStoreCompactReceipt;
use crate::ObjectStoreCompactAuthority;
use crate::ObjectStoreCompactCharge;
use crate::ObjectStoreCompactReceiptDecision;
use crate::contract::BoundedCanonicalWriter;
use crate::contract::validate_canonical_text;

const INTENT_DOMAIN: &[u8] = b"object-store-full-to-compact-intent-v1\0";
pub const OBJECT_STORE_FULL_TO_COMPACT_GLOBAL_SCOPE_ID: &str =
    "object-store-full-to-compact-global-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectStoreFullToCompactScope {
    Global,
    Cell,
    Tenant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectStoreFullToCompactDimension {
    Rows,
    Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectStoreFullRecordOwnership {
    pub provider_boundary_id: String,
    pub authenticated_cell_id: String,
    pub authenticated_tenant_id: String,
    pub logical_request_id: String,
    pub attempt_id: String,
    pub source_authority_blake3: [u8; 32],
    pub rows: u64,
    pub bytes: u64,
    pub concurrency: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectStoreRecordStorageCounter {
    pub scope: ObjectStoreFullToCompactScope,
    pub scope_id: String,
    pub full_record_rows: u64,
    pub full_record_bytes: u64,
    pub compact_rows: u64,
    pub compact_bytes: u64,
    pub counter_revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectStoreFullToCompactPolicy {
    pub policy_revision: String,
    pub max_full_record_rows_global: u64,
    pub max_full_record_bytes_global: u64,
    pub max_full_record_rows_per_cell: u64,
    pub max_full_record_bytes_per_cell: u64,
    pub max_full_record_rows_per_tenant: u64,
    pub max_full_record_bytes_per_tenant: u64,
    pub max_compact_rows_global: u64,
    pub max_compact_bytes_global: u64,
    pub max_compact_rows_per_cell: u64,
    pub max_compact_bytes_per_cell: u64,
    pub max_compact_rows_per_tenant: u64,
    pub max_compact_bytes_per_tenant: u64,
    pub full_record_low_water_reserve_rows: u64,
    pub full_record_low_water_reserve_bytes: u64,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ObjectStoreFullToCompactLifecycle {
    FullOwned {
        source_authority_blake3: [u8; 32],
    },
    CompactInstalled {
        transfer_fingerprint: [u8; 32],
        compact: Box<CanonicalObjectStoreCompactReceipt>,
    },
    Conflict,
}

pub struct ObjectStoreFullToCompactInput<'a> {
    pub compact_plan: &'a ObjectStoreCompactReceiptDecision,
    pub full_ownership: &'a ObjectStoreFullRecordOwnership,
    pub global_counter: &'a ObjectStoreRecordStorageCounter,
    pub cell_counter: &'a ObjectStoreRecordStorageCounter,
    pub tenant_counter: &'a ObjectStoreRecordStorageCounter,
    pub policy: &'a ObjectStoreFullToCompactPolicy,
    pub lifecycle: &'a ObjectStoreFullToCompactLifecycle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ObjectStoreFullToCompactExpectedRevisions {
    pub global: u64,
    pub cell: u64,
    pub tenant: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectStoreFullToCompactNextCounters {
    pub global: ObjectStoreRecordStorageCounter,
    pub cell: ObjectStoreRecordStorageCounter,
    pub tenant: ObjectStoreRecordStorageCounter,
}

#[derive(Clone, Debug, PartialEq)]
pub enum ObjectStoreFullToCompactDecision {
    ApplyFullToCompact {
        policy_revision: String,
        transfer_fingerprint: [u8; 32],
        expected_source_authority_blake3: [u8; 32],
        expected_counter_revisions: ObjectStoreFullToCompactExpectedRevisions,
        next_counters: Box<ObjectStoreFullToCompactNextCounters>,
        compact: Box<CanonicalObjectStoreCompactReceipt>,
    },
    ReplayTransfer {
        transfer_fingerprint: [u8; 32],
        compact: Box<CanonicalObjectStoreCompactReceipt>,
    },
    RetainFullCompactCapacity {
        exhausted_scope: ObjectStoreFullToCompactScope,
        exhausted_dimension: ObjectStoreFullToCompactDimension,
    },
    TransferConflict,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum FullToCompactError {
    #[error("full-to-compact input does not carry an applied compact plan")]
    InvalidCompactPlan,
    #[error("full-to-compact stable identity is not canonical")]
    InvalidIdentity,
    #[error("full-record ownership is malformed")]
    InvalidFullOwnership,
    #[error("full-to-compact counter scope or value is invalid")]
    InvalidCounter,
    #[error("full-to-compact policy is invalid")]
    InvalidPolicy,
    #[error("full-to-compact counter subtraction underflows")]
    CounterUnderflow,
    #[error("full-to-compact counter addition overflows")]
    CounterOverflow,
    #[error("child full-to-compact counter exceeds the global counter")]
    ChildExceedsGlobal,
    #[error("full-to-compact canonical intent exceeds its bound")]
    CanonicalTooLarge,
}

struct AppliedCompaction<'a> {
    expected_authority_blake3: [u8; 32],
    compact: &'a CanonicalObjectStoreCompactReceipt,
    compact_charge: ObjectStoreCompactCharge,
}

fn applied_compaction(
    value: &ObjectStoreCompactReceiptDecision,
) -> Result<AppliedCompaction<'_>, FullToCompactError> {
    let ObjectStoreCompactReceiptDecision::ApplyCompaction {
        expected_authority_blake3,
        expected_submit_receipt_blake3,
        expected_get_outcome_blake3,
        compact,
        compact_charge,
    } = value
    else {
        return Err(FullToCompactError::InvalidCompactPlan);
    };
    let bytes = u64::try_from(compact.canonical_bytes().len())
        .map_err(|_| FullToCompactError::InvalidCompactPlan)?;
    if compact_charge.rows != 1
        || compact_charge.concurrency != 0
        || compact_charge.bytes != bytes
        || compact.compact_blake3() != &compact.value().compact_blake3
        || authority_digest(compact) != expected_authority_blake3
        || compact.value().submit_receipt.receipt_blake3() != expected_submit_receipt_blake3
        || compact.value().get_outcome.outcome_blake3() != expected_get_outcome_blake3
    {
        return Err(FullToCompactError::InvalidCompactPlan);
    }
    Ok(AppliedCompaction {
        expected_authority_blake3: *expected_authority_blake3,
        compact,
        compact_charge: *compact_charge,
    })
}

fn authority_digest(compact: &CanonicalObjectStoreCompactReceipt) -> &[u8; 32] {
    match &compact.value().authority {
        ObjectStoreCompactAuthority::RequestState(value) => value.state_blake3(),
    }
}

fn validate_identity(value: &str) -> Result<(), FullToCompactError> {
    validate_canonical_text(value, u32::MAX).map_err(|_| FullToCompactError::InvalidIdentity)
}

fn validate_ownership(value: &ObjectStoreFullRecordOwnership) -> Result<(), FullToCompactError> {
    for identity in [
        &value.provider_boundary_id,
        &value.authenticated_cell_id,
        &value.authenticated_tenant_id,
        &value.logical_request_id,
        &value.attempt_id,
    ] {
        validate_identity(identity)?;
    }
    if value.rows != 1 || value.bytes == 0 || value.concurrency != 0 {
        return Err(FullToCompactError::InvalidFullOwnership);
    }
    Ok(())
}

fn ownership_binds_compact(
    value: &ObjectStoreFullRecordOwnership,
    applied: &AppliedCompaction<'_>,
) -> bool {
    let compact = applied.compact.value();
    value.source_authority_blake3 == applied.expected_authority_blake3
        && value.provider_boundary_id == compact.provider_boundary_id
        && value.authenticated_cell_id == compact.authenticated_cell_id
        && value.authenticated_tenant_id == compact.authenticated_tenant_id
        && value.logical_request_id == compact.logical_request_id
        && value.attempt_id == compact.attempt_id
}

fn transfer_fingerprint(
    ownership: &ObjectStoreFullRecordOwnership,
    applied: &AppliedCompaction<'_>,
) -> Result<[u8; 32], FullToCompactError> {
    let mut output =
        BoundedCanonicalWriter::new(u32::MAX).map_err(|_| FullToCompactError::CanonicalTooLarge)?;
    output
        .raw(INTENT_DOMAIN)
        .and_then(|()| output.text(&ownership.provider_boundary_id))
        .and_then(|()| output.text(&ownership.authenticated_cell_id))
        .and_then(|()| output.text(&ownership.authenticated_tenant_id))
        .and_then(|()| output.text(&ownership.logical_request_id))
        .and_then(|()| output.text(&ownership.attempt_id))
        .and_then(|()| output.raw(&ownership.source_authority_blake3))
        .and_then(|()| output.u64(ownership.rows))
        .and_then(|()| output.u64(ownership.bytes))
        .and_then(|()| output.u64(ownership.concurrency))
        .and_then(|()| output.raw(applied.compact.compact_blake3()))
        .and_then(|()| output.u64(applied.compact_charge.rows))
        .and_then(|()| output.u64(applied.compact_charge.bytes))
        .and_then(|()| output.u64(applied.compact_charge.concurrency))
        .map_err(|_| FullToCompactError::CanonicalTooLarge)?;
    Ok(*blake3::hash(&output.finish()).as_bytes())
}

fn validate_policy(value: &ObjectStoreFullToCompactPolicy) -> Result<(), FullToCompactError> {
    validate_identity(&value.policy_revision).map_err(|_| FullToCompactError::InvalidPolicy)?;
    let full_rows = [
        value.max_full_record_rows_global,
        value.max_full_record_rows_per_cell,
        value.max_full_record_rows_per_tenant,
    ];
    let full_bytes = [
        value.max_full_record_bytes_global,
        value.max_full_record_bytes_per_cell,
        value.max_full_record_bytes_per_tenant,
    ];
    let compact = [
        value.max_compact_rows_global,
        value.max_compact_bytes_global,
        value.max_compact_rows_per_cell,
        value.max_compact_bytes_per_cell,
        value.max_compact_rows_per_tenant,
        value.max_compact_bytes_per_tenant,
    ];
    if full_rows
        .iter()
        .chain(full_bytes.iter())
        .chain(compact.iter())
        .any(|maximum| *maximum == 0)
        || full_rows
            .iter()
            .any(|maximum| value.full_record_low_water_reserve_rows > *maximum)
        || full_bytes
            .iter()
            .any(|maximum| value.full_record_low_water_reserve_bytes > *maximum)
    {
        return Err(FullToCompactError::InvalidPolicy);
    }
    Ok(())
}

fn validate_counter(
    value: &ObjectStoreRecordStorageCounter,
    expected_scope: ObjectStoreFullToCompactScope,
    expected_scope_id: &str,
) -> Result<(), FullToCompactError> {
    validate_identity(&value.scope_id).map_err(|_| FullToCompactError::InvalidCounter)?;
    if value.scope != expected_scope
        || value.scope_id != expected_scope_id
        || value.counter_revision == 0
    {
        return Err(FullToCompactError::InvalidCounter);
    }
    Ok(())
}

fn next_counter(
    value: &ObjectStoreRecordStorageCounter,
    ownership: &ObjectStoreFullRecordOwnership,
    applied: &AppliedCompaction<'_>,
) -> Result<ObjectStoreRecordStorageCounter, FullToCompactError> {
    Ok(ObjectStoreRecordStorageCounter {
        scope: value.scope,
        scope_id: value.scope_id.clone(),
        full_record_rows: value
            .full_record_rows
            .checked_sub(ownership.rows)
            .ok_or(FullToCompactError::CounterUnderflow)?,
        full_record_bytes: value
            .full_record_bytes
            .checked_sub(ownership.bytes)
            .ok_or(FullToCompactError::CounterUnderflow)?,
        compact_rows: value
            .compact_rows
            .checked_add(applied.compact_charge.rows)
            .ok_or(FullToCompactError::CounterOverflow)?,
        compact_bytes: value
            .compact_bytes
            .checked_add(applied.compact_charge.bytes)
            .ok_or(FullToCompactError::CounterOverflow)?,
        counter_revision: value
            .counter_revision
            .checked_add(1)
            .ok_or(FullToCompactError::CounterOverflow)?,
    })
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

fn exhausted_capacity(
    counters: &ObjectStoreFullToCompactNextCounters,
    policy: &ObjectStoreFullToCompactPolicy,
) -> Option<(
    ObjectStoreFullToCompactScope,
    ObjectStoreFullToCompactDimension,
)> {
    [
        (
            ObjectStoreFullToCompactScope::Global,
            ObjectStoreFullToCompactDimension::Rows,
            counters.global.compact_rows,
            policy.max_compact_rows_global,
        ),
        (
            ObjectStoreFullToCompactScope::Global,
            ObjectStoreFullToCompactDimension::Bytes,
            counters.global.compact_bytes,
            policy.max_compact_bytes_global,
        ),
        (
            ObjectStoreFullToCompactScope::Cell,
            ObjectStoreFullToCompactDimension::Rows,
            counters.cell.compact_rows,
            policy.max_compact_rows_per_cell,
        ),
        (
            ObjectStoreFullToCompactScope::Cell,
            ObjectStoreFullToCompactDimension::Bytes,
            counters.cell.compact_bytes,
            policy.max_compact_bytes_per_cell,
        ),
        (
            ObjectStoreFullToCompactScope::Tenant,
            ObjectStoreFullToCompactDimension::Rows,
            counters.tenant.compact_rows,
            policy.max_compact_rows_per_tenant,
        ),
        (
            ObjectStoreFullToCompactScope::Tenant,
            ObjectStoreFullToCompactDimension::Bytes,
            counters.tenant.compact_bytes,
            policy.max_compact_bytes_per_tenant,
        ),
    ]
    .into_iter()
    .find_map(|(scope, dimension, used, maximum)| (used > maximum).then_some((scope, dimension)))
}

pub fn decide_object_store_full_to_compact(
    input: &ObjectStoreFullToCompactInput<'_>,
) -> Result<ObjectStoreFullToCompactDecision, FullToCompactError> {
    let applied = applied_compaction(input.compact_plan)?;
    validate_ownership(input.full_ownership)?;
    if !ownership_binds_compact(input.full_ownership, &applied) {
        return Ok(ObjectStoreFullToCompactDecision::TransferConflict);
    }
    let fingerprint = transfer_fingerprint(input.full_ownership, &applied)?;

    match input.lifecycle {
        ObjectStoreFullToCompactLifecycle::Conflict => {
            return Ok(ObjectStoreFullToCompactDecision::TransferConflict);
        }
        ObjectStoreFullToCompactLifecycle::CompactInstalled {
            transfer_fingerprint,
            compact,
        } => {
            if transfer_fingerprint != &fingerprint
                || compact.compact_blake3() != applied.compact.compact_blake3()
                || compact.canonical_bytes() != applied.compact.canonical_bytes()
            {
                return Ok(ObjectStoreFullToCompactDecision::TransferConflict);
            }
            return Ok(ObjectStoreFullToCompactDecision::ReplayTransfer {
                transfer_fingerprint: fingerprint,
                compact: compact.clone(),
            });
        }
        ObjectStoreFullToCompactLifecycle::FullOwned {
            source_authority_blake3,
        } if source_authority_blake3 != &input.full_ownership.source_authority_blake3 => {
            return Ok(ObjectStoreFullToCompactDecision::TransferConflict);
        }
        ObjectStoreFullToCompactLifecycle::FullOwned { .. } => {}
    }

    validate_policy(input.policy)?;
    validate_counter(
        input.global_counter,
        ObjectStoreFullToCompactScope::Global,
        OBJECT_STORE_FULL_TO_COMPACT_GLOBAL_SCOPE_ID,
    )?;
    validate_counter(
        input.cell_counter,
        ObjectStoreFullToCompactScope::Cell,
        &input.full_ownership.authenticated_cell_id,
    )?;
    validate_counter(
        input.tenant_counter,
        ObjectStoreFullToCompactScope::Tenant,
        &input.full_ownership.authenticated_tenant_id,
    )?;
    if !children_within_global(
        input.global_counter,
        [input.cell_counter, input.tenant_counter],
    ) {
        return Err(FullToCompactError::ChildExceedsGlobal);
    }
    let next_counters = ObjectStoreFullToCompactNextCounters {
        global: next_counter(input.global_counter, input.full_ownership, &applied)?,
        cell: next_counter(input.cell_counter, input.full_ownership, &applied)?,
        tenant: next_counter(input.tenant_counter, input.full_ownership, &applied)?,
    };
    if !children_within_global(
        &next_counters.global,
        [&next_counters.cell, &next_counters.tenant],
    ) {
        return Err(FullToCompactError::ChildExceedsGlobal);
    }
    if let Some((exhausted_scope, exhausted_dimension)) =
        exhausted_capacity(&next_counters, input.policy)
    {
        return Ok(
            ObjectStoreFullToCompactDecision::RetainFullCompactCapacity {
                exhausted_scope,
                exhausted_dimension,
            },
        );
    }
    Ok(ObjectStoreFullToCompactDecision::ApplyFullToCompact {
        policy_revision: input.policy.policy_revision.clone(),
        transfer_fingerprint: fingerprint,
        expected_source_authority_blake3: input.full_ownership.source_authority_blake3,
        expected_counter_revisions: ObjectStoreFullToCompactExpectedRevisions {
            global: input.global_counter.counter_revision,
            cell: input.cell_counter.counter_revision,
            tenant: input.tenant_counter.counter_revision,
        },
        next_counters: Box::new(next_counters),
        compact: Box::new(applied.compact.clone()),
    })
}

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-029 private receipt/proof-namespace maintenance transactions.
//!
//! The caller performs strict wire and auth-grpc verification before entering
//! these functions. Every function still exact-checks the immutable database
//! binding under its first row lock. A verifier response is evidence, not a
//! replacement for the database predicate.

use std::time::SystemTime;

use tokio_postgres::Transaction;

use crate::domain::errors::DomainError;
use crate::domain::receipts;
use crate::domain::receipts::AuthorizationWitness;
use crate::domain::receipts::OperationBinding;
use crate::domain::receipts::ReceiptKey;
use crate::domain::schema;
use crate::domain::schema_mediated;

/// Frozen no-dispatch reason for a verified operation that crossed the strict
/// 365-day Lore-clock boundary before any dispatch became possible.
pub const MEDIATED_VERIFIED_UUID_STALE_NO_DISPATCH_V1: &str =
    "MEDIATED_VERIFIED_UUID_STALE_NO_DISPATCH_V1";
/// Receipt-v2 protocol revision.
pub const RECEIPT_PROTOCOL_REVISION_V2: i32 = 2;
/// Receipt protocol v2 deterministically selects prune interval schema v3.
pub const MARKER_INTERVAL_SCHEMA_REVISION_V3: i32 = 3;

fn maintenance_mutation_disabled() -> Result<(), DomainError> {
    Err(DomainError::InvalidInput(
        "domain-operation maintenance mutations are disabled until the complete receipt-v2 rail is implemented"
            .to_owned(),
    ))
}

/// Exact stale-finalize request after wire and platform permit verification.
#[derive(Debug, Clone)]
pub struct VerifiedStaleFinalizeInput {
    pub key: ReceiptKey,
    pub binding: OperationBinding,
    pub witness: AuthorizationWitness,
    pub expected_claim_identity_digest: Vec<u8>,
    pub stale_finalize_permit: Vec<u8>,
    pub stale_finalize_permit_revision: i64,
    pub permit_verification_digest: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedStaleFinalizeStatus {
    Committed,
    NotEligibleNotStale,
    IneligibleReceiptOrDispatchPossible,
    Mismatch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedStaleFinalizeResult {
    pub status: VerifiedStaleFinalizeStatus,
    pub stale_finalize_permit_revision: i64,
    pub committed_receipt_canonical: Vec<u8>,
    pub stale_finalize_clock: Option<SystemTime>,
    pub response_digest: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalStatusAttachPhase {
    Phase1TerminalAck,
    Phase2ReleaseAck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalStatusAttachAction {
    None,
    ActiveReleaseIntentAck,
    TombstonePrunePoll,
    TombstoneReleaseIntentComplete,
}

/// Exact terminal attachment request. Optional fields are admitted only in the
/// phase/action combinations enforced by the strict codec.
#[derive(Debug, Clone)]
pub struct TerminalStatusAttachInput {
    pub key: ReceiptKey,
    pub authorization_id: Vec<u8>,
    pub authorization_revision: i64,
    pub claim_id: Vec<u8>,
    pub claim_revision: i64,
    pub terminal_outcome: i16,
    pub terminal_receipt_sha256: Vec<u8>,
    pub platform_terminal_status_revision: i64,
    pub acknowledged_at: SystemTime,
    pub phase: TerminalStatusAttachPhase,
    pub action: TerminalStatusAttachAction,
    pub reserve_charge_revision: i64,
    pub reserve_charge_nonce: Vec<u8>,
    pub release_tombstone_digest: Option<Vec<u8>>,
    pub active_release_intent_revision: Option<i64>,
    pub active_release_intent_nonce: Option<Vec<u8>>,
    pub tombstone_reservation_revision: i64,
    pub tombstone_reservation_nonce: Vec<u8>,
    pub final_prune_digest: Option<Vec<u8>>,
    pub tombstone_release_intent_revision: Option<i64>,
    pub tombstone_release_intent_nonce: Option<Vec<u8>>,
    pub release_proof_reservation_revision: i64,
    pub release_proof_reservation_nonce: Vec<u8>,
    pub completion_marker_sequence: i64,
    pub expected_completion_marker_digest: Option<Vec<u8>>,
    pub request_digest: Vec<u8>,
    pub verification_digest: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalStatusAttachStatus {
    Phase1PendingRetention,
    Phase1TombstoneReady,
    Phase2ActiveReleaseAcked,
    Phase2TombstoneRetentionPending,
    Phase2TombstoneFinalPruned,
    Phase2ReleaseCompletionReady,
    Phase2PostPruneRecovery,
    Phase2PostPruneCompletionReplayRequired,
    Mismatch,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminalStatusAttachmentAck {
    pub status: TerminalStatusAttachStatus,
    pub fields: [Option<Vec<u8>>; 10],
    pub times: [Option<SystemTime>; 6],
    pub completion_marker_sequence: i64,
    pub range: Option<ProofRange>,
    pub informational_high_water: Option<i64>,
    pub response_digest: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofRange {
    pub start_sequence: i64,
    pub end_sequence: i64,
    pub digest: Vec<u8>,
    pub generation: i64,
}

/// Namespace authority key, excluding its replaceable epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofNamespaceKey {
    pub verified_issuer: String,
    pub authenticated_subject: String,
    pub tenant_scope_key: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ProofNamespaceMaterializeInput {
    pub key: ProofNamespaceKey,
    pub protocol_revision: i32,
    pub namespace_epoch: Vec<u8>,
    pub namespace_claim_revision: i64,
    pub namespace_claim_nonce: Vec<u8>,
    pub platform_capacity_revision: i64,
    pub lore_local_capacity_revision: i64,
    pub request_digest: Vec<u8>,
    pub verification_digest: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofNamespaceMaterializeStatus {
    Materialized,
    Mismatch,
    CapacityBlocked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofNamespaceMaterializeReceipt {
    pub status: ProofNamespaceMaterializeStatus,
    pub namespace_epoch: Vec<u8>,
    pub namespace_claim_revision: i64,
    pub namespace_claim_nonce: Vec<u8>,
    pub lore_namespace_revision: i64,
    pub lore_global_counter_revision: i64,
    pub lore_org_counter_revision: i64,
    pub created_at: SystemTime,
    pub materialization_receipt_digest: Vec<u8>,
    pub response_digest: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ProofNamespaceRetireInput {
    pub key: ProofNamespaceKey,
    pub protocol_revision: i32,
    pub namespace_epoch: Vec<u8>,
    pub quota_revision: i32,
    pub final_range_set_digest: Vec<u8>,
    pub final_high_water: i64,
    pub retirement_fence_generation: i64,
    pub retirement_permit_revision: i64,
    pub issued_at: SystemTime,
    pub expires_at: SystemTime,
    pub zero_platform_state_digest: Vec<u8>,
    pub request_digest: Vec<u8>,
    pub namespace_claim_revision: i64,
    pub namespace_claim_nonce: Vec<u8>,
    pub verification_digest: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofNamespaceRetireStatus {
    Retired,
    RetiredOrAbsent,
    NotQuiescent,
    Mismatch,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofNamespaceRetireAck {
    pub status: ProofNamespaceRetireStatus,
    pub namespace_epoch: Vec<u8>,
    pub retirement_fence_generation: i64,
    pub quota_revision: i32,
    pub final_range_set_digest: Vec<u8>,
    pub final_high_water: i64,
    pub retired_at: Option<SystemTime>,
    pub namespace_claim_revision: i64,
    pub namespace_claim_nonce: Vec<u8>,
    pub response_digest: Vec<u8>,
}

fn append_part(out: &mut Vec<u8>, value: &[u8]) -> Result<(), DomainError> {
    let length = u32::try_from(value.len())
        .map_err(|_| DomainError::InvalidInput("canonical field exceeds u32".to_owned()))?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn canonical_digest(domain: &[u8], parts: &[&[u8]]) -> Result<Vec<u8>, DomainError> {
    let mut canonical = Vec::new();
    append_part(&mut canonical, domain)?;
    for part in parts {
        append_part(&mut canonical, part)?;
    }
    Ok(blake3::hash(&canonical).as_bytes().to_vec())
}

/// Frozen CR-029 final range-set digest. Integer fields are unsigned u64 big
/// endian and ranges must already be ordered by start sequence.
pub fn proof_namespace_final_range_set_digest(
    tenant_scope_key: &[u8],
    epoch: &[u8],
    protocol_revision: i32,
    quota_revision: i32,
    final_high_water: i64,
    ranges: &[ProofRange],
) -> Result<Vec<u8>, DomainError> {
    use ring::digest::Context;
    use ring::digest::SHA256;

    let protocol = u64::try_from(protocol_revision)
        .map_err(|_| DomainError::InvalidInput("negative protocol revision".to_owned()))?;
    let quota = u64::try_from(quota_revision)
        .map_err(|_| DomainError::InvalidInput("negative quota revision".to_owned()))?;
    let high_water = u64::try_from(final_high_water)
        .map_err(|_| DomainError::InvalidInput("negative final high-water".to_owned()))?;
    let range_count = u64::try_from(ranges.len())
        .map_err(|_| DomainError::InvalidInput("range count exceeds u64".to_owned()))?;
    let mut digest = Context::new(&SHA256);
    digest.update(b"domain-marker-final-range-set-v2\0");
    digest.update(tenant_scope_key);
    digest.update(epoch);
    for value in [
        protocol,
        quota,
        MARKER_INTERVAL_SCHEMA_REVISION_V3 as u64,
        high_water,
        range_count,
    ] {
        digest.update(&value.to_be_bytes());
    }
    for range in ranges {
        let start = u64::try_from(range.start_sequence)
            .map_err(|_| DomainError::InvalidInput("negative range start".to_owned()))?;
        let end = u64::try_from(range.end_sequence)
            .map_err(|_| DomainError::InvalidInput("negative range end".to_owned()))?;
        let count = end
            .checked_sub(start)
            .and_then(|delta| delta.checked_add(1))
            .ok_or_else(|| DomainError::InvalidInput("invalid range bounds".to_owned()))?;
        let generation = u64::try_from(range.generation)
            .map_err(|_| DomainError::InvalidInput("negative range generation".to_owned()))?;
        for value in [start, end, count, generation] {
            digest.update(&value.to_be_bytes());
        }
        digest.update(&range.digest);
    }
    Ok(digest.finish().as_ref().to_vec())
}

fn receipt_binding_matches(row: &tokio_postgres::Row, input: &VerifiedStaleFinalizeInput) -> bool {
    row.get::<_, String>("method") == input.binding.method
        && row.get::<_, Vec<u8>>("scope") == input.binding.scope
        && row.get::<_, i32>("fingerprint_version") == input.binding.fingerprint_version
        && row.get::<_, Vec<u8>>("fingerprint") == input.binding.fingerprint
        && row.get::<_, Vec<u8>>("canonical_intent_digest") == input.binding.canonical_intent_digest
}

fn finalize_result(
    input: &VerifiedStaleFinalizeInput,
    status: VerifiedStaleFinalizeStatus,
    canonical: Vec<u8>,
    clock: Option<SystemTime>,
) -> Result<VerifiedStaleFinalizeResult, DomainError> {
    let status_byte = [match status {
        VerifiedStaleFinalizeStatus::Committed => 1,
        VerifiedStaleFinalizeStatus::NotEligibleNotStale => 2,
        VerifiedStaleFinalizeStatus::IneligibleReceiptOrDispatchPossible => 3,
        VerifiedStaleFinalizeStatus::Mismatch => 5,
    }];
    let revision = input.stale_finalize_permit_revision.to_be_bytes();
    let response_digest = canonical_digest(
        b"domain-operation-verified-stale-finalize-response-v1",
        &[&status_byte, &revision, &canonical],
    )?;
    Ok(VerifiedStaleFinalizeResult {
        status,
        stale_finalize_permit_revision: input.stale_finalize_permit_revision,
        committed_receipt_canonical: canonical,
        stale_finalize_clock: clock,
        response_digest,
    })
}

/// Terminalize one already-verified stale operation only when the exact
/// receipt namespace has never gained dispatch possibility.
pub async fn verified_stale_finalize(
    tx: &Transaction<'_>,
    input: &VerifiedStaleFinalizeInput,
) -> Result<VerifiedStaleFinalizeResult, DomainError> {
    maintenance_mutation_disabled()?;
    let clock = receipts::admission_clock(tx).await?;
    let operation_id = input.key.operation_id.as_bytes().to_vec();
    let existing = tx
        .query_opt(
            "SELECT method, scope, fingerprint_version, fingerprint, canonical_intent_digest, \
                    state, outcome, not_applied_reason, public_result, committed_at \
             FROM lore_domain_operation_receipts \
             WHERE verified_issuer=$1 AND authenticated_subject=$2 \
               AND tenant_scope_key=$3 AND operation_id=$4 FOR UPDATE",
            &[
                &input.key.verified_issuer,
                &input.key.authenticated_subject,
                &input.key.tenant_scope_key,
                &operation_id,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("stale finalize receipt lock", e))?;
    if let Some(row) = existing {
        if !receipt_binding_matches(&row, input) {
            return finalize_result(
                input,
                VerifiedStaleFinalizeStatus::Mismatch,
                Vec::new(),
                None,
            );
        }
        let state: i16 = row.get("state");
        let reason: Option<String> = row.get("not_applied_reason");
        if state == schema::RECEIPT_STATE_COMMITTED
            && reason.as_deref() == Some(MEDIATED_VERIFIED_UUID_STALE_NO_DISPATCH_V1)
        {
            let canonical: Option<Vec<u8>> = row.get("public_result");
            let committed_at: Option<SystemTime> = row.get("committed_at");
            return finalize_result(
                input,
                VerifiedStaleFinalizeStatus::Committed,
                canonical.unwrap_or_default(),
                committed_at,
            );
        }
        return finalize_result(
            input,
            VerifiedStaleFinalizeStatus::IneligibleReceiptOrDispatchPossible,
            Vec::new(),
            None,
        );
    }

    let fence = tx
        .query_opt(
            "SELECT method, scope, fingerprint_version, fingerprint, canonical_intent_digest, \
                    authorization_id, authorization_revision, verification_nonce, \
                    bound_fields_digest, consumed_ticket_sha256, expected_claim_identity_digest \
             FROM lore_domain_operation_dispatch_possibility_fences \
             WHERE verified_issuer=$1 AND authenticated_subject=$2 \
               AND tenant_scope_key=$3 AND operation_id=$4 FOR UPDATE",
            &[
                &input.key.verified_issuer,
                &input.key.authenticated_subject,
                &input.key.tenant_scope_key,
                &operation_id,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("stale finalize fence lock", e))?;
    if let Some(row) = fence {
        let exact = row.get::<_, String>("method") == input.binding.method
            && row.get::<_, Vec<u8>>("scope") == input.binding.scope
            && row.get::<_, i32>("fingerprint_version") == input.binding.fingerprint_version
            && row.get::<_, Vec<u8>>("fingerprint") == input.binding.fingerprint
            && row.get::<_, Vec<u8>>("canonical_intent_digest")
                == input.binding.canonical_intent_digest
            && row.get::<_, Vec<u8>>("authorization_id") == input.witness.authorization_id
            && row.get::<_, i64>("authorization_revision") == input.witness.authorization_revision
            && row.get::<_, Vec<u8>>("verification_nonce") == input.witness.verification_nonce
            && row.get::<_, Vec<u8>>("bound_fields_digest") == input.witness.bound_fields_digest
            && row.get::<_, Vec<u8>>("consumed_ticket_sha256")
                == input.witness.consumed_ticket_sha256
            && row.get::<_, Vec<u8>>("expected_claim_identity_digest")
                == input.expected_claim_identity_digest;
        return finalize_result(
            input,
            if exact {
                VerifiedStaleFinalizeStatus::IneligibleReceiptOrDispatchPossible
            } else {
                VerifiedStaleFinalizeStatus::Mismatch
            },
            Vec::new(),
            None,
        );
    }

    let uuid_time = receipts::uuid_v7_timestamp(&input.key.operation_id)?;
    let stale_boundary = clock
        .checked_sub(receipts::STALE_HORIZON)
        .ok_or_else(|| DomainError::Internal("stale finalize clock underflow".to_owned()))?;
    if uuid_time >= stale_boundary {
        return finalize_result(
            input,
            VerifiedStaleFinalizeStatus::NotEligibleNotStale,
            Vec::new(),
            Some(clock),
        );
    }

    let clock_ms = clock
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| DomainError::Internal("stale finalize clock precedes epoch".to_owned()))?
        .as_millis();
    let canonical = format!(
        "{}:{}:{}",
        MEDIATED_VERIFIED_UUID_STALE_NO_DISPATCH_V1, input.stale_finalize_permit_revision, clock_ms
    )
    .into_bytes();
    let hard_expires_at = clock
        .checked_add(receipts::PREPARED_HARD_TTL)
        .ok_or_else(|| DomainError::Internal("stale finalize TTL overflow".to_owned()))?;
    let full_result_expires_at = clock
        .checked_add(receipts::FULL_RESULT_RETENTION)
        .ok_or_else(|| DomainError::Internal("stale finalize retention overflow".to_owned()))?;
    let compact_expires_at = clock
        .checked_add(receipts::STALE_HORIZON + receipts::MARKER_SAFETY_EPSILON)
        .ok_or_else(|| {
            DomainError::Internal("stale finalize compact retention overflow".to_owned())
        })?;
    let mut execution_witness = Vec::new();
    for part in [
        input.expected_claim_identity_digest.as_slice(),
        input.stale_finalize_permit.as_slice(),
        input.permit_verification_digest.as_slice(),
    ] {
        append_part(&mut execution_witness, part)?;
    }
    tx.execute(
        "INSERT INTO lore_domain_operation_receipts ( \
             verified_issuer, authenticated_subject, tenant_scope_key, operation_id, \
             method, scope, fingerprint_version, fingerprint, canonical_intent_digest, \
             state, outcome, not_applied_reason_version, not_applied_reason, \
             authorization_id, authorization_revision, verification_nonce, bound_fields_digest, \
             consumed_ticket_sha256, execution_witness, public_result, uuid_timestamp, \
             prepared_at, hard_expires_at, committed_at, full_result_expires_at, compact_expires_at \
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20, \
                   $21,$22,$23,$24,$25,$26)",
        &[&input.key.verified_issuer, &input.key.authenticated_subject, &input.key.tenant_scope_key,
          &operation_id, &input.binding.method, &input.binding.scope, &input.binding.fingerprint_version,
          &input.binding.fingerprint, &input.binding.canonical_intent_digest,
          &schema::RECEIPT_STATE_COMMITTED, &schema::RECEIPT_OUTCOME_NOT_APPLIED,
          &receipts::REASON_VERSION, &MEDIATED_VERIFIED_UUID_STALE_NO_DISPATCH_V1,
          &input.witness.authorization_id, &input.witness.authorization_revision,
          &input.witness.verification_nonce, &input.witness.bound_fields_digest,
          &input.witness.consumed_ticket_sha256, &execution_witness, &canonical, &uuid_time,
          &clock, &hard_expires_at, &clock, &full_result_expires_at, &compact_expires_at],
    )
    .await
    .map_err(|e| DomainError::from_pg("stale finalize receipt insert", e))?;
    finalize_result(
        input,
        VerifiedStaleFinalizeStatus::Committed,
        canonical,
        Some(clock),
    )
}

fn materialize_receipt(
    input: &ProofNamespaceMaterializeInput,
    status: ProofNamespaceMaterializeStatus,
    namespace_revision: i64,
    global_revision: i64,
    created_at: SystemTime,
) -> Result<ProofNamespaceMaterializeReceipt, DomainError> {
    let status_byte = [match status {
        ProofNamespaceMaterializeStatus::Materialized => 1,
        ProofNamespaceMaterializeStatus::Mismatch => 2,
        ProofNamespaceMaterializeStatus::CapacityBlocked => 3,
    }];
    let claim_revision = input.namespace_claim_revision.to_be_bytes();
    let namespace_revision_bytes = namespace_revision.to_be_bytes();
    let global_revision_bytes = global_revision.to_be_bytes();
    let receipt_digest = canonical_digest(
        b"domain-proof-namespace-materialization-receipt-v1",
        &[
            &status_byte,
            &input.namespace_epoch,
            &claim_revision,
            &input.namespace_claim_nonce,
            &namespace_revision_bytes,
            &global_revision_bytes,
        ],
    )?;
    let response_digest = canonical_digest(
        b"domain-proof-namespace-materialization-response-v1",
        &[
            &receipt_digest,
            &input.request_digest,
            &input.verification_digest,
        ],
    )?;
    Ok(ProofNamespaceMaterializeReceipt {
        status,
        namespace_epoch: input.namespace_epoch.clone(),
        namespace_claim_revision: input.namespace_claim_revision,
        namespace_claim_nonce: input.namespace_claim_nonce.clone(),
        lore_namespace_revision: namespace_revision,
        lore_global_counter_revision: global_revision,
        lore_org_counter_revision: global_revision,
        created_at,
        materialization_receipt_digest: receipt_digest,
        response_digest,
    })
}

pub async fn proof_namespace_materialize(
    tx: &Transaction<'_>,
    input: &ProofNamespaceMaterializeInput,
) -> Result<ProofNamespaceMaterializeReceipt, DomainError> {
    maintenance_mutation_disabled()?;
    let clock = receipts::admission_clock(tx).await?;
    if input.protocol_revision != RECEIPT_PROTOCOL_REVISION_V2 {
        return Err(DomainError::InvalidInput(
            "proof namespace protocol revision is not v2".to_owned(),
        ));
    }
    let quota_revision = i32::try_from(input.platform_capacity_revision)
        .map_err(|_| DomainError::InvalidInput("capacity revision exceeds i32".to_owned()))?;
    tx.execute(
        "INSERT INTO lore_domain_proof_global_counters (id, counter_revision, quota_revision, \
             represented_namespace_rows, retained_marker_count, outstanding_proof_claims, \
             fragment_count, fragment_bytes, marker_bytes, updated_at) \
         VALUES (1,$1,$2,0,0,0,0,0,0,$3) ON CONFLICT (id) DO NOTHING",
        &[&input.lore_local_capacity_revision, &quota_revision, &clock],
    )
    .await
    .map_err(|e| DomainError::from_pg("proof namespace global counter bootstrap", e))?;
    let counter = tx
        .query_one(
            "SELECT counter_revision, quota_revision FROM lore_domain_proof_global_counters \
             WHERE id=1 FOR UPDATE",
            &[],
        )
        .await
        .map_err(|e| DomainError::from_pg("proof namespace global counter lock", e))?;
    let current_revision: i64 = counter.get("counter_revision");
    let current_quota_revision: i32 = counter.get("quota_revision");
    if current_revision != input.lore_local_capacity_revision
        || current_quota_revision != quota_revision
    {
        return materialize_receipt(
            input,
            ProofNamespaceMaterializeStatus::CapacityBlocked,
            0,
            current_revision,
            clock,
        );
    }
    let existing = tx
        .query_opt(
            "SELECT epoch, claim_revision, claim_nonce, materialization_receipt, created_at \
             FROM lore_domain_proof_namespaces \
             WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 \
               AND state <> $4 FOR UPDATE",
            &[
                &input.key.verified_issuer,
                &input.key.authenticated_subject,
                &input.key.tenant_scope_key,
                &schema_mediated::NAMESPACE_STATE_RETIRED,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("proof namespace existing epoch lock", e))?;
    if let Some(row) = existing {
        let exact = row.get::<_, Vec<u8>>("epoch") == input.namespace_epoch
            && row.get::<_, i64>("claim_revision") == input.namespace_claim_revision
            && row.get::<_, Vec<u8>>("claim_nonce") == input.namespace_claim_nonce;
        if !exact {
            return materialize_receipt(
                input,
                ProofNamespaceMaterializeStatus::Mismatch,
                0,
                current_revision,
                clock,
            );
        }
        return materialize_receipt(
            input,
            ProofNamespaceMaterializeStatus::Materialized,
            1,
            current_revision,
            row.get("created_at"),
        );
    }
    let next_global_revision = current_revision.checked_add(1).ok_or_else(|| {
        DomainError::Internal("proof global counter revision overflow".to_owned())
    })?;
    let receipt = materialize_receipt(
        input,
        ProofNamespaceMaterializeStatus::Materialized,
        1,
        next_global_revision,
        clock,
    )?;
    let canonical_receipt = receipt.materialization_receipt_digest.clone();
    tx.execute(
        "INSERT INTO lore_domain_proof_namespaces ( \
             verified_issuer, authenticated_subject, tenant_scope_key, epoch, protocol_revision, \
             quota_revision, marker_interval_schema_revision, claim_revision, claim_nonce, \
             next_sequence, high_water, retained_marker_count, outstanding_proof_claims, \
             fragment_count, state, materialization_receipt, created_at, updated_at \
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,1,0,0,0,0,$10,$11,$12,$13)",
        &[
            &input.key.verified_issuer,
            &input.key.authenticated_subject,
            &input.key.tenant_scope_key,
            &input.namespace_epoch,
            &input.protocol_revision,
            &quota_revision,
            &MARKER_INTERVAL_SCHEMA_REVISION_V3,
            &input.namespace_claim_revision,
            &input.namespace_claim_nonce,
            &schema_mediated::NAMESPACE_STATE_ACTIVE,
            &canonical_receipt,
            &clock,
            &clock,
        ],
    )
    .await
    .map_err(|e| DomainError::from_pg("proof namespace materialize", e))?;
    tx.execute(
        "UPDATE lore_domain_proof_global_counters SET counter_revision=$1, \
             represented_namespace_rows=represented_namespace_rows+1, updated_at=$2 WHERE id=1",
        &[&next_global_revision, &clock],
    )
    .await
    .map_err(|e| DomainError::from_pg("proof namespace global counter increment", e))?;
    Ok(receipt)
}

fn retire_ack(
    input: &ProofNamespaceRetireInput,
    status: ProofNamespaceRetireStatus,
    retired_at: Option<SystemTime>,
) -> Result<ProofNamespaceRetireAck, DomainError> {
    let status_byte = [match status {
        ProofNamespaceRetireStatus::Retired => 1,
        ProofNamespaceRetireStatus::RetiredOrAbsent => 2,
        ProofNamespaceRetireStatus::NotQuiescent => 3,
        ProofNamespaceRetireStatus::Mismatch => 4,
        ProofNamespaceRetireStatus::Expired => 5,
    }];
    let fence = input.retirement_fence_generation.to_be_bytes();
    let response_digest = canonical_digest(
        b"domain-proof-namespace-retire-response-v1",
        &[
            &status_byte,
            &input.namespace_epoch,
            &fence,
            &input.final_range_set_digest,
            &input.request_digest,
            &input.verification_digest,
        ],
    )?;
    Ok(ProofNamespaceRetireAck {
        status,
        namespace_epoch: input.namespace_epoch.clone(),
        retirement_fence_generation: input.retirement_fence_generation,
        quota_revision: input.quota_revision,
        final_range_set_digest: input.final_range_set_digest.clone(),
        final_high_water: input.final_high_water,
        retired_at,
        namespace_claim_revision: input.namespace_claim_revision,
        namespace_claim_nonce: input.namespace_claim_nonce.clone(),
        response_digest,
    })
}

pub async fn proof_namespace_retire(
    tx: &Transaction<'_>,
    input: &ProofNamespaceRetireInput,
) -> Result<ProofNamespaceRetireAck, DomainError> {
    maintenance_mutation_disabled()?;
    let clock = receipts::admission_clock(tx).await?;
    if input.protocol_revision != RECEIPT_PROTOCOL_REVISION_V2
        || input.retirement_fence_generation <= 0
        || input.retirement_permit_revision <= 0
    {
        return Err(DomainError::InvalidInput(
            "invalid proof namespace retirement revision".to_owned(),
        ));
    }
    if clock >= input.expires_at || input.issued_at >= input.expires_at {
        return retire_ack(input, ProofNamespaceRetireStatus::Expired, None);
    }
    if input.retirement_fence_generation != input.retirement_permit_revision {
        return retire_ack(input, ProofNamespaceRetireStatus::Mismatch, None);
    }
    let row = tx
        .query_opt(
            "SELECT epoch, protocol_revision, quota_revision, marker_interval_schema_revision, \
                    claim_revision, claim_nonce, high_water, retained_marker_count, \
                    outstanding_proof_claims, fragment_count \
             FROM lore_domain_proof_namespaces \
             WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 \
               AND state <> $4 FOR UPDATE",
            &[
                &input.key.verified_issuer,
                &input.key.authenticated_subject,
                &input.key.tenant_scope_key,
                &schema_mediated::NAMESPACE_STATE_RETIRED,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("proof namespace retirement lock", e))?;
    let Some(row) = row else {
        return retire_ack(input, ProofNamespaceRetireStatus::RetiredOrAbsent, None);
    };
    let exact = row.get::<_, Vec<u8>>("epoch") == input.namespace_epoch
        && row.get::<_, i32>("protocol_revision") == input.protocol_revision
        && row.get::<_, i32>("quota_revision") == input.quota_revision
        && row.get::<_, i32>("marker_interval_schema_revision")
            == MARKER_INTERVAL_SCHEMA_REVISION_V3
        && row.get::<_, i64>("claim_revision") == input.namespace_claim_revision
        && row.get::<_, Vec<u8>>("claim_nonce") == input.namespace_claim_nonce;
    if !exact {
        return retire_ack(input, ProofNamespaceRetireStatus::Mismatch, None);
    }
    let high_water: i64 = row.get("high_water");
    let retained: i64 = row.get("retained_marker_count");
    let outstanding: i64 = row.get("outstanding_proof_claims");
    let fragments: i64 = row.get("fragment_count");
    let range_rows = tx
        .query(
            "SELECT start_sequence, end_sequence, interval_digest, generation \
             FROM lore_domain_tombstone_marker_prune_ranges \
             WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 \
               AND epoch=$4 ORDER BY start_sequence FOR UPDATE",
            &[
                &input.key.verified_issuer,
                &input.key.authenticated_subject,
                &input.key.tenant_scope_key,
                &input.namespace_epoch,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("proof namespace retirement ranges", e))?;
    let ranges: Vec<ProofRange> = range_rows
        .iter()
        .map(|row| ProofRange {
            start_sequence: row.get("start_sequence"),
            end_sequence: row.get("end_sequence"),
            digest: row.get("interval_digest"),
            generation: row.get("generation"),
        })
        .collect();
    let range_count = i64::try_from(ranges.len())
        .map_err(|_| DomainError::Internal("range count exceeds i64".to_owned()))?;
    let actual_range_set_digest = proof_namespace_final_range_set_digest(
        &input.key.tenant_scope_key,
        &input.namespace_epoch,
        input.protocol_revision,
        input.quota_revision,
        input.final_high_water,
        &ranges,
    )?;
    if actual_range_set_digest != input.final_range_set_digest {
        return retire_ack(input, ProofNamespaceRetireStatus::Mismatch, None);
    }
    let complete_ranges = if input.final_high_water == 0 {
        range_count == 0
    } else {
        range_count == 1
            && ranges.first().is_some_and(|range| {
                range.start_sequence == 1 && range.end_sequence == input.final_high_water
            })
    };
    if high_water != input.final_high_water
        || retained != 0
        || outstanding != 0
        || fragments != range_count
        || !complete_ranges
    {
        return retire_ack(input, ProofNamespaceRetireStatus::NotQuiescent, None);
    }
    // Commit-time clock predicate. Equality is expired and deletes nothing.
    let deleted = tx
        .execute(
            "DELETE FROM lore_domain_proof_namespaces \
             WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 \
               AND epoch=$4 AND clock_timestamp() < $5",
            &[
                &input.key.verified_issuer,
                &input.key.authenticated_subject,
                &input.key.tenant_scope_key,
                &input.namespace_epoch,
                &input.expires_at,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("proof namespace retirement delete", e))?;
    if deleted != 1 {
        return retire_ack(input, ProofNamespaceRetireStatus::Expired, None);
    }
    tx.execute(
        "DELETE FROM lore_domain_tombstone_marker_prune_ranges \
         WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND epoch=$4",
        &[&input.key.verified_issuer, &input.key.authenticated_subject,
          &input.key.tenant_scope_key, &input.namespace_epoch],
    )
    .await
    .map_err(|e| DomainError::from_pg("proof namespace final range delete", e))?;
    tx.execute(
        "UPDATE lore_domain_proof_global_counters SET \
             counter_revision=counter_revision+1, \
             represented_namespace_rows=represented_namespace_rows-1, updated_at=$1 \
         WHERE id=1 AND represented_namespace_rows > 0",
        &[&clock],
    )
    .await
    .map_err(|e| DomainError::from_pg("proof namespace global counter decrement", e))?;
    retire_ack(input, ProofNamespaceRetireStatus::Retired, Some(clock))
}

fn empty_terminal_ack(status: TerminalStatusAttachStatus) -> TerminalStatusAttachmentAck {
    TerminalStatusAttachmentAck {
        status,
        fields: std::array::from_fn(|_| None),
        times: std::array::from_fn(|_| None),
        completion_marker_sequence: 0,
        range: None,
        informational_high_water: None,
        response_digest: Vec::new(),
    }
}

fn system_time_unix_millis(value: SystemTime) -> Result<i64, DomainError> {
    let millis = value
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| DomainError::InvalidInput("timestamp precedes Unix epoch".to_owned()))?
        .as_millis();
    i64::try_from(millis)
        .map_err(|_| DomainError::InvalidInput("timestamp milliseconds exceed i64".to_owned()))
}

fn canonical_terminal_ack(input: &TerminalStatusAttachInput) -> Result<Vec<u8>, DomainError> {
    let mut canonical = Vec::new();
    append_part(&mut canonical, b"domain-terminal-status-attachment-ack-v1")?;
    for field in [
        input.key.verified_issuer.as_bytes(),
        input.key.authenticated_subject.as_bytes(),
        input.key.tenant_scope_key.as_slice(),
        input.key.operation_id.as_bytes(),
        input.authorization_id.as_slice(),
        input.authorization_revision.to_be_bytes().as_slice(),
        input.claim_id.as_slice(),
        input.claim_revision.to_be_bytes().as_slice(),
        input.terminal_outcome.to_be_bytes().as_slice(),
        input.terminal_receipt_sha256.as_slice(),
        input
            .platform_terminal_status_revision
            .to_be_bytes()
            .as_slice(),
        system_time_unix_millis(input.acknowledged_at)?
            .to_be_bytes()
            .as_slice(),
    ] {
        append_part(&mut canonical, field)?;
    }
    Ok(canonical)
}

fn finish_terminal_ack(
    input: &TerminalStatusAttachInput,
    mut ack: TerminalStatusAttachmentAck,
) -> Result<TerminalStatusAttachmentAck, DomainError> {
    let status = [match ack.status {
        TerminalStatusAttachStatus::Phase1PendingRetention => 1,
        TerminalStatusAttachStatus::Phase1TombstoneReady => 2,
        TerminalStatusAttachStatus::Phase2ActiveReleaseAcked => 3,
        TerminalStatusAttachStatus::Phase2TombstoneRetentionPending => 4,
        TerminalStatusAttachStatus::Phase2TombstoneFinalPruned => 5,
        TerminalStatusAttachStatus::Phase2ReleaseCompletionReady => 6,
        TerminalStatusAttachStatus::Phase2PostPruneRecovery => 7,
        TerminalStatusAttachStatus::Phase2PostPruneCompletionReplayRequired => 8,
        TerminalStatusAttachStatus::Mismatch => 9,
        TerminalStatusAttachStatus::Invalid => 10,
    }];
    ack.response_digest = canonical_digest(
        b"domain-terminal-status-attachment-response-v1",
        &[
            &status,
            input.key.operation_id.as_bytes(),
            &input.request_digest,
            &input.verification_digest,
        ],
    )?;
    Ok(ack)
}

pub async fn terminal_status_attach(
    tx: &Transaction<'_>,
    input: &TerminalStatusAttachInput,
) -> Result<TerminalStatusAttachmentAck, DomainError> {
    maintenance_mutation_disabled()?;
    let clock = receipts::admission_clock(tx).await?;
    let key = &[
        &input.key.verified_issuer as &(dyn tokio_postgres::types::ToSql + Sync),
        &input.key.authenticated_subject,
        &input.key.tenant_scope_key,
        &input.key.operation_id.as_bytes().as_slice(),
    ];
    if input.phase == TerminalStatusAttachPhase::Phase1TerminalAck {
        let receipt = tx.query_opt(
            "SELECT method, scope, fingerprint_version, fingerprint, state, outcome, public_result, \
                    authorization_id, authorization_revision, compact_expires_at \
             FROM lore_domain_operation_receipts WHERE verified_issuer=$1 AND authenticated_subject=$2 \
               AND tenant_scope_key=$3 AND operation_id=$4 FOR UPDATE", key,
        ).await.map_err(|e| DomainError::from_pg("terminal attachment receipt lock", e))?;
        let fence = tx
            .query_opt(
                "SELECT authorization_id, authorization_revision, safe_prune_after, \
                    terminal_status_ack_digest, terminal_status_revision, terminal_status_ack_at \
             FROM lore_domain_operation_dispatch_possibility_fences \
             WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 \
               AND operation_id=$4 FOR UPDATE",
                key,
            )
            .await
            .map_err(|e| DomainError::from_pg("terminal attachment fence lock", e))?;
        let (Some(receipt), Some(fence)) = (receipt, fence) else {
            let tombstone = tx.query_opt(
                "SELECT terminal_ack_digest, receipt_prune_digest, fence_prune_digest, phase1_response, \
                        created_at, final_prune_after, tombstone_digest, authorization_id, authorization_revision, \
                        claim_id, claim_revision, reserve_charge_revision, reserve_charge_nonce \
                 FROM lore_domain_operation_reserve_release_tombstones WHERE verified_issuer=$1 \
                   AND authenticated_subject=$2 AND tenant_scope_key=$3 AND operation_id=$4 FOR UPDATE", key,
            ).await.map_err(|e| DomainError::from_pg("terminal phase1 tombstone replay", e))?;
            if let Some(row) = tombstone {
                let exact = row.get::<_, Vec<u8>>("authorization_id") == input.authorization_id
                    && row.get::<_, i64>("authorization_revision") == input.authorization_revision
                    && row.get::<_, Vec<u8>>("claim_id") == input.claim_id
                    && row.get::<_, i64>("claim_revision") == input.claim_revision
                    && row.get::<_, i64>("reserve_charge_revision")
                        == input.reserve_charge_revision
                    && row.get::<_, Vec<u8>>("reserve_charge_nonce") == input.reserve_charge_nonce;
                if exact {
                    let mut ack =
                        empty_terminal_ack(TerminalStatusAttachStatus::Phase1TombstoneReady);
                    ack.fields[0] = Some(row.get("phase1_response"));
                    ack.fields[1] = Some(row.get("terminal_ack_digest"));
                    ack.fields[2] = Some(row.get("receipt_prune_digest"));
                    ack.fields[3] = Some(row.get("fence_prune_digest"));
                    ack.fields[4] = Some(row.get("tombstone_digest"));
                    ack.times[0] = Some(row.get("created_at"));
                    ack.times[1] = Some(row.get("final_prune_after"));
                    return finish_terminal_ack(input, ack);
                }
            }
            return finish_terminal_ack(
                input,
                empty_terminal_ack(TerminalStatusAttachStatus::Mismatch),
            );
        };
        let exact = receipt.get::<_, i16>("state") == schema::RECEIPT_STATE_COMMITTED
            && receipt.get::<_, Option<i16>>("outcome") == Some(input.terminal_outcome)
            && receipt
                .get::<_, Option<Vec<u8>>>("authorization_id")
                .as_deref()
                == Some(input.authorization_id.as_slice())
            && receipt.get::<_, Option<i64>>("authorization_revision")
                == Some(input.authorization_revision)
            && fence.get::<_, Vec<u8>>("authorization_id") == input.authorization_id
            && fence.get::<_, i64>("authorization_revision") == input.authorization_revision;
        let public_result = receipt
            .get::<_, Option<Vec<u8>>>("public_result")
            .unwrap_or_default();
        let receipt_sha = ring::digest::digest(&ring::digest::SHA256, &public_result);
        if !exact || receipt_sha.as_ref() != input.terminal_receipt_sha256 {
            return finish_terminal_ack(
                input,
                empty_terminal_ack(TerminalStatusAttachStatus::Mismatch),
            );
        }
        let terminal_ack_canonical = canonical_terminal_ack(input)?;
        let terminal_ack = ring::digest::digest(&ring::digest::SHA256, &terminal_ack_canonical)
            .as_ref()
            .to_vec();
        if let Some(existing) = fence.get::<_, Option<Vec<u8>>>("terminal_status_ack_digest") {
            if existing != terminal_ack
                || fence.get::<_, Option<i64>>("terminal_status_revision")
                    != Some(input.platform_terminal_status_revision)
            {
                return finish_terminal_ack(
                    input,
                    empty_terminal_ack(TerminalStatusAttachStatus::Mismatch),
                );
            }
        } else {
            tx.execute(
                "UPDATE lore_domain_operation_dispatch_possibility_fences SET \
                    terminal_status_ack_digest=$5, terminal_status_revision=$6, terminal_status_ack_at=$7 \
                 WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND operation_id=$4",
                &[key[0], key[1], key[2], key[3], &terminal_ack, &input.platform_terminal_status_revision,
                  &input.acknowledged_at],
            ).await.map_err(|e| DomainError::from_pg("terminal attachment acknowledgement", e))?;
        }
        let prune_after: SystemTime = receipt
            .get::<_, Option<SystemTime>>("compact_expires_at")
            .unwrap_or(fence.get("safe_prune_after"));
        if clock < prune_after {
            let mut ack = empty_terminal_ack(TerminalStatusAttachStatus::Phase1PendingRetention);
            ack.fields[0] = Some(terminal_ack_canonical);
            ack.fields[1] = Some(terminal_ack);
            return finish_terminal_ack(input, ack);
        }
        let receipt_prune = canonical_digest(
            b"domain-receipt-final-prune-v1",
            &[
                input.key.operation_id.as_bytes(),
                &input.terminal_receipt_sha256,
                &input.request_digest,
            ],
        )?;
        let fence_prune = canonical_digest(
            b"domain-dispatch-fence-prune-v1",
            &[
                input.key.operation_id.as_bytes(),
                &terminal_ack,
                &input.request_digest,
            ],
        )?;
        let compact_after = clock
            .checked_add(std::time::Duration::from_secs(30 * 24 * 60 * 60))
            .ok_or_else(|| DomainError::Internal("tombstone compact time overflow".to_owned()))?;
        let final_prune_after = clock
            .checked_add(std::time::Duration::from_secs(365 * 24 * 60 * 60))
            .ok_or_else(|| DomainError::Internal("tombstone retention overflow".to_owned()))?;
        let tombstone_digest = canonical_digest(
            b"domain-reserve-release-tombstone-v1",
            &[
                input.key.operation_id.as_bytes(),
                &input.authorization_id,
                &input.claim_id,
                &terminal_ack,
                &receipt_prune,
                &fence_prune,
                &input.request_digest,
            ],
        )?;
        let phase1_response = terminal_ack_canonical;
        let tombstone_reservation_claim = canonical_digest(
            b"domain-tombstone-reservation-claim-v1",
            &[
                &input.tombstone_reservation_revision.to_be_bytes(),
                &input.tombstone_reservation_nonce,
                input.key.operation_id.as_bytes(),
            ],
        )?;
        tx.execute(
            "INSERT INTO lore_domain_operation_reserve_release_tombstones (verified_issuer, \
                authenticated_subject, tenant_scope_key, operation_id, method, scope, fingerprint_version, \
                fingerprint, authorization_id, authorization_revision, claim_id, claim_revision, \
                reserve_charge_revision, reserve_charge_nonce, tombstone_reservation_revision, \
                tombstone_reservation_nonce, terminal_ack_digest, receipt_prune_digest, fence_prune_digest, \
                phase1_response, created_at, compact_after, final_prune_after, tombstone_digest) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24) \
             ON CONFLICT DO NOTHING",
            &[key[0],key[1],key[2],key[3],&receipt.get::<_,String>("method"),
              &receipt.get::<_,Vec<u8>>("scope"),&receipt.get::<_,i32>("fingerprint_version"),
              &receipt.get::<_,Vec<u8>>("fingerprint"),&input.authorization_id,&input.authorization_revision,
              &input.claim_id,&input.claim_revision,&input.reserve_charge_revision,&input.reserve_charge_nonce,
              &input.tombstone_reservation_revision,&input.tombstone_reservation_nonce,&terminal_ack,
              &receipt_prune,&fence_prune,&phase1_response,&clock,&compact_after,&final_prune_after,&tombstone_digest],
        ).await.map_err(|e| DomainError::from_pg("terminal attachment tombstone insert", e))?;
        tx.execute("DELETE FROM lore_domain_operation_receipts WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND operation_id=$4", key)
            .await.map_err(|e| DomainError::from_pg("terminal attachment receipt prune", e))?;
        tx.execute("DELETE FROM lore_domain_operation_dispatch_possibility_fences WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND operation_id=$4", key)
            .await.map_err(|e| DomainError::from_pg("terminal attachment fence prune", e))?;
        let mut ack = empty_terminal_ack(TerminalStatusAttachStatus::Phase1TombstoneReady);
        ack.fields[0] = Some(phase1_response);
        ack.fields[1] = Some(terminal_ack);
        ack.fields[2] = Some(receipt_prune);
        ack.fields[3] = Some(fence_prune);
        ack.fields[4] = Some(tombstone_digest);
        ack.fields[6] = Some(tombstone_reservation_claim);
        ack.times[0] = Some(clock);
        ack.times[1] = Some(final_prune_after);
        return finish_terminal_ack(input, ack);
    }

    let tombstone = tx
        .query_opt(
            "SELECT tombstone_digest, active_release_intent_digest, active_release_intent_ack_at, \
                final_prune_after, terminal_ack_digest, receipt_prune_digest, fence_prune_digest, \
                authorization_id, authorization_revision, claim_id, claim_revision, \
                reserve_charge_revision, reserve_charge_nonce, \
                tombstone_reservation_revision, tombstone_reservation_nonce \
         FROM lore_domain_operation_reserve_release_tombstones WHERE verified_issuer=$1 \
           AND authenticated_subject=$2 AND tenant_scope_key=$3 AND operation_id=$4 FOR UPDATE",
            key,
        )
        .await
        .map_err(|e| DomainError::from_pg("terminal phase2 tombstone lock", e))?;
    let Some(tombstone) = tombstone else {
        let marker = tx.query_opt(
            "SELECT marker_digest, completion_ack, created_at, retain_until, sequence, namespace_epoch \
             FROM lore_domain_operation_tombstone_release_completion_markers WHERE verified_issuer=$1 \
               AND authenticated_subject=$2 AND tenant_scope_key=$3 AND operation_id=$4", key,
        ).await.map_err(|e| DomainError::from_pg("terminal completion replay lookup", e))?;
        if let Some(marker) = marker {
            let mut ack =
                empty_terminal_ack(TerminalStatusAttachStatus::Phase2ReleaseCompletionReady);
            ack.fields[8] = Some(marker.get("marker_digest"));
            ack.fields[0] = marker.get("completion_ack");
            ack.times[4] = Some(marker.get("created_at"));
            ack.times[5] = Some(marker.get("retain_until"));
            ack.completion_marker_sequence = marker.get("sequence");
            ack.fields[9] = ack.fields[8].clone();
            return finish_terminal_ack(input, ack);
        }
        return finish_terminal_ack(
            input,
            empty_terminal_ack(
                if input.action == TerminalStatusAttachAction::TombstonePrunePoll {
                    TerminalStatusAttachStatus::Phase2PostPruneCompletionReplayRequired
                } else {
                    TerminalStatusAttachStatus::Mismatch
                },
            ),
        );
    };
    if tombstone.get::<_, Vec<u8>>("authorization_id") != input.authorization_id
        || tombstone.get::<_, i64>("authorization_revision") != input.authorization_revision
        || tombstone.get::<_, Vec<u8>>("claim_id") != input.claim_id
        || tombstone.get::<_, i64>("claim_revision") != input.claim_revision
        || tombstone.get::<_, i64>("reserve_charge_revision") != input.reserve_charge_revision
        || tombstone.get::<_, Vec<u8>>("reserve_charge_nonce") != input.reserve_charge_nonce
        || tombstone.get::<_, Vec<u8>>("tombstone_digest")
            != input.release_tombstone_digest.clone().unwrap_or_default()
        || tombstone.get::<_, i64>("tombstone_reservation_revision")
            != input.tombstone_reservation_revision
        || tombstone.get::<_, Vec<u8>>("tombstone_reservation_nonce")
            != input.tombstone_reservation_nonce
    {
        return finish_terminal_ack(
            input,
            empty_terminal_ack(TerminalStatusAttachStatus::Mismatch),
        );
    }
    match input.action {
        TerminalStatusAttachAction::ActiveReleaseIntentAck => {
            let intent = input
                .active_release_intent_nonce
                .clone()
                .unwrap_or_default();
            let intent_digest = canonical_digest(
                b"domain-active-release-intent-ack-v1",
                &[
                    input.key.operation_id.as_bytes(),
                    &intent,
                    &input
                        .active_release_intent_revision
                        .unwrap_or_default()
                        .to_be_bytes(),
                    &input.request_digest,
                ],
            )?;
            if let Some(existing) =
                tombstone.get::<_, Option<Vec<u8>>>("active_release_intent_digest")
            {
                if existing != intent_digest {
                    return finish_terminal_ack(
                        input,
                        empty_terminal_ack(TerminalStatusAttachStatus::Mismatch),
                    );
                }
            } else {
                tx.execute("UPDATE lore_domain_operation_reserve_release_tombstones SET active_release_intent_digest=$5, active_release_intent_ack_at=$6 WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND operation_id=$4",
                    &[key[0],key[1],key[2],key[3],&intent_digest,&clock]).await
                    .map_err(|e| DomainError::from_pg("active release intent acknowledgement", e))?;
            }
            let mut ack = empty_terminal_ack(TerminalStatusAttachStatus::Phase2ActiveReleaseAcked);
            ack.fields[5] = Some(intent_digest);
            ack.times[2] = Some(clock);
            finish_terminal_ack(input, ack)
        }
        TerminalStatusAttachAction::TombstonePrunePoll => {
            let final_after: SystemTime = tombstone.get("final_prune_after");
            let mut ack = empty_terminal_ack(if clock < final_after {
                TerminalStatusAttachStatus::Phase2TombstoneRetentionPending
            } else {
                TerminalStatusAttachStatus::Phase2TombstoneFinalPruned
            });
            ack.times[1] = Some(final_after);
            finish_terminal_ack(input, ack)
        }
        TerminalStatusAttachAction::TombstoneReleaseIntentComplete => {
            let final_after: SystemTime = tombstone.get("final_prune_after");
            if clock < final_after
                || tombstone
                    .get::<_, Option<Vec<u8>>>("active_release_intent_digest")
                    .is_none()
            {
                return finish_terminal_ack(
                    input,
                    empty_terminal_ack(TerminalStatusAttachStatus::Phase2TombstoneRetentionPending),
                );
            }
            let namespace = tx.query_opt(
                "SELECT epoch, high_water FROM lore_domain_proof_namespaces WHERE verified_issuer=$1 \
                 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND state <> $4 FOR UPDATE",
                &[key[0],key[1],key[2],&schema_mediated::NAMESPACE_STATE_RETIRED],
            ).await.map_err(|e| DomainError::from_pg("completion namespace lock", e))?;
            let Some(namespace) = namespace else {
                return finish_terminal_ack(
                    input,
                    empty_terminal_ack(TerminalStatusAttachStatus::Mismatch),
                );
            };
            let epoch: Vec<u8> = namespace.get("epoch");
            let marker_digest = canonical_digest(
                b"domain-tombstone-release-completion-marker-v1",
                &[
                    input.key.operation_id.as_bytes(),
                    &epoch,
                    &input.completion_marker_sequence.to_be_bytes(),
                    &tombstone.get::<_, Vec<u8>>("tombstone_digest"),
                    &input.final_prune_digest.clone().unwrap_or_default(),
                    &input.request_digest,
                ],
            )?;
            if input.expected_completion_marker_digest.as_deref() != Some(marker_digest.as_slice())
            {
                return finish_terminal_ack(
                    input,
                    empty_terminal_ack(TerminalStatusAttachStatus::Mismatch),
                );
            }
            let retain_until = clock
                .checked_add(std::time::Duration::from_secs(365 * 24 * 60 * 60))
                .ok_or_else(|| DomainError::Internal("completion retention overflow".to_owned()))?;
            let completion_ack = canonical_digest(
                b"domain-tombstone-release-completion-ack-v1",
                &[&marker_digest, &input.request_digest],
            )?;
            tx.execute(
                "INSERT INTO lore_domain_operation_tombstone_release_completion_markers \
                 (verified_issuer,authenticated_subject,tenant_scope_key,operation_id,namespace_epoch,sequence, \
                  tombstone_digest,release_intent_digest,final_prune_digest,marker_reservation_revision, \
                  marker_reservation_nonce,completion_ack,marker_digest,created_at,retain_until) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
                &[key[0],key[1],key[2],key[3],&epoch,&input.completion_marker_sequence,
                  &tombstone.get::<_,Vec<u8>>("tombstone_digest"),
                  &tombstone.get::<_,Option<Vec<u8>>>("active_release_intent_digest").unwrap_or_default(),
                  &input.final_prune_digest.clone().unwrap_or_default(),&input.release_proof_reservation_revision,
                  &input.release_proof_reservation_nonce,&completion_ack,&marker_digest,&clock,&retain_until],
            ).await.map_err(|e| DomainError::from_pg("completion marker insert", e))?;
            tx.execute("DELETE FROM lore_domain_operation_reserve_release_tombstones WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND operation_id=$4", key)
                .await.map_err(|e| DomainError::from_pg("completion tombstone delete", e))?;
            tx.execute("UPDATE lore_domain_proof_namespaces SET high_water=GREATEST(high_water,$5), next_sequence=GREATEST(next_sequence,$5+1), retained_marker_count=retained_marker_count+1, updated_at=$6 WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND epoch=$4",
                &[key[0],key[1],key[2],&epoch,&input.completion_marker_sequence,&clock]).await
                .map_err(|e| DomainError::from_pg("completion namespace update", e))?;
            let mut ack =
                empty_terminal_ack(TerminalStatusAttachStatus::Phase2ReleaseCompletionReady);
            ack.fields[0] = Some(completion_ack);
            ack.fields[8] = Some(marker_digest);
            ack.fields[9] = ack.fields[8].clone();
            ack.fields[7] = input.final_prune_digest.clone();
            ack.times[3] = Some(final_after);
            ack.times[4] = Some(clock);
            ack.times[5] = Some(retain_until);
            ack.completion_marker_sequence = input.completion_marker_sequence;
            ack.informational_high_water = Some(namespace.get("high_water"));
            finish_terminal_ack(input, ack)
        }
        TerminalStatusAttachAction::None => finish_terminal_ack(
            input,
            empty_terminal_ack(TerminalStatusAttachStatus::Invalid),
        ),
    }
}

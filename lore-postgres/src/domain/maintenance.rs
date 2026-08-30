// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-029 private receipt/proof-namespace maintenance transactions.
//!
//! The caller performs strict wire and auth-grpc verification before entering
//! these functions. Receipt-keyed operations exact-check their immutable
//! binding under the receipt-key lock; namespace operations instead take the
//! documented counter/namespace lock order before checking the namespace
//! binding. A verifier response is evidence, not a replacement for either
//! database predicate.

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
    /// Verified organization identity from the mediated request.
    pub org_uuid: Vec<u8>,
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

fn sha256_digest(domain: &[u8], parts: &[&[u8]]) -> Result<Vec<u8>, DomainError> {
    use ring::digest::SHA256;

    let mut canonical = Vec::new();
    append_part(&mut canonical, domain)?;
    for part in parts {
        append_part(&mut canonical, part)?;
    }
    Ok(ring::digest::digest(&SHA256, &canonical).as_ref().to_vec())
}

fn completion_request_binding(input: &TerminalStatusAttachInput) -> Result<Vec<u8>, DomainError> {
    let acknowledged_at = system_time_unix_millis(input.acknowledged_at)?.to_be_bytes();
    let action = [match input.action {
        TerminalStatusAttachAction::None => 0,
        TerminalStatusAttachAction::ActiveReleaseIntentAck => 1,
        TerminalStatusAttachAction::TombstonePrunePoll => 2,
        TerminalStatusAttachAction::TombstoneReleaseIntentComplete => 3,
    }];
    canonical_digest(
        b"domain-terminal-status-completion-request-binding-v1",
        &[
            input.key.verified_issuer.as_bytes(),
            input.key.authenticated_subject.as_bytes(),
            &input.key.tenant_scope_key,
            input.key.operation_id.as_bytes(),
            &input.authorization_id,
            &input.authorization_revision.to_be_bytes(),
            &input.claim_id,
            &input.claim_revision.to_be_bytes(),
            &input.terminal_outcome.to_be_bytes(),
            &input.terminal_receipt_sha256,
            &input.platform_terminal_status_revision.to_be_bytes(),
            &acknowledged_at,
            &action,
            &input.reserve_charge_revision.to_be_bytes(),
            &input.reserve_charge_nonce,
            input
                .release_tombstone_digest
                .as_deref()
                .unwrap_or_default(),
            &input
                .active_release_intent_revision
                .unwrap_or_default()
                .to_be_bytes(),
            input
                .active_release_intent_nonce
                .as_deref()
                .unwrap_or_default(),
            &input.tombstone_reservation_revision.to_be_bytes(),
            &input.tombstone_reservation_nonce,
            input.final_prune_digest.as_deref().unwrap_or_default(),
            &input
                .tombstone_release_intent_revision
                .unwrap_or_default()
                .to_be_bytes(),
            input
                .tombstone_release_intent_nonce
                .as_deref()
                .unwrap_or_default(),
            &input.release_proof_reservation_revision.to_be_bytes(),
            &input.release_proof_reservation_nonce,
            &input.completion_marker_sequence.to_be_bytes(),
            &input.request_digest,
            &input.verification_digest,
        ],
    )
}

fn completion_marker_digest(
    input: &TerminalStatusAttachInput,
    epoch: &[u8],
    tombstone_digest: &[u8],
) -> Result<Vec<u8>, DomainError> {
    sha256_digest(
        b"domain-tombstone-release-completion-marker-v1\0",
        &[
            input.key.verified_issuer.as_bytes(),
            input.key.authenticated_subject.as_bytes(),
            &input.key.tenant_scope_key,
            input.key.operation_id.as_bytes(),
            epoch,
            &input.authorization_revision.to_be_bytes(),
            &input.claim_revision.to_be_bytes(),
            &input.tombstone_reservation_revision.to_be_bytes(),
            &input.tombstone_reservation_nonce,
            &input.release_proof_reservation_revision.to_be_bytes(),
            &input.release_proof_reservation_nonce,
            &input.completion_marker_sequence.to_be_bytes(),
            &input.terminal_receipt_sha256,
            tombstone_digest,
            &input
                .active_release_intent_revision
                .unwrap_or_default()
                .to_be_bytes(),
            input
                .active_release_intent_nonce
                .as_deref()
                .unwrap_or_default(),
            input.final_prune_digest.as_deref().unwrap_or_default(),
            &input
                .tombstone_release_intent_revision
                .unwrap_or_default()
                .to_be_bytes(),
            input
                .tombstone_release_intent_nonce
                .as_deref()
                .unwrap_or_default(),
            &input.request_digest,
        ],
    )
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

fn proof_range_digest(
    key: &ProofNamespaceKey,
    epoch: &[u8],
    protocol_revision: i32,
    quota_revision: i32,
    start: i64,
    end: i64,
) -> Result<Vec<u8>, DomainError> {
    let protocol = u64::try_from(protocol_revision)
        .map_err(|_| DomainError::InvalidInput("negative protocol revision".to_owned()))?;
    let quota = u64::try_from(quota_revision)
        .map_err(|_| DomainError::InvalidInput("negative quota revision".to_owned()))?;
    let start = u64::try_from(start)
        .map_err(|_| DomainError::InvalidInput("negative range start".to_owned()))?;
    let end = u64::try_from(end)
        .map_err(|_| DomainError::InvalidInput("negative range end".to_owned()))?;
    let count = end
        .checked_sub(start)
        .and_then(|delta| delta.checked_add(1))
        .ok_or_else(|| DomainError::InvalidInput("invalid range bounds".to_owned()))?;
    sha256_digest(
        b"domain-marker-prune-interval-v3\0",
        &[
            &key.tenant_scope_key,
            epoch,
            &protocol.to_be_bytes(),
            &quota.to_be_bytes(),
            &(MARKER_INTERVAL_SCHEMA_REVISION_V3 as u64).to_be_bytes(),
            &start.to_be_bytes(),
            &end.to_be_bytes(),
            &count.to_be_bytes(),
            &end.to_be_bytes(),
        ],
    )
}

fn proof_range_byte_charge(key: &ProofNamespaceKey) -> Result<i64, DomainError> {
    let fixed = 16_usize
        .checked_add(6 * std::mem::size_of::<u64>())
        .and_then(|value| value.checked_add(32))
        .ok_or_else(|| DomainError::Internal("proof range byte charge overflow".to_owned()))?;
    let bytes = key
        .verified_issuer
        .len()
        .checked_add(key.authenticated_subject.len())
        .and_then(|value| value.checked_add(key.tenant_scope_key.len()))
        .and_then(|value| value.checked_add(fixed))
        .ok_or_else(|| DomainError::Internal("proof range byte charge overflow".to_owned()))?;
    i64::try_from(bytes)
        .map_err(|_| DomainError::Internal("proof range byte charge exceeds i64".to_owned()))
}

fn completion_marker_byte_charge(
    key: &ReceiptKey,
    completion_ack: &[u8],
) -> Result<i64, DomainError> {
    let fixed = 16_usize
        .checked_add(16)
        .and_then(|value| value.checked_add(std::mem::size_of::<u64>()))
        .and_then(|value| value.checked_add(std::mem::size_of::<i64>()))
        .and_then(|value| value.checked_add(10 * 32))
        .and_then(|value| value.checked_add(completion_ack.len()))
        .ok_or_else(|| {
            DomainError::Internal("completion marker byte charge overflow".to_owned())
        })?;
    let bytes = key
        .verified_issuer
        .len()
        .checked_add(key.authenticated_subject.len())
        .and_then(|value| value.checked_add(key.tenant_scope_key.len()))
        .and_then(|value| value.checked_add(fixed))
        .ok_or_else(|| {
            DomainError::Internal("completion marker byte charge overflow".to_owned())
        })?;
    i64::try_from(bytes)
        .map_err(|_| DomainError::Internal("completion marker byte charge exceeds i64".to_owned()))
}

fn receipt_binding_matches(row: &tokio_postgres::Row, input: &VerifiedStaleFinalizeInput) -> bool {
    row.get::<_, String>("method") == input.binding.method
        && row.get::<_, Vec<u8>>("scope") == input.binding.scope
        && row.get::<_, i32>("fingerprint_version") == input.binding.fingerprint_version
        && row.get::<_, Vec<u8>>("fingerprint") == input.binding.fingerprint
        && row.get::<_, Vec<u8>>("canonical_intent_digest") == input.binding.canonical_intent_digest
}

fn dispatch_fence_matches(row: &tokio_postgres::Row, input: &VerifiedStaleFinalizeInput) -> bool {
    receipt_binding_matches(row, input)
        && row.get::<_, Vec<u8>>("authorization_id") == input.witness.authorization_id
        && row.get::<_, i64>("authorization_revision") == input.witness.authorization_revision
        && row.get::<_, Vec<u8>>("verification_nonce") == input.witness.verification_nonce
        && row.get::<_, Vec<u8>>("bound_fields_digest") == input.witness.bound_fields_digest
        && row.get::<_, Vec<u8>>("consumed_ticket_sha256") == input.witness.consumed_ticket_sha256
        && row.get::<_, Vec<u8>>("expected_claim_identity_digest")
            == input.expected_claim_identity_digest
}

fn stale_finalize_execution_witness(
    input: &VerifiedStaleFinalizeInput,
) -> Result<Vec<u8>, DomainError> {
    canonical_digest(
        b"domain-verified-stale-finalize-execution-witness-v1",
        &[
            &input.witness.authorization_id,
            &input.witness.authorization_revision.to_be_bytes(),
            &input.witness.verification_nonce,
            &input.witness.bound_fields_digest,
            &input.witness.consumed_ticket_sha256,
            &input.expected_claim_identity_digest,
            &input.stale_finalize_permit,
            &input.stale_finalize_permit_revision.to_be_bytes(),
            &input.permit_verification_digest,
        ],
    )
}

fn stale_finalize_receipt_matches(
    row: &tokio_postgres::Row,
    input: &VerifiedStaleFinalizeInput,
    execution_witness: &[u8],
) -> bool {
    receipt_binding_matches(row, input)
        && row.get::<_, Option<Vec<u8>>>("authorization_id").as_deref()
            == Some(input.witness.authorization_id.as_slice())
        && row.get::<_, Option<i64>>("authorization_revision")
            == Some(input.witness.authorization_revision)
        && row
            .get::<_, Option<Vec<u8>>>("verification_nonce")
            .as_deref()
            == Some(input.witness.verification_nonce.as_slice())
        && row
            .get::<_, Option<Vec<u8>>>("bound_fields_digest")
            .as_deref()
            == Some(input.witness.bound_fields_digest.as_slice())
        && row
            .get::<_, Option<Vec<u8>>>("consumed_ticket_sha256")
            .as_deref()
            == Some(input.witness.consumed_ticket_sha256.as_slice())
        && row
            .get::<_, Option<Vec<u8>>>("execution_witness")
            .as_deref()
            == Some(execution_witness)
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
    let clock = receipts::admission_clock(tx).await?;
    let operation_id = input.key.operation_id.as_bytes().to_vec();
    let execution_witness = stale_finalize_execution_witness(input)?;
    let existing = tx
        .query_opt(
            "SELECT method, scope, fingerprint_version, fingerprint, canonical_intent_digest, \
                    state, outcome, not_applied_reason, public_result, committed_at, \
                    authorization_id, authorization_revision, verification_nonce, \
                    bound_fields_digest, consumed_ticket_sha256, execution_witness \
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
            && row.get::<_, Option<i16>>("outcome") == Some(schema::RECEIPT_OUTCOME_NOT_APPLIED)
            && reason.as_deref() == Some(MEDIATED_VERIFIED_UUID_STALE_NO_DISPATCH_V1)
        {
            if !stale_finalize_receipt_matches(&row, input, &execution_witness) {
                return finalize_result(
                    input,
                    VerifiedStaleFinalizeStatus::Mismatch,
                    Vec::new(),
                    None,
                );
            }
            let canonical: Option<Vec<u8>> = row.get("public_result");
            let committed_at: Option<SystemTime> = row.get("committed_at");
            return finalize_result(
                input,
                VerifiedStaleFinalizeStatus::Committed,
                canonical.unwrap_or_default(),
                committed_at,
            );
        }
        if fence
            .as_ref()
            .is_some_and(|row| !dispatch_fence_matches(row, input))
        {
            return finalize_result(
                input,
                VerifiedStaleFinalizeStatus::Mismatch,
                Vec::new(),
                None,
            );
        }
        return finalize_result(
            input,
            VerifiedStaleFinalizeStatus::IneligibleReceiptOrDispatchPossible,
            Vec::new(),
            None,
        );
    }

    if let Some(row) = fence {
        let exact = dispatch_fence_matches(&row, input);
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

    // Phase 1 replaces the ordinary receipt and dispatch fence atomically with
    // a tombstone. A stale-finalize retry must therefore consult that durable
    // successor under the same receipt-key lock before making a time decision.
    let tombstone = tx
        .query_opt(
            "SELECT method, scope, fingerprint_version, fingerprint, canonical_intent_digest, \
                    authorization_id, authorization_revision \
             FROM lore_domain_operation_reserve_release_tombstones \
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
        .map_err(|e| DomainError::from_pg("stale finalize tombstone lock", e))?;
    if let Some(row) = tombstone {
        let exact = row.get::<_, String>("method") == input.binding.method
            && row.get::<_, Vec<u8>>("scope") == input.binding.scope
            && row.get::<_, i32>("fingerprint_version") == input.binding.fingerprint_version
            && row.get::<_, Vec<u8>>("fingerprint") == input.binding.fingerprint
            && row.get::<_, Vec<u8>>("canonical_intent_digest")
                == input.binding.canonical_intent_digest
            && row.get::<_, Vec<u8>>("authorization_id") == input.witness.authorization_id
            && row.get::<_, i64>("authorization_revision") == input.witness.authorization_revision;
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

    // Completion markers intentionally retain only the proof identity, not the
    // original operation binding. Existence under the exact receipt key is
    // nevertheless decisive evidence that dispatch and terminalization were
    // possible, so it can never be converted into a fresh NOT_APPLIED receipt.
    let completion_marker = tx
        .query_opt(
            "SELECT marker_digest \
             FROM lore_domain_operation_tombstone_release_completion_markers \
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
        .map_err(|e| DomainError::from_pg("stale finalize completion marker lock", e))?;
    if completion_marker.is_some() {
        return finalize_result(
            input,
            VerifiedStaleFinalizeStatus::IneligibleReceiptOrDispatchPossible,
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
    let inserted = tx
        .query_opt(
        "INSERT INTO lore_domain_operation_receipts ( \
             verified_issuer, authenticated_subject, tenant_scope_key, operation_id, \
             method, scope, fingerprint_version, fingerprint, canonical_intent_digest, \
             state, outcome, not_applied_reason_version, not_applied_reason, \
             authorization_id, authorization_revision, verification_nonce, bound_fields_digest, \
             consumed_ticket_sha256, execution_witness, public_result, uuid_timestamp, \
             prepared_at, hard_expires_at, committed_at, full_result_expires_at, compact_expires_at \
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20, \
                   $21,$22,$23,$24,$25,$26) \
         ON CONFLICT DO NOTHING RETURNING committed_at",
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
    if inserted.is_none() {
        let conflict = tx
            .query_one(
                "SELECT method, scope, fingerprint_version, fingerprint, canonical_intent_digest, \
                        state, outcome, not_applied_reason, public_result, committed_at, \
                        authorization_id, authorization_revision, verification_nonce, \
                        bound_fields_digest, consumed_ticket_sha256, execution_witness \
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
            .map_err(|e| DomainError::from_pg("stale finalize receipt conflict", e))?;
        if !receipt_binding_matches(&conflict, input) {
            return finalize_result(
                input,
                VerifiedStaleFinalizeStatus::Mismatch,
                Vec::new(),
                None,
            );
        }
        let is_stale_terminal = conflict.get::<_, i16>("state") == schema::RECEIPT_STATE_COMMITTED
            && conflict.get::<_, Option<i16>>("outcome")
                == Some(schema::RECEIPT_OUTCOME_NOT_APPLIED)
            && conflict
                .get::<_, Option<String>>("not_applied_reason")
                .as_deref()
                == Some(MEDIATED_VERIFIED_UUID_STALE_NO_DISPATCH_V1);
        if is_stale_terminal {
            if !stale_finalize_receipt_matches(&conflict, input, &execution_witness) {
                return finalize_result(
                    input,
                    VerifiedStaleFinalizeStatus::Mismatch,
                    Vec::new(),
                    None,
                );
            }
            return finalize_result(
                input,
                VerifiedStaleFinalizeStatus::Committed,
                conflict
                    .get::<_, Option<Vec<u8>>>("public_result")
                    .unwrap_or_default(),
                conflict.get("committed_at"),
            );
        }
        return finalize_result(
            input,
            VerifiedStaleFinalizeStatus::IneligibleReceiptOrDispatchPossible,
            Vec::new(),
            None,
        );
    }
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
    org_revision: i64,
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
    let org_revision_bytes = org_revision.to_be_bytes();
    let receipt_digest = canonical_digest(
        b"domain-proof-namespace-materialization-receipt-v1",
        &[
            &status_byte,
            &input.namespace_epoch,
            &claim_revision,
            &input.namespace_claim_nonce,
            &namespace_revision_bytes,
            &global_revision_bytes,
            &org_revision_bytes,
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
        lore_org_counter_revision: org_revision,
        created_at,
        materialization_receipt_digest: receipt_digest,
        response_digest,
    })
}

pub async fn proof_namespace_materialize(
    tx: &Transaction<'_>,
    input: &ProofNamespaceMaterializeInput,
) -> Result<ProofNamespaceMaterializeReceipt, DomainError> {
    let clock = receipts::admission_clock(tx).await?;
    if input.protocol_revision != RECEIPT_PROTOCOL_REVISION_V2 {
        return Err(DomainError::InvalidInput(
            "proof namespace protocol revision is not v2".to_owned(),
        ));
    }
    let quota_revision = i32::try_from(input.platform_capacity_revision)
        .map_err(|_| DomainError::InvalidInput("capacity revision exceeds i32".to_owned()))?;
    if input.key.org_uuid.len() != 16 {
        return Err(DomainError::InvalidInput(
            "proof namespace organization UUID must be 16 bytes".to_owned(),
        ));
    }
    let counter = tx
        .query_opt(
            "SELECT counter_revision, quota_revision, represented_namespace_rows \
             FROM lore_domain_proof_global_counters \
             WHERE id=1 FOR UPDATE",
            &[],
        )
        .await
        .map_err(|e| DomainError::from_pg("proof namespace global counter lock", e))?;
    let Some(counter) = counter else {
        return materialize_receipt(
            input,
            ProofNamespaceMaterializeStatus::CapacityBlocked,
            0,
            0,
            0,
            clock,
        );
    };
    let current_revision: i64 = counter.get("counter_revision");
    let current_quota_revision: i32 = counter.get("quota_revision");
    let global_rows: i64 = counter.get("represented_namespace_rows");
    let org_counter = tx
        .query_opt(
            "SELECT counter_revision, quota_revision, represented_namespace_rows \
             FROM lore_domain_proof_org_counters WHERE org_uuid=$1 FOR UPDATE",
            &[&input.key.org_uuid],
        )
        .await
        .map_err(|e| DomainError::from_pg("proof namespace org counter lock", e))?;
    let Some(org_counter) = org_counter else {
        return materialize_receipt(
            input,
            ProofNamespaceMaterializeStatus::CapacityBlocked,
            0,
            current_revision,
            0,
            clock,
        );
    };
    let current_org_revision: i64 = org_counter.get("counter_revision");
    let current_org_quota_revision: i32 = org_counter.get("quota_revision");
    let org_rows: i64 = org_counter.get("represented_namespace_rows");
    let existing = tx
        .query_opt(
            "SELECT epoch, org_uuid, protocol_revision, quota_revision, claim_revision, claim_nonce, \
                    materialization_receipt, materialization_request_digest, \
                    materialization_verification_digest, materialization_response_digest, \
                    namespace_revision, materialized_global_counter_revision, \
                    materialized_org_counter_revision, created_at, state \
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
            && row.get::<_, Vec<u8>>("org_uuid") == input.key.org_uuid
            && row.get::<_, i32>("protocol_revision") == input.protocol_revision
            && row.get::<_, i32>("quota_revision") == quota_revision
            && row.get::<_, i64>("claim_revision") == input.namespace_claim_revision
            && row.get::<_, Vec<u8>>("claim_nonce") == input.namespace_claim_nonce
            && row.get::<_, Vec<u8>>("materialization_request_digest") == input.request_digest
            && row.get::<_, Vec<u8>>("materialization_verification_digest")
                == input.verification_digest
            && row.get::<_, i16>("state") == schema_mediated::NAMESPACE_STATE_ACTIVE;
        if !exact {
            return materialize_receipt(
                input,
                ProofNamespaceMaterializeStatus::Mismatch,
                0,
                current_revision,
                current_org_revision,
                clock,
            );
        }
        let materialization_receipt_digest =
            row.get::<_, Option<Vec<u8>>>("materialization_receipt");
        let response_digest = row.get::<_, Option<Vec<u8>>>("materialization_response_digest");
        let (Some(materialization_receipt_digest), Some(response_digest)) =
            (materialization_receipt_digest, response_digest)
        else {
            return materialize_receipt(
                input,
                ProofNamespaceMaterializeStatus::Mismatch,
                0,
                current_revision,
                current_org_revision,
                clock,
            );
        };
        return Ok(ProofNamespaceMaterializeReceipt {
            status: ProofNamespaceMaterializeStatus::Materialized,
            namespace_epoch: input.namespace_epoch.clone(),
            namespace_claim_revision: input.namespace_claim_revision,
            namespace_claim_nonce: input.namespace_claim_nonce.clone(),
            lore_namespace_revision: row.get("namespace_revision"),
            lore_global_counter_revision: row.get("materialized_global_counter_revision"),
            lore_org_counter_revision: row.get("materialized_org_counter_revision"),
            created_at: row.get("created_at"),
            materialization_receipt_digest,
            response_digest,
        });
    }
    if current_revision != input.lore_local_capacity_revision
        || current_quota_revision != quota_revision
        || current_org_quota_revision != quota_revision
    {
        return materialize_receipt(
            input,
            ProofNamespaceMaterializeStatus::CapacityBlocked,
            0,
            current_revision,
            current_org_revision,
            clock,
        );
    }
    let next_global_revision = current_revision.checked_add(1).ok_or_else(|| {
        DomainError::Internal("proof global counter revision overflow".to_owned())
    })?;
    let next_org_revision = current_org_revision
        .checked_add(1)
        .ok_or_else(|| DomainError::Internal("proof org counter revision overflow".to_owned()))?;
    let next_global_rows = global_rows.checked_add(1).ok_or_else(|| {
        DomainError::Internal("proof global represented rows overflow".to_owned())
    })?;
    let next_org_rows = org_rows
        .checked_add(1)
        .ok_or_else(|| DomainError::Internal("proof org represented rows overflow".to_owned()))?;
    let receipt = materialize_receipt(
        input,
        ProofNamespaceMaterializeStatus::Materialized,
        1,
        next_global_revision,
        next_org_revision,
        clock,
    )?;
    let canonical_receipt = receipt.materialization_receipt_digest.clone();
    tx.execute(
        "INSERT INTO lore_domain_proof_namespaces ( \
             verified_issuer, authenticated_subject, tenant_scope_key, org_uuid, epoch, protocol_revision, \
             quota_revision, marker_interval_schema_revision, claim_revision, claim_nonce, \
             next_sequence, high_water, retained_marker_count, outstanding_proof_claims, \
             fragment_count, state, materialization_receipt, materialization_request_digest, \
             materialization_verification_digest, materialization_response_digest, namespace_revision, \
             materialized_global_counter_revision, materialized_org_counter_revision, created_at, updated_at \
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,1,0,0,0,0,$11,$12,$13,$14,$15,1,$16,$17,$18,$19)",
        &[
            &input.key.verified_issuer,
            &input.key.authenticated_subject,
            &input.key.tenant_scope_key,
            &input.key.org_uuid,
            &input.namespace_epoch,
            &input.protocol_revision,
            &quota_revision,
            &MARKER_INTERVAL_SCHEMA_REVISION_V3,
            &input.namespace_claim_revision,
            &input.namespace_claim_nonce,
            &schema_mediated::NAMESPACE_STATE_ACTIVE,
            &canonical_receipt,
            &input.request_digest,
            &input.verification_digest,
            &receipt.response_digest,
            &next_global_revision,
            &next_org_revision,
            &clock,
            &clock,
        ],
    )
    .await
    .map_err(|e| DomainError::from_pg("proof namespace materialize", e))?;
    let global_updated = tx
        .execute(
            "UPDATE lore_domain_proof_global_counters SET counter_revision=$1, \
             represented_namespace_rows=$2, updated_at=$3 WHERE id=1 AND counter_revision=$4",
            &[
                &next_global_revision,
                &next_global_rows,
                &clock,
                &current_revision,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("proof namespace global counter increment", e))?;
    if global_updated != 1 {
        return Err(DomainError::Internal(
            "proof namespace global counter changed under lock".to_owned(),
        ));
    }
    let org_updated = tx
        .execute(
            "UPDATE lore_domain_proof_org_counters SET counter_revision=$2, \
                 represented_namespace_rows=$3, updated_at=$4 \
             WHERE org_uuid=$1 AND counter_revision=$5",
            &[
                &input.key.org_uuid,
                &next_org_revision,
                &next_org_rows,
                &clock,
                &current_org_revision,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("proof namespace org counter increment", e))?;
    if org_updated != 1 {
        return Err(DomainError::Internal(
            "proof namespace org counter changed under lock".to_owned(),
        ));
    }
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
    let clock = receipts::admission_clock(tx).await?;
    let issued_at = system_time_at_wire_millisecond(input.issued_at)?;
    let expires_at = system_time_at_wire_millisecond(input.expires_at)?;
    if input.protocol_revision != RECEIPT_PROTOCOL_REVISION_V2
        || input.retirement_fence_generation <= 0
        || input.retirement_permit_revision <= 0
    {
        return Err(DomainError::InvalidInput(
            "invalid proof namespace retirement revision".to_owned(),
        ));
    }
    if clock >= expires_at || issued_at >= expires_at {
        return retire_ack(input, ProofNamespaceRetireStatus::Expired, None);
    }
    if input.key.org_uuid.len() != 16 {
        return Err(DomainError::InvalidInput(
            "proof namespace organization UUID must be 16 bytes".to_owned(),
        ));
    }
    let global_counter = tx
        .query_opt(
            "SELECT counter_revision, represented_namespace_rows, fragment_count, fragment_bytes \
             FROM lore_domain_proof_global_counters WHERE id=1 FOR UPDATE",
            &[],
        )
        .await
        .map_err(|e| DomainError::from_pg("proof retirement global counter lock", e))?;
    let org_counter = tx
        .query_opt(
            "SELECT counter_revision, represented_namespace_rows, fragment_count, fragment_bytes \
             FROM lore_domain_proof_org_counters WHERE org_uuid=$1 FOR UPDATE",
            &[&input.key.org_uuid],
        )
        .await
        .map_err(|e| DomainError::from_pg("proof retirement org counter lock", e))?;
    let row = tx
        .query_opt(
            "SELECT epoch, org_uuid, protocol_revision, quota_revision, marker_interval_schema_revision, \
                    claim_revision, claim_nonce, high_water, retained_marker_count, \
                    outstanding_proof_claims, fragment_count, state \
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
        && row.get::<_, Vec<u8>>("org_uuid") == input.key.org_uuid
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
            "SELECT start_sequence, end_sequence, interval_digest, generation, byte_charge \
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
    let range_bytes = range_rows.iter().try_fold(0_i64, |total, row| {
        total
            .checked_add(row.get::<_, i64>("byte_charge"))
            .ok_or_else(|| DomainError::Internal("retirement range bytes overflow".to_owned()))
    })?;
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
    let Some(global_counter) = global_counter else {
        return Err(DomainError::Internal(
            "proof namespace exists without global counter".to_owned(),
        ));
    };
    let Some(org_counter) = org_counter else {
        return Err(DomainError::Internal(
            "proof namespace exists without organization counter".to_owned(),
        ));
    };
    let next_global_revision = global_counter
        .get::<_, i64>("counter_revision")
        .checked_add(1)
        .ok_or_else(|| {
            DomainError::Internal("proof global counter revision overflow".to_owned())
        })?;
    let next_org_revision = org_counter
        .get::<_, i64>("counter_revision")
        .checked_add(1)
        .ok_or_else(|| DomainError::Internal("proof org counter revision overflow".to_owned()))?;
    let global_rows = global_counter
        .get::<_, i64>("represented_namespace_rows")
        .checked_sub(1)
        .ok_or_else(|| {
            DomainError::Internal("proof global represented rows underflow".to_owned())
        })?;
    let org_rows = org_counter
        .get::<_, i64>("represented_namespace_rows")
        .checked_sub(1)
        .ok_or_else(|| DomainError::Internal("proof org represented rows underflow".to_owned()))?;
    let global_fragments = global_counter
        .get::<_, i64>("fragment_count")
        .checked_sub(range_count)
        .ok_or_else(|| DomainError::Internal("proof global fragments underflow".to_owned()))?;
    let org_fragments = org_counter
        .get::<_, i64>("fragment_count")
        .checked_sub(range_count)
        .ok_or_else(|| DomainError::Internal("proof org fragments underflow".to_owned()))?;
    let global_fragment_bytes = global_counter
        .get::<_, i64>("fragment_bytes")
        .checked_sub(range_bytes)
        .ok_or_else(|| DomainError::Internal("proof global fragment bytes underflow".to_owned()))?;
    let org_fragment_bytes = org_counter
        .get::<_, i64>("fragment_bytes")
        .checked_sub(range_bytes)
        .ok_or_else(|| DomainError::Internal("proof org fragment bytes underflow".to_owned()))?;
    let transitioned = tx
        .execute(
            "UPDATE lore_domain_proof_namespaces SET state=$5, updated_at=$6 \
             WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 \
               AND epoch=$4 AND state IN ($5,$7)",
            &[
                &input.key.verified_issuer,
                &input.key.authenticated_subject,
                &input.key.tenant_scope_key,
                &input.namespace_epoch,
                &schema_mediated::NAMESPACE_STATE_DRAINING,
                &clock,
                &schema_mediated::NAMESPACE_STATE_ACTIVE,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("proof namespace drain transition", e))?;
    if transitioned != 1 {
        return retire_ack(input, ProofNamespaceRetireStatus::Mismatch, None);
    }
    // One clock-predicated statement owns the bounded delete and both counter
    // decrements. Equality is expired, and every CTE then changes zero rows.
    let transition = tx
        .query_one(
            "WITH eligible AS ( \
                 SELECT 1 FROM lore_domain_proof_namespaces \
                 WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 \
                   AND epoch=$4 AND state=$5 AND clock_timestamp() < $6 \
             ), deleted_ranges AS ( \
                 DELETE FROM lore_domain_tombstone_marker_prune_ranges \
                 WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 \
                   AND epoch=$4 AND EXISTS (SELECT 1 FROM eligible) RETURNING 1 \
             ), deleted_namespace AS ( \
                 DELETE FROM lore_domain_proof_namespaces \
                 WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 \
                   AND epoch=$4 AND EXISTS (SELECT 1 FROM eligible) RETURNING 1 \
             ), updated_global AS ( \
                 UPDATE lore_domain_proof_global_counters SET counter_revision=$7, \
                   represented_namespace_rows=$8, fragment_count=$9, fragment_bytes=$10, updated_at=$11 \
                 WHERE id=1 AND EXISTS (SELECT 1 FROM deleted_namespace) RETURNING 1 \
             ), updated_org AS ( \
                 UPDATE lore_domain_proof_org_counters SET counter_revision=$12, \
                   represented_namespace_rows=$13, fragment_count=$14, fragment_bytes=$15, updated_at=$11 \
                 WHERE org_uuid=$16 AND EXISTS (SELECT 1 FROM deleted_namespace) RETURNING 1 \
             ) SELECT (SELECT count(*) FROM deleted_namespace)::bigint AS namespaces, \
                      (SELECT count(*) FROM deleted_ranges)::bigint AS ranges, \
                      (SELECT count(*) FROM updated_global)::bigint AS globals, \
                      (SELECT count(*) FROM updated_org)::bigint AS orgs",
            &[
                &input.key.verified_issuer,
                &input.key.authenticated_subject,
                &input.key.tenant_scope_key,
                &input.namespace_epoch,
                &schema_mediated::NAMESPACE_STATE_DRAINING,
                &expires_at,
                &next_global_revision,
                &global_rows,
                &global_fragments,
                &global_fragment_bytes,
                &clock,
                &next_org_revision,
                &org_rows,
                &org_fragments,
                &org_fragment_bytes,
                &input.key.org_uuid,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("proof namespace retirement transition", e))?;
    let deleted: i64 = transition.get("namespaces");
    if deleted == 0 {
        tx.execute(
            "UPDATE lore_domain_proof_namespaces SET state=$5, updated_at=$6 \
             WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 \
               AND epoch=$4 AND state=$7",
            &[
                &input.key.verified_issuer,
                &input.key.authenticated_subject,
                &input.key.tenant_scope_key,
                &input.namespace_epoch,
                &schema_mediated::NAMESPACE_STATE_ACTIVE,
                &clock,
                &schema_mediated::NAMESPACE_STATE_DRAINING,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("proof namespace expired drain rollback", e))?;
        return retire_ack(input, ProofNamespaceRetireStatus::Expired, None);
    }
    if transition.get::<_, i64>("ranges") != range_count
        || transition.get::<_, i64>("globals") != 1
        || transition.get::<_, i64>("orgs") != 1
    {
        return Err(DomainError::Internal(
            "proof namespace retirement counter transition was incomplete".to_owned(),
        ));
    }
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

fn system_time_at_wire_millisecond(value: SystemTime) -> Result<SystemTime, DomainError> {
    let millis = system_time_unix_millis(value)?;
    let millis = u64::try_from(millis)
        .map_err(|_| DomainError::InvalidInput("negative timestamp milliseconds".to_owned()))?;
    SystemTime::UNIX_EPOCH
        .checked_add(std::time::Duration::from_millis(millis))
        .ok_or_else(|| DomainError::InvalidInput("timestamp milliseconds overflow".to_owned()))
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
        input.reserve_charge_revision.to_be_bytes().as_slice(),
        input.reserve_charge_nonce.as_slice(),
        input
            .tombstone_reservation_revision
            .to_be_bytes()
            .as_slice(),
        input.tombstone_reservation_nonce.as_slice(),
        input
            .release_proof_reservation_revision
            .to_be_bytes()
            .as_slice(),
        input.release_proof_reservation_nonce.as_slice(),
        input.completion_marker_sequence.to_be_bytes().as_slice(),
        input.request_digest.as_slice(),
        input.verification_digest.as_slice(),
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

async fn prune_completion_marker(
    tx: &Transaction<'_>,
    input: &TerminalStatusAttachInput,
    marker: &tokio_postgres::Row,
    clock: SystemTime,
) -> Result<(ProofRange, i64), DomainError> {
    let epoch: Vec<u8> = marker.get("namespace_epoch");
    let sequence: i64 = marker.get("sequence");
    let marker_bytes: i64 = marker.get("byte_charge");
    let org_identity = tx
        .query_one(
            "SELECT org_uuid FROM lore_domain_proof_namespaces \
             WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 \
               AND epoch=$4 AND state=$5",
            &[
                &input.key.verified_issuer,
                &input.key.authenticated_subject,
                &input.key.tenant_scope_key,
                &epoch,
                &schema_mediated::NAMESPACE_STATE_ACTIVE,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("completion marker org identity read", e))?;
    let org_uuid: Vec<u8> = org_identity.get("org_uuid");
    let key = ProofNamespaceKey {
        verified_issuer: input.key.verified_issuer.clone(),
        authenticated_subject: input.key.authenticated_subject.clone(),
        org_uuid: org_uuid.clone(),
        tenant_scope_key: input.key.tenant_scope_key.clone(),
    };
    let global = tx
        .query_one(
            "SELECT counter_revision, retained_marker_count, fragment_count, fragment_bytes, marker_bytes \
             FROM lore_domain_proof_global_counters WHERE id=1 FOR UPDATE",
            &[],
        )
        .await
        .map_err(|e| DomainError::from_pg("completion prune global counter lock", e))?;
    let org = tx
        .query_one(
            "SELECT counter_revision, retained_marker_count, fragment_count, fragment_bytes, marker_bytes \
             FROM lore_domain_proof_org_counters WHERE org_uuid=$1 FOR UPDATE",
            &[&org_uuid],
        )
        .await
        .map_err(|e| DomainError::from_pg("completion prune org counter lock", e))?;
    let namespace = tx
        .query_one(
            "SELECT org_uuid, protocol_revision, quota_revision, high_water, retained_marker_count, \
                    fragment_count FROM lore_domain_proof_namespaces \
             WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 \
               AND epoch=$4 AND state=$5 FOR UPDATE",
            &[
                &input.key.verified_issuer,
                &input.key.authenticated_subject,
                &input.key.tenant_scope_key,
                &epoch,
                &schema_mediated::NAMESPACE_STATE_ACTIVE,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("completion marker namespace lock", e))?;
    if namespace.get::<_, Vec<u8>>("org_uuid") != org_uuid {
        return Err(DomainError::Internal(
            "completion namespace organization changed under lock".to_owned(),
        ));
    }
    let lower = sequence.saturating_sub(1);
    let upper = sequence.checked_add(1).ok_or_else(|| {
        DomainError::Internal("completion sequence successor overflow".to_owned())
    })?;
    let neighbors = tx
        .query(
            "SELECT start_sequence, end_sequence, created_at_ms, byte_charge \
             FROM lore_domain_tombstone_marker_prune_ranges \
             WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 \
               AND epoch=$4 AND end_sequence >= $5 AND start_sequence <= $6 \
             ORDER BY start_sequence FOR UPDATE",
            &[
                &input.key.verified_issuer,
                &input.key.authenticated_subject,
                &input.key.tenant_scope_key,
                &epoch,
                &lower,
                &upper,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("completion prune neighbor lock", e))?;
    if neighbors.len() > 2
        || neighbors.iter().any(|row| {
            row.get::<_, i64>("start_sequence") <= sequence
                && row.get::<_, i64>("end_sequence") >= sequence
        })
    {
        return Err(DomainError::Internal(
            "completion prune ranges overlap the live marker".to_owned(),
        ));
    }
    let mut start = sequence;
    let mut end = sequence;
    let marker_created_ms = system_time_unix_millis(marker.get("created_at"))?;
    let mut created_at_ms = marker_created_ms;
    let mut removed_range_bytes = 0_i64;
    for neighbor in &neighbors {
        let neighbor_start: i64 = neighbor.get("start_sequence");
        let neighbor_end: i64 = neighbor.get("end_sequence");
        let adjacent_left = neighbor_end.checked_add(1) == Some(sequence);
        let adjacent_right = sequence.checked_add(1) == Some(neighbor_start);
        if !adjacent_left && !adjacent_right {
            return Err(DomainError::Internal(
                "completion prune selected a non-adjacent range".to_owned(),
            ));
        }
        start = start.min(neighbor_start);
        end = end.max(neighbor_end);
        created_at_ms = created_at_ms.min(neighbor.get("created_at_ms"));
        removed_range_bytes = removed_range_bytes
            .checked_add(neighbor.get("byte_charge"))
            .ok_or_else(|| DomainError::Internal("completion prune bytes overflow".to_owned()))?;
    }
    let protocol_revision: i32 = namespace.get("protocol_revision");
    let quota_revision: i32 = namespace.get("quota_revision");
    let digest = proof_range_digest(&key, &epoch, protocol_revision, quota_revision, start, end)?;
    let range_bytes = proof_range_byte_charge(&key)?;
    let range_count = i64::try_from(neighbors.len())
        .map_err(|_| DomainError::Internal("completion neighbor count exceeds i64".to_owned()))?;
    let fragment_delta = 1_i64
        .checked_sub(range_count)
        .ok_or_else(|| DomainError::Internal("completion fragment delta underflow".to_owned()))?;
    let namespace_retained = namespace
        .get::<_, i64>("retained_marker_count")
        .checked_sub(1)
        .ok_or_else(|| DomainError::Internal("namespace retained marker underflow".to_owned()))?;
    let namespace_fragments = namespace
        .get::<_, i64>("fragment_count")
        .checked_add(fragment_delta)
        .ok_or_else(|| DomainError::Internal("namespace fragment count overflow".to_owned()))?;
    let next_global_revision = global
        .get::<_, i64>("counter_revision")
        .checked_add(1)
        .ok_or_else(|| DomainError::Internal("global counter revision overflow".to_owned()))?;
    let next_org_revision = org
        .get::<_, i64>("counter_revision")
        .checked_add(1)
        .ok_or_else(|| DomainError::Internal("org counter revision overflow".to_owned()))?;
    let counter_values = |row: &tokio_postgres::Row| -> Result<(i64, i64, i64, i64), DomainError> {
        let retained = row
            .get::<_, i64>("retained_marker_count")
            .checked_sub(1)
            .ok_or_else(|| DomainError::Internal("counter retained marker underflow".to_owned()))?;
        let fragments = row
            .get::<_, i64>("fragment_count")
            .checked_add(fragment_delta)
            .ok_or_else(|| DomainError::Internal("counter fragment count overflow".to_owned()))?;
        let fragment_bytes = row
            .get::<_, i64>("fragment_bytes")
            .checked_sub(removed_range_bytes)
            .and_then(|value| value.checked_add(range_bytes))
            .ok_or_else(|| DomainError::Internal("counter fragment bytes overflow".to_owned()))?;
        let remaining_marker_bytes = row
            .get::<_, i64>("marker_bytes")
            .checked_sub(marker_bytes)
            .ok_or_else(|| DomainError::Internal("counter marker bytes underflow".to_owned()))?;
        Ok((retained, fragments, fragment_bytes, remaining_marker_bytes))
    };
    let global_values = counter_values(&global)?;
    let org_values = counter_values(&org)?;
    for neighbor in &neighbors {
        tx.execute(
            "DELETE FROM lore_domain_tombstone_marker_prune_ranges \
             WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 \
               AND epoch=$4 AND start_sequence=$5",
            &[
                &input.key.verified_issuer,
                &input.key.authenticated_subject,
                &input.key.tenant_scope_key,
                &epoch,
                &neighbor.get::<_, i64>("start_sequence"),
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("completion prune neighbor delete", e))?;
    }
    let sequence_count = end
        .checked_sub(start)
        .and_then(|delta| delta.checked_add(1))
        .ok_or_else(|| DomainError::Internal("completion range count overflow".to_owned()))?;
    tx.execute(
        "INSERT INTO lore_domain_tombstone_marker_prune_ranges (verified_issuer, \
             authenticated_subject, tenant_scope_key, epoch, protocol_revision, quota_revision, \
             marker_interval_schema_revision, start_sequence, end_sequence, sequence_count, \
             generation, created_at_ms, row_charge, byte_charge, interval_digest) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$9,$11,1,$12,$13)",
        &[
            &input.key.verified_issuer,
            &input.key.authenticated_subject,
            &input.key.tenant_scope_key,
            &epoch,
            &protocol_revision,
            &quota_revision,
            &MARKER_INTERVAL_SCHEMA_REVISION_V3,
            &start,
            &end,
            &sequence_count,
            &created_at_ms,
            &range_bytes,
            &digest,
        ],
    )
    .await
    .map_err(|e| DomainError::from_pg("completion prune range insert", e))?;
    tx.execute(
        "DELETE FROM lore_domain_operation_tombstone_release_completion_markers \
         WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 \
           AND operation_id=$4",
        &[
            &input.key.verified_issuer,
            &input.key.authenticated_subject,
            &input.key.tenant_scope_key,
            &input.key.operation_id.as_bytes().as_slice(),
        ],
    )
    .await
    .map_err(|e| DomainError::from_pg("completion marker delete", e))?;
    let updated_namespace = tx
        .execute(
            "UPDATE lore_domain_proof_namespaces SET retained_marker_count=$5, fragment_count=$6, \
             updated_at=$7 WHERE verified_issuer=$1 AND authenticated_subject=$2 \
             AND tenant_scope_key=$3 AND epoch=$4",
            &[
                &input.key.verified_issuer,
                &input.key.authenticated_subject,
                &input.key.tenant_scope_key,
                &epoch,
                &namespace_retained,
                &namespace_fragments,
                &clock,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("completion prune namespace counters", e))?;
    let updated_global = tx.execute(
        "UPDATE lore_domain_proof_global_counters SET counter_revision=$1, retained_marker_count=$2, \
             fragment_count=$3, fragment_bytes=$4, marker_bytes=$5, updated_at=$6 WHERE id=1",
        &[&next_global_revision, &global_values.0, &global_values.1, &global_values.2,
          &global_values.3, &clock],
    ).await.map_err(|e| DomainError::from_pg("completion prune global counters", e))?;
    let updated_org = tx.execute(
        "UPDATE lore_domain_proof_org_counters SET counter_revision=$2, retained_marker_count=$3, \
             fragment_count=$4, fragment_bytes=$5, marker_bytes=$6, updated_at=$7 WHERE org_uuid=$1",
        &[&org_uuid, &next_org_revision, &org_values.0, &org_values.1, &org_values.2,
          &org_values.3, &clock],
    ).await.map_err(|e| DomainError::from_pg("completion prune org counters", e))?;
    if updated_namespace != 1 || updated_global != 1 || updated_org != 1 {
        return Err(DomainError::Internal(
            "completion prune counter transition was incomplete".to_owned(),
        ));
    }
    Ok((
        ProofRange {
            start_sequence: start,
            end_sequence: end,
            digest,
            generation: end,
        },
        namespace.get("high_water"),
    ))
}

pub async fn terminal_status_attach(
    tx: &Transaction<'_>,
    input: &TerminalStatusAttachInput,
) -> Result<TerminalStatusAttachmentAck, DomainError> {
    let clock = receipts::admission_clock(tx).await?;
    let acknowledged_at = system_time_at_wire_millisecond(input.acknowledged_at)?;
    let key = &[
        &input.key.verified_issuer as &(dyn tokio_postgres::types::ToSql + Sync),
        &input.key.authenticated_subject,
        &input.key.tenant_scope_key,
        &input.key.operation_id.as_bytes().as_slice(),
    ];
    if input.phase == TerminalStatusAttachPhase::Phase1TerminalAck {
        let receipt = tx.query_opt(
            "SELECT method, scope, fingerprint_version, fingerprint, canonical_intent_digest, \
                    state, outcome, public_result, \
                    authorization_id, authorization_revision, compact_expires_at \
             FROM lore_domain_operation_receipts WHERE verified_issuer=$1 AND authenticated_subject=$2 \
               AND tenant_scope_key=$3 AND operation_id=$4 FOR UPDATE", key,
        ).await.map_err(|e| DomainError::from_pg("terminal attachment receipt lock", e))?;
        let fence = tx
            .query_opt(
                "SELECT method, scope, fingerprint_version, fingerprint, canonical_intent_digest, \
                    authorization_id, authorization_revision, safe_prune_after, \
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
                        claim_id, claim_revision, reserve_charge_revision, reserve_charge_nonce, \
                        tombstone_reservation_revision, tombstone_reservation_nonce, \
                        release_proof_reservation_revision, release_proof_reservation_nonce, \
                        terminal_outcome, terminal_receipt_sha256, platform_terminal_status_revision, \
                        platform_acknowledged_at, phase1_request_digest, phase1_verification_digest \
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
                    && row.get::<_, Vec<u8>>("reserve_charge_nonce") == input.reserve_charge_nonce
                    && row.get::<_, i64>("tombstone_reservation_revision")
                        == input.tombstone_reservation_revision
                    && row.get::<_, Vec<u8>>("tombstone_reservation_nonce")
                        == input.tombstone_reservation_nonce
                    && row.get::<_, i64>("release_proof_reservation_revision")
                        == input.release_proof_reservation_revision
                    && row.get::<_, Vec<u8>>("release_proof_reservation_nonce")
                        == input.release_proof_reservation_nonce
                    && row.get::<_, i16>("terminal_outcome") == input.terminal_outcome
                    && row.get::<_, Vec<u8>>("terminal_receipt_sha256")
                        == input.terminal_receipt_sha256
                    && row.get::<_, i64>("platform_terminal_status_revision")
                        == input.platform_terminal_status_revision
                    && row.get::<_, SystemTime>("platform_acknowledged_at") == acknowledged_at
                    && row.get::<_, Vec<u8>>("phase1_request_digest") == input.request_digest
                    && row.get::<_, Vec<u8>>("phase1_verification_digest")
                        == input.verification_digest;
                if exact {
                    let mut ack =
                        empty_terminal_ack(TerminalStatusAttachStatus::Phase1TombstoneReady);
                    ack.fields[0] = Some(row.get("phase1_response"));
                    ack.fields[1] = Some(row.get("terminal_ack_digest"));
                    ack.fields[2] = Some(row.get("receipt_prune_digest"));
                    ack.fields[3] = Some(row.get("fence_prune_digest"));
                    ack.fields[4] = Some(row.get("tombstone_digest"));
                    ack.fields[6] = Some(canonical_digest(
                        b"domain-tombstone-reservation-claim-v1",
                        &[
                            &input.tombstone_reservation_revision.to_be_bytes(),
                            &input.tombstone_reservation_nonce,
                            input.key.operation_id.as_bytes(),
                        ],
                    )?);
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
            && fence.get::<_, i64>("authorization_revision") == input.authorization_revision
            && receipt.get::<_, String>("method") == fence.get::<_, String>("method")
            && receipt.get::<_, Vec<u8>>("scope") == fence.get::<_, Vec<u8>>("scope")
            && receipt.get::<_, i32>("fingerprint_version")
                == fence.get::<_, i32>("fingerprint_version")
            && receipt.get::<_, Vec<u8>>("fingerprint") == fence.get::<_, Vec<u8>>("fingerprint")
            && receipt.get::<_, Vec<u8>>("canonical_intent_digest")
                == fence.get::<_, Vec<u8>>("canonical_intent_digest");
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
        if let Some(existing) = fence.get::<_, Option<Vec<u8>>>("terminal_status_ack_digest")
            && (existing != terminal_ack
                || fence.get::<_, Option<i64>>("terminal_status_revision")
                    != Some(input.platform_terminal_status_revision))
        {
            return finish_terminal_ack(
                input,
                empty_terminal_ack(TerminalStatusAttachStatus::Mismatch),
            );
        }
        let prune_after: SystemTime = receipt
            .get::<_, Option<SystemTime>>("compact_expires_at")
            .unwrap_or(fence.get("safe_prune_after"));
        if clock < prune_after {
            if fence
                .get::<_, Option<Vec<u8>>>("terminal_status_ack_digest")
                .is_none()
            {
                tx.execute(
                    "UPDATE lore_domain_operation_dispatch_possibility_fences SET \
                        terminal_status_ack_digest=$5, terminal_status_revision=$6, terminal_status_ack_at=$7 \
                     WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND operation_id=$4",
                    &[key[0], key[1], key[2], key[3], &terminal_ack,
                      &input.platform_terminal_status_revision, &acknowledged_at],
                ).await.map_err(|e| DomainError::from_pg("terminal attachment acknowledgement", e))?;
            }
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
        let commit_retention = clock
            .checked_add(std::time::Duration::from_secs(365 * 24 * 60 * 60))
            .ok_or_else(|| DomainError::Internal("tombstone retention overflow".to_owned()))?;
        let uuid_retention = receipts::uuid_v7_timestamp(&input.key.operation_id)?
            .checked_add(receipts::STALE_HORIZON + receipts::MARKER_SAFETY_EPSILON)
            .ok_or_else(|| DomainError::Internal("tombstone UUID retention overflow".to_owned()))?;
        let final_prune_after = std::cmp::max(commit_retention, uuid_retention);
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
        let inserted = tx.query_opt(
            "INSERT INTO lore_domain_operation_reserve_release_tombstones (verified_issuer, \
                authenticated_subject, tenant_scope_key, operation_id, method, scope, fingerprint_version, \
                fingerprint, canonical_intent_digest, authorization_id, authorization_revision, claim_id, claim_revision, \
                reserve_charge_revision, reserve_charge_nonce, tombstone_reservation_revision, \
                tombstone_reservation_nonce, terminal_ack_digest, receipt_prune_digest, fence_prune_digest, \
                phase1_response, phase1_request_digest, phase1_verification_digest, terminal_outcome, \
                terminal_receipt_sha256, platform_terminal_status_revision, platform_acknowledged_at, \
                release_proof_reservation_revision, release_proof_reservation_nonce, created_at, compact_after, \
                final_prune_after, tombstone_digest) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20, \
                     $21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33) \
             ON CONFLICT DO NOTHING RETURNING tombstone_digest",
            &[key[0],key[1],key[2],key[3],&receipt.get::<_,String>("method"),
              &receipt.get::<_,Vec<u8>>("scope"),&receipt.get::<_,i32>("fingerprint_version"),
              &receipt.get::<_,Vec<u8>>("fingerprint"),&receipt.get::<_,Vec<u8>>("canonical_intent_digest"),
              &input.authorization_id,&input.authorization_revision,
              &input.claim_id,&input.claim_revision,&input.reserve_charge_revision,&input.reserve_charge_nonce,
              &input.tombstone_reservation_revision,&input.tombstone_reservation_nonce,&terminal_ack,
              &receipt_prune,&fence_prune,&phase1_response,&input.request_digest,&input.verification_digest,
              &input.terminal_outcome,&input.terminal_receipt_sha256,&input.platform_terminal_status_revision,
              &acknowledged_at,&input.release_proof_reservation_revision,
              &input.release_proof_reservation_nonce,&clock,&compact_after,&final_prune_after,&tombstone_digest],
        ).await.map_err(|e| DomainError::from_pg("terminal attachment tombstone insert", e))?;
        if inserted.is_none() {
            let conflict = tx.query_opt(
                "SELECT terminal_ack_digest, receipt_prune_digest, fence_prune_digest, phase1_response, \
                        tombstone_digest, authorization_id, authorization_revision, claim_id, claim_revision, \
                        reserve_charge_revision, reserve_charge_nonce, tombstone_reservation_revision, \
                        tombstone_reservation_nonce, release_proof_reservation_revision, \
                        release_proof_reservation_nonce, terminal_outcome, terminal_receipt_sha256, \
                        platform_terminal_status_revision, platform_acknowledged_at, phase1_request_digest, \
                        phase1_verification_digest, created_at, final_prune_after \
                 FROM lore_domain_operation_reserve_release_tombstones WHERE verified_issuer=$1 \
                   AND authenticated_subject=$2 AND tenant_scope_key=$3 AND operation_id=$4 FOR UPDATE",
                key,
            ).await.map_err(|e| DomainError::from_pg("terminal attachment tombstone conflict", e))?;
            let Some(conflict) = conflict else {
                return finish_terminal_ack(
                    input,
                    empty_terminal_ack(TerminalStatusAttachStatus::Mismatch),
                );
            };
            let exact_conflict = conflict.get::<_, Vec<u8>>("terminal_ack_digest") == terminal_ack
                && conflict.get::<_, Vec<u8>>("receipt_prune_digest") == receipt_prune
                && conflict.get::<_, Vec<u8>>("fence_prune_digest") == fence_prune
                && conflict.get::<_, Vec<u8>>("phase1_response") == phase1_response
                && conflict.get::<_, Vec<u8>>("tombstone_digest") == tombstone_digest
                && conflict.get::<_, Vec<u8>>("authorization_id") == input.authorization_id
                && conflict.get::<_, i64>("authorization_revision") == input.authorization_revision
                && conflict.get::<_, Vec<u8>>("claim_id") == input.claim_id
                && conflict.get::<_, i64>("claim_revision") == input.claim_revision
                && conflict.get::<_, i64>("reserve_charge_revision")
                    == input.reserve_charge_revision
                && conflict.get::<_, Vec<u8>>("reserve_charge_nonce") == input.reserve_charge_nonce
                && conflict.get::<_, i64>("tombstone_reservation_revision")
                    == input.tombstone_reservation_revision
                && conflict.get::<_, Vec<u8>>("tombstone_reservation_nonce")
                    == input.tombstone_reservation_nonce
                && conflict.get::<_, i64>("release_proof_reservation_revision")
                    == input.release_proof_reservation_revision
                && conflict.get::<_, Vec<u8>>("release_proof_reservation_nonce")
                    == input.release_proof_reservation_nonce
                && conflict.get::<_, i16>("terminal_outcome") == input.terminal_outcome
                && conflict.get::<_, Vec<u8>>("terminal_receipt_sha256")
                    == input.terminal_receipt_sha256
                && conflict.get::<_, i64>("platform_terminal_status_revision")
                    == input.platform_terminal_status_revision
                && conflict.get::<_, SystemTime>("platform_acknowledged_at") == acknowledged_at
                && conflict.get::<_, Vec<u8>>("phase1_request_digest") == input.request_digest
                && conflict.get::<_, Vec<u8>>("phase1_verification_digest")
                    == input.verification_digest;
            if !exact_conflict {
                return finish_terminal_ack(
                    input,
                    empty_terminal_ack(TerminalStatusAttachStatus::Mismatch),
                );
            }
        }
        if fence
            .get::<_, Option<Vec<u8>>>("terminal_status_ack_digest")
            .is_none()
        {
            tx.execute(
                "UPDATE lore_domain_operation_dispatch_possibility_fences SET \
                    terminal_status_ack_digest=$5, terminal_status_revision=$6, terminal_status_ack_at=$7 \
                 WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND operation_id=$4",
                &[key[0], key[1], key[2], key[3], &terminal_ack,
                  &input.platform_terminal_status_revision, &acknowledged_at],
            ).await.map_err(|e| DomainError::from_pg("terminal attachment acknowledgement", e))?;
        }
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
            "SELECT tombstone_digest, active_release_intent_digest, active_release_intent_revision, \
                active_release_intent_nonce, active_release_intent_ack_at, \
                final_prune_after, terminal_ack_digest, receipt_prune_digest, fence_prune_digest, \
                authorization_id, authorization_revision, claim_id, claim_revision, \
                reserve_charge_revision, reserve_charge_nonce, \
                tombstone_reservation_revision, tombstone_reservation_nonce, \
                release_proof_reservation_revision, release_proof_reservation_nonce, \
                terminal_outcome, terminal_receipt_sha256, platform_terminal_status_revision, \
                platform_acknowledged_at \
         FROM lore_domain_operation_reserve_release_tombstones WHERE verified_issuer=$1 \
           AND authenticated_subject=$2 AND tenant_scope_key=$3 AND operation_id=$4 FOR UPDATE",
            key,
        )
        .await
        .map_err(|e| DomainError::from_pg("terminal phase2 tombstone lock", e))?;
    let Some(tombstone) = tombstone else {
        let marker = tx.query_opt(
            "SELECT marker_digest, completion_ack, created_at, retain_until, sequence, namespace_epoch, \
                    tombstone_digest, final_prune_digest, final_prune_after, \
                    completion_request_binding, completion_request_digest, \
                    completion_verification_digest, byte_charge \
             FROM lore_domain_operation_tombstone_release_completion_markers WHERE verified_issuer=$1 \
               AND authenticated_subject=$2 AND tenant_scope_key=$3 AND operation_id=$4 FOR UPDATE", key,
        ).await.map_err(|e| DomainError::from_pg("terminal completion replay lookup", e))?;
        if let Some(marker) = marker {
            let is_completion =
                input.action == TerminalStatusAttachAction::TombstoneReleaseIntentComplete;
            let request_binding = completion_request_binding(input)?;
            let epoch: Vec<u8> = marker.get("namespace_epoch");
            let tombstone_digest: Vec<u8> = marker.get("tombstone_digest");
            let marker_digest = completion_marker_digest(input, &epoch, &tombstone_digest)?;
            let exact = is_completion
                && marker.get::<_, i64>("sequence") == input.completion_marker_sequence
                && marker.get::<_, Vec<u8>>("completion_request_binding") == request_binding
                && marker.get::<_, Vec<u8>>("completion_request_digest") == input.request_digest
                && marker.get::<_, Vec<u8>>("completion_verification_digest")
                    == input.verification_digest
                && marker.get::<_, Vec<u8>>("final_prune_digest")
                    == input.final_prune_digest.clone().unwrap_or_default()
                && marker.get::<_, Vec<u8>>("marker_digest") == marker_digest
                && input.expected_completion_marker_digest.as_deref()
                    == Some(marker_digest.as_slice());
            if is_completion && !exact {
                return finish_terminal_ack(
                    input,
                    empty_terminal_ack(TerminalStatusAttachStatus::Mismatch),
                );
            }
            let retain_until: SystemTime = marker.get("retain_until");
            if clock >= retain_until {
                let (range, high_water) =
                    prune_completion_marker(tx, input, &marker, clock).await?;
                let mut ack = empty_terminal_ack(if is_completion {
                    TerminalStatusAttachStatus::Phase2PostPruneRecovery
                } else {
                    TerminalStatusAttachStatus::Phase2PostPruneCompletionReplayRequired
                });
                if is_completion {
                    ack.fields[8] = Some(marker_digest);
                    ack.fields[9] = Some(range.digest.clone());
                    ack.range = Some(range);
                    ack.completion_marker_sequence = input.completion_marker_sequence;
                    ack.informational_high_water = Some(high_water);
                }
                return finish_terminal_ack(input, ack);
            }
            if !is_completion {
                return finish_terminal_ack(
                    input,
                    empty_terminal_ack(
                        TerminalStatusAttachStatus::Phase2PostPruneCompletionReplayRequired,
                    ),
                );
            }
            let mut ack =
                empty_terminal_ack(TerminalStatusAttachStatus::Phase2ReleaseCompletionReady);
            ack.fields[8] = Some(marker_digest);
            ack.fields[0] = marker.get("completion_ack");
            ack.times[4] = Some(marker.get("created_at"));
            ack.times[5] = Some(retain_until);
            ack.completion_marker_sequence = marker.get("sequence");
            ack.fields[9] = ack.fields[8].clone();
            ack.fields[7] = Some(marker.get("final_prune_digest"));
            ack.times[3] = Some(marker.get("final_prune_after"));
            ack.informational_high_water = Some(marker.get("sequence"));
            return finish_terminal_ack(input, ack);
        }
        if input.action == TerminalStatusAttachAction::TombstoneReleaseIntentComplete {
            let namespace = tx.query_opt(
                "SELECT epoch, high_water FROM lore_domain_proof_namespaces WHERE verified_issuer=$1 \
                 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND state <> $4 FOR UPDATE",
                &[key[0],key[1],key[2],&schema_mediated::NAMESPACE_STATE_RETIRED],
            ).await.map_err(|e| DomainError::from_pg("post-prune namespace lock", e))?;
            if let Some(namespace) = namespace {
                let epoch: Vec<u8> = namespace.get("epoch");
                let tombstone_digest = input
                    .release_tombstone_digest
                    .as_deref()
                    .unwrap_or_default();
                let expected = completion_marker_digest(input, &epoch, tombstone_digest)?;
                if input.expected_completion_marker_digest.as_deref() != Some(expected.as_slice()) {
                    return finish_terminal_ack(
                        input,
                        empty_terminal_ack(TerminalStatusAttachStatus::Mismatch),
                    );
                }
                let range = tx
                    .query_opt(
                        "SELECT start_sequence, end_sequence, interval_digest, generation \
                     FROM lore_domain_tombstone_marker_prune_ranges \
                     WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 \
                       AND epoch=$4 AND start_sequence <= $5 AND end_sequence >= $5 FOR UPDATE",
                        &[
                            key[0],
                            key[1],
                            key[2],
                            &epoch,
                            &input.completion_marker_sequence,
                        ],
                    )
                    .await
                    .map_err(|e| DomainError::from_pg("post-prune containing range", e))?;
                if let Some(range) = range {
                    let proof = ProofRange {
                        start_sequence: range.get("start_sequence"),
                        end_sequence: range.get("end_sequence"),
                        digest: range.get("interval_digest"),
                        generation: range.get("generation"),
                    };
                    let mut ack =
                        empty_terminal_ack(TerminalStatusAttachStatus::Phase2PostPruneRecovery);
                    ack.fields[8] = Some(expected);
                    ack.fields[9] = Some(proof.digest.clone());
                    ack.completion_marker_sequence = input.completion_marker_sequence;
                    ack.range = Some(proof);
                    ack.informational_high_water = Some(namespace.get("high_water"));
                    return finish_terminal_ack(input, ack);
                }
            }
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
        || tombstone.get::<_, i64>("release_proof_reservation_revision")
            != input.release_proof_reservation_revision
        || tombstone.get::<_, Vec<u8>>("release_proof_reservation_nonce")
            != input.release_proof_reservation_nonce
        || tombstone.get::<_, i16>("terminal_outcome") != input.terminal_outcome
        || tombstone.get::<_, Vec<u8>>("terminal_receipt_sha256") != input.terminal_receipt_sha256
        || tombstone.get::<_, i64>("platform_terminal_status_revision")
            != input.platform_terminal_status_revision
        || tombstone.get::<_, SystemTime>("platform_acknowledged_at") != acknowledged_at
    {
        return finish_terminal_ack(
            input,
            empty_terminal_ack(TerminalStatusAttachStatus::Mismatch),
        );
    }
    match input.action {
        TerminalStatusAttachAction::ActiveReleaseIntentAck => {
            let intent_revision = input.active_release_intent_revision.unwrap_or_default();
            let intent = input
                .active_release_intent_nonce
                .clone()
                .unwrap_or_default();
            let intent_digest = canonical_digest(
                b"domain-active-release-intent-ack-v1",
                &[
                    input.key.operation_id.as_bytes(),
                    &intent,
                    &intent_revision.to_be_bytes(),
                    &input.request_digest,
                ],
            )?;
            let acknowledged_at = if let Some(existing) =
                tombstone.get::<_, Option<Vec<u8>>>("active_release_intent_digest")
            {
                if existing != intent_digest
                    || tombstone.get::<_, Option<i64>>("active_release_intent_revision")
                        != Some(intent_revision)
                    || tombstone
                        .get::<_, Option<Vec<u8>>>("active_release_intent_nonce")
                        .as_deref()
                        != Some(intent.as_slice())
                {
                    return finish_terminal_ack(
                        input,
                        empty_terminal_ack(TerminalStatusAttachStatus::Mismatch),
                    );
                }
                tombstone
                    .get::<_, Option<SystemTime>>("active_release_intent_ack_at")
                    .ok_or_else(|| {
                        DomainError::Internal(
                            "active release intent digest exists without acknowledgement time"
                                .to_owned(),
                        )
                    })?
            } else {
                tx.execute("UPDATE lore_domain_operation_reserve_release_tombstones SET active_release_intent_digest=$5, active_release_intent_revision=$6, active_release_intent_nonce=$7, active_release_intent_ack_at=$8 WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND operation_id=$4",
                    &[key[0],key[1],key[2],key[3],&intent_digest,&intent_revision,&intent,&clock]).await
                    .map_err(|e| DomainError::from_pg("active release intent acknowledgement", e))?;
                clock
            };
            let mut ack = empty_terminal_ack(TerminalStatusAttachStatus::Phase2ActiveReleaseAcked);
            ack.fields[5] = Some(intent_digest);
            ack.times[2] = Some(acknowledged_at);
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
            if tombstone.get::<_, Option<i64>>("active_release_intent_revision")
                != input.active_release_intent_revision
                || tombstone
                    .get::<_, Option<Vec<u8>>>("active_release_intent_nonce")
                    .as_deref()
                    != input.active_release_intent_nonce.as_deref()
            {
                return finish_terminal_ack(
                    input,
                    empty_terminal_ack(TerminalStatusAttachStatus::Mismatch),
                );
            }
            let org_identity = tx
                .query_opt(
                    "SELECT org_uuid FROM lore_domain_proof_namespaces WHERE verified_issuer=$1 \
                 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND state <> $4",
                    &[
                        key[0],
                        key[1],
                        key[2],
                        &schema_mediated::NAMESPACE_STATE_RETIRED,
                    ],
                )
                .await
                .map_err(|e| DomainError::from_pg("completion org identity read", e))?;
            let Some(org_identity) = org_identity else {
                return finish_terminal_ack(
                    input,
                    empty_terminal_ack(TerminalStatusAttachStatus::Mismatch),
                );
            };
            let org_uuid: Vec<u8> = org_identity.get("org_uuid");
            let global = tx
                .query_one(
                    "SELECT counter_revision, retained_marker_count, marker_bytes \
                 FROM lore_domain_proof_global_counters WHERE id=1 FOR UPDATE",
                    &[],
                )
                .await
                .map_err(|e| DomainError::from_pg("completion global counter lock", e))?;
            let org = tx
                .query_one(
                    "SELECT counter_revision, retained_marker_count, marker_bytes \
                 FROM lore_domain_proof_org_counters WHERE org_uuid=$1 FOR UPDATE",
                    &[&org_uuid],
                )
                .await
                .map_err(|e| DomainError::from_pg("completion org counter lock", e))?;
            let namespace = tx.query_opt(
                "SELECT epoch, org_uuid, next_sequence, high_water FROM lore_domain_proof_namespaces WHERE verified_issuer=$1 \
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
            if namespace.get::<_, Vec<u8>>("org_uuid") != org_uuid {
                return finish_terminal_ack(
                    input,
                    empty_terminal_ack(TerminalStatusAttachStatus::Mismatch),
                );
            }
            let expected_sequence: i64 = namespace.get("next_sequence");
            if input.completion_marker_sequence != expected_sequence {
                return finish_terminal_ack(
                    input,
                    empty_terminal_ack(TerminalStatusAttachStatus::Mismatch),
                );
            }
            let next_sequence = expected_sequence
                .checked_add(1)
                .ok_or_else(|| DomainError::Internal("completion sequence overflow".to_owned()))?;
            let tombstone_digest: Vec<u8> = tombstone.get("tombstone_digest");
            let marker_digest = completion_marker_digest(input, &epoch, &tombstone_digest)?;
            if input.expected_completion_marker_digest.as_deref() != Some(marker_digest.as_slice())
            {
                return finish_terminal_ack(
                    input,
                    empty_terminal_ack(TerminalStatusAttachStatus::Mismatch),
                );
            }
            let commit_retention = clock
                .checked_add(std::time::Duration::from_secs(365 * 24 * 60 * 60))
                .ok_or_else(|| DomainError::Internal("completion retention overflow".to_owned()))?;
            let uuid_retention = receipts::uuid_v7_timestamp(&input.key.operation_id)?
                .checked_add(receipts::STALE_HORIZON + receipts::MARKER_SAFETY_EPSILON)
                .ok_or_else(|| {
                    DomainError::Internal("completion UUID retention overflow".to_owned())
                })?;
            let retain_until = std::cmp::max(commit_retention, uuid_retention);
            let completion_ack = canonical_digest(
                b"domain-tombstone-release-completion-ack-v1",
                &[&marker_digest, &input.request_digest],
            )?;
            let request_binding = completion_request_binding(input)?;
            let marker_bytes = completion_marker_byte_charge(&input.key, &completion_ack)?;
            let next_global_revision = global
                .get::<_, i64>("counter_revision")
                .checked_add(1)
                .ok_or_else(|| {
                    DomainError::Internal("global counter revision overflow".to_owned())
                })?;
            let next_org_revision = org
                .get::<_, i64>("counter_revision")
                .checked_add(1)
                .ok_or_else(|| DomainError::Internal("org counter revision overflow".to_owned()))?;
            let global_retained = global
                .get::<_, i64>("retained_marker_count")
                .checked_add(1)
                .ok_or_else(|| {
                    DomainError::Internal("global retained marker overflow".to_owned())
                })?;
            let org_retained = org
                .get::<_, i64>("retained_marker_count")
                .checked_add(1)
                .ok_or_else(|| DomainError::Internal("org retained marker overflow".to_owned()))?;
            let global_marker_bytes = global
                .get::<_, i64>("marker_bytes")
                .checked_add(marker_bytes)
                .ok_or_else(|| DomainError::Internal("global marker bytes overflow".to_owned()))?;
            let org_marker_bytes = org
                .get::<_, i64>("marker_bytes")
                .checked_add(marker_bytes)
                .ok_or_else(|| DomainError::Internal("org marker bytes overflow".to_owned()))?;
            tx.execute(
                "INSERT INTO lore_domain_operation_tombstone_release_completion_markers \
                 (verified_issuer,authenticated_subject,tenant_scope_key,operation_id,namespace_epoch,sequence, \
                  tombstone_digest,release_intent_digest,final_prune_digest,marker_reservation_revision, \
                  final_prune_after,marker_reservation_nonce,completion_request_binding,completion_request_digest, \
                  completion_verification_digest,completion_ack,marker_digest,byte_charge,created_at,retain_until) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)",
                &[key[0],key[1],key[2],key[3],&epoch,&input.completion_marker_sequence,
                  &tombstone_digest,
                  &tombstone.get::<_,Option<Vec<u8>>>("active_release_intent_digest").unwrap_or_default(),
                  &input.final_prune_digest.clone().unwrap_or_default(),&input.release_proof_reservation_revision,
                  &final_after,&input.release_proof_reservation_nonce,&request_binding,&input.request_digest,
                  &input.verification_digest,&completion_ack,&marker_digest,&marker_bytes,&clock,&retain_until],
            ).await.map_err(|e| DomainError::from_pg("completion marker insert", e))?;
            tx.execute("DELETE FROM lore_domain_operation_reserve_release_tombstones WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND operation_id=$4", key)
                .await.map_err(|e| DomainError::from_pg("completion tombstone delete", e))?;
            let namespace_updated = tx.execute("UPDATE lore_domain_proof_namespaces SET high_water=$5, next_sequence=$6, retained_marker_count=retained_marker_count+1, updated_at=$7 WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND epoch=$4 AND next_sequence=$5",
                &[key[0],key[1],key[2],&epoch,&input.completion_marker_sequence,&next_sequence,&clock]).await
                .map_err(|e| DomainError::from_pg("completion namespace update", e))?;
            let global_updated = tx.execute(
                "UPDATE lore_domain_proof_global_counters SET counter_revision=$1, retained_marker_count=$2, \
                 marker_bytes=$3, updated_at=$4 WHERE id=1",
                &[&next_global_revision,&global_retained,&global_marker_bytes,&clock],
            ).await.map_err(|e| DomainError::from_pg("completion global counter update", e))?;
            let org_updated = tx.execute(
                "UPDATE lore_domain_proof_org_counters SET counter_revision=$2, retained_marker_count=$3, \
                 marker_bytes=$4, updated_at=$5 WHERE org_uuid=$1",
                &[&org_uuid,&next_org_revision,&org_retained,&org_marker_bytes,&clock],
            ).await.map_err(|e| DomainError::from_pg("completion org counter update", e))?;
            if namespace_updated != 1 || global_updated != 1 || org_updated != 1 {
                return Err(DomainError::Internal(
                    "completion marker counter transition was incomplete".to_owned(),
                ));
            }
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
            ack.informational_high_water = Some(input.completion_marker_sequence);
            finish_terminal_ack(input, ack)
        }
        TerminalStatusAttachAction::None => finish_terminal_ack(
            input,
            empty_terminal_ack(TerminalStatusAttachStatus::Invalid),
        ),
    }
}

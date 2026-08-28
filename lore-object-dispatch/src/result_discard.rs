// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Pure result-discard fingerprint and receipt contracts.
//!
//! These functions prove that an unusable terminal result is superseded, removed, tombstoned, or
//! durably cancelled. They do not update result disposition, fence fetches, purge payloads, or
//! authorize provider traffic.

use std::fmt;

use lore_proto::lore::object_dispatch::v1::DurableConsumerCancellationKindV1;
use lore_proto::lore::object_dispatch::v1::DurableConsumerCancelledProofV1;
use lore_proto::lore::object_dispatch::v1::DurableConsumerContextV1;
use lore_proto::lore::object_dispatch::v1::DurableConsumerKindV1;
use lore_proto::lore::object_dispatch::v1::FragmentLifecycleConsumerContextV1;
use lore_proto::lore::object_dispatch::v1::FragmentLifecycleSupersededProofV1;
use lore_proto::lore::object_dispatch::v1::FragmentLifecycleSupersessionKindV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultDiscardReceiptV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultDiscardStateV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultDiscardV1;
use lore_proto::lore::object_dispatch::v1::StartupAdmissionConsumerContextV1;
use lore_proto::lore::object_dispatch::v1::StartupSupersededProofV1;
use lore_proto::lore::object_dispatch::v1::object_store_result_discard_v1;
use lore_proto::lore::object_dispatch::v1::object_store_terminal_result_v1;
use lore_proto::lore::object_dispatch::v1::result_consumer_context_v1;
use thiserror::Error;

use crate::contract::BoundedCanonicalWriter;
use crate::contract::canonical_uuid_v7_timestamp;
use crate::contract::validate_canonical_text;
use crate::request::validate_result_consumer_context;
use crate::result_ack::ObjectStoreResultAckAuthority;
use crate::result_ack::ResultAckLimits;

const DISCARD_FINGERPRINT_DOMAIN: &[u8] = b"object-dispatch-discard-v1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResultDiscardLimits {
    pub ack: ResultAckLimits,
    pub max_checkpoint_id_bytes: u32,
    pub max_operation_id_bytes: u32,
    pub max_revision_id_bytes: u32,
}

#[derive(Clone, PartialEq)]
pub struct ValidatedObjectStoreResultDiscard {
    discard: ObjectStoreResultDiscardV1,
    canonical_discard_bytes: Vec<u8>,
    discard_fingerprint: [u8; 32],
}

impl ValidatedObjectStoreResultDiscard {
    pub fn discard(&self) -> &ObjectStoreResultDiscardV1 {
        &self.discard
    }

    pub fn canonical_discard_bytes(&self) -> &[u8] {
        &self.canonical_discard_bytes
    }

    pub fn discard_fingerprint(&self) -> &[u8; 32] {
        &self.discard_fingerprint
    }
}

impl fmt::Debug for ValidatedObjectStoreResultDiscard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedObjectStoreResultDiscard")
            .field("discard", &"[REDACTED]")
            .field("canonical_discard_bytes", &"[REDACTED]")
            .field("discard_fingerprint", &"[REDACTED]")
            .finish()
    }
}

pub struct ResultDiscardReceiptInput<'a> {
    pub terminal_result_id: &'a str,
    pub discard_fingerprint: &'a [u8],
    pub discarded_at_unix_ms: i64,
    pub payload_purge_after_unix_ms: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ResultDiscardError {
    #[error("object-store result discard limits are invalid")]
    InvalidLimits,
    #[error("object-store result discard text is not canonical and bounded")]
    InvalidCanonicalText,
    #[error("object-store result discard UUID is not canonical RFC 9562 UUIDv7")]
    InvalidUuidV7,
    #[error("object-store result discard does not match stored authority")]
    AuthorityMismatch,
    #[error("object-store result discard consumer context is invalid")]
    InvalidConsumerContext,
    #[error("object-store result discard terminal tuple is invalid")]
    TerminalResultMismatch,
    #[error("object-store result discard byte-result handle is invalid")]
    InvalidByteResultHandle,
    #[error("object-store result discard proof is invalid")]
    InvalidProof,
    #[error("object-store result discard fingerprint preimage exceeds its bound")]
    PreimageTooLarge,
    #[error("object-store result discard receipt is invalid")]
    InvalidReceipt,
}

pub fn validate_object_store_result_discard(
    input: &ObjectStoreResultDiscardV1,
    authority: &ObjectStoreResultAckAuthority<'_>,
    limits: &ResultDiscardLimits,
) -> Result<ValidatedObjectStoreResultDiscard, ResultDiscardError> {
    validate_limits(limits)?;
    validate_result_consumer_context(
        authority.operation,
        authority.consumer_context,
        authority.authenticated_identity,
        &limits.ack.identity,
    )
    .map_err(|_| ResultDiscardError::InvalidConsumerContext)?;

    for (actual, expected) in [
        (&input.protocol_revision, authority.protocol_revision),
        (&input.provider_boundary_id, authority.provider_boundary_id),
        (
            &input.authenticated_cell_id,
            authority.authenticated_cell_id,
        ),
        (
            &input.authenticated_tenant_id,
            authority.authenticated_tenant_id,
        ),
        (&input.logical_request_id, authority.logical_request_id),
        (&input.attempt_id, authority.attempt_id),
    ] {
        validate_text(actual, limits.ack.identity.max_identity_bytes)?;
        if actual != expected {
            return Err(ResultDiscardError::AuthorityMismatch);
        }
    }
    canonical_uuid_v7_timestamp(&input.logical_request_id)
        .map_err(|_| ResultDiscardError::InvalidUuidV7)?;
    canonical_uuid_v7_timestamp(&input.attempt_id)
        .map_err(|_| ResultDiscardError::InvalidUuidV7)?;

    let stored_result = authority.terminal_result.result();
    validate_text(
        &input.terminal_result_id,
        limits.ack.max_terminal_result_id_bytes,
    )?;
    if input.terminal_result_id != stored_result.terminal_result_id
        || input.canonical_result_size != authority.terminal_result.canonical_result_size()
        || input.canonical_result_blake3.as_ref()
            != authority.terminal_result.canonical_result_blake3()
    {
        return Err(ResultDiscardError::TerminalResultMismatch);
    }
    let expected_handle = match stored_result.result.as_ref() {
        Some(object_store_terminal_result_v1::Result::ByteResult(result)) => {
            Some(result.handle.as_str())
        }
        _ => None,
    };
    if input.byte_result_handle.as_deref() != expected_handle {
        return Err(ResultDiscardError::InvalidByteResultHandle);
    }
    if let Some(handle) = input.byte_result_handle.as_deref() {
        validate_text(handle, limits.ack.max_result_handle_bytes)
            .map_err(|_| ResultDiscardError::InvalidByteResultHandle)?;
    }

    let mut writer = BoundedCanonicalWriter::new(limits.ack.max_fingerprint_preimage_bytes)
        .map_err(|_| ResultDiscardError::InvalidLimits)?;
    write_raw(&mut writer, DISCARD_FINGERPRINT_DOMAIN)?;
    for value in [
        &input.protocol_revision,
        &input.provider_boundary_id,
        &input.authenticated_cell_id,
        &input.authenticated_tenant_id,
        &input.logical_request_id,
        &input.attempt_id,
        &input.terminal_result_id,
    ] {
        write_text(&mut writer, value)?;
    }
    write_u64(&mut writer, input.canonical_result_size)?;
    write_raw(&mut writer, input.canonical_result_blake3.as_ref())?;
    write_optional_text(&mut writer, input.byte_result_handle.as_deref())?;
    encode_proof(&mut writer, input.proof.as_ref(), authority, limits)?;

    let canonical_discard_bytes = writer.finish();
    let discard_fingerprint = *blake3::hash(&canonical_discard_bytes).as_bytes();
    Ok(ValidatedObjectStoreResultDiscard {
        discard: input.clone(),
        canonical_discard_bytes,
        discard_fingerprint,
    })
}

pub fn build_object_store_result_discard_receipt(
    input: &ResultDiscardReceiptInput<'_>,
    limits: &ResultDiscardLimits,
) -> Result<ObjectStoreResultDiscardReceiptV1, ResultDiscardError> {
    validate_limits(limits)?;
    validate_text(
        input.terminal_result_id,
        limits.ack.max_terminal_result_id_bytes,
    )?;
    if input.discard_fingerprint.len() != 32
        || input.discarded_at_unix_ms < 0
        || input
            .payload_purge_after_unix_ms
            .is_some_and(|purge| purge < input.discarded_at_unix_ms)
    {
        return Err(ResultDiscardError::InvalidReceipt);
    }
    Ok(ObjectStoreResultDiscardReceiptV1 {
        state: ObjectStoreResultDiscardStateV1::ObjectStoreResultDiscardStateDiscarded as i32,
        terminal_result_id: input.terminal_result_id.to_owned(),
        discard_fingerprint: input.discard_fingerprint.to_vec().into(),
        discarded_at_unix_ms: input.discarded_at_unix_ms,
        payload_purge_after_unix_ms: input.payload_purge_after_unix_ms,
    })
}

fn validate_limits(limits: &ResultDiscardLimits) -> Result<(), ResultDiscardError> {
    if [
        limits.ack.identity.max_identity_bytes,
        limits.ack.identity.max_authenticated_scope_bytes,
        limits.ack.max_terminal_result_id_bytes,
        limits.ack.max_result_handle_bytes,
        limits.ack.max_fingerprint_preimage_bytes,
        limits.max_checkpoint_id_bytes,
        limits.max_operation_id_bytes,
        limits.max_revision_id_bytes,
    ]
    .contains(&0)
    {
        return Err(ResultDiscardError::InvalidLimits);
    }
    Ok(())
}

fn validate_text(value: &str, maximum: u32) -> Result<(), ResultDiscardError> {
    validate_canonical_text(value, maximum).map_err(|_| ResultDiscardError::InvalidCanonicalText)
}

fn encode_proof(
    writer: &mut BoundedCanonicalWriter,
    proof: Option<&object_store_result_discard_v1::Proof>,
    authority: &ObjectStoreResultAckAuthority<'_>,
    limits: &ResultDiscardLimits,
) -> Result<(), ResultDiscardError> {
    let consumer = authority
        .consumer_context
        .consumer
        .as_ref()
        .ok_or(ResultDiscardError::InvalidConsumerContext)?;
    let proof = proof.ok_or(ResultDiscardError::InvalidProof)?;
    match proof {
        object_store_result_discard_v1::Proof::FragmentLifecycleSuperseded(proof) => match consumer
        {
            result_consumer_context_v1::Consumer::FragmentLifecycle(context) => {
                encode_fragment_proof(writer, proof, context, authority, limits)
            }
            result_consumer_context_v1::Consumer::StartupAdmission(_)
            | result_consumer_context_v1::Consumer::DurableConsumer(_) => {
                Err(ResultDiscardError::InvalidProof)
            }
        },
        object_store_result_discard_v1::Proof::StartupSuperseded(proof) => match consumer {
            result_consumer_context_v1::Consumer::StartupAdmission(context) => {
                encode_startup_proof(writer, proof, context, authority, limits)
            }
            result_consumer_context_v1::Consumer::FragmentLifecycle(_)
            | result_consumer_context_v1::Consumer::DurableConsumer(_) => {
                Err(ResultDiscardError::InvalidProof)
            }
        },
        object_store_result_discard_v1::Proof::DurableConsumerCancelled(proof) => match consumer {
            result_consumer_context_v1::Consumer::DurableConsumer(context) => {
                encode_durable_proof(writer, proof, context, authority, limits)
            }
            result_consumer_context_v1::Consumer::FragmentLifecycle(_)
            | result_consumer_context_v1::Consumer::StartupAdmission(_) => {
                Err(ResultDiscardError::InvalidProof)
            }
        },
    }
}

fn encode_fragment_proof(
    writer: &mut BoundedCanonicalWriter,
    proof: &FragmentLifecycleSupersededProofV1,
    context: &FragmentLifecycleConsumerContextV1,
    authority: &ObjectStoreResultAckAuthority<'_>,
    limits: &ResultDiscardLimits,
) -> Result<(), ResultDiscardError> {
    if proof.fragment_id != context.fragment_id
        || proof.repository_id != context.repository_id
        || proof.association_context != context.association_context
        || proof.repository_generation != context.repository_generation
        || proof.association_epoch != context.association_epoch
        || proof.lifecycle_generation != context.lifecycle_generation
        || proof.fragment_epoch != context.fragment_epoch
        || proof.lifecycle_fence != context.lifecycle_fence
        || proof.reader_lease_id != context.reader_lease_id
        || proof.reader_fence != context.reader_fence
        || proof.terminal_result_blake3.as_ref()
            != authority.terminal_result.canonical_result_blake3()
        || proof.no_exposure_checkpoint_revision == 0
        || proof.no_exposure_checkpoint_fence == 0
    {
        return Err(ResultDiscardError::InvalidProof);
    }
    validate_text(
        &proof.no_exposure_checkpoint_id,
        limits.max_checkpoint_id_bytes,
    )
    .map_err(|_| ResultDiscardError::InvalidProof)?;

    let kind = closed_supersession_kind(proof.supersession_kind)?;
    let physical = [
        proof.superseding_lifecycle_generation,
        proof.superseding_fragment_epoch,
        proof.superseding_lifecycle_fence,
    ];
    let association = [
        proof.successor_repository_generation,
        proof.successor_association_epoch,
    ];
    match kind {
        FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindSuccessor
        | FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindRemoved => {
            let [Some(generation), Some(epoch), Some(fence)] = physical else {
                return Err(ResultDiscardError::InvalidProof);
            };
            if association.iter().any(Option::is_some)
                || proof.repository_tombstone_revision.is_some()
                || generation <= context.lifecycle_generation
                || fence <= context.lifecycle_fence
                || (kind
                    == FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindSuccessor
                    && epoch <= context.fragment_epoch)
                || (kind
                    == FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindRemoved
                    && epoch < context.fragment_epoch)
            {
                return Err(ResultDiscardError::InvalidProof);
            }
        }
        FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindAssociationTombstoned => {
            let (Some(repository_generation), Some(association_epoch)) =
                (context.repository_generation, context.association_epoch)
            else {
                return Err(ResultDiscardError::InvalidProof);
            };
            let [Some(successor_repository), Some(successor_association)] = association else {
                return Err(ResultDiscardError::InvalidProof);
            };
            if physical.iter().any(Option::is_some)
                || proof.repository_tombstone_revision.is_some()
                || successor_repository <= repository_generation
                || successor_association <= association_epoch
            {
                return Err(ResultDiscardError::InvalidProof);
            }
        }
        FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindRepositoryTombstoned => {
            let Some(repository_generation) = context.repository_generation else {
                return Err(ResultDiscardError::InvalidProof);
            };
            let Some(tombstone) = proof.repository_tombstone_revision else {
                return Err(ResultDiscardError::InvalidProof);
            };
            if context.association_epoch.is_none()
                || physical.iter().any(Option::is_some)
                || association.iter().any(Option::is_some)
                || tombstone <= repository_generation
            {
                return Err(ResultDiscardError::InvalidProof);
            }
        }
        FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindUnspecified => {
            return Err(ResultDiscardError::InvalidProof);
        }
    }

    write_u32(writer, 20)?;
    write_raw(writer, proof.fragment_id.as_ref())?;
    write_optional_text(writer, proof.repository_id.as_deref())?;
    write_optional_text(writer, proof.association_context.as_deref())?;
    write_optional_u64(writer, proof.repository_generation)?;
    write_optional_u64(writer, proof.association_epoch)?;
    write_u64(writer, proof.lifecycle_generation)?;
    write_u64(writer, proof.fragment_epoch)?;
    write_u64(writer, proof.lifecycle_fence)?;
    write_optional_text(writer, proof.reader_lease_id.as_deref())?;
    write_optional_u64(writer, proof.reader_fence)?;
    write_u32(writer, kind as u32)?;
    write_optional_u64(writer, proof.superseding_lifecycle_generation)?;
    write_optional_u64(writer, proof.superseding_fragment_epoch)?;
    write_optional_u64(writer, proof.superseding_lifecycle_fence)?;
    write_text(writer, &proof.no_exposure_checkpoint_id)?;
    write_u64(writer, proof.no_exposure_checkpoint_revision)?;
    write_u64(writer, proof.no_exposure_checkpoint_fence)?;
    write_raw(writer, proof.terminal_result_blake3.as_ref())?;
    write_optional_u64(writer, proof.successor_repository_generation)?;
    write_optional_u64(writer, proof.successor_association_epoch)?;
    write_optional_u64(writer, proof.repository_tombstone_revision)
}

fn encode_startup_proof(
    writer: &mut BoundedCanonicalWriter,
    proof: &StartupSupersededProofV1,
    context: &StartupAdmissionConsumerContextV1,
    authority: &ObjectStoreResultAckAuthority<'_>,
    limits: &ResultDiscardLimits,
) -> Result<(), ResultDiscardError> {
    if proof.policy_revision != context.policy_revision
        || proof.allocation_revision != context.allocation_revision
        || proof.config_revision != context.config_revision
        || proof.startup_attempt_id != context.startup_attempt_id
        || proof.readiness_generation != context.readiness_generation
        || proof.terminal_result_blake3.as_ref()
            != authority.terminal_result.canonical_result_blake3()
        || proof.superseding_startup_attempt_id == proof.startup_attempt_id
        || proof.superseding_readiness_generation <= proof.readiness_generation
        || proof.no_exposure_checkpoint_revision == 0
        || proof.no_exposure_checkpoint_fence == 0
    {
        return Err(ResultDiscardError::InvalidProof);
    }
    for value in [
        &proof.policy_revision,
        &proof.allocation_revision,
        &proof.config_revision,
        &proof.startup_attempt_id,
        &proof.superseding_policy_revision,
        &proof.superseding_allocation_revision,
        &proof.superseding_config_revision,
        &proof.superseding_startup_attempt_id,
    ] {
        validate_text(value, limits.max_revision_id_bytes)
            .map_err(|_| ResultDiscardError::InvalidProof)?;
    }
    validate_text(
        &proof.no_exposure_checkpoint_id,
        limits.max_checkpoint_id_bytes,
    )
    .map_err(|_| ResultDiscardError::InvalidProof)?;

    write_u32(writer, 21)?;
    write_text(writer, &proof.policy_revision)?;
    write_text(writer, &proof.allocation_revision)?;
    write_text(writer, &proof.config_revision)?;
    write_text(writer, &proof.startup_attempt_id)?;
    write_u64(writer, proof.readiness_generation)?;
    write_text(writer, &proof.superseding_policy_revision)?;
    write_text(writer, &proof.superseding_allocation_revision)?;
    write_text(writer, &proof.superseding_config_revision)?;
    write_text(writer, &proof.superseding_startup_attempt_id)?;
    write_u64(writer, proof.superseding_readiness_generation)?;
    write_text(writer, &proof.no_exposure_checkpoint_id)?;
    write_u64(writer, proof.no_exposure_checkpoint_revision)?;
    write_u64(writer, proof.no_exposure_checkpoint_fence)?;
    write_raw(writer, proof.terminal_result_blake3.as_ref())
}

fn encode_durable_proof(
    writer: &mut BoundedCanonicalWriter,
    proof: &DurableConsumerCancelledProofV1,
    context: &DurableConsumerContextV1,
    authority: &ObjectStoreResultAckAuthority<'_>,
    limits: &ResultDiscardLimits,
) -> Result<(), ResultDiscardError> {
    if proof.consumer_kind != context.consumer_kind
        || proof.authenticated_scope != context.authenticated_scope
        || proof.operation_id != context.operation_id
        || proof.checkpoint_revision != context.checkpoint_revision
        || proof.checkpoint_fence != context.checkpoint_fence
        || proof.terminal_result_blake3.as_ref()
            != authority.terminal_result.canonical_result_blake3()
        || proof.disposition_checkpoint_revision == 0
        || proof.disposition_checkpoint_fence == 0
        || proof.no_exposure_checkpoint_revision == 0
        || proof.no_exposure_checkpoint_fence == 0
        || !lex_greater(
            proof.disposition_checkpoint_revision,
            proof.disposition_checkpoint_fence,
            proof.checkpoint_revision,
            proof.checkpoint_fence,
        )
        || proof.disposition_checkpoint_fence < proof.checkpoint_fence
        || lex_less(
            proof.no_exposure_checkpoint_revision,
            proof.no_exposure_checkpoint_fence,
            proof.disposition_checkpoint_revision,
            proof.disposition_checkpoint_fence,
        )
    {
        return Err(ResultDiscardError::InvalidProof);
    }
    validate_text(&proof.operation_id, limits.max_operation_id_bytes)
        .map_err(|_| ResultDiscardError::InvalidProof)?;
    validate_text(
        &proof.disposition_checkpoint_id,
        limits.max_checkpoint_id_bytes,
    )
    .map_err(|_| ResultDiscardError::InvalidProof)?;
    validate_text(
        &proof.no_exposure_checkpoint_id,
        limits.max_checkpoint_id_bytes,
    )
    .map_err(|_| ResultDiscardError::InvalidProof)?;

    let consumer_kind = closed_consumer_kind(proof.consumer_kind)?;
    let cancellation_kind = closed_cancellation_kind(proof.cancellation_kind)?;
    match cancellation_kind {
        DurableConsumerCancellationKindV1::DurableConsumerCancellationKindCancelled => {
            if proof.superseding_operation_id.is_some() {
                return Err(ResultDiscardError::InvalidProof);
            }
        }
        DurableConsumerCancellationKindV1::DurableConsumerCancellationKindSuperseded => {
            let Some(successor) = proof.superseding_operation_id.as_deref() else {
                return Err(ResultDiscardError::InvalidProof);
            };
            validate_text(successor, limits.max_operation_id_bytes)
                .map_err(|_| ResultDiscardError::InvalidProof)?;
            if successor == proof.operation_id {
                return Err(ResultDiscardError::InvalidProof);
            }
        }
        DurableConsumerCancellationKindV1::DurableConsumerCancellationKindUnspecified => {
            return Err(ResultDiscardError::InvalidProof);
        }
    }

    write_u32(writer, 22)?;
    write_u32(writer, consumer_kind as u32)?;
    write_text(writer, &proof.authenticated_scope)?;
    write_text(writer, &proof.operation_id)?;
    write_u64(writer, proof.checkpoint_revision)?;
    write_u64(writer, proof.checkpoint_fence)?;
    write_u32(writer, cancellation_kind as u32)?;
    write_text(writer, &proof.disposition_checkpoint_id)?;
    write_u64(writer, proof.disposition_checkpoint_revision)?;
    write_u64(writer, proof.disposition_checkpoint_fence)?;
    write_optional_text(writer, proof.superseding_operation_id.as_deref())?;
    write_text(writer, &proof.no_exposure_checkpoint_id)?;
    write_u64(writer, proof.no_exposure_checkpoint_revision)?;
    write_u64(writer, proof.no_exposure_checkpoint_fence)?;
    write_raw(writer, proof.terminal_result_blake3.as_ref())
}

fn closed_supersession_kind(
    raw: i32,
) -> Result<FragmentLifecycleSupersessionKindV1, ResultDiscardError> {
    match FragmentLifecycleSupersessionKindV1::try_from(raw) {
        Ok(kind @ FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindSuccessor)
        | Ok(kind @ FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindRemoved)
        | Ok(
            kind
            @ FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindAssociationTombstoned,
        )
        | Ok(
            kind
            @ FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindRepositoryTombstoned,
        ) => Ok(kind),
        Ok(FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindUnspecified)
        | Err(_) => Err(ResultDiscardError::InvalidProof),
    }
}

fn closed_consumer_kind(raw: i32) -> Result<DurableConsumerKindV1, ResultDiscardError> {
    match DurableConsumerKindV1::try_from(raw) {
        Ok(kind @ DurableConsumerKindV1::DurableConsumerKindJob)
        | Ok(kind @ DurableConsumerKindV1::DurableConsumerKindOperator)
        | Ok(kind @ DurableConsumerKindV1::DurableConsumerKindMigrator) => Ok(kind),
        Ok(DurableConsumerKindV1::DurableConsumerKindUnspecified) | Err(_) => {
            Err(ResultDiscardError::InvalidProof)
        }
    }
}

fn closed_cancellation_kind(
    raw: i32,
) -> Result<DurableConsumerCancellationKindV1, ResultDiscardError> {
    match DurableConsumerCancellationKindV1::try_from(raw) {
        Ok(kind @ DurableConsumerCancellationKindV1::DurableConsumerCancellationKindCancelled)
        | Ok(kind @ DurableConsumerCancellationKindV1::DurableConsumerCancellationKindSuperseded) => {
            Ok(kind)
        }
        Ok(DurableConsumerCancellationKindV1::DurableConsumerCancellationKindUnspecified)
        | Err(_) => Err(ResultDiscardError::InvalidProof),
    }
}

fn lex_greater(next_revision: u64, next_fence: u64, prior_revision: u64, prior_fence: u64) -> bool {
    next_revision > prior_revision || (next_revision == prior_revision && next_fence > prior_fence)
}

fn lex_less(next_revision: u64, next_fence: u64, prior_revision: u64, prior_fence: u64) -> bool {
    next_revision < prior_revision || (next_revision == prior_revision && next_fence < prior_fence)
}

fn write_raw(writer: &mut BoundedCanonicalWriter, value: &[u8]) -> Result<(), ResultDiscardError> {
    writer
        .raw(value)
        .map_err(|_| ResultDiscardError::PreimageTooLarge)
}

fn write_u32(writer: &mut BoundedCanonicalWriter, value: u32) -> Result<(), ResultDiscardError> {
    writer
        .u32(value)
        .map_err(|_| ResultDiscardError::PreimageTooLarge)
}

fn write_u64(writer: &mut BoundedCanonicalWriter, value: u64) -> Result<(), ResultDiscardError> {
    writer
        .u64(value)
        .map_err(|_| ResultDiscardError::PreimageTooLarge)
}

fn write_text(writer: &mut BoundedCanonicalWriter, value: &str) -> Result<(), ResultDiscardError> {
    writer
        .text(value)
        .map_err(|_| ResultDiscardError::PreimageTooLarge)
}

fn write_optional_text(
    writer: &mut BoundedCanonicalWriter,
    value: Option<&str>,
) -> Result<(), ResultDiscardError> {
    writer
        .u8(u8::from(value.is_some()))
        .map_err(|_| ResultDiscardError::PreimageTooLarge)?;
    if let Some(value) = value {
        write_text(writer, value)?;
    }
    Ok(())
}

fn write_optional_u64(
    writer: &mut BoundedCanonicalWriter,
    value: Option<u64>,
) -> Result<(), ResultDiscardError> {
    writer
        .u8(u8::from(value.is_some()))
        .map_err(|_| ResultDiscardError::PreimageTooLarge)?;
    if let Some(value) = value {
        write_u64(writer, value)?;
    }
    Ok(())
}

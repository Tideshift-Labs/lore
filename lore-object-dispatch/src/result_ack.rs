// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Pure result-ACK fingerprint and receipt contracts.
//!
//! These functions validate caller-supplied ACKs against stored request and terminal-result
//! authority. They do not read durable state, purge payloads, or authorize provider traffic.

use std::fmt;

use lore_proto::lore::object_dispatch::v1::DurableConsumerContextV1;
use lore_proto::lore::object_dispatch::v1::DurableConsumerKindV1;
use lore_proto::lore::object_dispatch::v1::DurableConsumerResultAckProofV1;
use lore_proto::lore::object_dispatch::v1::FragmentLifecycleConsumerContextV1;
use lore_proto::lore::object_dispatch::v1::FragmentLifecycleResultAckProofV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultAckReceiptV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultAckStateV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultAckV1;
use lore_proto::lore::object_dispatch::v1::ResultConsumerContextV1;
use lore_proto::lore::object_dispatch::v1::StartupAdmissionConsumerContextV1;
use lore_proto::lore::object_dispatch::v1::StartupAdmissionResultAckProofV1;
use lore_proto::lore::object_dispatch::v1::object_store_request_v1;
use lore_proto::lore::object_dispatch::v1::object_store_result_ack_v1;
use lore_proto::lore::object_dispatch::v1::object_store_terminal_result_v1;
use lore_proto::lore::object_dispatch::v1::result_consumer_context_v1;
use thiserror::Error;

use crate::contract::BoundedCanonicalWriter;
use crate::contract::canonical_uuid_v7_timestamp;
use crate::contract::validate_canonical_text;
use crate::request::AuthenticatedConsumerIdentity;
use crate::request::RequestIdentityLimits;
use crate::request::validate_result_consumer_context;
use crate::terminal_result::CanonicalTerminalResult;

const ACK_FINGERPRINT_DOMAIN: &[u8] = b"object-dispatch-ack-v1\0";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResultAckLimits {
    pub identity: RequestIdentityLimits,
    pub max_terminal_result_id_bytes: u32,
    pub max_result_handle_bytes: u32,
    pub max_fingerprint_preimage_bytes: u32,
}

pub struct ObjectStoreResultAckAuthority<'a> {
    pub operation: &'a object_store_request_v1::Operation,
    pub consumer_context: &'a ResultConsumerContextV1,
    pub authenticated_identity: &'a AuthenticatedConsumerIdentity,
    pub protocol_revision: &'a str,
    pub provider_boundary_id: &'a str,
    pub authenticated_cell_id: &'a str,
    pub authenticated_tenant_id: &'a str,
    pub logical_request_id: &'a str,
    pub attempt_id: &'a str,
    pub terminal_result: &'a CanonicalTerminalResult,
}

#[derive(Clone, PartialEq)]
pub struct ValidatedObjectStoreResultAck {
    ack: ObjectStoreResultAckV1,
    canonical_ack_bytes: Vec<u8>,
    ack_fingerprint: [u8; 32],
}

impl ValidatedObjectStoreResultAck {
    pub fn ack(&self) -> &ObjectStoreResultAckV1 {
        &self.ack
    }

    pub fn canonical_ack_bytes(&self) -> &[u8] {
        &self.canonical_ack_bytes
    }

    pub fn ack_fingerprint(&self) -> &[u8; 32] {
        &self.ack_fingerprint
    }
}

impl fmt::Debug for ValidatedObjectStoreResultAck {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedObjectStoreResultAck")
            .field("ack", &"[REDACTED]")
            .field("canonical_ack_bytes", &"[REDACTED]")
            .field("ack_fingerprint", &"[REDACTED]")
            .finish()
    }
}

pub struct ResultAckReceiptInput<'a> {
    pub terminal_result_id: &'a str,
    pub ack_fingerprint: &'a [u8],
    pub acked_at_unix_ms: i64,
    pub payload_purge_after_unix_ms: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum ResultAckError {
    #[error("object-store result ACK limits are invalid")]
    InvalidLimits,
    #[error("object-store result ACK text is not canonical and bounded")]
    InvalidCanonicalText,
    #[error("object-store result ACK UUID is not canonical RFC 9562 UUIDv7")]
    InvalidUuidV7,
    #[error("object-store result ACK does not match stored authority")]
    AuthorityMismatch,
    #[error("object-store result ACK consumer context is invalid")]
    InvalidConsumerContext,
    #[error("object-store result ACK terminal tuple is invalid")]
    TerminalResultMismatch,
    #[error("object-store result ACK byte-result handle is invalid")]
    InvalidByteResultHandle,
    #[error("object-store result ACK proof is invalid")]
    InvalidProof,
    #[error("object-store result ACK fingerprint preimage exceeds its bound")]
    PreimageTooLarge,
    #[error("object-store result ACK receipt is invalid")]
    InvalidReceipt,
}

pub fn validate_object_store_result_ack(
    input: &ObjectStoreResultAckV1,
    authority: &ObjectStoreResultAckAuthority<'_>,
    limits: &ResultAckLimits,
) -> Result<ValidatedObjectStoreResultAck, ResultAckError> {
    validate_limits(limits)?;
    validate_result_consumer_context(
        authority.operation,
        authority.consumer_context,
        authority.authenticated_identity,
        &limits.identity,
    )
    .map_err(|_| ResultAckError::InvalidConsumerContext)?;

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
        validate_text(actual, limits.identity.max_identity_bytes)?;
        if actual != expected {
            return Err(ResultAckError::AuthorityMismatch);
        }
    }
    canonical_uuid_v7_timestamp(&input.logical_request_id)
        .map_err(|_| ResultAckError::InvalidUuidV7)?;
    canonical_uuid_v7_timestamp(&input.attempt_id).map_err(|_| ResultAckError::InvalidUuidV7)?;

    let stored_result = authority.terminal_result.result();
    validate_text(
        &input.terminal_result_id,
        limits.max_terminal_result_id_bytes,
    )?;
    if input.terminal_result_id != stored_result.terminal_result_id
        || input.canonical_result_size != authority.terminal_result.canonical_result_size()
        || input.canonical_result_blake3.as_ref()
            != authority.terminal_result.canonical_result_blake3()
    {
        return Err(ResultAckError::TerminalResultMismatch);
    }
    let expected_handle = match stored_result.result.as_ref() {
        Some(object_store_terminal_result_v1::Result::ByteResult(result)) => {
            Some(result.handle.as_str())
        }
        _ => None,
    };
    if input.byte_result_handle.as_deref() != expected_handle {
        return Err(ResultAckError::InvalidByteResultHandle);
    }
    if let Some(handle) = input.byte_result_handle.as_deref() {
        validate_text(handle, limits.max_result_handle_bytes)
            .map_err(|_| ResultAckError::InvalidByteResultHandle)?;
    }

    let mut writer = BoundedCanonicalWriter::new(limits.max_fingerprint_preimage_bytes)
        .map_err(|_| ResultAckError::InvalidLimits)?;
    write_raw(&mut writer, ACK_FINGERPRINT_DOMAIN)?;
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
    encode_proof(
        &mut writer,
        input.proof.as_ref(),
        authority.consumer_context,
        authority.terminal_result.canonical_result_blake3(),
    )?;

    let canonical_ack_bytes = writer.finish();
    let ack_fingerprint = *blake3::hash(&canonical_ack_bytes).as_bytes();
    Ok(ValidatedObjectStoreResultAck {
        ack: input.clone(),
        canonical_ack_bytes,
        ack_fingerprint,
    })
}

pub fn build_object_store_result_ack_receipt(
    input: &ResultAckReceiptInput<'_>,
    limits: &ResultAckLimits,
) -> Result<ObjectStoreResultAckReceiptV1, ResultAckError> {
    validate_limits(limits)?;
    validate_text(
        input.terminal_result_id,
        limits.max_terminal_result_id_bytes,
    )?;
    if input.ack_fingerprint.len() != 32
        || input.acked_at_unix_ms < 0
        || input
            .payload_purge_after_unix_ms
            .is_some_and(|purge| purge < input.acked_at_unix_ms)
    {
        return Err(ResultAckError::InvalidReceipt);
    }
    Ok(ObjectStoreResultAckReceiptV1 {
        state: ObjectStoreResultAckStateV1::ObjectStoreResultAckStateAcked as i32,
        terminal_result_id: input.terminal_result_id.to_owned(),
        ack_fingerprint: input.ack_fingerprint.to_vec().into(),
        acked_at_unix_ms: input.acked_at_unix_ms,
        payload_purge_after_unix_ms: input.payload_purge_after_unix_ms,
    })
}

fn validate_limits(limits: &ResultAckLimits) -> Result<(), ResultAckError> {
    if [
        limits.identity.max_identity_bytes,
        limits.identity.max_authenticated_scope_bytes,
        limits.max_terminal_result_id_bytes,
        limits.max_result_handle_bytes,
        limits.max_fingerprint_preimage_bytes,
    ]
    .contains(&0)
    {
        return Err(ResultAckError::InvalidLimits);
    }
    Ok(())
}

fn validate_text(value: &str, maximum: u32) -> Result<(), ResultAckError> {
    validate_canonical_text(value, maximum).map_err(|_| ResultAckError::InvalidCanonicalText)
}

fn encode_proof(
    writer: &mut BoundedCanonicalWriter,
    proof: Option<&object_store_result_ack_v1::Proof>,
    context: &ResultConsumerContextV1,
    terminal_digest: &[u8; 32],
) -> Result<(), ResultAckError> {
    let consumer = context
        .consumer
        .as_ref()
        .ok_or(ResultAckError::InvalidConsumerContext)?;
    let proof = proof.ok_or(ResultAckError::InvalidProof)?;
    match proof {
        object_store_result_ack_v1::Proof::FragmentLifecycle(proof) => match consumer {
            result_consumer_context_v1::Consumer::FragmentLifecycle(context) => {
                encode_fragment_proof(writer, proof, context, terminal_digest)
            }
            result_consumer_context_v1::Consumer::StartupAdmission(_)
            | result_consumer_context_v1::Consumer::DurableConsumer(_) => {
                Err(ResultAckError::InvalidProof)
            }
        },
        object_store_result_ack_v1::Proof::StartupAdmission(proof) => match consumer {
            result_consumer_context_v1::Consumer::StartupAdmission(context) => {
                encode_startup_proof(writer, proof, context, terminal_digest)
            }
            result_consumer_context_v1::Consumer::FragmentLifecycle(_)
            | result_consumer_context_v1::Consumer::DurableConsumer(_) => {
                Err(ResultAckError::InvalidProof)
            }
        },
        object_store_result_ack_v1::Proof::DurableConsumer(proof) => match consumer {
            result_consumer_context_v1::Consumer::DurableConsumer(context) => {
                encode_durable_proof(writer, proof, context, terminal_digest)
            }
            result_consumer_context_v1::Consumer::FragmentLifecycle(_)
            | result_consumer_context_v1::Consumer::StartupAdmission(_) => {
                Err(ResultAckError::InvalidProof)
            }
        },
    }
}

fn encode_fragment_proof(
    writer: &mut BoundedCanonicalWriter,
    proof: &FragmentLifecycleResultAckProofV1,
    context: &FragmentLifecycleConsumerContextV1,
    terminal_digest: &[u8; 32],
) -> Result<(), ResultAckError> {
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
        || proof.terminal_result_blake3.as_ref() != terminal_digest
    {
        return Err(ResultAckError::InvalidProof);
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
    write_raw(writer, proof.terminal_result_blake3.as_ref())
}

fn encode_startup_proof(
    writer: &mut BoundedCanonicalWriter,
    proof: &StartupAdmissionResultAckProofV1,
    context: &StartupAdmissionConsumerContextV1,
    terminal_digest: &[u8; 32],
) -> Result<(), ResultAckError> {
    if proof.policy_revision != context.policy_revision
        || proof.allocation_revision != context.allocation_revision
        || proof.config_revision != context.config_revision
        || proof.startup_attempt_id != context.startup_attempt_id
        || proof.readiness_generation != context.readiness_generation
        || proof.terminal_result_blake3.as_ref() != terminal_digest
    {
        return Err(ResultAckError::InvalidProof);
    }
    write_u32(writer, 21)?;
    write_text(writer, &proof.policy_revision)?;
    write_text(writer, &proof.allocation_revision)?;
    write_text(writer, &proof.config_revision)?;
    write_text(writer, &proof.startup_attempt_id)?;
    write_u64(writer, proof.readiness_generation)?;
    write_raw(writer, proof.terminal_result_blake3.as_ref())
}

fn encode_durable_proof(
    writer: &mut BoundedCanonicalWriter,
    proof: &DurableConsumerResultAckProofV1,
    context: &DurableConsumerContextV1,
    terminal_digest: &[u8; 32],
) -> Result<(), ResultAckError> {
    if proof.consumer_kind != context.consumer_kind
        || proof.authenticated_scope != context.authenticated_scope
        || proof.operation_id != context.operation_id
        || proof.checkpoint_revision != context.checkpoint_revision
        || proof.checkpoint_fence != context.checkpoint_fence
        || proof.terminal_result_blake3.as_ref() != terminal_digest
    {
        return Err(ResultAckError::InvalidProof);
    }
    let kind = match DurableConsumerKindV1::try_from(proof.consumer_kind) {
        Ok(DurableConsumerKindV1::DurableConsumerKindJob) => 1,
        Ok(DurableConsumerKindV1::DurableConsumerKindOperator) => 2,
        Ok(DurableConsumerKindV1::DurableConsumerKindMigrator) => 3,
        Ok(DurableConsumerKindV1::DurableConsumerKindUnspecified) | Err(_) => {
            return Err(ResultAckError::InvalidProof);
        }
    };
    write_u32(writer, 22)?;
    write_u32(writer, kind)?;
    write_text(writer, &proof.authenticated_scope)?;
    write_text(writer, &proof.operation_id)?;
    write_u64(writer, proof.checkpoint_revision)?;
    write_u64(writer, proof.checkpoint_fence)?;
    write_raw(writer, proof.terminal_result_blake3.as_ref())
}

fn write_raw(writer: &mut BoundedCanonicalWriter, value: &[u8]) -> Result<(), ResultAckError> {
    writer
        .raw(value)
        .map_err(|_| ResultAckError::PreimageTooLarge)
}

fn write_u32(writer: &mut BoundedCanonicalWriter, value: u32) -> Result<(), ResultAckError> {
    writer
        .u32(value)
        .map_err(|_| ResultAckError::PreimageTooLarge)
}

fn write_u64(writer: &mut BoundedCanonicalWriter, value: u64) -> Result<(), ResultAckError> {
    writer
        .u64(value)
        .map_err(|_| ResultAckError::PreimageTooLarge)
}

fn write_text(writer: &mut BoundedCanonicalWriter, value: &str) -> Result<(), ResultAckError> {
    writer
        .text(value)
        .map_err(|_| ResultAckError::PreimageTooLarge)
}

fn write_optional_text(
    writer: &mut BoundedCanonicalWriter,
    value: Option<&str>,
) -> Result<(), ResultAckError> {
    writer
        .u8(u8::from(value.is_some()))
        .map_err(|_| ResultAckError::PreimageTooLarge)?;
    if let Some(value) = value {
        write_text(writer, value)?;
    }
    Ok(())
}

fn write_optional_u64(
    writer: &mut BoundedCanonicalWriter,
    value: Option<u64>,
) -> Result<(), ResultAckError> {
    writer
        .u8(u8::from(value.is_some()))
        .map_err(|_| ResultAckError::PreimageTooLarge)?;
    if let Some(value) = value {
        write_u64(writer, value)?;
    }
    Ok(())
}

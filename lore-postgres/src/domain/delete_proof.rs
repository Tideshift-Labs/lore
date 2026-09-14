// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-029 delete proofs. The coordinator loads receipt evidence under its lock.

use tokio_postgres::Transaction;

use super::errors::DomainError;
use super::receipts::OperationBinding;
use super::receipts::ReceiptKey;

/// Persisted receipt fields used by the frozen proof encoding.
pub struct DeleteProofReceipt<'a> {
    pub key: &'a ReceiptKey,
    pub binding: &'a OperationBinding,
    pub client_attempt_id: Option<&'a [u8]>,
}

fn fixed(bytes: &[u8], width: usize) -> Result<(), DomainError> {
    if bytes.len() != width {
        return Err(DomainError::InvalidInput(format!(
            "delete proof requires {width} bytes, got {}",
            bytes.len()
        )));
    }
    Ok(())
}

fn frame(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), DomainError> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| DomainError::InvalidInput("delete proof field exceeds u32".into()))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn prefix(domain: &[u8], receipt: &DeleteProofReceipt<'_>) -> Result<Vec<u8>, DomainError> {
    let mut out = domain.to_vec();
    let key = receipt.key;
    let binding = receipt.binding;
    fixed(&binding.fingerprint, 32)?;
    fixed(&binding.canonical_intent_digest, 32)?;
    for bytes in [
        key.verified_issuer.as_bytes(),
        key.authenticated_subject.as_bytes(),
        &key.tenant_scope_key,
        key.operation_id.as_bytes(),
        binding.method.as_bytes(),
        &binding.scope,
    ] {
        frame(&mut out, bytes)?;
    }
    let version = u32::try_from(binding.fingerprint_version).map_err(|_| {
        DomainError::InvalidInput("negative delete proof fingerprint version".into())
    })?;
    out.extend_from_slice(&version.to_be_bytes());
    frame(&mut out, &binding.fingerprint)?;
    frame(&mut out, &binding.canonical_intent_digest)?;
    match receipt.client_attempt_id {
        None => out.push(0),
        Some(attempt) => {
            fixed(attempt, 16)?;
            out.push(1);
            out.extend_from_slice(attempt);
        }
    }
    Ok(out)
}

/// Exact unkeyed BLAKE3 preimage, also exercised against independent goldens.
pub fn repository_delete_preimage(
    receipt: &DeleteProofReceipt<'_>,
    repository_id: &[u8],
    prior: u64,
    committed: u64,
) -> Result<Vec<u8>, DomainError> {
    fixed(repository_id, 16)?;
    let mut out = prefix(b"lore-repository-delete-proof-v1\0", receipt)?;
    out.extend_from_slice(repository_id);
    out.extend_from_slice(&prior.to_be_bytes());
    out.extend_from_slice(&committed.to_be_bytes());
    Ok(out)
}

/// Exact branch proof preimage; its suffix is taken from the locked branch.
pub fn branch_delete_preimage(
    receipt: &DeleteProofReceipt<'_>,
    repository_id: &[u8],
    branch_id: &[u8],
    repository_generation: u64,
    prior: u64,
    committed: u64,
    final_latest_hash: &[u8],
) -> Result<Vec<u8>, DomainError> {
    fixed(repository_id, 16)?;
    fixed(branch_id, 16)?;
    fixed(final_latest_hash, 32)?;
    let mut out = prefix(b"lore-branch-delete-proof-v1\0", receipt)?;
    out.extend_from_slice(repository_id);
    out.extend_from_slice(branch_id);
    out.extend_from_slice(&repository_generation.to_be_bytes());
    out.extend_from_slice(&prior.to_be_bytes());
    out.extend_from_slice(&committed.to_be_bytes());
    out.extend_from_slice(final_latest_hash);
    Ok(out)
}

/// Load the already-locked receipt, never a replacement attempt from headers.
pub(crate) async fn persisted_receipt(
    tx: &Transaction<'_>,
    key: &ReceiptKey,
) -> Result<(OperationBinding, Option<Vec<u8>>), DomainError> {
    let row = tx.query_one("SELECT method, scope, fingerprint_version, fingerprint, canonical_intent_digest, client_attempt_id FROM lore_domain_operation_receipts WHERE verified_issuer=$1 AND authenticated_subject=$2 AND tenant_scope_key=$3 AND operation_id=$4", &[&key.verified_issuer, &key.authenticated_subject, &key.tenant_scope_key, &key.operation_id.as_bytes().as_slice()]).await.map_err(|e| DomainError::from_pg("delete proof receipt", e))?;
    Ok((
        OperationBinding {
            method: row.get("method"),
            scope: row.get("scope"),
            fingerprint_version: row.get("fingerprint_version"),
            fingerprint: row.get("fingerprint"),
            canonical_intent_digest: row.get("canonical_intent_digest"),
        },
        row.get("client_attempt_id"),
    ))
}

pub(crate) fn generation(value: i64) -> Result<u64, DomainError> {
    u64::try_from(value)
        .map_err(|_| DomainError::Internal("negative stored delete generation".into()))
}

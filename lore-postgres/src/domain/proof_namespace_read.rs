// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Read-only proof namespace authority, separate from mutation admission.

use async_trait::async_trait;

use super::errors::DomainError;
use super::maintenance::ProofNamespaceKey;
use super::store::PostgresDomainStore;

#[derive(Debug, Clone)]
pub struct ProofNamespaceStateInput {
    pub key: ProofNamespaceKey,
    pub protocol_revision: i32,
    pub namespace_epoch: Vec<u8>,
    pub namespace_claim_revision: i64,
    pub namespace_claim_nonce: Vec<u8>,
}

/// Only quiescent results carry retirement evidence. Absence grants no release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProofNamespaceState {
    MatchedQuiescent {
        quota_revision: u64,
        final_high_water: u64,
        final_range_set_digest: Vec<u8>,
    },
    MatchedNotQuiescent {
        quota_revision: u64,
    },
    Absent,
    Mismatch,
}

#[async_trait]
pub trait ProofNamespaceStateReader: Send + Sync {
    async fn proof_namespace_state_get(
        &self,
        input: &ProofNamespaceStateInput,
    ) -> Result<ProofNamespaceState, DomainError>;
}

#[async_trait]
impl ProofNamespaceStateReader for PostgresDomainStore {
    async fn proof_namespace_state_get(
        &self,
        input: &ProofNamespaceStateInput,
    ) -> Result<ProofNamespaceState, DomainError> {
        let mut client = self
            .pool()
            .get()
            .await
            .map_err(|e| DomainError::from_pool("proof namespace read", e))?;
        let tx = client
            .build_transaction()
            .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
            .read_only(true)
            .start()
            .await
            .map_err(|e| DomainError::from_pg("proof namespace snapshot", e))?;
        tx.batch_execute("SET LOCAL statement_timeout = '5s'")
            .await
            .map_err(|e| DomainError::from_pg("proof namespace read bound", e))?;
        let result = super::maintenance::proof_namespace_state_get(&tx, input).await?;
        tx.commit()
            .await
            .map_err(|e| DomainError::from_pg("proof namespace read complete", e))?;
        Ok(result)
    }
}

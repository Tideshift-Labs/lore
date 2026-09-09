// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::time::SystemTime;

use lore_postgres::domain::coordinator::*;
use lore_postgres::domain::maintenance::*;
use lore_postgres::domain::receipts::*;

use super::*;

pub(super) struct PausedStore {
    pub inner: Arc<dyn DomainTransactionStore>,
    pub reached: tokio::sync::Notify,
    pub resume: tokio::sync::Notify,
    pub captured: StdMutex<Option<BranchPushCommitInput>>,
    pub pause: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl DomainTransactionStore for PausedStore {
    async fn domain_operation_clock_get(&self) -> Result<SystemTime, DomainError> {
        self.inner.domain_operation_clock_get().await
    }
    async fn domain_operation_prepare(
        &self,
        key: &ReceiptKey,
        binding: &OperationBinding,
        witness: Option<&AuthorizationWitness>,
        client_attempt_id: Option<uuid::Uuid>,
    ) -> Result<PrepareResult, DomainError> {
        self.inner
            .domain_operation_prepare(key, binding, witness, client_attempt_id)
            .await
    }
    async fn domain_operation_prepare_direct(
        &self,
        key: &ReceiptKey,
        binding: &OperationBinding,
        evidence: &lore_postgres::domain::receipts::DirectAuthorizationEvidence,
        client_attempt_id: Option<uuid::Uuid>,
    ) -> Result<PrepareResult, DomainError> {
        self.inner
            .domain_operation_prepare_direct(key, binding, evidence, client_attempt_id)
            .await
    }
    async fn domain_operation_receipt_get(
        &self,
        key: &ReceiptKey,
        binding: &OperationBinding,
    ) -> Result<ReceiptLookup, DomainError> {
        self.inner.domain_operation_receipt_get(key, binding).await
    }
    async fn domain_operation_attempt_receipt_get(
        &self,
        verified_issuer: &str,
        authenticated_subject: &str,
        client_attempt_id: &uuid::Uuid,
    ) -> Result<AttemptReceipt, DomainError> {
        self.inner
            .domain_operation_attempt_receipt_get(
                verified_issuer,
                authenticated_subject,
                client_attempt_id,
            )
            .await
    }
    async fn domain_operation_verified_stale_finalize(
        &self,
        input: &VerifiedStaleFinalizeInput,
    ) -> Result<VerifiedStaleFinalizeResult, DomainError> {
        self.inner
            .domain_operation_verified_stale_finalize(input)
            .await
    }
    async fn domain_operation_terminal_status_attach(
        &self,
        input: &TerminalStatusAttachInput,
    ) -> Result<TerminalStatusAttachmentAck, DomainError> {
        self.inner
            .domain_operation_terminal_status_attach(input)
            .await
    }
    async fn domain_operation_proof_namespace_materialize(
        &self,
        input: &ProofNamespaceMaterializeInput,
    ) -> Result<ProofNamespaceMaterializeReceipt, DomainError> {
        self.inner
            .domain_operation_proof_namespace_materialize(input)
            .await
    }
    async fn domain_operation_proof_namespace_retire(
        &self,
        input: &ProofNamespaceRetireInput,
    ) -> Result<ProofNamespaceRetireAck, DomainError> {
        self.inner
            .domain_operation_proof_namespace_retire(input)
            .await
    }
    async fn repository_snapshot(
        &self,
        repository_id: &[u8],
    ) -> Result<Option<RepositorySnapshot>, DomainError> {
        self.inner.repository_snapshot(repository_id).await
    }
    async fn branch_snapshot(
        &self,
        repository_id: &[u8],
        branch_id: &[u8],
    ) -> Result<Option<BranchSnapshot>, DomainError> {
        self.inner.branch_snapshot(repository_id, branch_id).await
    }
    async fn repository_create(
        &self,
        operation: &GovernedOperation,
        input: &RepositoryCreateInput,
    ) -> Result<MutationResult, DomainError> {
        self.inner.repository_create(operation, input).await
    }
    async fn repository_delete(
        &self,
        operation: &GovernedOperation,
        input: &RepositoryDeleteInput,
    ) -> Result<MutationResult, DomainError> {
        self.inner.repository_delete(operation, input).await
    }
    async fn branch_create_terminal_replay(
        &self,
        key: &ReceiptKey,
        binding: &OperationBinding,
    ) -> Result<Option<BranchCreateResult>, DomainError> {
        self.inner.branch_create_terminal_replay(key, binding).await
    }
    async fn branch_create_replay(
        &self,
        operation: &GovernedOperation,
    ) -> Result<Option<BranchCreateResult>, DomainError> {
        self.inner.branch_create_replay(operation).await
    }
    async fn branch_create(
        &self,
        operation: &GovernedOperation,
        input: &BranchCreateInput,
    ) -> Result<BranchCreateResult, DomainError> {
        self.inner.branch_create(operation, input).await
    }
    async fn branch_delete(
        &self,
        operation: &GovernedOperation,
        input: &BranchDeleteInput,
    ) -> Result<MutationResult, DomainError> {
        self.inner.branch_delete(operation, input).await
    }
    async fn metadata_compare_and_swap(
        &self,
        operation: &GovernedOperation,
        input: &MetadataCasInput,
    ) -> Result<MutationResult, DomainError> {
        self.inner.metadata_compare_and_swap(operation, input).await
    }
    async fn branch_push_commit(
        &self,
        operation: &GovernedOperation,
        input: &BranchPushCommitInput,
    ) -> Result<MutationResult, DomainError> {
        *self.captured.lock().unwrap() = Some(input.clone());
        if self.pause.load(std::sync::atomic::Ordering::SeqCst) {
            self.reached.notify_one();
            self.resume.notified().await;
        }
        self.inner.branch_push_commit(operation, input).await
    }
    async fn begin_obliterate(
        &self,
        operation: &GovernedOperation,
        repository_id: &[u8],
        event: Option<&PendingEvent>,
    ) -> Result<MutationResult, DomainError> {
        self.inner
            .begin_obliterate(operation, repository_id, event)
            .await
    }
}

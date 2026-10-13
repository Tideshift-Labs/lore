// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! WP-120: a `DomainTransactionStore` that answers only repository and branch
//! snapshots, with scripted generations. The refresh-read handler tests use it
//! to prove a generation is attached, passed through and omitted without a
//! Postgres database; every other method panics so a handler that wanders past
//! the snapshot read fails loudly.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use async_trait::async_trait;
use lore_postgres::domain::coordinator::BranchDeleteInput;
use lore_postgres::domain::coordinator::BranchPushCommitInput;
use lore_postgres::domain::coordinator::BranchSnapshot;
use lore_postgres::domain::coordinator::DomainTransactionStore;
use lore_postgres::domain::coordinator::GovernedOperation;
use lore_postgres::domain::coordinator::MetadataCasInput;
use lore_postgres::domain::coordinator::MutationResult;
use lore_postgres::domain::coordinator::PendingEvent;
use lore_postgres::domain::coordinator::RepositoryCreateInput;
use lore_postgres::domain::coordinator::RepositoryDeleteInput;
use lore_postgres::domain::coordinator::RepositorySnapshot;
use lore_postgres::domain::errors::DomainError;
use lore_postgres::domain::errors::DomainOutcome;
use lore_postgres::domain::maintenance::ProofNamespaceMaterializeInput;
use lore_postgres::domain::maintenance::ProofNamespaceMaterializeReceipt;
use lore_postgres::domain::maintenance::ProofNamespaceRetireAck;
use lore_postgres::domain::maintenance::ProofNamespaceRetireInput;
use lore_postgres::domain::maintenance::TerminalStatusAttachInput;
use lore_postgres::domain::maintenance::TerminalStatusAttachmentAck;
use lore_postgres::domain::maintenance::VerifiedStaleFinalizeInput;
use lore_postgres::domain::maintenance::VerifiedStaleFinalizeResult;
use lore_postgres::domain::receipts::AuthorizationWitness;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptKey;
use lore_postgres::domain::receipts::ReceiptLookup;
use lore_server::domain::DomainContext;

/// Scripted snapshot answers plus read counters. `None` generations model an
/// absent row.
pub struct GenerationStore {
    pub repository_generation: Option<i64>,
    pub branch_generation: Option<i64>,
    pub repository_reads: AtomicUsize,
    pub branch_reads: AtomicUsize,
    /// When set, every snapshot read answers a transient store failure.
    fail_reads: bool,
    /// When set, every snapshot read is stamped on this shared sequence.
    log: Option<Arc<SequenceLog>>,
    /// Runs once, during the first snapshot read, before it answers. Lets a test move the
    /// name mapping between the handler's two resolves.
    on_first_read: Option<ReadHook>,
    hook_fired: AtomicBool,
}

/// An async side effect a [`GenerationStore`] runs during its first snapshot read.
pub type ReadHook = Arc<dyn Fn() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// A shared monotonic clock that stamps generation reads and projection
/// (mutable-store) loads, so a test can assert which came first.
#[derive(Default)]
pub struct SequenceLog {
    next: AtomicUsize,
    generation_reads: Mutex<Vec<usize>>,
    projection_loads: Mutex<Vec<usize>>,
}

impl SequenceLog {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn tick(&self) -> usize {
        self.next.fetch_add(1, Ordering::SeqCst)
    }

    fn record_generation_read(&self) {
        let stamp = self.tick();
        self.generation_reads
            .lock()
            .expect("sequence log lock")
            .push(stamp);
    }

    fn record_projection_load(&self) {
        let stamp = self.tick();
        self.projection_loads
            .lock()
            .expect("sequence log lock")
            .push(stamp);
    }

    /// Stamps of every generation read, in order.
    pub fn generation_reads(&self) -> Vec<usize> {
        self.generation_reads
            .lock()
            .expect("sequence log lock")
            .clone()
    }

    /// Stamps of every projection load, in order.
    pub fn projection_loads(&self) -> Vec<usize> {
        self.projection_loads
            .lock()
            .expect("sequence log lock")
            .clone()
    }

    /// Forget everything recorded so far (the clock keeps running).
    pub fn clear(&self) {
        self.generation_reads
            .lock()
            .expect("sequence log lock")
            .clear();
        self.projection_loads
            .lock()
            .expect("sequence log lock")
            .clear();
    }
}

/// A `MutableStore` that stamps every `load` on a [`SequenceLog`] and
/// delegates everything to the wrapped store. The handler's projection reads
/// (pointer and name lookups) all pass through `load`.
pub struct RecordingMutableStore {
    inner: Arc<dyn lore_storage::MutableStore>,
    log: Arc<SequenceLog>,
}

impl RecordingMutableStore {
    pub fn wrap(
        inner: Arc<dyn lore_storage::MutableStore>,
        log: Arc<SequenceLog>,
    ) -> Arc<dyn lore_storage::MutableStore> {
        Arc::new(Self { inner, log })
    }
}

#[async_trait]
impl lore_storage::MutableStore for RecordingMutableStore {
    async fn load(
        self: Arc<Self>,
        partition: lore_base::types::Partition,
        key: lore_base::types::Hash,
        key_type: lore_base::types::KeyType,
    ) -> Result<lore_base::types::Hash, lore_storage::StoreError> {
        self.log.record_projection_load();
        self.inner.clone().load(partition, key, key_type).await
    }

    async fn store(
        self: Arc<Self>,
        partition: lore_base::types::Partition,
        key: lore_base::types::Hash,
        value: lore_base::types::Hash,
        key_type: lore_base::types::KeyType,
    ) -> Result<(), lore_storage::StoreError> {
        self.inner
            .clone()
            .store(partition, key, value, key_type)
            .await
    }

    async fn compare_and_swap(
        self: Arc<Self>,
        partition: lore_base::types::Partition,
        key: lore_base::types::Hash,
        expected: lore_base::types::Hash,
        value: lore_base::types::Hash,
        key_type: lore_base::types::KeyType,
    ) -> Result<lore_base::types::Hash, lore_storage::StoreError> {
        self.inner
            .clone()
            .compare_and_swap(partition, key, expected, value, key_type)
            .await
    }

    async fn list(
        self: Arc<Self>,
        partition: lore_base::types::Partition,
        key_type: lore_base::types::KeyType,
    ) -> Result<lore_storage::KeyValueStream, lore_storage::StoreError> {
        self.inner.clone().list(partition, key_type).await
    }

    async fn flush(self: Arc<Self>, sync_data: bool) -> Result<(), lore_storage::StoreError> {
        self.inner.clone().flush(sync_data).await
    }
}

impl GenerationStore {
    pub fn new(repository_generation: Option<i64>, branch_generation: Option<i64>) -> Arc<Self> {
        Arc::new(Self {
            repository_generation,
            branch_generation,
            repository_reads: AtomicUsize::new(0),
            branch_reads: AtomicUsize::new(0),
            fail_reads: false,
            log: None,
            on_first_read: None,
            hook_fired: AtomicBool::new(false),
        })
    }

    /// A store that runs `hook` once, during its first snapshot read.
    pub fn with_read_hook(
        repository_generation: Option<i64>,
        branch_generation: Option<i64>,
        hook: ReadHook,
    ) -> Arc<Self> {
        Arc::new(Self {
            repository_generation,
            branch_generation,
            repository_reads: AtomicUsize::new(0),
            branch_reads: AtomicUsize::new(0),
            fail_reads: false,
            log: None,
            on_first_read: Some(hook),
            hook_fired: AtomicBool::new(false),
        })
    }

    /// A store whose every snapshot read is stamped on `log`.
    pub fn recording(
        repository_generation: Option<i64>,
        branch_generation: Option<i64>,
        log: Arc<SequenceLog>,
    ) -> Arc<Self> {
        Arc::new(Self {
            repository_generation,
            branch_generation,
            repository_reads: AtomicUsize::new(0),
            branch_reads: AtomicUsize::new(0),
            fail_reads: false,
            log: Some(log),
            on_first_read: None,
            hook_fired: AtomicBool::new(false),
        })
    }

    /// A store whose every snapshot read fails with a transient error.
    pub fn failing() -> Arc<Self> {
        Arc::new(Self {
            repository_generation: Some(1),
            branch_generation: Some(1),
            repository_reads: AtomicUsize::new(0),
            branch_reads: AtomicUsize::new(0),
            fail_reads: true,
            log: None,
            on_first_read: None,
            hook_fired: AtomicBool::new(false),
        })
    }

    async fn note_read(&self) -> Result<(), DomainError> {
        if let Some(hook) = &self.on_first_read
            && !self.hook_fired.swap(true, Ordering::SeqCst)
        {
            hook().await;
        }
        if let Some(log) = &self.log {
            log.record_generation_read();
        }
        if self.fail_reads {
            return Err(DomainError::Transient(
                "GenerationStore scripted read failure".to_owned(),
            ));
        }
        Ok(())
    }

    /// A domain context over this store, enforcement on or off.
    pub fn context(self: &Arc<Self>, enforcement: bool) -> Arc<DomainContext> {
        let store: Arc<dyn DomainTransactionStore> = self.clone();
        Arc::new(DomainContext::new(store, enforcement))
    }
}
#[async_trait]
impl DomainTransactionStore for GenerationStore {
    async fn branch_push_refuse(
        &self,
        _operation: &GovernedOperation,
    ) -> Result<DomainOutcome, DomainError> {
        // Generation read tests never reach push refusal; no real store can settle it.
        Err(DomainError::OutcomeUnknown(
            "GenerationStore does not model push refusal".to_owned(),
        ))
    }

    async fn domain_operation_prepare_direct(
        &self,
        _key: &ReceiptKey,
        _binding: &OperationBinding,
        _evidence: &lore_postgres::domain::receipts::DirectAuthorizationEvidence,
        _client_attempt_id: Option<uuid::Uuid>,
    ) -> Result<PrepareResult, DomainError> {
        unreachable!("GenerationStore never prepares direct operations")
    }

    // WP-120's public attempt lookup. Stated rather than defaulted: a store that answers
    // "no receipt" when it simply cannot look one up would report a real attempt as absent,
    // and absence is what tells a client to stop waiting.
    async fn domain_operation_attempt_receipt_get(
        &self,
        _verified_issuer: &str,
        _authenticated_subject: &str,
        _client_attempt_id: &uuid::Uuid,
    ) -> Result<lore_postgres::domain::receipts::AttemptReceipt, DomainError> {
        unreachable!("GenerationStore does not serve attempt receipt lookups")
    }

    async fn domain_operation_clock_get(&self) -> Result<std::time::SystemTime, DomainError> {
        unreachable!("GenerationStore only answers repository and branch snapshots")
    }

    async fn domain_operation_prepare(
        &self,
        _key: &ReceiptKey,
        _binding: &OperationBinding,
        _witness: Option<&AuthorizationWitness>,
        _client_attempt_id: Option<uuid::Uuid>,
    ) -> Result<PrepareResult, DomainError> {
        unreachable!("GenerationStore only answers repository and branch snapshots")
    }

    async fn domain_operation_receipt_get(
        &self,
        _key: &ReceiptKey,
        _binding: &OperationBinding,
    ) -> Result<ReceiptLookup, DomainError> {
        unreachable!("GenerationStore only answers repository and branch snapshots")
    }

    async fn domain_operation_verified_stale_finalize(
        &self,
        _input: &VerifiedStaleFinalizeInput,
    ) -> Result<VerifiedStaleFinalizeResult, DomainError> {
        unreachable!("GenerationStore only answers repository and branch snapshots")
    }

    async fn domain_operation_terminal_status_attach(
        &self,
        _input: &TerminalStatusAttachInput,
    ) -> Result<TerminalStatusAttachmentAck, DomainError> {
        unreachable!("GenerationStore only answers repository and branch snapshots")
    }

    async fn domain_operation_proof_namespace_materialize(
        &self,
        _input: &ProofNamespaceMaterializeInput,
    ) -> Result<ProofNamespaceMaterializeReceipt, DomainError> {
        unreachable!("GenerationStore only answers repository and branch snapshots")
    }

    async fn domain_operation_proof_namespace_retire(
        &self,
        _input: &ProofNamespaceRetireInput,
    ) -> Result<ProofNamespaceRetireAck, DomainError> {
        unreachable!("GenerationStore only answers repository and branch snapshots")
    }

    async fn repository_snapshot(
        &self,
        repository_id: &[u8],
    ) -> Result<Option<RepositorySnapshot>, DomainError> {
        self.repository_reads.fetch_add(1, Ordering::SeqCst);
        self.note_read().await?;
        Ok(self
            .repository_generation
            .map(|generation| RepositorySnapshot {
                repository_id: repository_id.to_vec(),
                live: true,
                generation,
                name: "generation-store".to_owned(),
                metadata_hash: vec![0; 32],
                default_branch_id: vec![0; 16],
            }))
    }

    async fn branch_snapshot(
        &self,
        repository_id: &[u8],
        branch_id: &[u8],
    ) -> Result<Option<BranchSnapshot>, DomainError> {
        self.branch_reads.fetch_add(1, Ordering::SeqCst);
        self.note_read().await?;
        Ok(self.branch_generation.map(|generation| BranchSnapshot {
            repository_id: repository_id.to_vec(),
            branch_id: branch_id.to_vec(),
            live: true,
            generation,
            repository_generation: 1,
            name: "main".to_owned(),
            metadata_hash: vec![0; 32],
            latest_hash: vec![0; 32],
        }))
    }
    async fn branch_create_terminal_replay(
        &self,
        _key: &ReceiptKey,
        _binding: &OperationBinding,
    ) -> Result<Option<lore_postgres::domain::coordinator::BranchCreateResult>, DomainError> {
        unreachable!("This test store does not prepare branch creation")
    }
    async fn branch_create_replay(
        &self,
        _operation: &GovernedOperation,
    ) -> Result<Option<lore_postgres::domain::coordinator::BranchCreateResult>, DomainError> {
        unreachable!("This test store does not execute branch creation")
    }
    async fn branch_create(
        &self,
        _operation: &GovernedOperation,
        _input: &lore_postgres::domain::coordinator::BranchCreateInput,
    ) -> Result<lore_postgres::domain::coordinator::BranchCreateResult, DomainError> {
        unreachable!("This test store does not execute branch creation")
    }

    async fn repository_create(
        &self,
        _operation: &GovernedOperation,
        _input: &RepositoryCreateInput,
    ) -> Result<MutationResult, DomainError> {
        unreachable!("GenerationStore only answers repository and branch snapshots")
    }

    async fn repository_delete(
        &self,
        _operation: &GovernedOperation,
        _input: &RepositoryDeleteInput,
    ) -> Result<MutationResult, DomainError> {
        unreachable!("GenerationStore only answers repository and branch snapshots")
    }

    async fn branch_delete(
        &self,
        _operation: &GovernedOperation,
        _input: &BranchDeleteInput,
    ) -> Result<MutationResult, DomainError> {
        unreachable!("GenerationStore only answers repository and branch snapshots")
    }

    async fn metadata_compare_and_swap(
        &self,
        _operation: &GovernedOperation,
        _input: &MetadataCasInput,
    ) -> Result<MutationResult, DomainError> {
        unreachable!("GenerationStore only answers repository and branch snapshots")
    }

    async fn branch_push_commit(
        &self,
        _operation: &GovernedOperation,
        _input: &BranchPushCommitInput,
    ) -> Result<MutationResult, DomainError> {
        unreachable!("GenerationStore only answers repository and branch snapshots")
    }

    async fn begin_obliterate(
        &self,
        _operation: &GovernedOperation,
        _repository_id: &[u8],
        _event: Option<&PendingEvent>,
    ) -> Result<MutationResult, DomainError> {
        unreachable!("GenerationStore only answers repository and branch snapshots")
    }
}

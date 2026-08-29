// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The narrow server-facing domain transaction trait (CR-029 Phase 3).
//!
//! `DomainTransactionStore` is deliberately its own trait rather than methods
//! bolted onto `MutableStore`, `ImmutableStore`, or `LockStore`. Those three are
//! implemented by wrapping stores in `lore-server` (`ReplicatedStore`,
//! `GrpcReplica`) that have no way to forward a domain transaction without
//! growing their own wire protocol — and a trait method with a default body is
//! inherited silently by every one of them, which is how a capability comes to
//! look implemented everywhere and work nowhere.
//!
//! Every method returns a typed result. SQLSTATE and driver errors are mapped
//! once, in [`crate::domain::errors`], not separately in every handler.
//!
//! # The invariants these methods exist to hold
//!
//! * **Every transaction updates its domain rows and all affected
//!   `lore_mutable` rows in the same Postgres transaction.** The domain rows are
//!   the lifecycle and generation authority; the projection must never lead
//!   them.
//! * **Locks are taken in the F-032-3 order**, receipt first, outbox last, via
//!   [`crate::domain::lock_order::LockSequence`], which checks it rather than
//!   trusting the call site.
//! * **Identities are never reused.** A tombstone row is permanent, and it is
//!   the fence that stops a delayed delete or push from targeting a later object
//!   with the same ID.
//! * **A name is released in the same transaction that tombstones its owner**,
//!   so a name is recyclable only after the prior owner is tombstoned.
//! * **A linearized conflict or precondition rejection commits `NOT_APPLIED`,
//!   its exact public result, and no domain mutation or event.** It is a
//!   decisive outcome, not an error.
//! * **`OutcomeUnknown` is never retried and never inferred** from later
//!   repository, branch, or tombstone state.
//!
//! # Side-effect boundary (R-SHOULD-4)
//!
//! These methods take plain data and a transaction. They are handed no store
//! handle, no auth client, no filesystem path, and no network client, so a
//! handler physically cannot perform immutable-store, auth-gRPC, file, or
//! network work inside the domain transaction — the boundary is structural
//! rather than a rule someone has to remember. Today's handlers do exactly that
//! work mid-sequence (worklog 254 §A.1: an auth-gRPC round trip and two
//! immutable-store serializations interleaved with six unsynchronised writes),
//! which is what this shape removes.

use async_trait::async_trait;

use crate::domain::errors::DomainError;
use crate::domain::errors::DomainOutcome;
use crate::domain::receipts::OperationBinding;
use crate::domain::receipts::ReceiptKey;

/// A repository as the domain rows see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositorySnapshot {
    /// 16-byte identity.
    pub repository_id: Vec<u8>,
    /// False once tombstoned. A tombstoned repository still has a row.
    pub live: bool,
    /// Monotonic; increases on metadata/lifecycle change and whenever an
    /// operation makes previously queryable content unavailable.
    pub generation: i64,
    /// Exact name bytes; repository names do not fold case.
    pub name: String,
    /// Current metadata pointer.
    pub metadata_hash: Vec<u8>,
    /// Default branch identity.
    pub default_branch_id: Vec<u8>,
}

/// A branch as the domain rows see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchSnapshot {
    /// Owning repository.
    pub repository_id: Vec<u8>,
    /// 16-byte branch identity.
    pub branch_id: Vec<u8>,
    /// False once tombstoned. A branch tombstone keeps its last record so
    /// delete stays idempotent.
    pub live: bool,
    /// Monotonic branch generation.
    pub generation: i64,
    /// Repository generation this branch was last written against.
    pub repository_generation: i64,
    /// Authored name. The live-name key is `lowercase(name)`.
    pub name: String,
    /// Current metadata pointer.
    pub metadata_hash: Vec<u8>,
    /// Current tip.
    pub latest_hash: Vec<u8>,
}

/// Everything a governed mutation carries besides its own arguments.
///
/// The operation ID, fingerprint, and prepare token arrive as gRPC **request
/// metadata** (`lore-domain-operation-id-bin`,
/// `lore-domain-operation-fingerprint-bin`, `lore-domain-prepare-token-bin`),
/// read by the one shared extractor at handler entry. They are not request
/// message fields, which is what keeps CR-029 `[SERVER]`-clean.
#[derive(Debug, Clone)]
pub struct GovernedOperation {
    /// Selects the receipt namespace.
    pub key: ReceiptKey,
    /// The caller-known intent an exact retry must reproduce.
    pub binding: OperationBinding,
    /// The single-use token returned by prepare.
    pub prepare_token: [u8; 32],
}

/// Create one repository and its default branch, atomically.
#[derive(Debug, Clone)]
pub struct RepositoryCreateInput {
    /// 16-byte repository identity, chosen by the caller.
    pub repository_id: Vec<u8>,
    /// Exact name to claim.
    pub name: String,
    /// Metadata pointer to publish.
    pub metadata_hash: Vec<u8>,
    /// Default branch identity.
    pub default_branch_id: Vec<u8>,
    /// Default branch name, as authored.
    pub default_branch_name: String,
    /// Default branch metadata pointer.
    pub default_branch_metadata_hash: Vec<u8>,
    /// Default branch tip.
    pub default_branch_latest_hash: Vec<u8>,
    /// Canonical creation fingerprint and its schema version.
    pub creation_fingerprint: Vec<u8>,
    /// Fingerprint schema version.
    pub creation_fingerprint_version: i32,
    /// `lore_mutable` projection rows this transaction must write in step.
    pub projection: Vec<ProjectionWrite>,
    /// Classified event to append last, if any.
    pub event: Option<PendingEvent>,
}

/// One `lore_mutable` row a domain transaction must write alongside its domain
/// rows, in the same transaction.
///
/// The projection is a *compatibility* surface for reads and non-domain key
/// types. It exists so today's readers keep working, and it must never lead the
/// domain rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionWrite {
    /// Partition the row lives in.
    pub partition: Vec<u8>,
    /// Wire `KeyType` discriminant.
    pub key_type: i16,
    /// Hashed key.
    pub key: Vec<u8>,
    /// Value, or `None` to delete the row.
    pub value: Option<Vec<u8>>,
}

/// A classified event to append to the outbox as the transaction's last write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingEvent {
    /// Cell identity, from trusted server configuration.
    pub cell_id: String,
    /// Classified event kind.
    pub event_kind: String,
    /// Aggregate kind the event is about.
    pub aggregate_kind: String,
    /// Aggregate identity.
    pub aggregate_id: Vec<u8>,
    /// Committed aggregate version, opaque bounded bytes.
    pub aggregate_version: Vec<u8>,
    /// Payload schema version.
    pub payload_schema_version: i32,
    /// Bounded identity/version payload. Never repository content.
    pub payload: Vec<u8>,
}

/// Tombstone one repository, releasing its name in the same transaction.
#[derive(Debug, Clone)]
pub struct RepositoryDeleteInput {
    /// Identity to tombstone.
    pub repository_id: Vec<u8>,
    /// Generation the caller expects to be tombstoning.
    pub expected_generation: Option<i64>,
    /// Attempt-compatible immutable delete proof recorded on the tombstone.
    pub delete_proof: Vec<u8>,
    /// Projection rows to remove in step.
    pub projection: Vec<ProjectionWrite>,
    /// Classified event to append last, if any.
    pub event: Option<PendingEvent>,
}

/// Compare-and-swap one metadata pointer.
#[derive(Debug, Clone)]
pub struct MetadataCasInput {
    /// Target repository.
    pub repository_id: Vec<u8>,
    /// Target branch, or `None` for the repository's own metadata.
    pub branch_id: Option<Vec<u8>>,
    /// Pointer the caller believes is current.
    pub expected_hash: Vec<u8>,
    /// Pointer to publish.
    pub new_hash: Vec<u8>,
    /// Projection rows to write in step.
    pub projection: Vec<ProjectionWrite>,
    /// Classified event to append last, if any.
    pub event: Option<PendingEvent>,
}

/// Publish one branch tip.
#[derive(Debug, Clone)]
pub struct BranchPushCommitInput {
    /// Target repository.
    pub repository_id: Vec<u8>,
    /// Target branch.
    pub branch_id: Vec<u8>,
    /// Repository generation the preflight observed. A mismatch means an
    /// obliteration or lifecycle change raced the push.
    pub expected_repository_generation: i64,
    /// Branch generation the preflight observed.
    pub expected_branch_generation: i64,
    /// Tip the caller believes is current.
    pub expected_latest_hash: Vec<u8>,
    /// Tip to publish.
    pub new_latest_hash: Vec<u8>,
    /// Projection rows to write in step.
    pub projection: Vec<ProjectionWrite>,
    /// Classified event to append last, if any.
    pub event: Option<PendingEvent>,
}

/// The outcome of one governed mutation, as committed into its receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MutationResult {
    /// `APPLIED`, or `NOT_APPLIED` with a versioned reason.
    pub outcome: DomainOutcome,
    /// Repository generation after the transaction, when one applies.
    pub repository_generation: Option<i64>,
    /// Branch generation after the transaction, when one applies.
    pub branch_generation: Option<i64>,
}

impl MutationResult {
    /// A decisive rejection: no domain mutation, no event, an exact public
    /// result. This is a committed outcome, not an error.
    pub fn rejected(reason: &str) -> Self {
        Self {
            outcome: DomainOutcome::NotApplied {
                reason_version: crate::domain::receipts::REASON_VERSION,
                reason: reason.to_owned(),
            },
            repository_generation: None,
            branch_generation: None,
        }
    }
}

// --- Frozen rejection reasons ---------------------------------------------

/// The caller's expected generation did not match the locked row.
pub const GENERATION_MISMATCH_V1: &str = "GENERATION_MISMATCH_V1";
/// The target identity is tombstoned. Permanent; retrying cannot help.
pub const TOMBSTONED_V1: &str = "TOMBSTONED_V1";
/// The target identity has never existed.
pub const NOT_FOUND_V1: &str = "NOT_FOUND_V1";
/// A live owner already holds the requested name.
pub const NAME_TAKEN_V1: &str = "NAME_TAKEN_V1";
/// The identity already exists with a different creation fingerprint.
pub const FINGERPRINT_MISMATCH_V1: &str = "FINGERPRINT_MISMATCH_V1";
/// The compare-and-swap predicate did not hold.
pub const CAS_MISMATCH_V1: &str = "CAS_MISMATCH_V1";
/// The prepare token was absent, wrong, or already consumed.
pub const ADMISSION_REJECTED_V1: &str = "ADMISSION_REJECTED_V1";

/// The narrow server-facing domain transaction API.
///
/// Implemented by `PostgresDomainStore` for production and by a test-only fake
/// coordinator in `lore-server`. Deliberately **not** implemented via a trait
/// default anywhere: an implementor that cannot honour a method must fail to
/// compile rather than silently inherit a body.
#[async_trait]
pub trait DomainTransactionStore: Send + Sync {
    /// Read one repository's domain row. `None` when the identity never existed.
    async fn repository_snapshot(
        &self,
        repository_id: &[u8],
    ) -> Result<Option<RepositorySnapshot>, DomainError>;

    /// Read one branch's domain row.
    async fn branch_snapshot(
        &self,
        repository_id: &[u8],
        branch_id: &[u8],
    ) -> Result<Option<BranchSnapshot>, DomainError>;

    /// Create a repository, its default branch, both name rows, every affected
    /// projection row, and the outbox event — or none of them.
    async fn repository_create(
        &self,
        operation: &GovernedOperation,
        input: &RepositoryCreateInput,
    ) -> Result<MutationResult, DomainError>;

    /// Tombstone a repository, release its live name, tombstone its branches,
    /// and remove the projection rows, in one transaction.
    ///
    /// This replaces a delete that is currently unbounded in write count and
    /// error-swallowing per branch (worklog 254 §A.2), where a crash mid-loop
    /// leaves a repository whose name and metadata are gone but whose branch
    /// rows survive with nothing to re-drive them.
    async fn repository_delete(
        &self,
        operation: &GovernedOperation,
        input: &RepositoryDeleteInput,
    ) -> Result<MutationResult, DomainError>;

    /// Compare-and-swap a repository or branch metadata pointer.
    async fn metadata_compare_and_swap(
        &self,
        operation: &GovernedOperation,
        input: &MetadataCasInput,
    ) -> Result<MutationResult, DomainError>;

    /// Publish a branch tip under both the repository and branch generation
    /// fences.
    ///
    /// The repository-generation check is what closes the push-versus-obliterate
    /// race: obliteration begin increments the repository generation in the same
    /// transaction that records its fence, so a push that observed the older
    /// generation is rejected rather than committing across it.
    async fn branch_push_commit(
        &self,
        operation: &GovernedOperation,
        input: &BranchPushCommitInput,
    ) -> Result<MutationResult, DomainError>;

    /// Increment a repository's generation as the obliteration fence.
    ///
    /// Called by the immutable-lifecycle package's obliteration-begin
    /// transition. WP-116 owns only this fence, not fragment state.
    async fn begin_obliterate(
        &self,
        operation: &GovernedOperation,
        repository_id: &[u8],
    ) -> Result<MutationResult, DomainError>;
}

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

use std::time::SystemTime;

use async_trait::async_trait;

use crate::domain::errors::DomainError;
use crate::domain::errors::DomainOutcome;
use crate::domain::maintenance::ProofNamespaceMaterializeInput;
use crate::domain::maintenance::ProofNamespaceMaterializeReceipt;
use crate::domain::maintenance::ProofNamespaceRetireAck;
use crate::domain::maintenance::ProofNamespaceRetireInput;
use crate::domain::maintenance::TerminalStatusAttachInput;
use crate::domain::maintenance::TerminalStatusAttachmentAck;
use crate::domain::maintenance::VerifiedStaleFinalizeInput;
use crate::domain::maintenance::VerifiedStaleFinalizeResult;
use crate::domain::receipts::AuthorizationWitness;
use crate::domain::receipts::OperationBinding;
use crate::domain::receipts::PrepareResult;
use crate::domain::receipts::ReceiptKey;
use crate::domain::receipts::ReceiptLookup;

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
    /// Classified events to append last, in the order given.
    ///
    /// A bounded `Vec` rather than one slot because this transition owes two
    /// rows, not one. CR-032's classification table requires a row for
    /// "Repository live publication" **and** a row for "Branch create", and
    /// this method commits both in one transaction: the repository row at
    /// generation 1 and its default branch at generation 1. One `Option` can
    /// express `repository.published` or `branch.created`, never both.
    ///
    /// The owner resolved that choice on 2026-09-03 in favour of the `Vec`
    /// over a CR-032 amendment folding the default branch into
    /// `repository.published`: a consumer that tracks branches must see the
    /// default branch appear the same way every other branch does.
    ///
    /// Bounded by [`MAX_PENDING_EVENTS`] and checked by
    /// [`validate_pending_events`] before the transaction opens, so one
    /// mutation can never turn into an unbounded outbox write.
    pub events: Vec<PendingEvent>,
}

/// The most classified events one governed mutation may append.
///
/// Repository create is the only method that needs more than one today, and it
/// needs exactly two. The cap is deliberately a small constant rather than the
/// exact current count: CR-032's classification table is what decides how many
/// rows a transition owes, and a table change should not have to move a bound
/// as well. It is not a `Vec` with no ceiling, because the ceiling is the
/// property that keeps an outbox append bounded by the mutation that caused it.
pub const MAX_PENDING_EVENTS: usize = 4;

/// Reject an over-long event carriage before the transaction opens.
///
/// Checked at the top of the coordinator method rather than at the append step:
/// an overrun discovered mid-transaction would roll back domain work that was
/// already correct, while an overrun discovered here costs no transaction at
/// all. This mirrors the same before-the-transaction placement the outbox
/// builders use for their own width checks.
pub fn validate_pending_events(events: &[PendingEvent], method: &str) -> Result<(), DomainError> {
    if events.len() > MAX_PENDING_EVENTS {
        return Err(DomainError::InvalidInput(format!(
            "{method} carries {} outbox events, but one governed mutation may append at most \
             {MAX_PENDING_EVENTS}",
            events.len()
        )));
    }
    Ok(())
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

/// Where the ordinal half of an event's `aggregate_version` comes from.
///
/// CR-032 F-032-4 (PIN-2) requires the ordinal to be the version the
/// transaction **committed**. Four of the six append-capable coordinator
/// methods compute that value inside their own transaction and never take it as
/// an input — `metadata_compare_and_swap` reads the repository/branch
/// generation under the row lock, `repository_delete` may be called with no
/// expected generation, `begin_obliterate` derives its fence from the locked
/// row, and every lock mutation draws its fence from a sequence — so a caller
/// that pre-computed the ordinal would be guessing. A wrong ordinal is not a
/// cosmetic defect: it travels inside the frozen `idempotency_key` preimage, so
/// it would silently mis-key the event and break exact-retry dedupe.
///
/// The builder therefore names *which* committed value it wants, and the
/// coordinator's own append step resolves it from the transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommittedOrdinal {
    /// The repository generation this transaction committed.
    RepositoryGeneration,
    /// The branch generation this transaction committed. Only valid on a method
    /// that commits one; anywhere else it is a programming error, not a
    /// fallback.
    BranchGeneration,
    /// A value the caller already knows exactly, such as a lock namespace fence
    /// the coordinator hands back in the same transaction.
    Exact(u64),
}

/// The committed versions one transaction can resolve a [`CommittedOrdinal`]
/// against. `branch_generation` is `None` on a method that commits none.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommittedVersions {
    /// Repository generation as committed by this transaction.
    pub repository_generation: i64,
    /// Branch generation as committed by this transaction, where there is one.
    pub branch_generation: Option<i64>,
}

impl CommittedOrdinal {
    /// Resolve to the exact committed ordinal, or fail.
    ///
    /// Deliberately has no fallback arm. An event that asked for a branch
    /// generation on a method that commits none is a builder/caller mismatch,
    /// and substituting the repository generation would publish a plausible,
    /// wrong, permanently-keyed version.
    pub fn resolve(self, committed: CommittedVersions) -> Result<u64, DomainError> {
        let signed = match self {
            Self::RepositoryGeneration => committed.repository_generation,
            Self::BranchGeneration => committed.branch_generation.ok_or_else(|| {
                DomainError::Internal(
                    "outbox event asked for the committed branch generation, but this \
                     transaction commits none"
                        .to_owned(),
                )
            })?,
            Self::Exact(value) => return Ok(value),
        };
        u64::try_from(signed).map_err(|_| {
            DomainError::Internal(format!(
                "outbox aggregate_version ordinal must be non-negative, got {signed}"
            ))
        })
    }
}

/// A classified event to append to the outbox as the transaction's last write.
///
/// The `aggregate_version` bytes are **not** carried here. See
/// [`CommittedOrdinal`]: the ordinal is resolved by the coordinator from the
/// values its own transaction committed, and only the bounded identity half is
/// caller-supplied.
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
    /// Which committed version the ordinal half of `aggregate_version` takes.
    pub aggregate_ordinal: CommittedOrdinal,
    /// The bounded identity half of `aggregate_version`: an exact revision
    /// hash, a lock owner token, an association epoch, or empty where the event
    /// kind has none.
    pub aggregate_identity: Vec<u8>,
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
    /// Classified events to append last, in the order given.
    ///
    /// The same bounded `Vec` as
    /// [`RepositoryCreateInput::events`](RepositoryCreateInput::events),
    /// checked by [`validate_pending_events`] before the transaction opens.
    ///
    /// This field previously carried a single `Option` with a recorded
    /// `BLOCKED(WP-116)` reasoning that a repository tombstone owes N
    /// `branch.deleted` rows for its N tombstoned branches, which one slot
    /// cannot express and a cap of [`MAX_PENDING_EVENTS`] cannot either. **That
    /// reasoning is superseded.** CR-032's classification table answers this
    /// transition directly: a repository tombstone emits "One
    /// repository-generation event, not one row per hidden association", and
    /// the same rule governs the branches it hides. The transition is one
    /// bounded generation event, `repository.tombstoned`, keyed on the
    /// committed repository generation — not one event per branch. A consumer
    /// that tracks branches invalidates the whole repository on that row; it
    /// does not need N rows to learn that N branches went away together, and
    /// producing them would make an unbounded outbox write out of one bounded
    /// mutation.
    ///
    /// The `Vec` rather than a single slot is kept for symmetry with create and
    /// because the cap is what makes "bounded" a checked property rather than a
    /// claim; a delete carries one event today.
    ///
    /// PIN(WP-119): one consequence of the bounded answer is worth naming
    /// rather than discovering. This transaction bumps `generation` on every
    /// live branch row it tombstones, and publishes no `branch` event for any
    /// of them, so a consumer that checks the **branch** aggregate ordinal for
    /// contiguity sees each branch's ordinal stop one short, permanently. That
    /// is a gap in CR-032's consumer rules, not a reason to emit N rows: the
    /// repository event is what tells a consumer the whole repository is gone,
    /// and a branch of a tombstoned repository has no further transitions to be
    /// contiguous with. Raise it with the CR owner before a consumer relies on
    /// per-branch contiguity across a repository tombstone.
    pub events: Vec<PendingEvent>,
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
    /// Repository lock generation captured by SCHEMA-117 preflight.
    pub expected_repository_lock_generation: i64,
    /// Branch lock generation captured by SCHEMA-117 preflight.
    pub expected_branch_lock_generation: i64,
    /// Namespace fence captured by SCHEMA-117 preflight.
    pub expected_branch_lock_namespace_last_applied_fence: i64,
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
    /// The pointer the transaction observed, on a compare-and-swap that lost.
    ///
    /// CR-029 Phase 5 requires the metadata CAS handlers to "preserve v1's
    /// in-band current pointer on CAS loss": a CAS miss is a successful RPC
    /// whose response carries the value that was actually there, not an error.
    /// The ungoverned path gets that from the store's own CAS return value.
    /// The governed path has to carry it out of the transaction, because the
    /// only read that can be trusted is the one taken under the row lock the
    /// transaction already holds. A re-read after the transaction commits is a
    /// second source of truth that a concurrent writer can move in between, and
    /// it would answer a question the caller did not ask: not "what did the CAS
    /// see" but "what is there now".
    ///
    /// `None` on every other outcome, including an applied CAS.
    pub observed_pointer: Option<Vec<u8>>,
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
            observed_pointer: None,
        }
    }

    /// A decisive compare-and-swap loss that carries the pointer the
    /// transaction observed under its row lock.
    pub fn cas_lost(observed: Vec<u8>) -> Self {
        Self {
            observed_pointer: Some(observed),
            ..Self::rejected(CAS_MISMATCH_V1)
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
    /// Sample the authoritative Postgres clock used by receipt admission.
    ///
    /// This is read-only and creates no operation identity. The private
    /// control-plane rail uses it to fail closed on unsafe cross-database
    /// clock skew before allocating an authorization ticket.
    async fn domain_operation_clock_get(&self) -> Result<SystemTime, DomainError>;

    /// Create or exact-load the one keyed `PREPARED` admission row.
    ///
    /// The authorization witness is immutable server-only evidence. It is not
    /// part of the caller-known fingerprint and must already have been verified
    /// before this method is called.
    async fn domain_operation_prepare(
        &self,
        key: &ReceiptKey,
        binding: &OperationBinding,
        witness: Option<&AuthorizationWitness>,
    ) -> Result<PrepareResult, DomainError>;

    /// Load one receipt or compact future-rejection marker in its exact
    /// authenticated namespace. This never returns the consume token.
    async fn domain_operation_receipt_get(
        &self,
        key: &ReceiptKey,
        binding: &OperationBinding,
    ) -> Result<ReceiptLookup, DomainError>;

    /// Terminalize an already-verified stale operation only after auth-grpc
    /// atomically claims its current finalizer permit.
    async fn domain_operation_verified_stale_finalize(
        &self,
        input: &VerifiedStaleFinalizeInput,
    ) -> Result<VerifiedStaleFinalizeResult, DomainError>;

    /// Persist/advance the two-phase terminal attachment lifecycle.
    async fn domain_operation_terminal_status_attach(
        &self,
        input: &TerminalStatusAttachInput,
    ) -> Result<TerminalStatusAttachmentAck, DomainError>;

    /// Materialize a platform-reserved proof namespace in Lore Postgres.
    async fn domain_operation_proof_namespace_materialize(
        &self,
        input: &ProofNamespaceMaterializeInput,
    ) -> Result<ProofNamespaceMaterializeReceipt, DomainError>;

    /// Retire an exact quiescent proof namespace epoch.
    async fn domain_operation_proof_namespace_retire(
        &self,
        input: &ProofNamespaceRetireInput,
    ) -> Result<ProofNamespaceRetireAck, DomainError>;

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
    ///
    /// `event` carries CR-032 PIN-3's `repository.obliterated` row. This method
    /// takes it as a bare parameter rather than inside an input struct because
    /// its only other argument is the repository id; the five struct-carrying
    /// methods each already had several.
    async fn begin_obliterate(
        &self,
        operation: &GovernedOperation,
        repository_id: &[u8],
        event: Option<&PendingEvent>,
    ) -> Result<MutationResult, DomainError>;
}

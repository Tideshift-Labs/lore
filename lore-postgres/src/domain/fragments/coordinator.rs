// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-031's single Postgres fragment lifecycle coordinator.
//!
//! # The two invariants this file exists to hold
//!
//! **One predicate.** `query`, `get_metadata`, `get`, `copy`, push proof, and
//! repository stats each implement the "is this fragment usable here" predicate
//! separately today (`store/immutable_store.rs:793-799`, `:848-878`, `:880-912`).
//! They happen to agree, but a change to one does not reach the others, and
//! `repair_missing_payload` already leaves association residue no reader
//! accounts for. [`PostgresFragmentCoordinator::resolve`] is the one batched
//! answer all six consume.
//!
//! **No transaction across I/O.** Five paths hold a Postgres transaction *and* a
//! per-hash advisory lock across an S3 round trip today: `repair_missing_payload`
//! (`:478-503`), both arms of `put` (`:939-1001`, including the object PUT
//! itself at `:988-996`), `copy` (`:1158-1189`), `repository_stats`
//! (`:1240-1339`, one HEAD per row), and `rebuild_metering_projection`
//! (`:626-687`, under a table-level lock). That is what makes the store
//! impossible to compose across replicas, and it is why every operation here is
//! a **begin/commit pair** with nothing but a plain owned value in between.
//!
//! The shape is fixed:
//!
//! 1. a short transaction captures or publishes intent, epoch, fence, and
//!    repository generations;
//! 2. the transaction, the checked-out connection, **and every lock** are
//!    released — the returned intent borrows nothing, so this is structural
//!    rather than a convention;
//! 3. the caller performs file or provider I/O under a bounded deadline and
//!    WP-114's shared admission;
//! 4. a new short transaction takes rows in F-032-3 order and revalidates the
//!    captured witnesses; and
//! 5. the result is published, or the loser is fenced with no mutation.
//!
//! This coordinator performs **no I/O of its own** and constructs no provider
//! client. Step 3 belongs to the caller, and WP-114's governed client is the
//! only route to a bucket (CR-031's no-second-client rule, checkable here by
//! construction: this module has no S3 dependency).
//!
//! The structural claim is about the **intent API**: every `begin_*` returns an
//! owned value, so no I/O phase can be holding a transaction. One method is
//! deliberately outside it. [`PostgresFragmentCoordinator::revalidate_push_witness`]
//! borrows the caller's `Transaction`, because it must be atomic with that
//! push's own publication and cannot own a second one. It performs no I/O
//! itself, and it takes no lock class earlier than `Fragments`, so it can
//! neither span I/O nor invert F-032-3 — but it is a borrow, and the claim
//! above is scoped around it rather than quietly contradicted by it.
//!
//! # Scope as of the SCHEMA-118 window
//!
//! Phases 2 and 3: schema, readiness, the batched resolver, and the begin/commit
//! pairs with their witnesses and lock order. The provider-consuming halves
//! (Phase 4 onward — repair through the governed client, version-aware physical
//! purge, backfill) wait on WP-114's CD-1/CD-3/CD-4/CD-5 and are not here.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;

use deadpool_postgres::Pool;
use deadpool_postgres::Transaction;

use crate::domain::PostgresDomainStore;
use crate::domain::errors::DomainError;
// WP-118 Phase 9. Expands to nothing in a default build; `failpoints::hit` is
// not nameable there. See `super::failpoint`.
use crate::domain::fragments::failpoint;
use crate::domain::fragments::provider::FRAGMENT_PROVIDER_SEND_TIMEOUT_MAX_MILLIS;
use crate::domain::fragments::schema;
use crate::domain::fragments::states::EpochAuthority;
use crate::domain::fragments::states::FragmentLifecycleState;
use crate::domain::fragments::states::FragmentWriteClaimState;
use crate::domain::fragments::states::MissingDiagnostic;
use crate::domain::lock_order::LockClass;
use crate::domain::lock_order::LockSequence;
use crate::domain::schema::STATE_LIVE;

/// Fixed for WP-118 by CR-031's F-031 amendment. A push whose lifecycle scalar
/// moved may revalidate at most this many exact required fragments; a larger
/// request is refused **before any fragment row is locked**.
pub const MAX_PUSH_FRAGMENT_REVALIDATIONS: usize = 4_096;

/// Admission bound on shared-hash fanout for a readable/unreadable transition.
///
/// CR-031 requires the fanout be measured and explicitly bounded *before*
/// mutating, because the transition must visit every live-associated repository
/// atomically and a partial fanout is forbidden. The alternative to a bound is
/// an unbounded row-lock set inside one transaction, which is the shape that
/// deadlocks.
///
/// **This value is a bound, not a measurement.** It is set to
/// [`MAX_PUSH_FRAGMENT_REVALIDATIONS`] so the two per-transaction row budgets
/// match, and staging measurement should replace it with a number derived from
/// real shared-hash distribution before wider rollout.
pub const MAX_LIFECYCLE_GENERATION_FANOUT: usize = MAX_PUSH_FRAGMENT_REVALIDATIONS;

const DIRECT_WRITE_NORMAL_OPERATION: [u8; 16] = *b"wp118-direct-v1N";
const DIRECT_WRITE_REPAIR_OPERATION: [u8; 16] = *b"wp118-direct-v1R";
const OBLITERATE_OPERATION_PREFIX: [u8; 12] = *b"wp118-del-v1";
const OBLITERATE_ORIGIN_PREPARING_STAGE: u8 = 1;
const OBLITERATE_ORIGIN_PREPARING_REMOTE_NORMAL: u8 = 2;
const OBLITERATE_ORIGIN_PREPARING_REMOTE_REPAIR: u8 = 3;
const OBLITERATE_ORIGIN_STAGED: u8 = 4;
const OBLITERATE_ORIGIN_REMOTE: u8 = 5;
const OBLITERATE_ORIGIN_MISSING: u8 = 6;

/// Maximum body size one durable direct-write claim accepts.
pub const MAX_FRAGMENT_WRITE_CLAIM_BODY_BYTES: u64 = 256 * 1024;
/// Largest terminal-claim prune request accepted by one call.
pub const MAX_FRAGMENT_WRITE_CLAIM_PRUNE_BATCH: u32 = 1_000;
const MAX_FRAGMENT_WRITE_CLAIM_DURATION_MILLIS: u128 = i32::MAX as u128;

/// How many members one staged reader lease may cover.
///
/// The third per-transaction row budget in `LockClass::Fragments`.
///
/// **This closes a consistency gap, not a measured regression.** Both siblings
/// that take this lock class bound their row set — `revalidate_push_witness` at
/// [`MAX_PUSH_FRAGMENT_REVALIDATIONS`] and the fanout at
/// [`MAX_LIFECYCLE_GENERATION_FANOUT`] — while `lock_lease_member_heads` took a
/// `FOR SHARE` row lock per member over an unbounded set. Nobody has load-tested
/// row-lock or multixact behaviour at thousands of members, so **whether an
/// unbounded set causes real trouble at realistic hydration sizes is unmeasured**
/// and is not claimed here. The bound is worth having because its neighbours
/// have one and it costs nothing, not because a hazard was demonstrated.
///
/// **Set to [`MAX_PUSH_FRAGMENT_REVALIDATIONS`] deliberately**, following the
/// precedent [`MAX_LIFECYCLE_GENERATION_FANOUT`] already set. This is not
/// consistency for its own sake: the cost being bounded is a set-based row-lock
/// acquisition over `lore_fragment_lifecycle`, which is the same table, the same
/// lock class, and the same statement shape as the push fallback's. Giving the
/// lease path a different budget would mean claiming its locks cost something
/// different, which nothing measured supports.
///
/// **A caller over the bound splits into several leases, and that is sound**
/// where the push equivalent is not. A push's required set must be revalidated
/// atomically, so exceeding 4,096 is a genuine refusal of work. Leases are
/// independent: two leases over disjoint halves of one hydration protect exactly
/// what one lease over the whole would have. So this bound is a batching
/// instruction rather than a ceiling on hydration size, which is why a bound
/// this generous is safe even though a staged working set should rarely
/// approach it.
///
/// Like its siblings, this is a bound and not a measurement. Phase 5 gives this
/// method its first caller; real staged-batch distribution should replace the
/// number before wider rollout.
pub const MAX_STAGED_LEASE_MEMBERS: usize = MAX_PUSH_FRAGMENT_REVALIDATIONS;

/// Postgres-only CR-031 coordinator, sharing CR-029's pool and database.
///
/// Cloneable and cheap: two clones are two handles on one pool. Two *separately
/// constructed* coordinators against one database are two independent
/// replicas for test purposes, which is the composition CR-031 has to survive.
#[derive(Clone)]
pub struct PostgresFragmentCoordinator {
    pool: Pool,
    database_identity: String,
}

impl PostgresDomainStore {
    /// Obtain the fragment lifecycle coordinator on the exact CR-029 pool and
    /// database.
    ///
    /// Sharing the pool is deliberate: a fragment transaction and a repository
    /// transaction can touch the same repository row, so they must be able to
    /// participate in one lock order, and F-032-3 is only a total order if both
    /// run against one database.
    pub fn fragment_coordinator(&self) -> PostgresFragmentCoordinator {
        PostgresFragmentCoordinator {
            pool: self.pool().clone(),
            database_identity: self.identity().as_marker(),
        }
    }
}

// ---------------------------------------------------------------------------
// Readiness
// ---------------------------------------------------------------------------

/// Cell-wide provider-write capability recorded in SCHEMA-118.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FragmentWriteCapability {
    /// Rolling-upgrade posture. Lifecycle reads and governed writes may run,
    /// but Phase 6B destructive work must refuse.
    Optional,
    /// Every process with provider write authority has been moved to
    /// `write-claims-v1` under the named external credential revision.
    ClaimsRequired {
        provider_write_authority_revision: String,
    },
}

impl FragmentWriteCapability {
    pub fn claims_required(&self) -> bool {
        matches!(self, Self::ClaimsRequired { .. })
    }

    pub fn provider_write_authority_revision(&self) -> Option<&str> {
        match self {
            Self::Optional => None,
            Self::ClaimsRequired {
                provider_write_authority_revision,
            } => Some(provider_write_authority_revision),
        }
    }

    fn decode(bits: i16, revision: Option<String>) -> Result<Self, DomainError> {
        match (bits, revision) {
            (schema::WRITE_CAPABILITY_OPTIONAL, None) => Ok(Self::Optional),
            (schema::WRITE_CAPABILITY_CLAIMS_REQUIRED, Some(revision))
                if valid_write_authority_revision(&revision) =>
            {
                Ok(Self::ClaimsRequired {
                    provider_write_authority_revision: revision,
                })
            }
            _ => Err(DomainError::NotReady(
                "fragment write capability row has an invalid shape".to_owned(),
            )),
        }
    }
}

/// Explicit operator assertion used to cross the cell-wide write-capability
/// cutover.
///
/// Constructing this value does not prove an external provider action. The
/// caller must first rotate provider write credentials and revoke the old
/// revision from every pre-claims replica. Persisting the revision makes that
/// prerequisite auditable and lets new replicas exact-attest it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentWriteCapabilityCutover {
    provider_write_authority_revision: String,
}

impl FragmentWriteCapabilityCutover {
    pub fn new(provider_write_authority_revision: &str) -> Result<Self, DomainError> {
        if !valid_write_authority_revision(provider_write_authority_revision) {
            return Err(DomainError::InvalidInput(
                "provider write-authority revision must contain 1..=64 ASCII alphanumeric, '.', '-', or '_' characters"
                    .to_owned(),
            ));
        }
        Ok(Self {
            provider_write_authority_revision: provider_write_authority_revision.to_owned(),
        })
    }

    pub fn provider_write_authority_revision(&self) -> &str {
        &self.provider_write_authority_revision
    }
}

/// Readiness projection used by server construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentLifecycleReadiness {
    /// Whether the migration-owned SCHEMA-118 objects exist in this database.
    ///
    /// False is a **routing answer, not an error**. CR-031 keeps the lifecycle
    /// DDL migration-owned and out of the legacy immutable store's
    /// self-bootstrap, so a cell the migration has not reached is simply a cell
    /// that has not been cut over, and it boots on the legacy route. Reading
    /// this as an error is the INV-EE P0-1 failure: it aborted startup on every
    /// unmigrated cell.
    pub provisioned: bool,
    /// Schema revision stored in the database.
    pub schema_version: i64,
    /// Backfill state, one of the `BACKFILL_*` constants.
    pub backfill_state: i16,
    /// Whether the cutover marker is set.
    pub cutover_at_present: bool,
    /// Whether lifecycle routing is enabled.
    pub lifecycle_enabled: bool,
    /// Durable cell-wide provider-write cutover state.
    pub write_capability: FragmentWriteCapability,
    /// Positive database-identity match against this process's domain store.
    pub same_database: bool,
    /// The fence sequence's next value is above every persisted fence.
    pub sequence_headroom: bool,
    /// Heads that name no current epoch row, or a readable head whose manifest
    /// does not match its epoch. Always zero on a healthy cell; a nonzero count
    /// is damage and blocks enabling.
    pub unresolved_rows: i64,
}

impl FragmentLifecycleReadiness {
    /// The verdict for a database the SCHEMA-118 migration has not reached.
    ///
    /// Every field reads as "no lifecycle evidence", so a caller that only
    /// checks `lifecycle_enabled` and a caller that checks the whole evidence
    /// set reach the same legacy-route conclusion.
    pub fn not_provisioned() -> Self {
        Self {
            provisioned: false,
            schema_version: 0,
            backfill_state: schema::BACKFILL_NOT_STARTED,
            cutover_at_present: false,
            lifecycle_enabled: false,
            write_capability: FragmentWriteCapability::Optional,
            same_database: false,
            sequence_headroom: false,
            unresolved_rows: 0,
        }
    }

    /// Whether every precondition for routing fragment decisions through this
    /// coordinator holds. Fails closed on each missing piece.
    ///
    /// The upper schema-version bound belongs here rather than only in
    /// [`PostgresFragmentCoordinator::enable_lifecycle`]: a Phase 5 boot gate
    /// will consult this method, and a cell whose schema is newer than this
    /// binary understands must route legacy rather than interpret rows written
    /// against a revision it predates.
    pub fn ready_for_lifecycle(&self) -> bool {
        self.provisioned
            && self.schema_version >= 1
            && self.schema_version <= schema::FRAGMENT_SCHEMA_VERSION
            && self.backfill_state == schema::BACKFILL_CUTOVER
            && self.cutover_at_present
            && self.same_database
            && self.sequence_headroom
            && self.unresolved_rows == 0
    }
}

/// Minimal capability projection used by legacy immutable-store construction.
/// It deliberately reads no lifecycle authority and grants no operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentWriteCapabilityReadiness {
    pub provisioned: bool,
    pub schema_version: i64,
    pub write_capability: FragmentWriteCapability,
}

/// Read the cell-wide write capability through an already constructed
/// Postgres store pool.
pub async fn read_fragment_write_capability(
    pool: &Pool,
) -> Result<FragmentWriteCapabilityReadiness, DomainError> {
    let client = pool
        .get()
        .await
        .map_err(|error| DomainError::from_pool("fragment capability pool", error))?;
    match fragment_schema_presence(&client).await? {
        FragmentSchemaPresence::Absent => Ok(FragmentWriteCapabilityReadiness {
            provisioned: false,
            schema_version: 0,
            write_capability: FragmentWriteCapability::Optional,
        }),
        FragmentSchemaPresence::Partial { present } => Err(DomainError::NotReady(format!(
            "SCHEMA-118 is partially installed: {present} of {} probed relations exist",
            schema::FRAGMENT_SCHEMA_RELATIONS.len()
        ))),
        FragmentSchemaPresence::Complete => {
            let row = client
                .query_opt(
                    "SELECT schema_version, write_capability, provider_write_authority_revision \
                       FROM lore_fragment_schema_state WHERE id = 1",
                    &[],
                )
                .await
                .map_err(|error| {
                    DomainError::from_pg("fragment write capability readiness", error)
                })?
                .ok_or_else(|| {
                    DomainError::NotReady("SCHEMA-118 capability singleton is absent".to_owned())
                })?;
            Ok(FragmentWriteCapabilityReadiness {
                provisioned: true,
                schema_version: row.get("schema_version"),
                write_capability: FragmentWriteCapability::decode(
                    row.get("write_capability"),
                    row.get("provider_write_authority_revision"),
                )?,
            })
        }
    }
}

/// How much of the migration-owned SCHEMA-118 schema this database holds.
///
/// A relation-level probe, not a schema check. `Complete` says every probed
/// relation exists; it says nothing about the columns, indexes, and constraints
/// [`schema::FRAGMENT_SCHEMA`] also installs. Those fail closed on their own —
/// a missing column is SQLSTATE 42703 out of the readiness query itself — so
/// this probe's only job is to separate "the migration never ran here" from
/// "it ran and something is missing".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FragmentSchemaPresence {
    /// The migration has not reached this database. A routing answer.
    Absent,
    /// Some probed relations exist and some do not — never a migration's output.
    Partial {
        present: i64,
    },
    Complete,
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/// The exact representation one epoch names. Immutable once written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentManifest {
    /// Which authority backs the bytes.
    pub authority: EpochAuthority,
    /// Exact key or path. For a normal first write this is the legacy bare-hash
    /// key; a repair successor uses a server-only immutable epoch key.
    pub object_key: String,
    /// Manifest identity, revalidated after I/O.
    pub manifest_id: Vec<u8>,
    /// Encoded size.
    pub size_payload: i64,
    /// Decoded size.
    pub size_content: i64,
    /// Decoded content hash.
    pub decoded_hash: Vec<u8>,
    /// Persisted payload flags, already masked to
    /// `CONTENT_STRUCTURE_MASK | ENCODING_MASK`.
    pub payload_flags: i64,
}

/// Everything a delayed operation must find unchanged to publish its result.
///
/// Captured before I/O and revalidated after it. This is the whole fencing
/// mechanism: an operation never asks "is this still fine", it asks "is this
/// *exactly* what I captured".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochWitness {
    /// The FragmentId.
    pub hash: Vec<u8>,
    /// The exact epoch captured.
    pub epoch: i64,
    /// The exact state captured.
    pub state: FragmentLifecycleState,
    /// The exact manifest identity captured.
    pub manifest_id: Option<Vec<u8>>,
    /// The exact head fence captured.
    pub fence: i64,
}

/// One resolved fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentResolution {
    /// The FragmentId asked about.
    pub hash: Vec<u8>,
    /// The verdict.
    pub verdict: FragmentVerdict,
}

/// Batched projection for [`ImmutableStore::query`](lore_storage::ImmutableStore::query).
/// Both booleans come from the same set-based statement and the same canonical
/// readability joins as [`PostgresFragmentCoordinator::resolve`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentQueryMatch {
    pub hash: Vec<u8>,
    pub exact_context_readable: bool,
    pub partition_readable: bool,
}

/// One exact repository-context fragment lookup requested by
/// [`PostgresFragmentCoordinator::resolve_query_matches`].
///
/// Named fields keep the hash/context binding explicit at the API and SQL
/// projection boundaries. Both values are byte identities, so a positional
/// tuple would compile unchanged if a caller accidentally swapped them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentQueryRequest {
    pub hash: Vec<u8>,
    pub context: Vec<u8>,
}

/// Distinct readable-fragment accounting for one live repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentRepositoryStats {
    pub fragment_count: u64,
    pub payload_bytes: u64,
    pub content_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ScopedFragmentResolution {
    resolution: FragmentResolution,
    exact_context_readable: bool,
}

/// The verdict for one fragment in one repository/context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FragmentVerdict {
    /// Every clause of the resolution contract held in one snapshot.
    Readable {
        /// Revalidation witness for the caller's post-I/O commit.
        witness: EpochWitness,
        /// The representation to read.
        manifest: FragmentManifest,
        /// The association's own epoch, for diagnostics.
        association_epoch: i64,
    },
    /// No match. Every non-readable state, a tombstoned or generation-stale
    /// association, a tombstoned repository, and an absent row all collapse to
    /// this: the caller must not distinguish them, because doing so leaks
    /// whether a hash exists in another repository.
    Absent,
}

impl FragmentVerdict {
    /// Whether this verdict permits a positive answer.
    pub fn is_readable(&self) -> bool {
        matches!(self, Self::Readable { .. })
    }
}

// ---------------------------------------------------------------------------
// Intents — the value that survives between a begin and its commit
// ---------------------------------------------------------------------------

/// A fenced intent published by a `begin_*` call.
///
/// Deliberately owns everything and borrows nothing: it cannot hold a
/// transaction, a connection, or a lock, so "the caller did I/O with a
/// transaction open" is not expressible rather than merely discouraged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentIntent {
    /// The FragmentId.
    pub hash: Vec<u8>,
    /// The epoch this operation will publish if it wins.
    pub epoch: i64,
    /// The fence issued to this operation.
    pub fence: i64,
    /// The object key or staged path this operation must write.
    pub object_key: String,
    /// Which authority the published epoch will name.
    pub authority: EpochAuthority,
    /// Direct-write lineage recovered from the durable active-operation token.
    /// `None` for stage, promotion, and obliteration intents.
    direct_write_kind: Option<DirectWriteKind>,
    /// Exact durable provider-write claim for a direct remote publication.
    /// `None` for stage, promotion, and obliteration intents.
    write_claim: Option<FragmentWriteClaim>,
    /// The head as captured at begin, for post-I/O revalidation. `None` when
    /// this operation created the head.
    pub captured: Option<EpochWitness>,
}

impl FragmentIntent {
    /// Whether this intent is an ordinary first publication or a repair
    /// successor. Survives a `PreparingRemote` retry and process restart.
    pub fn direct_write_kind(&self) -> Option<DirectWriteKind> {
        self.direct_write_kind
    }

    /// Durable claim that must be authorized and settled around provider I/O.
    pub fn write_claim(&self) -> Option<&FragmentWriteClaim> {
        self.write_claim.as_ref()
    }
}

/// The immutable-key lineage of one direct remote publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectWriteKind {
    /// Normal first publication at the legacy bare-hash key.
    Normal,
    /// Successor to a diagnosed `Missing` head at an immutable epoch key.
    Repair,
}

/// Caller-supplied fields that are known before a direct-write epoch and fence
/// are allocated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentWriteClaimInput {
    logical_request_id: [u8; 16],
    attempt_id: [u8; 16],
    body_blake3: [u8; 32],
    body_size: u64,
    send_timeout_millis: i64,
    late_effect_bound_millis: i64,
}

impl FragmentWriteClaimInput {
    /// Validate one exact provider-write attempt before any database work.
    pub fn new(
        logical_request_id: [u8; 16],
        attempt_id: [u8; 16],
        body_blake3: [u8; 32],
        body_size: u64,
        send_timeout: Duration,
        late_effect_bound: Duration,
    ) -> Result<Self, DomainError> {
        if logical_request_id == [0; 16] || attempt_id == [0; 16] {
            return Err(DomainError::InvalidInput(
                "fragment write claim identifiers must be nonzero".to_owned(),
            ));
        }
        if body_size > MAX_FRAGMENT_WRITE_CLAIM_BODY_BYTES {
            return Err(DomainError::InvalidInput(format!(
                "fragment write claim body exceeds {MAX_FRAGMENT_WRITE_CLAIM_BODY_BYTES} bytes"
            )));
        }
        let send_timeout_millis = duration_millis("fragment write send timeout", send_timeout)?;
        if send_timeout_millis
            > i64::try_from(FRAGMENT_PROVIDER_SEND_TIMEOUT_MAX_MILLIS).map_err(|_| {
                DomainError::Internal(
                    "fragment provider send-timeout maximum exceeds i64".to_owned(),
                )
            })?
        {
            return Err(DomainError::InvalidInput(format!(
                "fragment write send timeout exceeds {FRAGMENT_PROVIDER_SEND_TIMEOUT_MAX_MILLIS} milliseconds"
            )));
        }
        let late_effect_bound_millis =
            duration_millis("fragment write late-effect bound", late_effect_bound)?;
        send_timeout_millis
            .checked_add(late_effect_bound_millis)
            .ok_or_else(|| {
                DomainError::InvalidInput(
                    "fragment write claim deadline interval overflows".to_owned(),
                )
            })?;
        Ok(Self {
            logical_request_id,
            attempt_id,
            body_blake3,
            body_size,
            send_timeout_millis,
            late_effect_bound_millis,
        })
    }
}

/// Exact durable binding for one provider-write attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentWriteClaim {
    logical_request_id: [u8; 16],
    attempt_id: [u8; 16],
    hash: Vec<u8>,
    epoch: i64,
    fence: i64,
    authority: EpochAuthority,
    object_key: String,
    body_blake3: [u8; 32],
    body_size: u64,
    send_not_after: SystemTime,
    hard_not_after: SystemTime,
}

impl FragmentWriteClaim {
    pub fn logical_request_id(&self) -> &[u8; 16] {
        &self.logical_request_id
    }

    pub fn attempt_id(&self) -> &[u8; 16] {
        &self.attempt_id
    }

    pub fn hash(&self) -> &[u8] {
        &self.hash
    }

    pub fn epoch(&self) -> i64 {
        self.epoch
    }

    pub fn fence(&self) -> i64 {
        self.fence
    }

    pub fn authority(&self) -> EpochAuthority {
        self.authority
    }

    pub fn object_key(&self) -> &str {
        &self.object_key
    }

    pub fn body_blake3(&self) -> &[u8; 32] {
        &self.body_blake3
    }

    pub fn body_size(&self) -> u64 {
        self.body_size
    }

    pub fn send_not_after(&self) -> SystemTime {
        self.send_not_after
    }

    pub fn hard_not_after(&self) -> SystemTime {
        self.hard_not_after
    }
}

/// One authorization minted from the database clock immediately before the
/// bounded charge/send future is polled.
#[derive(Debug, PartialEq, Eq)]
pub struct AuthorizedFragmentWrite {
    send_budget: Duration,
}

impl AuthorizedFragmentWrite {
    pub fn send_budget(&self) -> Duration {
        self.send_budget
    }
}

/// Durable settlement of one provider-write claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentWriteSettlement {
    Decisive,
    Ambiguous,
    NoSend,
}

/// Bounded, DB-clock retention policy for one terminal-claim prune pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FragmentWriteClaimPruneBatch {
    max_claims: i64,
    terminal_retention_millis: i64,
}

impl FragmentWriteClaimPruneBatch {
    pub fn new(max_claims: u32, terminal_retention: Duration) -> Result<Self, DomainError> {
        if !(1..=MAX_FRAGMENT_WRITE_CLAIM_PRUNE_BATCH).contains(&max_claims) {
            return Err(DomainError::InvalidInput(format!(
                "fragment write-claim prune batch must be between 1 and {MAX_FRAGMENT_WRITE_CLAIM_PRUNE_BATCH}"
            )));
        }
        Ok(Self {
            max_claims: i64::from(max_claims),
            terminal_retention_millis: duration_millis(
                "fragment write-claim terminal retention",
                terminal_retention,
            )?,
        })
    }
}

/// Outcome of one terminal-claim prune pass.
///
/// `pruned` alone cannot tell a caller whether there was nothing to do or
/// whether the whole batch was consumed by skips: both report zero. `examined`
/// accounts for every candidate the plan returned, so
/// `examined == pruned + skipped_blocked + skipped_missing_evidence` always
/// holds: `examined == 0` is a genuinely empty batch, and
/// `examined == batch.max_claims` says the batch was full and another pass is
/// worthwhile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FragmentWriteClaimPruneReport {
    /// Candidates the plan query returned.
    pub examined: u64,
    /// Claim rows deleted.
    pub pruned: u64,
    /// Candidates skipped because the hash carried a live send barrier when
    /// the head lock was taken.
    pub skipped_blocked: u64,
    /// Candidates whose own claim row was gone, no longer in the state the
    /// plan saw, or outside the retention window by the time the head lock was
    /// taken, so no row was deleted.
    pub skipped_missing_evidence: u64,
}

impl FragmentWriteClaimPruneReport {
    fn new(examined: usize) -> Result<Self, DomainError> {
        Ok(Self {
            examined: u64::try_from(examined).map_err(|_| {
                DomainError::Internal("fragment write claim prune batch exceeds u64".to_owned())
            })?,
            ..Self::default()
        })
    }

    // One accumulation policy for all three counters. Every candidate advances
    // exactly one of them by one, and the candidate count is bounded by
    // `MAX_FRAGMENT_WRITE_CLAIM_PRUNE_BATCH`, so none can reach the saturation
    // point. `deleted` is 0 or 1 because both deletes key on the primary key.
    fn record_pruned(&mut self, deleted: u64) {
        self.pruned = self.pruned.saturating_add(deleted);
    }

    fn record_blocked(&mut self) {
        self.skipped_blocked = self.skipped_blocked.saturating_add(1);
    }

    fn record_missing_evidence(&mut self) {
        self.skipped_missing_evidence = self.skipped_missing_evidence.saturating_add(1);
    }
}

impl FragmentWriteSettlement {
    fn state(self) -> FragmentWriteClaimState {
        match self {
            Self::Decisive => FragmentWriteClaimState::Decisive,
            Self::Ambiguous => FragmentWriteClaimState::Ambiguous,
            Self::NoSend => FragmentWriteClaimState::NoSend,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FragmentWriteClaimBarrier {
    Clear,
    BlockedUntil(SystemTime),
}

enum FragmentWriteClaimCreation {
    Created(FragmentWriteClaim),
    BlockedUntil(SystemTime),
}

struct FragmentWriteClaimLineage<'a> {
    hash: &'a [u8],
    epoch: i64,
    fence: i64,
    authority: EpochAuthority,
    object_key: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FragmentWriteCleanupTarget {
    logical_request_id: [u8; 16],
    attempt_id: [u8; 16],
    hash: Vec<u8>,
    epoch: i64,
    fence: i64,
    authority: EpochAuthority,
    object_key: String,
    body_blake3: [u8; 32],
    body_size: u64,
}

struct FragmentWriteClaimInventory {
    blocked_until: Option<SystemTime>,
    cleanup_targets: Vec<FragmentWriteCleanupTarget>,
}

/// Exact association which owns one durable coordinated obliteration.
///
/// The association row is tombstoned at begin and its `association_epoch` is
/// replaced by this globally unique fence. That makes the exact
/// `(hash, repository, context)` tuple the only caller that can resume the
/// deletion sequence after a crash; another tombstoned association cannot
/// steal it merely because it names the same globally deduplicated hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentObliterateOwnership {
    hash: Vec<u8>,
    repository_id: Vec<u8>,
    context: Vec<u8>,
    fence: i64,
}

impl FragmentObliterateOwnership {
    pub fn hash(&self) -> &[u8] {
        &self.hash
    }

    pub fn repository_id(&self) -> &[u8] {
        &self.repository_id
    }

    pub fn context(&self) -> &[u8] {
        &self.context
    }

    pub fn fence(&self) -> i64 {
        self.fence
    }
}

/// One exact physical representation which must be proved gone before the
/// lifecycle head can become `Tombstoned`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FragmentPurgeTarget {
    hash: Vec<u8>,
    epoch: i64,
    authority: EpochAuthority,
    object_key: String,
    provider_body_blake3: Option<[u8; 32]>,
    provider_body_size: Option<u64>,
    provider_claim_fence: Option<i64>,
}

impl FragmentPurgeTarget {
    pub fn hash(&self) -> &[u8] {
        &self.hash
    }

    pub fn epoch(&self) -> i64 {
        self.epoch
    }

    pub fn authority(&self) -> EpochAuthority {
        self.authority
    }

    pub fn object_key(&self) -> &str {
        &self.object_key
    }

    pub fn provider_body_blake3(&self) -> Option<&[u8; 32]> {
        self.provider_body_blake3.as_ref()
    }

    pub fn provider_body_size(&self) -> Option<u64> {
        self.provider_body_size
    }

    pub fn provider_claim_fence(&self) -> Option<i64> {
        self.provider_claim_fence
    }
}

/// Current-epoch representation retained for exact child discovery while the
/// head is already unreadable in `DeletingChildren`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentObliterateRepresentation {
    target: FragmentPurgeTarget,
    manifest: Option<FragmentManifest>,
}

impl FragmentObliterateRepresentation {
    pub fn target(&self) -> &FragmentPurgeTarget {
        &self.target
    }

    pub fn manifest(&self) -> Option<&FragmentManifest> {
        self.manifest.as_ref()
    }
}

/// Durable phase represented by a coordinated obliteration intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentObliteratePhase {
    Children,
    Payload,
}

/// Owned deletion intent. It borrows no database resource and can therefore
/// cross waits, recursive child work, and provider/file I/O safely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentObliterateIntent {
    ownership: FragmentObliterateOwnership,
    phase: FragmentObliteratePhase,
    current_epoch: i64,
    origin: u8,
    current: Option<FragmentObliterateRepresentation>,
    purge_targets: Vec<FragmentPurgeTarget>,
    purge_evidence_epochs: Vec<i64>,
    metering_present: bool,
    blocked_until: Option<SystemTime>,
    provider_write_authority_revision: String,
}

impl FragmentObliterateIntent {
    pub fn ownership(&self) -> &FragmentObliterateOwnership {
        &self.ownership
    }

    pub fn phase(&self) -> FragmentObliteratePhase {
        self.phase
    }

    pub fn current_epoch(&self) -> i64 {
        self.current_epoch
    }

    pub fn current(&self) -> Option<&FragmentObliterateRepresentation> {
        self.current.as_ref()
    }

    pub fn purge_targets(&self) -> &[FragmentPurgeTarget] {
        &self.purge_targets
    }

    pub fn provider_write_authority_revision(&self) -> &str {
        &self.provider_write_authority_revision
    }
}

/// Result of exact-association coordinated obliterate admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FragmentObliterateBegin {
    NoOp,
    AssociationOnly,
    Blocked {
        intent: Box<FragmentObliterateIntent>,
        blocked_until: SystemTime,
    },
    Ready(Box<FragmentObliterateIntent>),
}

/// Exact proof minted inside `lore-postgres` only after a staged collaborator
/// or the governed unversioned transport completed one target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentPurgeProof {
    target: FragmentPurgeTarget,
}

impl FragmentPurgeProof {
    pub(crate) fn new(target: FragmentPurgeTarget) -> Self {
        Self { target }
    }
}

/// Outcome of a `begin_*` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeginOutcome {
    /// The intent is published and the caller may perform I/O.
    Admitted(Box<FragmentIntent>),
    /// The fragment is already readable at a current epoch. The caller performs
    /// no I/O and no write; this is the dedup short-circuit today's `put` takes
    /// at `store/immutable_store.rs:948-950`.
    ///
    /// Carries the head as observed under its lock, not a resolution: a begin
    /// call knows nothing about a repository or context, so it cannot answer
    /// the association half of the resolution contract and must not pretend to.
    AlreadyReadable(Box<EpochWitness>),
    /// The head is inside a deletion sequence or tombstoned, so no new
    /// representation may be published against it.
    Fenced(String),
    /// A prior attempt on the same exact head can still have a late effect.
    WriteClaimBlocked { hard_not_after: SystemTime },
}

/// Outcome of a `commit_*` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitVerdict {
    /// The captured witnesses still held and the result is published.
    Published,
    /// A witness moved. **No mutation was made**, and the caller's I/O result
    /// must be discarded. Obliterate or a repair successor won the race.
    Fenced,
    /// The I/O failed, but the representation the head already names is still
    /// authoritative, so nothing changed and nothing was demoted.
    ///
    /// Only promotion produces this. It is deliberately not `Fenced` (no
    /// witness moved) and deliberately not a `Missing` publication (the staged
    /// file is still good — only the upload failed).
    Abandoned,
}

impl CommitVerdict {
    /// Whether the operation published.
    pub fn published(self) -> bool {
        matches!(self, Self::Published)
    }

    /// Whether the fragment's readability is unchanged by this outcome.
    pub fn left_representation_intact(self) -> bool {
        matches!(self, Self::Fenced | Self::Abandoned)
    }
}

/// What the caller observed during its I/O phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IoObservation {
    /// The representation is valid and matches its manifest.
    Valid(FragmentManifest),
    /// The expected authority was absent, truncated, corrupt, or in an encoding
    /// this build cannot decode. Commits `Missing` and fails closed.
    Unusable(MissingDiagnostic),
}

// ---------------------------------------------------------------------------
// Push witness
// ---------------------------------------------------------------------------

/// The two per-repository scalars F-031-1 freezes as the entire push witness.
///
/// Both are columns on the repository row, so they add no lock position to
/// F-032-3 and a push that already locks that row reads them for free.
///
/// The cell-global variant this replaced was measured starving: 65 to 102
/// aborted attempts per successful push and outright starvation at three
/// uploaders, against 0 aborts and floor latency for the per-repository shape
/// (INV-DZ probe addendum).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PushGenerationWitness {
    /// Moves on association create, copy, and tombstone.
    pub content_association_generation: i64,
    /// Moves on a readable/unreadable transition of any fragment this
    /// repository has a live association to.
    pub fragment_lifecycle_generation: i64,
}

/// What a final push transaction may do given its witness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushWitnessVerdict {
    /// Neither scalar moved. Commit with no fragment-row read at all.
    Unchanged,
    /// The lifecycle scalar moved and every exact required fragment is still
    /// readable, at its captured epoch or at a semantically equivalent one.
    /// The push may commit.
    FallbackSatisfied {
        /// How many fragment rows the fallback actually revalidated.
        revalidated: usize,
    },
    /// A required fragment became missing, deleting, tombstoned, or different.
    /// Known `ABORTED`; take a fresh preflight.
    Aborted {
        /// Frozen reason code.
        reason: &'static str,
    },
}

/// Reason code for a changed-scalar push whose required set exceeds
/// [`MAX_PUSH_FRAGMENT_REVALIDATIONS`]. Returned **before any fragment row is
/// locked**, so it is a known no-commit refusal rather than an ambiguous abort.
pub const REQUIRED_FRAGMENT_REVALIDATION_LIMIT: &str = "required_fragment_revalidation_limit";

/// Reason code for a required fragment that is no longer readable, or is
/// readable only at an epoch that is not semantically equivalent to the one
/// preflight captured.
pub const REQUIRED_FRAGMENT_CHANGED: &str = "required_fragment_changed";

/// A fragment the push requires, at the exact epoch preflight resolved it to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequiredFragment {
    /// The FragmentId.
    pub hash: Vec<u8>,
    /// The epoch preflight saw.
    pub epoch: i64,
}

// ---------------------------------------------------------------------------
// Staged reader leases
// ---------------------------------------------------------------------------

/// [`DomainError::PreconditionRejected`] reason for a lease whose member set
/// names something other than a live `Staged` epoch of this cell — a `Remote`
/// epoch, an epoch that does not exist, or one whose bytes are already proved
/// gone (`DISPOSITION_PURGED`).
pub const STAGED_LEASE_MEMBER_NOT_STAGED: &str = "staged_lease_member_not_staged";

/// Reason for a duplicate `lease_id` whose row has vanished between the
/// conflicting insert and the replay read. See [`replay_staged_lease`].
///
/// **Phase 6 obligation, deliberately uncovered.** Neither tier pins this, and
/// that is a decision rather than an oversight: the only thing that can delete
/// a lease row is the expiry reaper, which does not exist yet. Nor can
/// `reader_fence`'s ordering against cleanup be settled without that consumer —
/// there is nothing yet that reads the fence and decides whether a staged epoch
/// is safe to reclaim. Manufacturing a test against an absent consumer would
/// pin this branch's shape while proving nothing about the contract it exists
/// to serve. Phase 6 owns both: covering this branch, and stating what
/// `reader_fence` must order against.
pub const STAGED_LEASE_VANISHED: &str = "staged_lease_vanished";

/// Reason for a duplicate `lease_id` whose member set is not the one the
/// existing lease covers. An id collision, not a retry.
pub const STAGED_LEASE_MEMBER_SET_MISMATCH: &str = "staged_lease_member_set_mismatch";

/// Reason for a duplicate `lease_id` naming a lease that is already terminal.
/// A released lease is never resurrected.
pub const STAGED_LEASE_ALREADY_RELEASED: &str = "staged_lease_already_released";

/// A batched durable reader lease over one hydration request's staged
/// fragments.
///
/// Scoped to `Staged` epochs only. A `Remote` read takes no lease and
/// revalidates read-only after byte I/O, because an immutable remote object is
/// not removed under a reader — which is what keeps the hottest read path free
/// of a write per 256 KiB (R-SHOULD-6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedReaderLease {
    /// Lease identity.
    pub lease_id: Vec<u8>,
    /// Monotonic reader fence.
    pub reader_fence: i64,
    /// Hard expiry. Cleanup waits for terminal or hard-expired leases.
    pub deadline: SystemTime,
    /// The (hash, epoch) pairs this one lease covers.
    pub members: Vec<(Vec<u8>, i64)>,
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

impl PostgresFragmentCoordinator {
    /// Install SCHEMA-118 for isolated component fixtures.
    ///
    /// **Production construction does not call this method**, and that is the
    /// point rather than an omission. CR-031 keeps the lifecycle DDL
    /// migration-owned and out of both the legacy immutable store's
    /// self-bootstrap `SCHEMA` and `PostgresDomainStore::connect`, so a cell
    /// the migration has not reached boots and answers on the legacy route
    /// instead of failing. Auto-applying it here would make every unmigrated
    /// cell silently cut over on a binary roll — and applying it at boot is
    /// what aborted startup on unmigrated cells in INV-EE P0-1's sibling case.
    pub async fn bootstrap(&self) -> Result<(), DomainError> {
        crate::pool::ensure_schema(&self.pool, schema::FRAGMENT_SCHEMA)
            .await
            .map_err(|error| {
                DomainError::Internal(format!("fragment schema bootstrap: {error}"))
            })?;
        let client = self.checkout().await?;
        client
            .execute(
                "INSERT INTO lore_fragment_schema_state ( \
                     id, schema_version, backfill_version, backfill_state, \
                     database_identity, updated_at \
                 ) VALUES (1, $1, 0, $2, $3, clock_timestamp()) \
                 ON CONFLICT (id) DO NOTHING",
                &[
                    &schema::FRAGMENT_SCHEMA_VERSION,
                    &schema::BACKFILL_NOT_STARTED,
                    &self.database_identity,
                ],
            )
            .await
            .map_err(|error| DomainError::from_pg("fragment schema state insert", error))?;
        Ok(())
    }

    /// Current database-backed readiness evidence.
    ///
    /// This runs on the mandatory startup path, so exactly one absence is
    /// normal rather than exceptional: a database the SCHEMA-118 migration has
    /// not reached at all. That one answers "not provisioned, use the legacy
    /// route". Every other gap is damage and is refused, because a migration
    /// never produces a half-installed schema and neither does a rollback, so
    /// routing around one would silently return a cut-over cell to the legacy
    /// split-truth path this package exists to remove.
    pub async fn readiness(&self) -> Result<FragmentLifecycleReadiness, DomainError> {
        let client = self.checkout().await?;
        match fragment_schema_presence(&client).await? {
            FragmentSchemaPresence::Absent => {
                return Ok(FragmentLifecycleReadiness::not_provisioned());
            }
            FragmentSchemaPresence::Partial { present } => {
                return Err(DomainError::NotReady(format!(
                    "SCHEMA-118 is partially installed: {present} of {} probed relations exist. \
                     A migration never produces this state, so it is refused rather than routed \
                     around",
                    schema::FRAGMENT_SCHEMA_RELATIONS.len()
                )));
            }
            FragmentSchemaPresence::Complete => {}
        }

        let Some(row) = client
            .query_opt(
                "SELECT schema_version, backfill_state, cutover_at, lifecycle_enabled, \
                        write_capability, provider_write_authority_revision, \
                        database_identity, sequence_headroom_fence \
                   FROM lore_fragment_schema_state WHERE id = 1",
                &[],
            )
            .await
            .map_err(|error| DomainError::from_pg("fragment lifecycle readiness", error))?
        else {
            return Err(DomainError::NotReady(
                "SCHEMA-118 relations exist but their singleton schema-state row is absent; \
                 the installation is incomplete"
                    .to_owned(),
            ));
        };

        // The two generation columns live on `lore_domain_repositories`, which
        // CR-029 owns. They are part of SCHEMA-118's DDL, so a provisioned
        // schema always has them; their absence is damage. Reading around it is
        // the dangerous option: every push witness would silently read as
        // unchanged, and the obliteration fence would stop fencing.
        if !repository_generation_columns_present(&client).await? {
            return Err(DomainError::NotReady(
                "SCHEMA-118 is installed but lore_domain_repositories lacks its \
                 content_association_generation / fragment_lifecycle_generation columns; \
                 those are part of that schema, so this installation is damaged"
                    .to_owned(),
            ));
        }

        let max_fence: i64 = client
            .query_one(
                "SELECT GREATEST( \
                    COALESCE((SELECT max(last_fence) FROM lore_fragment_lifecycle), 0), \
                    COALESCE((SELECT max(fence) FROM lore_fragment_epochs), 0), \
                    COALESCE((SELECT max(reader_fence) FROM lore_fragment_staged_leases), 0))",
                &[],
            )
            .await
            .map_err(|error| DomainError::from_pg("fragment fence maximum", error))?
            .get(0);

        // A READABLE head whose current epoch has no row, or whose manifest does
        // not match that epoch's, is unresolvable by the resolver's join. It is
        // not a routing question; it is damage that would silently make
        // fragments absent.
        //
        // Scoped to readable states deliberately. A `PreparingStage`,
        // `PreparingRemote`, `Missing`, or `Tombstoned` head legitimately names
        // a `current_epoch` with no epoch row: `begin_publication` allocates the
        // epoch before the caller's I/O, and a first write that fails
        // validation commits `Missing` without ever inserting one. Counting
        // those as damage would let a single in-flight write, or one bad
        // upload, permanently block `enable_lifecycle` and flip boot readiness
        // on a healthy cell.
        let unresolved_rows: i64 = client
            .query_one(
                "SELECT count(*)::bigint FROM lore_fragment_lifecycle AS l \
                  WHERE l.state = ANY($1) \
                    AND NOT EXISTS ( \
                        SELECT 1 FROM lore_fragment_epochs AS e \
                         WHERE e.hash = l.hash AND e.epoch = l.current_epoch \
                           AND e.manifest_id = l.manifest_id)",
                &[&FragmentLifecycleState::readable_bits().as_slice()],
            )
            .await
            .map_err(|error| DomainError::from_pg("fragment unresolved readiness", error))?
            .get(0);

        let evidence: Option<i64> = row.get("sequence_headroom_fence");
        let sequence = client
            .query_one(
                "SELECT last_value, is_called FROM lore_fragment_fence_seq",
                &[],
            )
            .await
            .map_err(|error| DomainError::from_pg("fragment fence sequence readiness", error))?;
        let last_value: i64 = sequence.get("last_value");
        let is_called: bool = sequence.get("is_called");
        let next_value = if is_called {
            last_value.checked_add(1)
        } else {
            Some(last_value)
        };
        let cutover_at: Option<SystemTime> = row.get("cutover_at");
        let write_capability = FragmentWriteCapability::decode(
            row.get("write_capability"),
            row.get("provider_write_authority_revision"),
        )?;

        Ok(FragmentLifecycleReadiness {
            provisioned: true,
            schema_version: row.get("schema_version"),
            backfill_state: row.get("backfill_state"),
            cutover_at_present: cutover_at.is_some(),
            lifecycle_enabled: row.get("lifecycle_enabled"),
            write_capability,
            same_database: row.get::<_, String>("database_identity") == self.database_identity,
            sequence_headroom: evidence.is_some()
                && next_value.is_some_and(|value| value > max_fence),
            unresolved_rows,
        })
    }

    /// Enable lifecycle routing, refusing unless the cell is provably ready.
    ///
    /// The two schema CHECKs would reject the write anyway; this returns the
    /// typed [`DomainError::NotReady`] with the actual reason instead of a
    /// SQLSTATE 23514 an operator has to decode.
    pub async fn enable_lifecycle(&self) -> Result<(), DomainError> {
        let readiness = self.readiness().await?;
        // Checked BEFORE the general readiness verdict, because
        // `ready_for_lifecycle()` already folds the same upper bound in — so
        // behind it this arm was unreachable and its specific diagnostic could
        // never be emitted (INV-EF P2-1, INV-EE's dead-fallback class). An
        // operator whose cell is ahead of the binary needs to be told to roll
        // the binary forward, not handed a field dump.
        //
        // The `provisioned` conjunct is defence, not load-bearing: an
        // unprovisioned readiness reports `schema_version: 0`, which cannot
        // exceed the compiled version anyway. It stays so the arm reads as
        // "a provisioned cell is ahead of us" rather than relying on that
        // arithmetic remaining true if the sentinel ever changes.
        if readiness.provisioned && readiness.schema_version > schema::FRAGMENT_SCHEMA_VERSION {
            return Err(DomainError::NotReady(format!(
                "cell fragment schema_version {} is newer than this binary's {}; \
                 roll the binary forward before enabling lifecycle routing",
                readiness.schema_version,
                schema::FRAGMENT_SCHEMA_VERSION
            )));
        }
        if !readiness.ready_for_lifecycle() {
            return Err(DomainError::NotReady(format!(
                "provisioned={} schema_version={} backfill_state={} cutover={} \
                 same_database={} sequence_headroom={} unresolved_rows={}; \
                 lifecycle routing requires a completed backfill, a classified residue set, \
                 the cutover marker, proved sequence headroom, and a positive same-database \
                 match",
                readiness.provisioned,
                readiness.schema_version,
                readiness.backfill_state,
                readiness.cutover_at_present,
                readiness.same_database,
                readiness.sequence_headroom,
                readiness.unresolved_rows
            )));
        }
        let client = self.checkout().await?;
        // This is a single autocommit UPDATE rather than a transaction, so its
        // two anchors are pre/post write rather than locked/settled.
        failpoint!("cutover.enable_lifecycle.pre_write")?;
        client
            .execute(
                "UPDATE lore_fragment_schema_state \
                    SET lifecycle_enabled = true, updated_at = clock_timestamp() \
                  WHERE id = 1",
                &[],
            )
            .await
            .map_err(|error| DomainError::from_pg("fragment lifecycle enable", error))?;
        failpoint!("cutover.enable_lifecycle.post_write")?;
        Ok(())
    }

    /// Persist the cell-wide `write-claims-v1` requirement.
    ///
    /// This is intentionally not called by server boot or schema installation.
    /// The operator-facing caller must first rotate provider write credentials
    /// so every older replica loses write authority. The database records and
    /// exact-attests the supplied non-secret revision; it cannot prove the
    /// external credential revocation itself.
    pub async fn require_write_claims(
        &self,
        cutover: &FragmentWriteCapabilityCutover,
    ) -> Result<(), DomainError> {
        let readiness = self.readiness().await?;
        if readiness.schema_version != schema::FRAGMENT_SCHEMA_VERSION
            || !readiness.lifecycle_enabled
            || !readiness.ready_for_lifecycle()
        {
            return Err(DomainError::NotReady(
                "write-claims-v1 cutover requires exact current SCHEMA-118 readiness and enabled lifecycle routing"
                    .to_owned(),
            ));
        }
        let mut client = self.checkout().await?;
        let tx = client.transaction().await.map_err(|error| {
            DomainError::from_pg("fragment write capability cutover begin", error)
        })?;
        let row = tx
            .query_one(
                "SELECT write_capability, provider_write_authority_revision \
                   FROM lore_fragment_schema_state WHERE id = 1 FOR UPDATE",
                &[],
            )
            .await
            .map_err(|error| {
                DomainError::from_pg("fragment write capability cutover lock", error)
            })?;
        failpoint!("cutover.require_claims.locked")?;
        let current = FragmentWriteCapability::decode(
            row.get("write_capability"),
            row.get("provider_write_authority_revision"),
        )?;
        match current {
            FragmentWriteCapability::Optional => {
                tx.execute(
                    "UPDATE lore_fragment_schema_state \
                        SET write_capability = $1, provider_write_authority_revision = $2, \
                            write_claims_required_at = clock_timestamp(), \
                            updated_at = clock_timestamp() \
                      WHERE id = 1 AND write_capability = $3",
                    &[
                        &schema::WRITE_CAPABILITY_CLAIMS_REQUIRED,
                        &cutover.provider_write_authority_revision,
                        &schema::WRITE_CAPABILITY_OPTIONAL,
                    ],
                )
                .await
                .map_err(|error| {
                    DomainError::from_pg("fragment write capability cutover", error)
                })?;
            }
            FragmentWriteCapability::ClaimsRequired {
                provider_write_authority_revision,
            } if provider_write_authority_revision == cutover.provider_write_authority_revision => {
            }
            FragmentWriteCapability::ClaimsRequired { .. } => {
                return Err(DomainError::PreconditionRejected {
                    reason: "fragment_write_authority_revision_mismatch".to_owned(),
                    reason_version: 1,
                });
            }
        }
        classify_commit(
            tx.commit().await,
            "fragment write capability cutover commit",
        )?;
        failpoint!("cutover.require_claims.settled")?;
        Ok(())
    }

    /// The one batched resolver. `query`, `get_metadata`, `get`, `copy`, push
    /// proof, and repository stats all consume this and nothing else.
    ///
    /// A positive result requires one coherent snapshot proving all five
    /// clauses of CR-031's resolution contract: the repository is live, the
    /// exact association is live, the head resolves one current `Staged` or
    /// `Remote` epoch, the matching manifest is complete, and no newer
    /// repository generation invalidates it.
    ///
    /// The generation clause is `<=`, not `=`, and the difference is
    /// load-bearing. `lore_domain_repositories.generation` advances on ordinary
    /// repository mutations including a metadata CAS, so an equality test would
    /// make **every** fragment in a repository `Absent` the moment anyone
    /// changed its metadata. What the association's stored generation is for is
    /// ordering evidence: it can never legitimately be *ahead* of the
    /// repository, and a row that is would be a delayed write against a
    /// repository incarnation this one has already moved past. Repository
    /// tombstone is handled by the `r.state` clause instead, which is the
    /// permanent fence CR-031 actually relies on, since repository identities
    /// are never reused.
    ///
    /// **One statement, so one snapshot.** `lore-postgres` never sets an
    /// isolation level and runs at READ COMMITTED, where a single statement
    /// sees one consistent snapshot. That is exactly the coherence the contract
    /// asks for, so no explicit transaction is opened and no connection is held
    /// past the query — which matters because this is the hottest path in the
    /// system and a hydration of one large asset is thousands of calls.
    ///
    /// This answers from committed lifecycle proof. It does **not** promise a
    /// later GET cannot race physical deletion or independent provider loss;
    /// once a failure is observed, [`Self::mark_missing`] commits before a
    /// later positive resolution can be returned.
    pub async fn resolve(
        &self,
        repository_id: &[u8],
        context: &[u8],
        hashes: &[Vec<u8>],
    ) -> Result<Vec<FragmentResolution>, DomainError> {
        let requested = hashes
            .iter()
            .cloned()
            .map(|hash| FragmentQueryRequest {
                hash,
                context: context.to_vec(),
            })
            .collect::<Vec<_>>();
        Ok(self
            .resolve_scoped(repository_id, &requested)
            .await?
            .into_iter()
            .map(|scoped| {
                if scoped.exact_context_readable {
                    scoped.resolution
                } else {
                    FragmentResolution {
                        hash: scoped.resolution.hash,
                        verdict: FragmentVerdict::Absent,
                    }
                }
            })
            .collect())
    }

    /// Resolve exact-context and repository-partition matches together.
    /// One statement covers the whole batch and one ordinal row is returned for
    /// every request, so concurrent lifecycle changes cannot make the two
    /// projections disagree within one call.
    pub async fn resolve_query_matches(
        &self,
        repository_id: &[u8],
        requested: &[FragmentQueryRequest],
    ) -> Result<Vec<FragmentQueryMatch>, DomainError> {
        Ok(self
            .resolve_scoped(repository_id, requested)
            .await?
            .into_iter()
            .map(|scoped| FragmentQueryMatch {
                hash: scoped.resolution.hash,
                exact_context_readable: scoped.exact_context_readable,
                partition_readable: scoped.resolution.verdict.is_readable(),
            })
            .collect())
    }

    /// Resolve a readable hash anywhere in the live repository partition.
    /// This preserves the zero-context source form accepted by
    /// `ImmutableStore::copy` while still using the same scoped resolver and
    /// canonical readability joins as exact-context reads.
    pub async fn resolve_partition(
        &self,
        repository_id: &[u8],
        hashes: &[Vec<u8>],
    ) -> Result<Vec<FragmentResolution>, DomainError> {
        let requested = hashes
            .iter()
            .cloned()
            .map(|hash| FragmentQueryRequest {
                hash,
                context: Vec::new(),
            })
            .collect::<Vec<_>>();
        Ok(self
            .resolve_scoped(repository_id, &requested)
            .await?
            .into_iter()
            .map(|scoped| scoped.resolution)
            .collect())
    }

    /// Aggregate only fragments that satisfy the same repository,
    /// association, head, manifest, and disposition clauses as `resolve`.
    /// Manifest sizes are immutable authority, so no provider I/O or repair
    /// transaction is needed on this read path.
    pub async fn repository_stats(
        &self,
        repository_id: &[u8],
    ) -> Result<FragmentRepositoryStats, DomainError> {
        let client = self.checkout().await?;
        let row = client
            .query_one(
                "WITH readable AS ( \
                     SELECT DISTINCT a.hash, e.size_payload, e.size_content \
                       FROM lore_fragment_associations AS a \
                       JOIN lore_domain_repositories AS r ON r.repository_id = a.repository_id \
                       JOIN lore_fragment_lifecycle AS l ON l.hash = a.hash \
                       JOIN lore_fragment_epochs AS e \
                         ON e.hash = l.hash AND e.epoch = l.current_epoch \
                      WHERE a.repository_id = $1 \
                        AND a.state = $2 \
                        AND r.state = $3 \
                        AND a.repository_generation <= r.generation \
                        AND l.state = ANY($5) \
                        AND l.manifest_id = e.manifest_id \
                        AND e.disposition = $4 \
                 ) \
                 SELECT count(*)::bigint AS fragment_count, \
                        coalesce(sum(size_payload), 0)::bigint AS payload_bytes, \
                        coalesce(sum(size_content), 0)::bigint AS content_bytes \
                   FROM readable",
                &[
                    &repository_id,
                    &schema::ASSOCIATION_LIVE,
                    &STATE_LIVE,
                    &schema::DISPOSITION_CURRENT_ELIGIBLE,
                    &FragmentLifecycleState::readable_bits().as_slice(),
                ],
            )
            .await
            .map_err(|error| DomainError::from_pg("fragment repository stats", error))?;
        let read = |column: &str| -> Result<u64, DomainError> {
            let value: i64 = row.try_get(column).map_err(|error| {
                DomainError::Internal(format!(
                    "fragment repository stats column {column}: {error}"
                ))
            })?;
            u64::try_from(value).map_err(|_| {
                DomainError::Internal(format!(
                    "fragment repository stats column {column} is negative"
                ))
            })
        };
        Ok(FragmentRepositoryStats {
            fragment_count: read("fragment_count")?,
            payload_bytes: read("payload_bytes")?,
            content_bytes: read("content_bytes")?,
        })
    }

    /// Rebuild the repairable metering projection from lifecycle authority.
    ///
    /// This maintenance transaction takes table locks in the same broad order
    /// as fragment writers take row classes: lifecycle heads, immutable epoch
    /// evidence, associations, then the projection. The first lock is
    /// `EXCLUSIVE`, not `SHARE`: it must conflict with the table-level `ROW
    /// SHARE` acquired by every lifecycle-head `SELECT FOR UPDATE`/`FOR SHARE`,
    /// including a lookup that finds no row. That waits out every writer before
    /// the epoch lock and prevents a writer from crossing the snapshot while
    /// the remaining locks are acquired. Ordinary `ACCESS SHARE` readers stay
    /// available. No provider or file I/O occurs in this coordinator.
    ///
    /// The returned count is the exact number of authoritative projection
    /// rows installed. A `Missing` or deleting head retains its current epoch's
    /// metering evidence until physical purge commits. `Tombstoned` heads and
    /// `PURGED` epochs cannot enter the canonical projection.
    pub async fn rebuild_metering_projection(&self) -> Result<u64, DomainError> {
        let mut client = self.checkout().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|error| DomainError::from_pg("fragment metering rebuild begin", error))?;
        tx.batch_execute(
            "LOCK TABLE lore_fragment_lifecycle IN EXCLUSIVE MODE; \
             LOCK TABLE lore_fragment_epochs IN SHARE MODE; \
             LOCK TABLE lore_fragment_associations IN SHARE MODE; \
             LOCK TABLE lore_fragment_lifecycle_metering IN SHARE ROW EXCLUSIVE MODE;",
        )
        .await
        .map_err(|error| DomainError::from_pg("fragment metering rebuild locks", error))?;
        failpoint!("metering.rebuild.locked")?;

        // Materialise the authority predicate once. Every later statement
        // consumes this exact relation, so upsert and stale-row deletion cannot
        // drift onto subtly different lifecycle eligibility rules.
        tx.execute(
            "CREATE TEMPORARY TABLE lore_fragment_metering_rebuild ON COMMIT DROP AS \
             SELECT l.hash, l.current_epoch AS epoch, e.payload_flags, \
                    e.size_payload, e.size_content, e.authority \
               FROM lore_fragment_lifecycle AS l \
               JOIN lore_fragment_epochs AS e \
                 ON e.hash = l.hash AND e.epoch = l.current_epoch \
              WHERE e.disposition = $1 \
                AND ( \
                    (l.state = ANY($2) AND l.manifest_id = e.manifest_id) \
                    OR l.state = ANY($3) \
                )",
            &[
                &schema::DISPOSITION_CURRENT_ELIGIBLE,
                &FragmentLifecycleState::readable_bits().as_slice(),
                &[
                    FragmentLifecycleState::Missing.bits(),
                    FragmentLifecycleState::DeletingChildren.bits(),
                    FragmentLifecycleState::DeletingPayload.bits(),
                ]
                .as_slice(),
            ],
        )
        .await
        .map_err(|error| DomainError::from_pg("fragment metering rebuild projection", error))?;

        let authoritative = tx
            .query_one(
                "SELECT count(*)::bigint AS count FROM lore_fragment_metering_rebuild",
                &[],
            )
            .await
            .map_err(|error| DomainError::from_pg("fragment metering rebuild count", error))?
            .try_get::<_, i64>("count")
            .map_err(|error| {
                DomainError::Internal(format!(
                    "fragment metering rebuild count column is invalid: {error}"
                ))
            })?;
        let authoritative = u64::try_from(authoritative).map_err(|_| {
            DomainError::Internal("fragment metering rebuild count is negative".to_owned())
        })?;

        let upserted = tx
            .execute(
                "INSERT INTO lore_fragment_lifecycle_metering ( \
                     hash, epoch, payload_flags, size_payload, size_content, authority \
                 ) \
                 SELECT hash, epoch, payload_flags, size_payload, size_content, authority \
                   FROM lore_fragment_metering_rebuild \
                  ORDER BY hash \
                 ON CONFLICT (hash) DO UPDATE \
                    SET epoch = EXCLUDED.epoch, \
                        payload_flags = EXCLUDED.payload_flags, \
                        size_payload = EXCLUDED.size_payload, \
                        size_content = EXCLUDED.size_content, \
                        authority = EXCLUDED.authority, \
                        verified_at = clock_timestamp()",
                &[],
            )
            .await
            .map_err(|error| DomainError::from_pg("fragment metering rebuild upsert", error))?;
        if upserted != authoritative {
            return Err(DomainError::Internal(format!(
                "fragment metering rebuild upserted {upserted} rows for {authoritative} authoritative rows"
            )));
        }

        let stale = tx
            .query_one(
                "SELECT count(*)::bigint AS count \
                   FROM lore_fragment_lifecycle_metering AS m \
                  WHERE NOT EXISTS ( \
                        SELECT 1 FROM lore_fragment_metering_rebuild AS r WHERE r.hash = m.hash \
                  )",
                &[],
            )
            .await
            .map_err(|error| DomainError::from_pg("fragment metering rebuild stale count", error))?
            .try_get::<_, i64>("count")
            .map_err(|error| {
                DomainError::Internal(format!(
                    "fragment metering rebuild stale count column is invalid: {error}"
                ))
            })?;
        let stale = u64::try_from(stale).map_err(|_| {
            DomainError::Internal("fragment metering rebuild stale count is negative".to_owned())
        })?;
        let removed = tx
            .execute(
                "DELETE FROM lore_fragment_lifecycle_metering AS m \
                  WHERE NOT EXISTS ( \
                        SELECT 1 FROM lore_fragment_metering_rebuild AS r WHERE r.hash = m.hash \
                  )",
                &[],
            )
            .await
            .map_err(|error| {
                DomainError::from_pg("fragment metering rebuild stale delete", error)
            })?;
        if removed != stale {
            return Err(DomainError::Internal(format!(
                "fragment metering rebuild removed {removed} rows for {stale} stale rows"
            )));
        }

        let final_count = tx
            .query_one(
                "SELECT count(*)::bigint AS count FROM lore_fragment_lifecycle_metering",
                &[],
            )
            .await
            .map_err(|error| DomainError::from_pg("fragment metering rebuild final count", error))?
            .try_get::<_, i64>("count")
            .map_err(|error| {
                DomainError::Internal(format!(
                    "fragment metering rebuild final count column is invalid: {error}"
                ))
            })?;
        let final_count = u64::try_from(final_count).map_err(|_| {
            DomainError::Internal("fragment metering rebuild final count is negative".to_owned())
        })?;
        if final_count != authoritative {
            return Err(DomainError::Internal(format!(
                "fragment metering rebuild retained {final_count} rows for {authoritative} authoritative rows"
            )));
        }

        let mismatch = tx
            .query_opt(
                "SELECT 1 \
                   FROM lore_fragment_lifecycle_metering AS m \
                   FULL JOIN lore_fragment_metering_rebuild AS r USING (hash) \
                  WHERE m.hash IS NULL OR r.hash IS NULL \
                     OR m.epoch IS DISTINCT FROM r.epoch \
                     OR m.payload_flags IS DISTINCT FROM r.payload_flags \
                     OR m.size_payload IS DISTINCT FROM r.size_payload \
                     OR m.size_content IS DISTINCT FROM r.size_content \
                     OR m.authority IS DISTINCT FROM r.authority \
                  LIMIT 1",
                &[],
            )
            .await
            .map_err(|error| {
                DomainError::from_pg("fragment metering rebuild verification", error)
            })?;
        if mismatch.is_some() {
            return Err(DomainError::Internal(
                "fragment metering rebuild verification found a projection mismatch".to_owned(),
            ));
        }

        classify_commit(tx.commit().await, "fragment metering rebuild commit")?;
        failpoint!("metering.rebuild.settled")?;
        Ok(authoritative)
    }

    async fn resolve_scoped(
        &self,
        repository_id: &[u8],
        requested: &[FragmentQueryRequest],
    ) -> Result<Vec<ScopedFragmentResolution>, DomainError> {
        if requested.is_empty() {
            return Ok(Vec::new());
        }
        let hashes = requested
            .iter()
            .map(|request| request.hash.as_slice())
            .collect::<Vec<_>>();
        let contexts = requested
            .iter()
            .map(|request| request.context.as_slice())
            .collect::<Vec<_>>();
        let client = self.checkout().await?;
        let rows = client
            .query(
                "WITH requested AS ( \
                     SELECT request.hash, request.context, request.ordinality \
                       FROM unnest($2::bytea[], $3::bytea[]) WITH ORDINALITY \
                            AS request(hash, context, ordinality) \
                 ) \
                 SELECT request.ordinality     AS ordinality, \
                        request.hash           AS hash, \
                        bool_or(a.context = request.context) AS exact_context_readable, \
                        coalesce( \
                            min(a.association_epoch) FILTER (WHERE a.context = request.context), \
                            min(a.association_epoch) \
                        ) AS association_epoch, \
                        l.current_epoch      AS current_epoch, \
                        l.state              AS state, \
                        l.manifest_id        AS manifest_id, \
                        l.last_fence         AS last_fence, \
                        e.authority          AS authority, \
                        e.object_key         AS object_key, \
                        e.size_payload       AS size_payload, \
                        e.size_content       AS size_content, \
                        e.decoded_hash       AS decoded_hash, \
                        e.payload_flags      AS payload_flags \
                   FROM requested AS request \
                   JOIN lore_fragment_associations AS a ON a.hash = request.hash \
                   JOIN lore_domain_repositories   AS r ON r.repository_id = a.repository_id \
                   JOIN lore_fragment_lifecycle    AS l ON l.hash = a.hash \
                   JOIN lore_fragment_epochs       AS e \
                        ON e.hash = l.hash AND e.epoch = l.current_epoch \
                  WHERE a.repository_id = $1 \
                    AND a.state         = $4 \
                    AND r.state         = $5 \
                    AND a.repository_generation <= r.generation \
                    AND l.state = ANY($7) \
                    AND l.manifest_id = e.manifest_id \
                    AND e.disposition = $6 \
                  GROUP BY request.ordinality, request.hash, l.current_epoch, l.state, \
                           l.manifest_id, l.last_fence, e.authority, e.object_key, \
                           e.manifest_id, e.size_payload, e.size_content, e.decoded_hash, \
                           e.payload_flags \
                  ORDER BY request.ordinality",
                &[
                    &repository_id,
                    &hashes,
                    &contexts,
                    &schema::ASSOCIATION_LIVE,
                    &STATE_LIVE,
                    &schema::DISPOSITION_CURRENT_ELIGIBLE,
                    &FragmentLifecycleState::readable_bits().as_slice(),
                ],
            )
            .await
            .map_err(|error| DomainError::from_pg("fragment resolve", error))?;

        let mut readable: BTreeMap<i64, (bool, FragmentVerdict)> = BTreeMap::new();
        for row in rows {
            let hash: Vec<u8> = row.get("hash");
            let state = FragmentLifecycleState::from_bits(row.get("state"))?;
            let authority = EpochAuthority::from_bits(row.get("authority"))?;
            let manifest_id: Vec<u8> = row.get("manifest_id");
            readable.insert(
                row.get("ordinality"),
                (
                    row.get("exact_context_readable"),
                    FragmentVerdict::Readable {
                        witness: EpochWitness {
                            hash,
                            epoch: row.get("current_epoch"),
                            state,
                            manifest_id: Some(manifest_id.clone()),
                            fence: row.get("last_fence"),
                        },
                        manifest: FragmentManifest {
                            authority,
                            object_key: row.get("object_key"),
                            manifest_id,
                            size_payload: row.get("size_payload"),
                            size_content: row.get("size_content"),
                            decoded_hash: row.get("decoded_hash"),
                            payload_flags: row.get("payload_flags"),
                        },
                        association_epoch: row.get("association_epoch"),
                    },
                ),
            );
        }

        // Answer in the caller's order, with a verdict for every hash asked
        // about. A missing row is `Absent`, indistinguishable from a fenced or
        // tombstoned one on purpose.
        Ok(requested
            .iter()
            .enumerate()
            .map(|(index, request)| {
                let ordinal = i64::try_from(index + 1).unwrap_or(i64::MAX);
                let (exact_context_readable, verdict) = readable
                    .remove(&ordinal)
                    .unwrap_or((false, FragmentVerdict::Absent));
                ScopedFragmentResolution {
                    resolution: FragmentResolution {
                        hash: request.hash.clone(),
                        verdict,
                    },
                    exact_context_readable,
                }
            })
            .collect())
    }

    // -----------------------------------------------------------------------
    // Begin/commit pairs
    // -----------------------------------------------------------------------

    /// Publish a `PreparingRemote` intent for a direct write, then release
    /// everything.
    ///
    /// A normal first write takes the legacy bare-hash key so an existing cell's
    /// objects stay addressable; only a repair successor gets an immutable
    /// epoch key. The caller performs its conditional create-or-verify against
    /// that key with no database resource held.
    pub async fn begin_direct_write(
        &self,
        hash: &[u8],
        legacy_object_key: &str,
        claim: FragmentWriteClaimInput,
    ) -> Result<BeginOutcome, DomainError> {
        if legacy_object_key != legacy_hash_key(hash) {
            return Err(DomainError::InvalidInput(
                "direct write legacy object key does not match the fragment hash".to_owned(),
            ));
        }
        self.begin_publication(
            hash,
            EpochAuthority::Remote,
            Some(legacy_object_key),
            Some(&claim),
            false,
        )
        .await
    }

    /// Publish a `PreparingStage` intent. Allocates an epoch and fence without
    /// publishing any positive association; the file write, validation, flush,
    /// atomic finalize, and directory durability all happen outside Postgres.
    pub async fn begin_stage(&self, hash: &[u8]) -> Result<BeginOutcome, DomainError> {
        self.begin_publication(hash, EpochAuthority::Staged, None, None, false)
            .await
    }

    /// Claim the exact `Missing` epoch, state, and fence for a repair.
    ///
    /// Both explicit repair and put-on-`Missing` come through here: a client
    /// re-offering bytes whose FragmentId matches a `Missing` head is a
    /// first-class repair, which is what preserves today's cheap self-heal
    /// (`store/immutable_store.rs:955-980`) without ever overwriting the legacy
    /// key. The successor takes a greater epoch and its own immutable key.
    pub async fn claim_repair(
        &self,
        hash: &[u8],
        claim: FragmentWriteClaimInput,
    ) -> Result<BeginOutcome, DomainError> {
        let legacy_object_key = legacy_hash_key(hash);
        self.begin_publication(
            hash,
            EpochAuthority::Remote,
            Some(&legacy_object_key),
            Some(&claim),
            true,
        )
        .await
    }

    /// Authorize one exact prepared claim immediately before its bounded
    /// charge/send future is polled.
    pub async fn authorize_write_claim(
        &self,
        claim: &FragmentWriteClaim,
    ) -> Result<AuthorizedFragmentWrite, DomainError> {
        let local_started = Instant::now();
        let mut client = self.checkout().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|error| DomainError::from_pg("fragment write authorization begin", error))?;
        let mut sequence = LockSequence::new();
        let head = lock_fragment_head(&tx, &mut sequence, &claim.hash).await?;
        failpoint!("claim.authorize.locked")?;
        let lineage_matches = head.as_ref().is_some_and(|head| {
            head.current_epoch == claim.epoch
                && head.last_fence == claim.fence
                && head.state == FragmentLifecycleState::PreparingRemote
                && head.active_operation.as_deref().is_some_and(|token| {
                    (token == DIRECT_WRITE_NORMAL_OPERATION
                        && claim.object_key == legacy_hash_key(&claim.hash))
                        || (token == DIRECT_WRITE_REPAIR_OPERATION
                            && claim.object_key == repair_epoch_key(&claim.hash, claim.epoch))
                })
        });
        if !lineage_matches {
            settle_write_claim_locked(&tx, &mut sequence, claim, FragmentWriteSettlement::NoSend)
                .await?;
            classify_commit(tx.commit().await, "fragment write lineage refusal commit")?;
            return Err(DomainError::PreconditionRejected {
                reason: "fragment_write_lineage_moved".to_owned(),
                reason_version: 1,
            });
        }

        let Some(locked) = lock_write_claim_identity(
            &tx,
            &mut sequence,
            &claim.logical_request_id,
            &claim.attempt_id,
        )
        .await?
        else {
            return Err(DomainError::NotReady(
                "fragment write claim is absent".to_owned(),
            ));
        };
        if locked.claim != *claim {
            return Err(DomainError::InvalidInput(
                "fragment write claim binding does not match durable state".to_owned(),
            ));
        }
        if locked.state != FragmentWriteClaimState::Prepared {
            return Err(DomainError::PreconditionRejected {
                reason: "fragment_write_claim_not_prepared".to_owned(),
                reason_version: 1,
            });
        }
        let database_now: SystemTime = tx
            .query_one("SELECT clock_timestamp()", &[])
            .await
            .map_err(|error| DomainError::from_pg("fragment write authorization clock", error))?
            .get(0);
        let Some(database_budget) = claim.send_not_after.duration_since(database_now).ok() else {
            settle_write_claim_locked(&tx, &mut sequence, claim, FragmentWriteSettlement::NoSend)
                .await?;
            classify_commit(tx.commit().await, "fragment write expired refusal commit")?;
            return Err(DomainError::PreconditionRejected {
                reason: "fragment_write_send_deadline_expired".to_owned(),
                reason_version: 1,
            });
        };
        tx.execute(
            "UPDATE lore_fragment_write_claims \
                SET state = $3, authorized_at = clock_timestamp() \
              WHERE logical_request_id = $1 AND attempt_id = $2 AND state = $4",
            &[
                &claim.logical_request_id.as_slice(),
                &claim.attempt_id.as_slice(),
                &FragmentWriteClaimState::Sending.bits(),
                &FragmentWriteClaimState::Prepared.bits(),
            ],
        )
        .await
        .map_err(|error| DomainError::from_pg("fragment write authorize", error))?;
        classify_commit(tx.commit().await, "fragment write authorization commit")?;
        failpoint!("claim.authorize.settled")?;
        Ok(AuthorizedFragmentWrite {
            send_budget: database_budget.saturating_sub(local_started.elapsed()),
        })
    }

    /// Settle a claim in its own short transaction when no lifecycle
    /// publication transaction is available.
    pub async fn settle_write_claim(
        &self,
        claim: &FragmentWriteClaim,
        settlement: FragmentWriteSettlement,
    ) -> Result<(), DomainError> {
        let mut client = self.checkout().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|error| DomainError::from_pg("fragment write settlement begin", error))?;
        let mut sequence = LockSequence::new();
        let _ = lock_fragment_head(&tx, &mut sequence, &claim.hash).await?;
        failpoint!("claim.settle.locked")?;
        settle_write_claim_locked(&tx, &mut sequence, claim, settlement).await?;
        classify_commit(tx.commit().await, "fragment write settlement commit")?;
        failpoint!("claim.settle.settled")?;
        Ok(())
    }

    /// Prune a bounded batch of terminal write claims using database time.
    ///
    /// No scheduler calls this yet. Phase 6B or an operations package must
    /// explicitly invoke it. Prepared, Sending, and Ambiguous are never
    /// selected by age. A Decisive claim is deleted only when its exact target
    /// digest and size have been copied into durable epoch evidence; NoSend is
    /// safe after terminal retention because it never names a cleanup target.
    ///
    /// # Forward progress
    ///
    /// The plan query anti-joins against active claims, so a hash carrying a
    /// live barrier contributes its NoSend claims and withholds only its
    /// Decisive ones — exactly the rows the loop would skip. Selection, not
    /// ordering, is what fixes this: the order is by `settled_at`, so without
    /// the anti-join the oldest Decisive rows on one blocked hash win every
    /// slot on every pass, get skipped in the loop, and starve younger prunable
    /// rows on every other hash. A hash under continuous write traffic
    /// regenerates those claims indefinitely, so the batch never self-clears.
    ///
    /// The anti-join is a selection filter, not the safety property. It runs
    /// unlocked on a pooled connection, so a hash can gain an active claim
    /// between the plan and the head lock. `write_claim_barrier_for_prune` is
    /// the locked check that actually gates the delete.
    ///
    /// It sits inside the Decisive arm, not over the whole predicate, because
    /// the loop exempts NoSend from the barrier. A hash-wide anti-join over
    /// both arms would be stricter than the loop it feeds: it would stop
    /// selecting NoSend rows on a barriered hash that the loop would happily
    /// prune, so a hash under continuous write traffic would accumulate them
    /// forever. The plan and the loop must agree on strictness in both
    /// directions.
    ///
    /// **One skip the plan does not model.** The loop also skips a candidate
    /// whose hash has no lifecycle head, and nothing excludes that candidate
    /// from selection, so such a row would re-occupy a slot on every pass
    /// forever — the same head-of-line shape the anti-join removes. It is
    /// unreachable today: no statement deletes from `lore_fragment_lifecycle`
    /// (the two that look like it delete from `lore_fragment_lifecycle_metering`,
    /// a different table), and no foreign key ties the two tables, so a claim
    /// cannot outlive its head. Anyone adding a lifecycle delete path owes this
    /// plan query a matching head-existence term.
    pub async fn prune_terminal_write_claims(
        &self,
        batch: FragmentWriteClaimPruneBatch,
    ) -> Result<FragmentWriteClaimPruneReport, DomainError> {
        let client = self.checkout().await?;
        // The anti-join's state list is written as SQL literals, and must stay
        // that way. `0, 1, 3` are Prepared, Sending and Ambiguous, and the text
        // matches `lore_fragment_write_claims_barrier`'s partial predicate
        // exactly. Bound as a `$n` array instead, the planner cannot prove
        // partial-index implication, and a forced generic plan degrades the
        // subquery to a sequential scan of the whole claims table for every
        // candidate row. Measured on PostgreSQL 16.15: literals keep the index
        // scan, a bound array does not.
        //
        // The barrier arms mirror `write_claim_barrier_for_prune` exactly:
        // Prepared blocks on `send_not_after`, Sending and Ambiguous block on
        // `hard_not_after`. A uniform `hard_not_after` test would be stricter
        // than the loop and would newly starve any hash holding a Prepared row
        // whose send window has closed but whose hard window has not.
        let rows = client
            .query(
                "SELECT claim.logical_request_id, claim.attempt_id, claim.hash, claim.state \
                   FROM lore_fragment_write_claims AS claim \
                  WHERE claim.settled_at <= clock_timestamp() \
                                           - ($3::bigint * interval '1 millisecond') \
                    AND (claim.state = $1 \
                         OR (claim.state = $2 AND EXISTS ( \
                             SELECT 1 FROM lore_fragment_epochs AS epoch \
                              WHERE epoch.hash = claim.hash \
                                AND epoch.epoch = claim.epoch \
                                AND epoch.authority = claim.authority \
                                AND epoch.object_key = claim.object_key \
                                AND epoch.provider_body_blake3 = claim.body_blake3 \
                                AND epoch.provider_body_size = claim.body_size \
                                AND epoch.provider_claim_fence = claim.fence) \
                             AND NOT EXISTS ( \
                                 SELECT 1 FROM lore_fragment_write_claims AS active \
                                  WHERE active.hash = claim.hash \
                                    AND active.state IN (0, 1, 3) \
                                    AND (CASE WHEN active.state = 0 \
                                              THEN active.send_not_after \
                                              ELSE active.hard_not_after END) \
                                        > clock_timestamp()))) \
                  ORDER BY settled_at, logical_request_id, attempt_id \
                  LIMIT $4",
                &[
                    &FragmentWriteClaimState::NoSend.bits(),
                    &FragmentWriteClaimState::Decisive.bits(),
                    &batch.terminal_retention_millis,
                    &batch.max_claims,
                ],
            )
            .await
            .map_err(|error| DomainError::from_pg("fragment write claim prune plan", error))?;
        let candidates = rows
            .into_iter()
            .map(|row| {
                Ok(FragmentWriteClaimPruneCandidate {
                    logical_request_id: fixed_bytes::<16>(
                        row.get("logical_request_id"),
                        "fragment write prune logical request id",
                    )?,
                    attempt_id: fixed_bytes::<16>(
                        row.get("attempt_id"),
                        "fragment write prune attempt id",
                    )?,
                    hash: row.get("hash"),
                    state: FragmentWriteClaimState::from_bits(row.get("state"))?,
                })
            })
            .collect::<Result<Vec<_>, DomainError>>()?;
        drop(client);

        let mut report = FragmentWriteClaimPruneReport::new(candidates.len())?;
        for candidate in candidates {
            let mut client = self.checkout().await?;
            let tx = client
                .transaction()
                .await
                .map_err(|error| DomainError::from_pg("fragment write claim prune begin", error))?;
            let mut sequence = LockSequence::new();
            let head = lock_fragment_head(&tx, &mut sequence, &candidate.hash).await?;
            // The head row lock is the serialisation point that both the
            // barrier probe and the deletes rest on: every writer of
            // `lore_fragment_write_claims` takes it first, which is what lets
            // the probe read without `FOR UPDATE`. A hash with no head row
            // offers no such lock, so that premise would be false and this loop
            // must not proceed. `lock_fragment_head`'s own doc requires any
            // caller that proceeds on `None` to re-derive its argument; this
            // one cannot, so it stops instead of inheriting one.
            if head.is_none() {
                classify_commit(tx.commit().await, "headless claim prune release commit")?;
                report.record_missing_evidence();
                continue;
            }
            let blocked_until =
                write_claim_barrier_for_prune(&tx, &mut sequence, &candidate.hash).await?;
            // The barrier gates the Decisive arm only. A NoSend claim records
            // that no provider send occurred, so it names no cleanup target:
            // `write_claim_inventory_locked` contributes nothing for a NoSend
            // row, and obliterate therefore derives no purge target from one.
            // Another claim being in flight on this hash has no bearing on it,
            // and its delete is already an exact CAS on its own row.
            if candidate.state == FragmentWriteClaimState::Decisive && blocked_until.is_some() {
                classify_commit(
                    tx.commit().await,
                    "blocked claim inventory normalization commit",
                )?;
                report.record_blocked();
                continue;
            }
            // The candidate's own row, not a hash-wide scan: the exact target
            // this delete must bind is the candidate's own claim, and the
            // hash-wide inventory was only ever searched for it by identity.
            // Taken on both arms, not just the Decisive one that reads it, so
            // every prune delete locks its row before its own CAS.
            let locked = lock_write_claim_identity(
                &tx,
                &mut sequence,
                &candidate.logical_request_id,
                &candidate.attempt_id,
            )
            .await?;
            let deleted = match candidate.state {
                FragmentWriteClaimState::NoSend => {
                    tx.execute(
                        "DELETE FROM lore_fragment_write_claims \
                          WHERE logical_request_id = $1 AND attempt_id = $2 AND state = $3 \
                            AND settled_at <= clock_timestamp() \
                                - ($4::bigint * interval '1 millisecond')",
                        &[
                            &candidate.logical_request_id.as_slice(),
                            &candidate.attempt_id.as_slice(),
                            &FragmentWriteClaimState::NoSend.bits(),
                            &batch.terminal_retention_millis,
                        ],
                    )
                    .await
                }
                FragmentWriteClaimState::Decisive => {
                    let Some(target) = locked
                        .filter(|locked| locked.state == FragmentWriteClaimState::Decisive)
                        .map(|locked| locked.claim)
                    else {
                        classify_commit(tx.commit().await, "claim inventory normalization commit")?;
                        report.record_missing_evidence();
                        continue;
                    };
                    // Pruning a Decisive claim on a predecessor epoch removes
                    // obliterate's only handle on that older provider object,
                    // because `capture_obliterate_intent_locked` reads exactly
                    // one epoch row (the head's current epoch) and takes every
                    // other target from this table. That is deliberate, not a
                    // leak: CR-031 scopes obliterate to the current epoch's
                    // exact object key, and assigns quarantined and orphaned
                    // predecessor epochs to a later GC package. Their epoch rows
                    // survive quarantine (`commit_publication` updates
                    // `disposition`, it does not delete), so GC keeps a durable
                    // source that never depended on a claim row. What is removed
                    // here is an incidental handle. No GC package exists yet.
                    let body_size = i64::try_from(target.body_size).map_err(|_| {
                        DomainError::Internal(
                            "fragment write cleanup target size exceeds i64".to_owned(),
                        )
                    })?;
                    tx.execute(
                        "DELETE FROM lore_fragment_write_claims AS claim \
                          WHERE claim.logical_request_id = $1 AND claim.attempt_id = $2 \
                            AND claim.hash = $3 AND claim.epoch = $4 AND claim.fence = $5 \
                            AND claim.authority = $6 AND claim.object_key = $7 \
                            AND claim.body_blake3 = $8 AND claim.body_size = $9 \
                            AND claim.state = $10 \
                            AND claim.settled_at <= clock_timestamp() \
                                - ($11::bigint * interval '1 millisecond') \
                            AND EXISTS (SELECT 1 FROM lore_fragment_epochs AS epoch \
                                 WHERE epoch.hash = $3 AND epoch.epoch = $4 \
                                   AND epoch.authority = $6 AND epoch.object_key = $7 \
                                   AND epoch.provider_body_blake3 = $8 \
                                   AND epoch.provider_body_size = $9 \
                                   AND epoch.provider_claim_fence = $5)",
                        &[
                            &candidate.logical_request_id.as_slice(),
                            &candidate.attempt_id.as_slice(),
                            // The hash whose head this loop locked, not the
                            // locked row's own copy, so the delete's scope and
                            // the lock's scope agree by construction.
                            &candidate.hash,
                            &target.epoch,
                            &target.fence,
                            &target.authority.bits(),
                            &target.object_key,
                            &target.body_blake3.as_slice(),
                            &body_size,
                            &FragmentWriteClaimState::Decisive.bits(),
                            &batch.terminal_retention_millis,
                        ],
                    )
                    .await
                }
                // The plan query selects only NoSend and Decisive, so this arm
                // is unreachable. Count it rather than dropping it silently, so
                // the report's counters keep summing to `examined`.
                _ => {
                    classify_commit(tx.commit().await, "claim inventory normalization commit")?;
                    report.record_missing_evidence();
                    continue;
                }
            }
            .map_err(|error| DomainError::from_pg("fragment write claim prune delete", error))?;
            classify_commit(tx.commit().await, "fragment write claim prune commit")?;
            // A zero-row delete means the row moved out from under the plan
            // between the batch read and the head lock. Counting it keeps the
            // counters summing to `examined` instead of losing the candidate.
            if deleted == 0 {
                report.record_missing_evidence();
            } else {
                report.record_pruned(deleted);
            }
        }
        Ok(report)
    }

    /// Publish the result of a direct write or a repair.
    ///
    /// Opens a **new** short transaction, takes rows in F-032-3 order, and
    /// revalidates the exact epoch, state, manifest, and fence captured at
    /// begin. Anything that moved makes this a fenced loser with no mutation.
    pub async fn commit_remote(
        &self,
        intent: &FragmentIntent,
        observation: IoObservation,
        settlement: FragmentWriteSettlement,
    ) -> Result<CommitVerdict, DomainError> {
        if settlement == FragmentWriteSettlement::NoSend {
            return Err(DomainError::InvalidInput(
                "a no-send claim cannot publish a remote observation".to_owned(),
            ));
        }
        self.commit_publication(
            intent,
            observation,
            EpochAuthority::Remote,
            Some(settlement),
        )
        .await
    }

    /// Publish `Staged` plus its manifest, metering, and association
    /// atomically, once the file is finalized and durable.
    pub async fn commit_staged(
        &self,
        intent: &FragmentIntent,
        observation: IoObservation,
    ) -> Result<CommitVerdict, DomainError> {
        self.commit_publication(intent, observation, EpochAuthority::Staged, None)
            .await
    }

    /// Publish a repair successor by the same head CAS `commit_remote` uses,
    /// quarantining the predecessor epoch rather than overwriting it.
    pub async fn commit_repair(
        &self,
        intent: &FragmentIntent,
        observation: IoObservation,
        settlement: FragmentWriteSettlement,
    ) -> Result<CommitVerdict, DomainError> {
        if settlement == FragmentWriteSettlement::NoSend {
            return Err(DomainError::InvalidInput(
                "a no-send claim cannot publish a repair observation".to_owned(),
            ));
        }
        self.commit_publication(
            intent,
            observation,
            EpochAuthority::Remote,
            Some(settlement),
        )
        .await
    }

    /// Begin a promotion from `Staged` to `Remote`.
    ///
    /// The head stays `Staged` while the upload runs, so reads keep using the
    /// staged authority and nothing becomes unreadable during promotion. Only
    /// [`Self::commit_promotion`] switches it, and only after exact object
    /// verification.
    pub async fn begin_promotion(&self, hash: &[u8]) -> Result<BeginOutcome, DomainError> {
        let mut client = self.checkout().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|error| DomainError::from_pg("promotion begin", error))?;
        let mut sequence = LockSequence::new();
        let Some(head) = lock_fragment_head(&tx, &mut sequence, hash).await? else {
            return Err(DomainError::PreconditionRejected {
                reason: "fragment_head_absent".to_owned(),
                reason_version: 1,
            });
        };
        failpoint!("promotion.begin.locked")?;
        if head.state != FragmentLifecycleState::Staged {
            return Ok(BeginOutcome::Fenced(format!(
                "promotion requires a Staged head; this one is {}",
                head.state.label()
            )));
        }
        // Promotion allocates a NEW epoch, and must.
        //
        // The remote object is a different representation from the staged file:
        // different authority, different key. `lore_fragment_epochs` rows are
        // immutable, and the publication insert is `ON CONFLICT DO NOTHING`, so
        // reusing the staged epoch would leave the epoch row saying
        // `authority = Staged` with the staged path while the head said
        // `Remote`. The resolver would then hand readers a staged path that
        // cleanup is free to delete.
        //
        // The staged predecessor is quarantined by the same rule every other
        // publication uses, which is what makes its bytes reclaimable once the
        // reader leases over it drain.
        let epoch = next_fence(&tx).await?;
        let fence = next_fence(&tx).await?;
        stamp_operation_fence(&tx, hash, fence).await?;
        classify_commit(tx.commit().await, "promotion begin commit")?;
        failpoint!("promotion.begin.settled")?;
        Ok(BeginOutcome::Admitted(Box::new(FragmentIntent {
            hash: hash.to_vec(),
            epoch,
            fence,
            object_key: legacy_hash_key(hash),
            authority: EpochAuthority::Remote,
            direct_write_kind: None,
            write_claim: None,
            captured: Some(EpochWitness {
                hash: hash.to_vec(),
                epoch: head.current_epoch,
                state: head.state,
                manifest_id: head.manifest_id,
                fence: head.last_fence,
            }),
        })))
    }

    /// Switch a promoted head to `Remote` after exact object verification.
    ///
    /// Promotion does **not** share the other commits' failure handling, and the
    /// difference is the point. Everywhere else, an unusable observation means
    /// the representation the head names is gone, so committing `Missing` is
    /// the honest answer. In promotion the head names a `Staged` file that is
    /// still there and still good; only the *upload* failed. Routing this
    /// through the shared path would let a transient provider error demote a
    /// perfectly readable fragment and move every associated repository's
    /// lifecycle generation with it.
    ///
    /// It also needs no repository fanout: `Staged` and `Remote` are both
    /// readable, so a successful promotion crosses no readability boundary and
    /// moves no lifecycle scalar.
    pub async fn commit_promotion(
        &self,
        intent: &FragmentIntent,
        observation: IoObservation,
    ) -> Result<CommitVerdict, DomainError> {
        let manifest = match observation {
            IoObservation::Valid(manifest) => manifest,
            IoObservation::Unusable(_) => {
                return self.abandon_promotion(intent).await;
            }
        };
        self.commit_publication(
            intent,
            IoObservation::Valid(manifest),
            EpochAuthority::Remote,
            None,
        )
        .await
    }

    /// Give up on a promotion without touching the staged representation.
    ///
    /// A new fence is stamped so the abandoned intent cannot commit later, and
    /// the head stays exactly where it was.
    async fn abandon_promotion(
        &self,
        intent: &FragmentIntent,
    ) -> Result<CommitVerdict, DomainError> {
        let mut client = self.checkout().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|error| DomainError::from_pg("promotion abandon begin", error))?;
        let mut sequence = LockSequence::new();
        let Some(head) = lock_fragment_head(&tx, &mut sequence, &intent.hash).await? else {
            return Ok(CommitVerdict::Fenced);
        };
        if head.last_fence != intent.fence {
            return Ok(CommitVerdict::Fenced);
        }
        let fence = next_fence(&tx).await?;
        stamp_operation_fence(&tx, &intent.hash, fence).await?;
        classify_commit(tx.commit().await, "promotion abandon commit")?;
        Ok(CommitVerdict::Abandoned)
    }

    /// Commit durable `Missing` evidence for a fragment whose authority was
    /// observed absent, truncated, corrupt, or undecodable here.
    ///
    /// This retains associations and the last manifest for diagnosis and for
    /// repair to build on. It is deliberately not a row deletion: deleting the
    /// state row is what leaves today's association residue, so a fragment is
    /// advertised present to every pusher and unreadable on every read.
    pub async fn mark_missing(
        &self,
        witness: &EpochWitness,
        diagnostic: MissingDiagnostic,
    ) -> Result<CommitVerdict, DomainError> {
        let mut client = self.checkout().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|error| DomainError::from_pg("mark missing begin", error))?;
        let mut sequence = LockSequence::new();
        // Planned and locked BEFORE the head, because a readable-to-Missing
        // transition writes repository rows (position 1) and the head is
        // position 4. See `plan_lifecycle_fanout`.
        let fanout = plan_lifecycle_fanout(&tx, &witness.hash).await?;
        lock_lifecycle_fanout(&tx, &mut sequence, &fanout).await?;
        let Some(head) = lock_fragment_head(&tx, &mut sequence, &witness.hash).await? else {
            return Ok(CommitVerdict::Fenced);
        };
        failpoint!("lifecycle.mark_missing.locked")?;
        if !head.matches(witness) {
            return Ok(CommitVerdict::Fenced);
        }
        let was_readable = head.state.is_readable();
        let fence = next_fence(&tx).await?;
        tx.execute(
            "UPDATE lore_fragment_lifecycle \
                SET state = $2, manifest_id = NULL, last_fence = $3, \
                    active_operation = NULL, diagnostic_class = $4, \
                    updated_at = clock_timestamp() \
              WHERE hash = $1",
            &[
                &witness.hash,
                &FragmentLifecycleState::Missing.bits(),
                &fence,
                &diagnostic.bits(),
            ],
        )
        .await
        .map_err(|error| DomainError::from_pg("mark missing update", error))?;
        if was_readable {
            // Readable to unreadable is a lifecycle transition, so every
            // live-associated repository's scalar moves atomically with it —
            // and the growth check runs exactly here, because "did this
            // transaction lock what it is about to affect" only has force when
            // it is about to affect something. `mark_missing` on an already
            // non-readable head moves no scalar and touches no association, so
            // confirming would only manufacture a spurious `Contention` under
            // unrelated concurrent churn.
            //
            // `begin_obliterate` is the one path that confirms unconditionally,
            // because it retires associations whether or not the head was
            // readable, so it always affects something (INV-EF P1-1).
            let confirmed = confirm_lifecycle_fanout(&tx, &witness.hash, &fanout).await?;
            apply_lifecycle_generation(&tx, &confirmed).await?;
        }
        classify_commit(tx.commit().await, "mark missing commit")?;
        failpoint!("lifecycle.mark_missing.settled")?;
        Ok(CommitVerdict::Published)
    }

    /// Bind `(FragmentId, repository, context)` and move the repository's
    /// association scalar.
    ///
    /// Refuses against a deleting or tombstoned head: a new association must
    /// never be published while the hash is being taken down. `Missing` is
    /// deliberately *not* a deleting state, so an association may still be
    /// created against a missing fragment and repaired later.
    pub async fn create_association(
        &self,
        hash: &[u8],
        repository_id: &[u8],
        context: &[u8],
    ) -> Result<CommitVerdict, DomainError> {
        failpoint!("association.create.entry")?;
        let mut client = self.checkout().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|error| DomainError::from_pg("association create begin", error))?;
        let mut sequence = LockSequence::new();
        let Some(repository) =
            crate::domain::lock_order::lock_repository(&tx, &mut sequence, repository_id).await?
        else {
            return Err(DomainError::PreconditionRejected {
                reason: "repository_absent".to_owned(),
                reason_version: 1,
            });
        };
        failpoint!("association.create.locked")?;
        if repository.state != STATE_LIVE {
            return Ok(CommitVerdict::Fenced);
        }
        if let Some(head) = lock_fragment_head(&tx, &mut sequence, hash).await?
            && (head.state.is_deleting() || head.state == FragmentLifecycleState::Tombstoned)
        {
            return Ok(CommitVerdict::Fenced);
        }
        sequence.enter(LockClass::Associations)?;
        let association_epoch = next_fence(&tx).await?;
        tx.execute(
            "INSERT INTO lore_fragment_associations ( \
                 hash, repository_id, context, association_epoch, state, repository_generation \
             ) VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (hash, repository_id, context) DO UPDATE \
                SET association_epoch     = EXCLUDED.association_epoch, \
                    state                 = EXCLUDED.state, \
                    repository_generation = EXCLUDED.repository_generation, \
                    updated_at            = clock_timestamp()",
            &[
                &hash,
                &repository_id,
                &context,
                &association_epoch,
                &schema::ASSOCIATION_LIVE,
                &repository.generation,
            ],
        )
        .await
        .map_err(|error| DomainError::from_pg("association create insert", error))?;
        bump_association_generation(&tx, repository_id).await?;
        classify_commit(tx.commit().await, "association create commit")?;
        failpoint!("association.create.settled")?;
        Ok(CommitVerdict::Published)
    }

    /// Bind an association only while the exact readable head captured by a
    /// resolver still holds. This is the copy/dedup publication path: unlike
    /// [`Self::create_association`], it refuses `Missing` and every other
    /// witness movement atomically with the insert.
    pub async fn create_association_if_current(
        &self,
        witness: &EpochWitness,
        repository_id: &[u8],
        context: &[u8],
    ) -> Result<CommitVerdict, DomainError> {
        let mut client = self.checkout().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|error| DomainError::from_pg("guarded association begin", error))?;
        let mut sequence = LockSequence::new();
        let Some(repository) =
            crate::domain::lock_order::lock_repository(&tx, &mut sequence, repository_id).await?
        else {
            return Ok(CommitVerdict::Fenced);
        };
        if repository.state != STATE_LIVE {
            return Ok(CommitVerdict::Fenced);
        }
        let Some(head) = lock_fragment_head(&tx, &mut sequence, &witness.hash).await? else {
            return Ok(CommitVerdict::Fenced);
        };
        failpoint!("association.create_guarded.locked")?;
        if !head.matches(witness) || !head.state.is_readable() {
            return Ok(CommitVerdict::Fenced);
        }
        sequence.enter(LockClass::Associations)?;
        let association_epoch = next_fence(&tx).await?;
        tx.execute(
            "INSERT INTO lore_fragment_associations ( \
                 hash, repository_id, context, association_epoch, state, repository_generation \
             ) VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (hash, repository_id, context) DO UPDATE \
                SET association_epoch     = EXCLUDED.association_epoch, \
                    state                 = EXCLUDED.state, \
                    repository_generation = EXCLUDED.repository_generation, \
                    updated_at            = clock_timestamp()",
            &[
                &witness.hash,
                &repository_id,
                &context,
                &association_epoch,
                &schema::ASSOCIATION_LIVE,
                &repository.generation,
            ],
        )
        .await
        .map_err(|error| DomainError::from_pg("guarded association insert", error))?;
        bump_association_generation(&tx, repository_id).await?;
        classify_commit(tx.commit().await, "guarded association commit")?;
        failpoint!("association.create_guarded.settled")?;
        Ok(CommitVerdict::Published)
    }

    /// Tombstone one association and move the repository's association scalar.
    pub async fn tombstone_association(
        &self,
        hash: &[u8],
        repository_id: &[u8],
        context: &[u8],
    ) -> Result<CommitVerdict, DomainError> {
        failpoint!("association.tombstone.entry")?;
        let mut client = self.checkout().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|error| DomainError::from_pg("association tombstone begin", error))?;
        let mut sequence = LockSequence::new();
        if crate::domain::lock_order::lock_repository(&tx, &mut sequence, repository_id)
            .await?
            .is_none()
        {
            return Ok(CommitVerdict::Fenced);
        }
        failpoint!("association.tombstone.locked")?;
        sequence.enter(LockClass::Associations)?;
        let updated = tx
            .execute(
                "UPDATE lore_fragment_associations \
                    SET state = $4, updated_at = clock_timestamp() \
                  WHERE hash = $1 AND repository_id = $2 AND context = $3 AND state = $5",
                &[
                    &hash,
                    &repository_id,
                    &context,
                    &schema::ASSOCIATION_TOMBSTONED,
                    &schema::ASSOCIATION_LIVE,
                ],
            )
            .await
            .map_err(|error| DomainError::from_pg("association tombstone update", error))?;
        if updated == 0 {
            return Ok(CommitVerdict::Fenced);
        }
        bump_association_generation(&tx, repository_id).await?;
        classify_commit(tx.commit().await, "association tombstone commit")?;
        failpoint!("association.tombstone.settled")?;
        Ok(CommitVerdict::Published)
    }

    /// Atomically retire exactly one association and, only for the last live
    /// association, publish durable ownership of the coordinated deletion.
    ///
    /// The returned value owns every field needed after this transaction. No
    /// connection, transaction, or lock crosses a wait, recursive child call,
    /// staged cleanup, or provider request.
    pub async fn begin_obliterate(
        &self,
        hash: &[u8],
        repository_id: &[u8],
        context: &[u8],
        provider_write_authority_revision: &str,
    ) -> Result<FragmentObliterateBegin, DomainError> {
        if !valid_write_authority_revision(provider_write_authority_revision) {
            return Err(DomainError::InvalidInput(
                "coordinated obliterate requires a valid provider write-authority revision"
                    .to_owned(),
            ));
        }
        failpoint!("obliterate.begin.entry")?;
        let mut client = self.checkout().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|error| DomainError::from_pg("coordinated obliterate begin", error))?;
        let mut sequence = LockSequence::new();

        // Plan the complete live fanout before taking any row, then add the
        // requesting repository so an absent/foreign request serializes with a
        // concurrent bind of that exact association. Repository order remains
        // the first F-032-3 class and is globally sorted.
        let mut fanout = plan_lifecycle_fanout(&tx, hash).await?;
        if !fanout.iter().any(|id| id.as_slice() == repository_id) {
            if fanout.len() == MAX_LIFECYCLE_GENERATION_FANOUT {
                return Err(DomainError::PreconditionRejected {
                    reason: "lifecycle_generation_fanout_limit".to_owned(),
                    reason_version: 1,
                });
            }
            fanout.push(repository_id.to_vec());
            fanout.sort_unstable();
        }
        lock_lifecycle_fanout(&tx, &mut sequence, &fanout).await?;
        let Some(head) = lock_fragment_head(&tx, &mut sequence, hash).await? else {
            classify_commit(tx.commit().await, "absent coordinated obliterate commit")?;
            return Ok(FragmentObliterateBegin::NoOp);
        };
        let confirmed = confirm_lifecycle_fanout(&tx, hash, &fanout).await?;
        // Placed once, here, rather than beside each of this method's eight
        // commit sites: past this point the fanout and the head are both held,
        // so one anchor covers every exit.
        failpoint!("obliterate.begin.locked")?;

        let association = tx
            .query_opt(
                "SELECT association_epoch, state FROM lore_fragment_associations \
                  WHERE hash = $1 AND repository_id = $2 AND context = $3",
                &[&hash, &repository_id, &context],
            )
            .await
            .map_err(|error| {
                DomainError::from_pg("coordinated obliterate association lock", error)
            })?;

        if head.state.is_deleting() {
            let Some(row) = association else {
                classify_commit(tx.commit().await, "foreign obliterate retry commit")?;
                return Ok(FragmentObliterateBegin::NoOp);
            };
            let owns = row.get::<_, i16>("state") == schema::ASSOCIATION_TOMBSTONED
                && row.get::<_, i64>("association_epoch") == head.last_fence;
            if !owns {
                classify_commit(tx.commit().await, "foreign obliterate retry commit")?;
                return Ok(FragmentObliterateBegin::NoOp);
            }
            require_claims_write_capability(&tx, provider_write_authority_revision).await?;
            let intent = capture_obliterate_intent_locked(
                &tx,
                &mut sequence,
                hash,
                repository_id,
                context,
                &head,
                provider_write_authority_revision,
            )
            .await?;
            let blocked_until = obliterate_blocked_until_locked(&tx, &intent).await?;
            classify_commit(tx.commit().await, "coordinated obliterate retry commit")?;
            return Ok(match blocked_until {
                Some(blocked_until) => FragmentObliterateBegin::Blocked {
                    intent: Box::new(intent),
                    blocked_until,
                },
                None => FragmentObliterateBegin::Ready(Box::new(intent)),
            });
        }
        if head.state == FragmentLifecycleState::Tombstoned {
            classify_commit(tx.commit().await, "tombstoned obliterate replay commit")?;
            return Ok(FragmentObliterateBegin::NoOp);
        }

        let Some(association) = association else {
            classify_commit(tx.commit().await, "absent association obliterate commit")?;
            return Ok(FragmentObliterateBegin::NoOp);
        };
        if association.get::<_, i16>("state") != schema::ASSOCIATION_LIVE {
            classify_commit(tx.commit().await, "tombstoned foreign obliterate commit")?;
            return Ok(FragmentObliterateBegin::NoOp);
        }
        let live_association_count: i64 = tx
            .query_one(
                "SELECT count(*)::bigint FROM lore_fragment_associations \
                  WHERE hash = $1 AND state = $2",
                &[&hash, &schema::ASSOCIATION_LIVE],
            )
            .await
            .map_err(|error| {
                DomainError::from_pg("coordinated obliterate live association count", error)
            })?
            .get(0);
        if live_association_count > 1 {
            sequence.enter(LockClass::Associations)?;
            let association_fence = next_fence(&tx).await?;
            let updated = tx
                .execute(
                    "UPDATE lore_fragment_associations \
                        SET state = $4, association_epoch = $5, updated_at = clock_timestamp() \
                      WHERE hash = $1 AND repository_id = $2 AND context = $3 AND state = $6",
                    &[
                        &hash,
                        &repository_id,
                        &context,
                        &schema::ASSOCIATION_TOMBSTONED,
                        &association_fence,
                        &schema::ASSOCIATION_LIVE,
                    ],
                )
                .await
                .map_err(|error| DomainError::from_pg("association-only obliterate", error))?;
            if updated != 1 {
                return Err(DomainError::Contention(
                    "the exact fragment association moved while it was locked".to_owned(),
                ));
            }
            bump_association_generation(&tx, repository_id).await?;
            classify_commit(tx.commit().await, "association-only obliterate commit")?;
            return Ok(FragmentObliterateBegin::AssociationOnly);
        }
        if live_association_count != 1 {
            return Err(DomainError::Internal(
                "a locked live association was absent from the live-association count".to_owned(),
            ));
        }

        require_claims_write_capability(&tx, provider_write_authority_revision).await?;
        let origin = obliterate_origin_from_head(&head)?;
        let deletion_fence = next_fence(&tx).await?;
        let active_operation = encode_obliterate_operation(origin);
        let deleting_head = FragmentHeadLock {
            current_epoch: head.current_epoch,
            state: FragmentLifecycleState::DeletingChildren,
            manifest_id: None,
            last_fence: deletion_fence,
            active_operation: Some(active_operation.to_vec()),
        };
        let intent = capture_obliterate_intent_locked(
            &tx,
            &mut sequence,
            hash,
            repository_id,
            context,
            &deleting_head,
            provider_write_authority_revision,
        )
        .await?;
        let blocked_until = obliterate_blocked_until_locked(&tx, &intent).await?;
        sequence.enter(LockClass::Associations)?;
        let updated_association = tx
            .execute(
                "UPDATE lore_fragment_associations \
                    SET state = $4, association_epoch = $5, updated_at = clock_timestamp() \
                  WHERE hash = $1 AND repository_id = $2 AND context = $3 AND state = $6",
                &[
                    &hash,
                    &repository_id,
                    &context,
                    &schema::ASSOCIATION_TOMBSTONED,
                    &deletion_fence,
                    &schema::ASSOCIATION_LIVE,
                ],
            )
            .await
            .map_err(|error| DomainError::from_pg("owned obliterate association", error))?;
        if updated_association != 1 {
            return Err(DomainError::Contention(
                "the exact fragment association moved while it was locked".to_owned(),
            ));
        }
        let updated_head = tx
            .execute(
                "UPDATE lore_fragment_lifecycle \
                    SET state = $2, manifest_id = NULL, last_fence = $3, \
                        active_operation = $4, diagnostic_class = 0, \
                        updated_at = clock_timestamp() \
                  WHERE hash = $1 AND current_epoch = $5 AND state = $6 AND last_fence = $7",
                &[
                    &hash,
                    &FragmentLifecycleState::DeletingChildren.bits(),
                    &deletion_fence,
                    &active_operation.as_slice(),
                    &head.current_epoch,
                    &head.state.bits(),
                    &head.last_fence,
                ],
            )
            .await
            .map_err(|error| DomainError::from_pg("owned obliterate head transition", error))?;
        if updated_head != 1 {
            return Err(DomainError::Contention(
                "the fragment head moved while it was locked".to_owned(),
            ));
        }
        bump_association_generation(&tx, repository_id).await?;
        if head.state.is_readable() {
            apply_lifecycle_generation(&tx, &confirmed).await?;
        }
        classify_commit(tx.commit().await, "owned obliterate begin commit")?;
        // The ownership-publishing exit only. This method's other successful
        // exits (NoOp, foreign/coordinated retry, tombstoned replay) are
        // decisive answers about a deletion someone else owns, so they are not
        // anchored; WP-109's push/obliterate races all run through this one.
        failpoint!("obliterate.begin.settled")?;
        Ok(match blocked_until {
            Some(blocked_until) => FragmentObliterateBegin::Blocked {
                intent: Box::new(intent),
                blocked_until,
            },
            None => FragmentObliterateBegin::Ready(Box::new(intent)),
        })
    }

    /// Revalidate child-work ownership and advance to physical payload purge.
    pub async fn commit_obliterate_children(
        &self,
        intent: &FragmentObliterateIntent,
    ) -> Result<CommitVerdict, DomainError> {
        if intent.phase != FragmentObliteratePhase::Children {
            return Err(DomainError::InvalidInput(
                "obliterate children commit requires a children-phase intent".to_owned(),
            ));
        }
        let mut client = self.checkout().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|error| DomainError::from_pg("obliterate children commit begin", error))?;
        let mut sequence = LockSequence::new();
        if crate::domain::lock_order::lock_repository(
            &tx,
            &mut sequence,
            &intent.ownership.repository_id,
        )
        .await?
        .is_none()
        {
            return Ok(CommitVerdict::Fenced);
        }
        let Some(head) = lock_fragment_head(&tx, &mut sequence, &intent.ownership.hash).await?
        else {
            return Ok(CommitVerdict::Fenced);
        };
        failpoint!("obliterate.children.locked")?;
        if head.state != FragmentLifecycleState::DeletingChildren
            || !owned_obliterate_association_locked(&tx, &intent.ownership).await?
        {
            return Ok(CommitVerdict::Fenced);
        }
        require_claims_write_capability(&tx, &intent.provider_write_authority_revision).await?;
        let current = capture_obliterate_intent_locked(
            &tx,
            &mut sequence,
            &intent.ownership.hash,
            &intent.ownership.repository_id,
            &intent.ownership.context,
            &head,
            &intent.provider_write_authority_revision,
        )
        .await?;
        if current != *intent
            || obliterate_blocked_until_locked(&tx, &current)
                .await?
                .is_some()
        {
            return Ok(CommitVerdict::Fenced);
        }
        let updated = tx
            .execute(
                "UPDATE lore_fragment_lifecycle SET state = $2, updated_at = clock_timestamp() \
                  WHERE hash = $1 AND state = $3 AND last_fence = $4 \
                    AND active_operation = $5",
                &[
                    &intent.ownership.hash,
                    &FragmentLifecycleState::DeletingPayload.bits(),
                    &FragmentLifecycleState::DeletingChildren.bits(),
                    &intent.ownership.fence,
                    &encode_obliterate_operation(intent.origin).as_slice(),
                ],
            )
            .await
            .map_err(|error| DomainError::from_pg("obliterate children transition", error))?;
        if updated != 1 {
            return Ok(CommitVerdict::Fenced);
        }
        classify_commit(tx.commit().await, "obliterate children commit")?;
        failpoint!("obliterate.children.settled")?;
        Ok(CommitVerdict::Published)
    }

    /// Publish `Tombstoned` only after every captured exact target has a proof.
    pub async fn commit_obliterate_payload(
        &self,
        intent: &FragmentObliterateIntent,
        proofs: &[FragmentPurgeProof],
    ) -> Result<CommitVerdict, DomainError> {
        if intent.phase != FragmentObliteratePhase::Payload {
            return Err(DomainError::InvalidInput(
                "obliterate payload commit requires a payload-phase intent".to_owned(),
            ));
        }
        let mut proved = proofs
            .iter()
            .map(|proof| proof.target.clone())
            .collect::<Vec<_>>();
        proved.sort_unstable();
        proved.dedup();
        if proved != intent.purge_targets {
            return Err(DomainError::PreconditionRejected {
                reason: "fragment_obliterate_purge_proof_mismatch".to_owned(),
                reason_version: 1,
            });
        }

        let mut client = self.checkout().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|error| DomainError::from_pg("obliterate payload commit begin", error))?;
        let mut sequence = LockSequence::new();
        if crate::domain::lock_order::lock_repository(
            &tx,
            &mut sequence,
            &intent.ownership.repository_id,
        )
        .await?
        .is_none()
        {
            return Ok(CommitVerdict::Fenced);
        }
        let Some(head) = lock_fragment_head(&tx, &mut sequence, &intent.ownership.hash).await?
        else {
            return Ok(CommitVerdict::Fenced);
        };
        failpoint!("obliterate.payload.locked")?;
        if head.state != FragmentLifecycleState::DeletingPayload
            || !owned_obliterate_association_locked(&tx, &intent.ownership).await?
        {
            return Ok(CommitVerdict::Fenced);
        }
        require_claims_write_capability(&tx, &intent.provider_write_authority_revision).await?;
        let current = capture_obliterate_intent_locked(
            &tx,
            &mut sequence,
            &intent.ownership.hash,
            &intent.ownership.repository_id,
            &intent.ownership.context,
            &head,
            &intent.provider_write_authority_revision,
        )
        .await?;
        if current != *intent
            || obliterate_blocked_until_locked(&tx, &current)
                .await?
                .is_some()
        {
            return Ok(CommitVerdict::Fenced);
        }

        for epoch in &intent.purge_evidence_epochs {
            let updated = tx
                .execute(
                    "UPDATE lore_fragment_epochs SET disposition = $3 \
                      WHERE hash = $1 AND epoch = $2 AND disposition <> $3",
                    &[&intent.ownership.hash, &epoch, &schema::DISPOSITION_PURGED],
                )
                .await
                .map_err(|error| DomainError::from_pg("obliterate epoch disposition", error))?;
            if updated != 1 {
                return Ok(CommitVerdict::Fenced);
            }
        }
        let removed_metering = tx
            .execute(
                "DELETE FROM lore_fragment_lifecycle_metering WHERE hash = $1",
                &[&intent.ownership.hash],
            )
            .await
            .map_err(|error| DomainError::from_pg("obliterate metering removal", error))?;
        if removed_metering != u64::from(intent.metering_present) {
            return Ok(CommitVerdict::Fenced);
        }
        let final_fence = next_fence(&tx).await?;
        let updated = tx
            .execute(
                "UPDATE lore_fragment_lifecycle \
                    SET state = $2, manifest_id = NULL, last_fence = $3, \
                        active_operation = NULL, diagnostic_class = 0, \
                        updated_at = clock_timestamp() \
                  WHERE hash = $1 AND current_epoch = $4 AND state = $5 \
                    AND last_fence = $6 AND active_operation = $7",
                &[
                    &intent.ownership.hash,
                    &FragmentLifecycleState::Tombstoned.bits(),
                    &final_fence,
                    &intent.current_epoch,
                    &FragmentLifecycleState::DeletingPayload.bits(),
                    &intent.ownership.fence,
                    &encode_obliterate_operation(intent.origin).as_slice(),
                ],
            )
            .await
            .map_err(|error| DomainError::from_pg("obliterate tombstone update", error))?;
        if updated != 1 {
            return Ok(CommitVerdict::Fenced);
        }
        classify_commit(tx.commit().await, "obliterate payload commit")?;
        failpoint!("obliterate.payload.settled")?;
        Ok(CommitVerdict::Published)
    }

    // -----------------------------------------------------------------------
    // Push witness
    // -----------------------------------------------------------------------

    /// Read the two per-repository scalars a push preflight captures.
    pub async fn capture_push_witness(
        &self,
        repository_id: &[u8],
    ) -> Result<Option<PushGenerationWitness>, DomainError> {
        let client = self.checkout().await?;
        let row = client
            .query_opt(
                "SELECT content_association_generation, fragment_lifecycle_generation \
                   FROM lore_domain_repositories WHERE repository_id = $1",
                &[&repository_id],
            )
            .await
            .map_err(|error| DomainError::from_pg("push witness capture", error))?;
        Ok(row.map(|row| PushGenerationWitness {
            content_association_generation: row.get("content_association_generation"),
            fragment_lifecycle_generation: row.get("fragment_lifecycle_generation"),
        }))
    }

    /// Revalidate a captured push witness **inside the caller's final-push
    /// transaction**, after its receptor, repository, and branch locks.
    ///
    /// This takes a borrowed transaction rather than opening its own precisely
    /// because it must be atomic with the push's own publication; it is the one
    /// method here that does not own its transaction, and it takes no lock
    /// class earlier than `Fragments`, so it cannot invert F-032-3.
    ///
    /// The unchanged fast path reads no fragment row at all. A changed
    /// lifecycle scalar permits only the bounded exact-required-fragment
    /// fallback, in sorted hash order, in one set-based query. A request above
    /// [`MAX_PUSH_FRAGMENT_REVALIDATIONS`] is refused **before** any fragment
    /// row is taken, so the refusal is known-no-commit rather than ambiguous.
    ///
    /// A required fragment satisfies the fallback when its head is readable
    /// **and** its current epoch is the one preflight captured *or one
    /// semantically equivalent to it* — CR-031:266's allowance, decided by
    /// [`equivalent_epochs`], which is what lets a push survive an unrelated
    /// `Staged`->`Remote` promotion of a fragment it requires. Deciding it
    /// costs one extra statement and only when an epoch actually moved.
    pub async fn revalidate_push_witness(
        &self,
        tx: &Transaction<'_>,
        sequence: &mut LockSequence,
        repository_id: &[u8],
        captured: PushGenerationWitness,
        required: &[RequiredFragment],
    ) -> Result<PushWitnessVerdict, DomainError> {
        let Some(row) = tx
            .query_opt(
                "SELECT content_association_generation, fragment_lifecycle_generation \
                   FROM lore_domain_repositories WHERE repository_id = $1",
                &[&repository_id],
            )
            .await
            .map_err(|error| DomainError::from_pg("push witness revalidate", error))?
        else {
            return Ok(PushWitnessVerdict::Aborted {
                reason: REQUIRED_FRAGMENT_CHANGED,
            });
        };
        let current = PushGenerationWitness {
            content_association_generation: row.get("content_association_generation"),
            fragment_lifecycle_generation: row.get("fragment_lifecycle_generation"),
        };
        // One pure decision rather than two ordered `if`s. The precedence — an
        // association move outranks a lifecycle move even when both happened —
        // is what keeps obliterate-then-recreate out of reach of the
        // equivalence allowance, and as two positional branches it was
        // protected only by a comment and provably untested. As an enum it is
        // pinnable offline, which `classify_push_witness` tests do.
        match classify_push_witness(captured, current) {
            PushWitnessChange::Neither => return Ok(PushWitnessVerdict::Unchanged),
            PushWitnessChange::AssociationMoved => {
                // The association set itself moved. The fallback revalidates
                // representations, not membership, so it cannot cover this.
                return Ok(PushWitnessVerdict::Aborted {
                    reason: REQUIRED_FRAGMENT_CHANGED,
                });
            }
            PushWitnessChange::LifecycleOnly => {}
        }
        // Count first. This is the whole reason the limit is a known refusal:
        // it is checked before a single fragment row is locked, so a refused
        // push has provably mutated nothing.
        if required.len() > MAX_PUSH_FRAGMENT_REVALIDATIONS {
            return Ok(PushWitnessVerdict::Aborted {
                reason: REQUIRED_FRAGMENT_REVALIDATION_LIMIT,
            });
        }
        if required.is_empty() {
            return Ok(PushWitnessVerdict::FallbackSatisfied { revalidated: 0 });
        }
        sequence.enter(LockClass::Fragments)?;
        // Sorted hash order, so two transactions over an overlapping required
        // set acquire the overlap in the same sequence (F-032-3's within-class
        // rule). One set-based query, never a row at a time, because CR-031
        // fixes that shape for the push path.
        //
        // This deliberately differs from `lock_lifecycle_fanout`, which
        // locks its rows one at a time, and the difference is worth stating
        // because it looks like an inconsistency. Postgres does not *guarantee*
        // that `ORDER BY ... FOR UPDATE` acquires locks in the sorted order:
        // under a concurrent update it can re-fetch a row and emit it later.
        // Here that is acceptable, because every transaction reaching this
        // statement scans the same primary-key index ascending over its own
        // subset, so two overlapping sets still meet the overlap in the same
        // relative order; and the only other lock class this transaction may
        // still take is the outbox insert, which is last. The fanout path has
        // neither property — it locks `lore_domain_repositories`, a class that
        // sits *earlier* in F-032-3 than the fragment rows a concurrent
        // transition may already hold — so it cannot rely on executor order and
        // takes its rows explicitly instead.
        let mut sorted: Vec<&RequiredFragment> = required.iter().collect();
        sorted.sort_by(|left, right| left.hash.cmp(&right.hash));
        let hashes: Vec<Vec<u8>> = sorted.iter().map(|item| item.hash.clone()).collect();
        let rows = tx
            .query(
                "SELECT hash, current_epoch, state FROM lore_fragment_lifecycle \
                  WHERE hash = ANY($1) ORDER BY hash FOR UPDATE",
                &[&hashes],
            )
            .await
            .map_err(|error| DomainError::from_pg("push fallback revalidate", error))?;
        let mut observed: BTreeMap<Vec<u8>, (i64, i16)> = BTreeMap::new();
        for row in rows {
            observed.insert(
                row.get("hash"),
                (row.get("current_epoch"), row.get("state")),
            );
        }
        // Required fragments whose head is readable but at a *different* epoch
        // than preflight saw. CR-031:266 allows these through only when the new
        // epoch is semantically equivalent; `equivalent_epochs` below decides
        // that, and the common case leaves this empty and issues no extra
        // query at all.
        let mut divergent: Vec<DivergentEpoch<'_>> = Vec::new();
        for item in &sorted {
            let Some((epoch, state)) = observed.get(&item.hash) else {
                return Ok(PushWitnessVerdict::Aborted {
                    reason: REQUIRED_FRAGMENT_CHANGED,
                });
            };
            let state = FragmentLifecycleState::from_bits(*state)?;
            if !state.is_readable() {
                return Ok(PushWitnessVerdict::Aborted {
                    reason: REQUIRED_FRAGMENT_CHANGED,
                });
            }
            if *epoch != item.epoch {
                divergent.push(DivergentEpoch {
                    hash: &item.hash,
                    captured: item.epoch,
                    current: *epoch,
                });
            }
        }
        if !divergent.is_empty() && !equivalent_epochs(tx, captured, current, &divergent).await? {
            return Ok(PushWitnessVerdict::Aborted {
                reason: REQUIRED_FRAGMENT_CHANGED,
            });
        }
        Ok(PushWitnessVerdict::FallbackSatisfied {
            revalidated: sorted.len(),
        })
    }

    // -----------------------------------------------------------------------
    // Staged reader leases
    // -----------------------------------------------------------------------

    /// Open one bounded lease covering a batch of staged fragments for one
    /// hydration request.
    ///
    /// One transaction and one lease row for the whole batch, not one per
    /// 256 KiB fragment. The lease tables themselves hold no position in
    /// F-032-3 and need none.
    ///
    /// **This method is no longer outside `LockSequence`, and CR-031's recorded
    /// exemption for it no longer holds as written.** That exemption's stated
    /// reason was that lease maintenance takes no domain row; it now takes head
    /// rows `FOR SHARE`, because the disposition guard below is otherwise a
    /// plain unlocked read that nothing orders against `commit_obliterate`. See
    /// [`lock_lease_member_heads`] for the lock-order argument and for why the
    /// single-statement alternative does not actually serialise.
    ///
    /// # What this refuses, and why each refusal is here
    ///
    /// INV-EF P2-6 found this method enforcing nothing it depends on. All three
    /// gaps are closed here, before Phase 5 gives it a caller:
    ///
    /// * **Wrong-length `lease_id`.** Refused as
    ///   [`DomainError::InvalidInput`] before any database work, against
    ///   [`schema::STAGED_LEASE_ID_LEN`]. The DDL's
    ///   `octet_length(lease_id) = 16` CHECK stays as the backstop, but a
    ///   caller must not have to read a bare 23514 to learn it passed a
    ///   16-byte-shaped argument that was not 16 bytes.
    /// * **A member that is not a live `Staged` epoch.** The "Staged only"
    ///   scoping was convention: nothing stopped a lease being opened over a
    ///   `Remote` epoch, or over an epoch that does not exist at all. Every
    ///   member is now checked against its own `lore_fragment_epochs` row and
    ///   must carry [`schema::AUTHORITY_STAGED`].
    ///
    ///   The check is against the **epoch's** authority and deliberately not
    ///   against the head. A reader that resolved to a staged epoch and is
    ///   overtaken by a promotion still holds that staged path and still needs
    ///   its bytes kept, so requiring `lore_fragment_lifecycle.current_epoch`
    ///   to still name the member would refuse exactly the lease the reader
    ///   most needs. An epoch row's `authority` is never rewritten once
    ///   published, so it is a stable fact to enforce against.
    ///
    ///   `disposition` is checked in exactly one direction:
    ///   [`schema::DISPOSITION_QUARANTINED`] is **admitted**, because a
    ///   superseded staged epoch whose reader is still mid-hydration is
    ///   precisely what a lease exists to protect, while
    ///   [`schema::DISPOSITION_PURGED`] is **refused**, because those bytes are
    ///   proved gone and a lease over them would report protection that cannot
    ///   exist. `commit_obliterate` reaches a `Staged` head and purges its
    ///   epoch, so this is a reachable state, not a theoretical one.
    ///
    ///   Two things follow, and the second is easy to overstate. The guard is
    ///   **one epoch deep and not sufficient on its own**, which is why the
    ///   head is checked too; but the head check in turn **subsumes it in every
    ///   state reachable today**, because `commit_obliterate` is the only purge
    ///   and it tombstones the head in the same transaction, and a `Tombstoned`
    ///   head is terminal. So this is not two independent guards right now — it
    ///   is one live guard plus one kept for the reachable-state set Phase 6
    ///   introduces, where GC reclaims noncurrent and quarantined epochs
    ///   without tombstoning anything.
    ///
    ///   The one-epoch-deep problem in full: `commit_obliterate` purges only the epoch
    ///   that was current when it began, so a fragment staged, then promoted,
    ///   then obliterated ends `Tombstoned` with its promoted epoch purged and
    ///   its staged predecessor still merely `QUARANTINED` — leasable by the
    ///   disposition test alone. [`lock_lease_member_heads`] refuses a
    ///   `Tombstoned` or deleting head, which closes that without touching the
    ///   promotion case: a promoted head is `Remote` and readable.
    /// * **A duplicate hash in `members`, or an empty batch.** The member table
    ///   is keyed `(lease_id, hash)`, so two entries for one hash would persist
    ///   as one row while the returned lease claimed both — protection silently
    ///   dropped for the other epoch, and a faithful retry then refused as a
    ///   member-set mismatch. An empty batch would create a live lease
    ///   protecting nothing that a reaper must later clean. Both are
    ///   [`DomainError::InvalidInput`], refused before any database work.
    /// * **A duplicate `lease_id`.** See the idempotency rule below.
    ///
    /// # Duplicate `lease_id`: a replay returns the existing lease unchanged
    ///
    /// Every fence-carrying peer in this module is idempotent under retry; this
    /// method was the exception, failing a duplicate with a bare primary-key
    /// violation. A lost commit acknowledgement is a first-class outcome here
    /// (that is what [`DomainError::OutcomeUnknown`] exists for), so a caller
    /// that retries the same `lease_id` must get its lease back rather than an
    /// error — otherwise a lease it may already hold looks like a failure to
    /// acquire one.
    ///
    /// The deliberate choice is **return the existing lease exactly as it
    /// stands**, with its original `reader_fence` and `deadline`, and refuse
    /// anything that is not a faithful replay:
    ///
    /// * A duplicate never allocates a second reader fence and never moves the
    ///   deadline. Extending a lease is a different operation, and letting a
    ///   retry do it silently would let a caller keep bytes alive forever by
    ///   re-acquiring.
    /// * A duplicate over a **different member set** is refused. That is an id
    ///   collision, not a retry, and returning success would hand the caller
    ///   protection over members the lease does not cover.
    /// * A duplicate over an **already-released** lease is refused. `terminal`
    ///   is what tells cleanup it may act, so a released lease must not be
    ///   resurrected into something that reads as live protection.
    ///
    /// **The scope of that last guarantee is the row's lifetime, and no
    /// longer.** Once a reaper deletes a terminal or hard-expired lease row,
    /// its id is indistinguishable from one never used, and a later acquire
    /// with that id creates a fresh lease. Nothing here records a retired id,
    /// and nothing should until the reaper exists to define what retirement
    /// means — that is Phase 6's. What this method does guarantee is that it
    /// never *itself* turns a released lease back into a live one:
    /// [`replay_staged_lease`] refuses a vanished row decisively rather than
    /// retryably, so a caller cannot loop its way from
    /// [`STAGED_LEASE_ALREADY_RELEASED`] into a new lease under the same id.
    ///
    /// The sequence value burnt by a refused or replayed acquire is a gap, and
    /// gaps are valid: a fence is an ordering token, not a count.
    pub async fn acquire_staged_leases(
        &self,
        lease_id: &[u8],
        members: &[(Vec<u8>, i64)],
        deadline: SystemTime,
    ) -> Result<StagedReaderLease, DomainError> {
        validate_lease_id(lease_id)?;
        validate_lease_members(members)?;
        let mut client = self.checkout().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|error| DomainError::from_pg("staged lease begin", error))?;
        let member_hashes: Vec<&[u8]> = members.iter().map(|(hash, _)| hash.as_slice()).collect();
        let member_epochs: Vec<i64> = members.iter().map(|(_, epoch)| *epoch).collect();
        // Take the heads first. This both refuses a member whose fragment is
        // obliterated or mid-deletion and serialises the epoch-disposition
        // check below against the only two writers that can move it.
        let mut sequence = LockSequence::new();
        lock_lease_member_heads(&tx, &mut sequence, &member_hashes).await?;
        failpoint!("lease.acquire.locked")?;
        // Scope check second, so a refusal happens before anything is written
        // and the transaction has nothing to undo.
        if tx
            .query_opt(
                "SELECT member.hash FROM unnest($1::bytea[], $2::bigint[]) AS member(hash, epoch) \
                   LEFT JOIN lore_fragment_epochs AS e \
                     ON e.hash = member.hash AND e.epoch = member.epoch \
                        AND e.authority = $3 AND e.disposition <> $4 \
                  WHERE e.hash IS NULL LIMIT 1",
                &[
                    &member_hashes,
                    &member_epochs,
                    &schema::AUTHORITY_STAGED,
                    &schema::DISPOSITION_PURGED,
                ],
            )
            .await
            .map_err(|error| DomainError::from_pg("staged lease member scope", error))?
            .is_some()
        {
            return Err(DomainError::PreconditionRejected {
                reason: STAGED_LEASE_MEMBER_NOT_STAGED.to_owned(),
                reason_version: 1,
            });
        }
        let reader_fence = next_fence(&tx).await?;
        let inserted = tx
            .execute(
                "INSERT INTO lore_fragment_staged_leases (lease_id, reader_fence, deadline) \
                 VALUES ($1, $2, $3) ON CONFLICT (lease_id) DO NOTHING",
                &[&lease_id, &reader_fence, &deadline],
            )
            .await
            .map_err(|error| DomainError::from_pg("staged lease insert", error))?;
        if inserted == 0 {
            let existing = replay_staged_lease(&tx, lease_id, members).await?;
            // Deliberately not `classify_commit`. That maps a lost
            // acknowledgement to `OutcomeUnknown`, which is the right answer
            // only for a transaction that may have published something. This
            // one wrote nothing — it read the existing lease and its members —
            // so telling the caller its outcome is unknown would invent doubt
            // about a lease this call never created.
            tx.commit()
                .await
                .map_err(|error| DomainError::from_pg("staged lease replay commit", error))?;
            return Ok(existing);
        }
        // One round trip for the whole batch, not one per member. This is the
        // read path: a hydration of one large asset is thousands of 256 KiB
        // fragments, and a statement each would put the per-fragment write cost
        // back that batching the lease exists to remove.
        //
        // The `ON CONFLICT (lease_id, hash)` arm below is now unreachable
        // through this method, and the honest reason to keep it is defence in
        // depth rather than a race it handles. `validate_lease_members` refuses
        // a repeated hash, and a concurrent acquire under the same `lease_id`
        // loses the lease-row insert above and returns through the replay path
        // without ever reaching this statement — so no caller of this method
        // can produce the conflict. It stays because dropping it would turn a
        // future second writer of this table into a 23505 at the worst moment,
        // not because it is doing work today.
        //
        // The `$1::bytea` cast is defensive, not load-bearing. A review flagged
        // an uncast `$1` in an `INSERT ... SELECT` target list as a certain
        // 42P08; preparing both forms against PostgreSQL 16 shows it is not —
        // both infer `{bytea, bytea[], bigint[]}` from the target column. The
        // cast is kept because it matches this crate's convention and states
        // the intended type at the call site, but it fixed no defect and the
        // note is here so a later reader does not re-derive the same wrong
        // conclusion.
        tx.execute(
            "INSERT INTO lore_fragment_staged_lease_members (lease_id, hash, epoch) \
             SELECT $1::bytea, member.hash, member.epoch \
               FROM unnest($2::bytea[], $3::bigint[]) AS member(hash, epoch) \
             ON CONFLICT (lease_id, hash) DO NOTHING",
            &[&lease_id, &member_hashes, &member_epochs],
        )
        .await
        .map_err(|error| DomainError::from_pg("staged lease member insert", error))?;
        classify_commit(tx.commit().await, "staged lease commit")?;
        failpoint!("lease.acquire.settled")?;
        Ok(StagedReaderLease {
            lease_id: lease_id.to_vec(),
            reader_fence,
            deadline,
            members: members.to_vec(),
        })
    }

    /// Mark one lease terminal. Cleanup of a staged epoch waits for every lease
    /// over it to be terminal or hard-expired.
    ///
    /// The `lease_id` is length-checked here for the same reason it is on
    /// acquire. An **absent** lease is deliberately *not* an error: a release
    /// is the caller relinquishing protection, so a lease already reaped for
    /// hard expiry, or already released, is the outcome the caller asked for.
    /// Refusing would turn a normal reap race into a spurious failure on the
    /// one path whose whole job is to let go.
    pub async fn release_staged_lease(&self, lease_id: &[u8]) -> Result<(), DomainError> {
        validate_lease_id(lease_id)?;
        let client = self.checkout().await?;
        client
            .execute(
                "UPDATE lore_fragment_staged_leases SET terminal = true WHERE lease_id = $1",
                &[&lease_id],
            )
            .await
            .map_err(|error| DomainError::from_pg("staged lease release", error))?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Shared internals
    // -----------------------------------------------------------------------

    async fn begin_publication(
        &self,
        hash: &[u8],
        authority: EpochAuthority,
        legacy_object_key: Option<&str>,
        claim_input: Option<&FragmentWriteClaimInput>,
        require_missing: bool,
    ) -> Result<BeginOutcome, DomainError> {
        match (authority, claim_input) {
            (EpochAuthority::Remote, None) => {
                return Err(DomainError::InvalidInput(
                    "remote publication requires a durable write claim".to_owned(),
                ));
            }
            (EpochAuthority::Staged, Some(_)) => {
                return Err(DomainError::InvalidInput(
                    "staged publication cannot carry a provider write claim".to_owned(),
                ));
            }
            _ => {}
        }
        failpoint!("publication.begin.entry")?;
        let mut client = self.checkout().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|error| DomainError::from_pg("publication begin", error))?;
        let mut sequence = LockSequence::new();
        let existing = lock_fragment_head(&tx, &mut sequence, hash).await?;
        failpoint!("publication.begin.locked")?;
        if require_missing {
            match &existing {
                None => {
                    return Err(DomainError::PreconditionRejected {
                        reason: "fragment_head_absent".to_owned(),
                        reason_version: 1,
                    });
                }
                Some(head) if head.state == FragmentLifecycleState::Missing => {}
                Some(head)
                    if head.state == FragmentLifecycleState::PreparingRemote
                        && head.active_operation.as_deref()
                            == Some(DIRECT_WRITE_REPAIR_OPERATION.as_slice()) => {}
                Some(head) => {
                    return Ok(BeginOutcome::Fenced(format!(
                        "repair requires a Missing lineage; this head is {}",
                        head.state.label()
                    )));
                }
            }
        }
        if let Some(head) = &existing {
            if head.state.is_readable() {
                // The dedup short-circuit. No epoch is consumed, no fence is
                // issued, and the caller performs no I/O.
                return Ok(BeginOutcome::AlreadyReadable(Box::new(EpochWitness {
                    hash: hash.to_vec(),
                    epoch: head.current_epoch,
                    state: head.state,
                    manifest_id: head.manifest_id.clone(),
                    fence: head.last_fence,
                })));
            }
            if head.state.is_deleting() || head.state == FragmentLifecycleState::Tombstoned {
                return Ok(BeginOutcome::Fenced(format!(
                    "the head is {} and cannot accept a new representation",
                    head.state.label()
                )));
            }
            if authority == EpochAuthority::Remote
                && head.state == FragmentLifecycleState::PreparingRemote
            {
                let (object_key, direct_write_kind) = match head.active_operation.as_deref() {
                    Some(token) if token == DIRECT_WRITE_NORMAL_OPERATION => (
                        legacy_object_key
                            .ok_or_else(|| {
                                DomainError::NotReady(
                                    "PreparingRemote normal publication has no validated legacy key"
                                        .to_owned(),
                                )
                            })?
                            .to_owned(),
                        DirectWriteKind::Normal,
                    ),
                    Some(token) if token == DIRECT_WRITE_REPAIR_OPERATION => (
                        repair_epoch_key(hash, head.current_epoch),
                        DirectWriteKind::Repair,
                    ),
                    Some(_) => {
                        return Err(DomainError::NotReady(
                            "PreparingRemote head has an unknown direct-write lineage token"
                                .to_owned(),
                        ));
                    }
                    None => {
                        return Err(DomainError::NotReady(
                            "PreparingRemote head has no direct-write lineage token".to_owned(),
                        ));
                    }
                };
                let captured = Some(EpochWitness {
                    hash: hash.to_vec(),
                    epoch: head.current_epoch,
                    state: head.state,
                    manifest_id: head.manifest_id.clone(),
                    fence: head.last_fence,
                });
                let claim_input = claim_input.ok_or_else(|| {
                    DomainError::InvalidInput(
                        "remote publication requires a durable write claim".to_owned(),
                    )
                })?;
                let lineage = FragmentWriteClaimLineage {
                    hash,
                    epoch: head.current_epoch,
                    fence: head.last_fence,
                    authority,
                    object_key: &object_key,
                };
                let write_claim =
                    match create_write_claim_locked(&tx, &mut sequence, lineage, claim_input)
                        .await?
                    {
                        FragmentWriteClaimCreation::Created(claim) => claim,
                        FragmentWriteClaimCreation::BlockedUntil(hard_not_after) => {
                            return Ok(BeginOutcome::WriteClaimBlocked { hard_not_after });
                        }
                    };
                let intent = FragmentIntent {
                    hash: hash.to_vec(),
                    epoch: head.current_epoch,
                    fence: head.last_fence,
                    object_key,
                    authority,
                    direct_write_kind: Some(direct_write_kind),
                    write_claim: Some(write_claim),
                    captured,
                };
                classify_commit(tx.commit().await, "publication resume commit")?;
                return Ok(BeginOutcome::Admitted(Box::new(intent)));
            }
        }
        let epoch = next_fence(&tx).await?;
        let fence = next_fence(&tx).await?;
        let (object_key, direct_write_kind) =
            match (legacy_object_key, existing.as_ref().map(|head| head.state)) {
                // Re-offering bytes for a Missing head is a first-class repair.
                // It must never overwrite the legacy normal-write key: the
                // predecessor remains immutable evidence and the successor gets
                // its own epoch key.
                (Some(_), Some(FragmentLifecycleState::Missing)) => {
                    (repair_epoch_key(hash, epoch), Some(DirectWriteKind::Repair))
                }
                (Some(key), _) => (key.to_owned(), Some(DirectWriteKind::Normal)),
                (None, _) => (staged_epoch_key(hash, epoch), None),
            };
        let active_operation = direct_write_kind.map(|kind| match kind {
            DirectWriteKind::Normal => DIRECT_WRITE_NORMAL_OPERATION.to_vec(),
            DirectWriteKind::Repair => DIRECT_WRITE_REPAIR_OPERATION.to_vec(),
        });
        let preparing = match authority {
            EpochAuthority::Staged => FragmentLifecycleState::PreparingStage,
            EpochAuthority::Remote => FragmentLifecycleState::PreparingRemote,
        };
        tx.execute(
            "INSERT INTO lore_fragment_lifecycle ( \
                 hash, current_epoch, state, manifest_id, last_fence, active_operation \
             ) VALUES ($1, $2, $3, NULL, $4, $5) \
             ON CONFLICT (hash) DO UPDATE \
                SET current_epoch    = EXCLUDED.current_epoch, \
                    state            = EXCLUDED.state, \
                    manifest_id      = NULL, \
                    last_fence       = EXCLUDED.last_fence, \
                    active_operation = EXCLUDED.active_operation, \
                    diagnostic_class = 0, \
                    updated_at       = clock_timestamp()",
            &[&hash, &epoch, &preparing.bits(), &fence, &active_operation],
        )
        .await
        .map_err(|error| DomainError::from_pg("publication intent insert", error))?;
        let write_claim = if let Some(claim_input) = claim_input {
            let lineage = FragmentWriteClaimLineage {
                hash,
                epoch,
                fence,
                authority,
                object_key: &object_key,
            };
            match create_write_claim_locked(&tx, &mut sequence, lineage, claim_input).await? {
                FragmentWriteClaimCreation::Created(claim) => Some(claim),
                FragmentWriteClaimCreation::BlockedUntil(hard_not_after) => {
                    return Ok(BeginOutcome::WriteClaimBlocked { hard_not_after });
                }
            }
        } else {
            None
        };
        classify_commit(tx.commit().await, "publication begin commit")?;
        // The admission exit only. The resume commit above republishes an
        // intent this coordinator already owns and is not a new admission, so
        // it is deliberately not anchored.
        failpoint!("publication.begin.settled")?;
        Ok(BeginOutcome::Admitted(Box::new(FragmentIntent {
            hash: hash.to_vec(),
            epoch,
            fence,
            object_key,
            authority,
            direct_write_kind,
            write_claim,
            captured: existing.map(|head| EpochWitness {
                hash: hash.to_vec(),
                epoch: head.current_epoch,
                state: head.state,
                manifest_id: head.manifest_id,
                fence: head.last_fence,
            }),
        })))
    }

    async fn commit_publication(
        &self,
        intent: &FragmentIntent,
        observation: IoObservation,
        authority: EpochAuthority,
        settlement: Option<FragmentWriteSettlement>,
    ) -> Result<CommitVerdict, DomainError> {
        let write_claim = match (intent.write_claim.as_ref(), settlement) {
            (Some(claim), Some(settlement)) => Some((claim, settlement)),
            (None, None) => None,
            _ => {
                return Err(DomainError::InvalidInput(
                    "publication claim and settlement must be supplied together".to_owned(),
                ));
            }
        };
        let mut client = self.checkout().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|error| DomainError::from_pg("publication commit begin", error))?;
        let mut sequence = LockSequence::new();
        // Either arm below can move the head across the readable boundary, so
        // the repository fanout is planned and locked first regardless of which
        // one runs. Locking a superset is safe; discovering the need after the
        // head lock is an F-032-3 inversion.
        let fanout = plan_lifecycle_fanout(&tx, &intent.hash).await?;
        lock_lifecycle_fanout(&tx, &mut sequence, &fanout).await?;
        // Before the head lock, because the fanout locks are already held here
        // and this method's five commit sites all lie past this point. A pause
        // here is what makes a second process contend on the repository rows.
        failpoint!("publication.commit.locked")?;
        let Some(head) = lock_fragment_head(&tx, &mut sequence, &intent.hash).await? else {
            if let Some((claim, settlement)) = write_claim {
                settle_write_claim_locked(&tx, &mut sequence, claim, settlement).await?;
                classify_commit(tx.commit().await, "fenced publication settlement commit")?;
            }
            return Ok(CommitVerdict::Fenced);
        };
        // The fence this operation was issued at is the head's own fence only
        // while no other operation has touched it. Anything else means a
        // repair, an obliterate, or a competing write linearized in between.
        if head.last_fence != intent.fence {
            if let Some((claim, settlement)) = write_claim {
                settle_write_claim_locked(&tx, &mut sequence, claim, settlement).await?;
                classify_commit(tx.commit().await, "moved publication settlement commit")?;
            }
            return Ok(CommitVerdict::Fenced);
        }
        if head.state.is_deleting() || head.state == FragmentLifecycleState::Tombstoned {
            if let Some((claim, settlement)) = write_claim {
                settle_write_claim_locked(&tx, &mut sequence, claim, settlement).await?;
                classify_commit(tx.commit().await, "deleted publication settlement commit")?;
            }
            return Ok(CommitVerdict::Fenced);
        }
        let was_readable = head.state.is_readable();
        // Confirmed once, before either arm branches, so whichever arm runs moves
        // scalars over a set this transaction has proved it holds.
        //
        // Scoped to a readability *crossing* rather than run unconditionally.
        // Both arms below move a scalar only when they cross the boundary, and
        // an operation that moves no scalar has no repository rows to have
        // locked — so confirming anyway would turn a grown fanout into a
        // spurious retryable refusal on exactly the widely-shared-hash path that
        // never needed the check. A `Staged`->`Remote` promotion is the case
        // that bites: both states are readable, it crosses nothing, and an
        // unconditional confirm made it fail under unrelated concurrent
        // association churn.
        let will_be_readable = matches!(observation, IoObservation::Valid(_));
        let confirmed = if was_readable == will_be_readable {
            Vec::new()
        } else {
            confirm_lifecycle_fanout(&tx, &intent.hash, &fanout).await?
        };

        let manifest = match observation {
            IoObservation::Unusable(diagnostic) => {
                let fence = next_fence(&tx).await?;
                tx.execute(
                    "UPDATE lore_fragment_lifecycle \
                        SET state = $2, manifest_id = NULL, last_fence = $3, \
                            active_operation = NULL, diagnostic_class = $4, \
                            updated_at = clock_timestamp() \
                      WHERE hash = $1",
                    &[
                        &intent.hash,
                        &FragmentLifecycleState::Missing.bits(),
                        &fence,
                        &diagnostic.bits(),
                    ],
                )
                .await
                .map_err(|error| DomainError::from_pg("publication missing update", error))?;
                if was_readable {
                    apply_lifecycle_generation(&tx, &confirmed).await?;
                }
                if let Some((claim, settlement)) = write_claim {
                    settle_write_claim_locked(&tx, &mut sequence, claim, settlement).await?;
                }
                classify_commit(tx.commit().await, "publication missing commit")?;
                return Ok(CommitVerdict::Published);
            }
            IoObservation::Valid(manifest) => manifest,
        };

        let fence = next_fence(&tx).await?;
        let provider_body_blake3 = write_claim.map(|(claim, _)| claim.body_blake3.as_slice());
        let provider_body_size = write_claim
            .map(|(claim, _)| i64::try_from(claim.body_size))
            .transpose()
            .map_err(|_| {
                DomainError::Internal("fragment write claim body size exceeds i64".to_owned())
            })?;
        let provider_claim_fence = write_claim.map(|(claim, _)| claim.fence);
        // Immutable: a repair successor is a new row at a greater epoch, never
        // an update of an existing one. `DO NOTHING` covers only the exact
        // replay of one operation's own commit.
        tx.execute(
            "INSERT INTO lore_fragment_epochs ( \
                 hash, epoch, authority, object_key, manifest_id, size_payload, size_content, \
                 decoded_hash, payload_flags, provider_body_blake3, provider_body_size, \
                 provider_claim_fence, fence, validated_at, disposition \
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, \
                       clock_timestamp(), $14) \
             ON CONFLICT (hash, epoch) DO NOTHING",
            &[
                &intent.hash,
                &intent.epoch,
                &authority.bits(),
                &manifest.object_key,
                &manifest.manifest_id,
                &manifest.size_payload,
                &manifest.size_content,
                &manifest.decoded_hash,
                &manifest.payload_flags,
                &provider_body_blake3,
                &provider_body_size,
                &provider_claim_fence,
                &fence,
                &schema::DISPOSITION_CURRENT_ELIGIBLE,
            ],
        )
        .await
        .map_err(|error| DomainError::from_pg("publication epoch insert", error))?;

        // Quarantine every predecessor. The old bytes are retained as evidence
        // and never revived or overwritten; a later GC package owns reclaiming
        // them.
        tx.execute(
            "UPDATE lore_fragment_epochs SET disposition = $3 \
              WHERE hash = $1 AND epoch < $2 AND disposition = $4",
            &[
                &intent.hash,
                &intent.epoch,
                &schema::DISPOSITION_QUARANTINED,
                &schema::DISPOSITION_CURRENT_ELIGIBLE,
            ],
        )
        .await
        .map_err(|error| DomainError::from_pg("publication predecessor quarantine", error))?;

        let published = authority.readable_state();
        tx.execute(
            "UPDATE lore_fragment_lifecycle \
                SET current_epoch = $2, state = $3, manifest_id = $4, last_fence = $5, \
                    active_operation = NULL, diagnostic_class = 0, \
                    updated_at = clock_timestamp() \
              WHERE hash = $1",
            &[
                &intent.hash,
                &intent.epoch,
                &published.bits(),
                &manifest.manifest_id,
                &fence,
            ],
        )
        .await
        .map_err(|error| DomainError::from_pg("publication head update", error))?;

        tx.execute(
            "INSERT INTO lore_fragment_lifecycle_metering ( \
                 hash, epoch, payload_flags, size_payload, size_content, authority \
             ) VALUES ($1, $2, $3, $4, $5, $6) \
             ON CONFLICT (hash) DO UPDATE \
                SET epoch         = EXCLUDED.epoch, \
                    payload_flags = EXCLUDED.payload_flags, \
                    size_payload  = EXCLUDED.size_payload, \
                    size_content  = EXCLUDED.size_content, \
                    authority     = EXCLUDED.authority, \
                    verified_at   = clock_timestamp()",
            &[
                &intent.hash,
                &intent.epoch,
                &manifest.payload_flags,
                &manifest.size_payload,
                &manifest.size_content,
                &authority.bits(),
            ],
        )
        .await
        .map_err(|error| DomainError::from_pg("publication metering upsert", error))?;

        if !was_readable {
            // Unreadable to readable is a lifecycle transition too.
            apply_lifecycle_generation(&tx, &confirmed).await?;
        }
        if let Some((claim, settlement)) = write_claim {
            settle_write_claim_locked(&tx, &mut sequence, claim, settlement).await?;
        }
        classify_commit(tx.commit().await, "publication commit")?;
        failpoint!("publication.commit.settled")?;
        Ok(CommitVerdict::Published)
    }

    async fn checkout(&self) -> Result<deadpool_postgres::Client, DomainError> {
        self.pool
            .get()
            .await
            .map_err(|error| DomainError::from_pool("fragment coordinator pool", error))
    }
}

// ---------------------------------------------------------------------------
// Free helpers
// ---------------------------------------------------------------------------

/// One locked lifecycle head.
#[derive(Debug, Clone, PartialEq, Eq)]
struct FragmentHeadLock {
    current_epoch: i64,
    state: FragmentLifecycleState,
    manifest_id: Option<Vec<u8>>,
    last_fence: i64,
    active_operation: Option<Vec<u8>>,
}

struct LockedFragmentWriteClaim {
    claim: FragmentWriteClaim,
    state: FragmentWriteClaimState,
    unexpired: bool,
}

struct FragmentWriteClaimPruneCandidate {
    logical_request_id: [u8; 16],
    attempt_id: [u8; 16],
    hash: Vec<u8>,
    state: FragmentWriteClaimState,
}

impl FragmentHeadLock {
    /// Exact-match revalidation. Every captured field, not a subset: a
    /// same-epoch same-state head whose manifest was replaced by a repair is
    /// still a different representation.
    fn matches(&self, witness: &EpochWitness) -> bool {
        self.current_epoch == witness.epoch
            && self.state == witness.state
            && self.manifest_id == witness.manifest_id
            && self.last_fence == witness.fence
    }
}

/// Lock one lifecycle head (position 4, `LockClass::Fragments`).
///
/// **`None` means nothing was locked, not "locked an absent row".** `FOR UPDATE`
/// over zero rows takes no lock, so a caller that treats `None` as a benign
/// "no head yet" and carries on is running unserialised against every other
/// transaction doing the same. Every caller here except `create_association`
/// returns immediately on `None`; `create_association` deliberately proceeds,
/// which is sound only because a hash with no head row has no lifecycle
/// transition to race — nothing can be mid-flight against a head that does not
/// exist. Any future caller that proceeds on `None` must re-derive that
/// argument rather than inherit it.
async fn lock_fragment_head(
    tx: &Transaction<'_>,
    sequence: &mut LockSequence,
    hash: &[u8],
) -> Result<Option<FragmentHeadLock>, DomainError> {
    sequence.enter(LockClass::Fragments)?;
    let row = tx
        .query_opt(
            "SELECT current_epoch, state, manifest_id, last_fence, active_operation \
               FROM lore_fragment_lifecycle WHERE hash = $1 FOR UPDATE",
            &[&hash],
        )
        .await
        .map_err(|error| DomainError::from_pg("fragment head lock", error))?;
    row.map(|row| {
        Ok(FragmentHeadLock {
            current_epoch: row.get("current_epoch"),
            state: FragmentLifecycleState::from_bits(row.get("state"))?,
            manifest_id: row.get("manifest_id"),
            last_fence: row.get("last_fence"),
            active_operation: row.get("active_operation"),
        })
    })
    .transpose()
}

async fn create_write_claim_locked(
    tx: &Transaction<'_>,
    sequence: &mut LockSequence,
    lineage: FragmentWriteClaimLineage<'_>,
    input: &FragmentWriteClaimInput,
) -> Result<FragmentWriteClaimCreation, DomainError> {
    if let Some(existing) = lock_write_claim(tx, sequence, input).await? {
        let expected = FragmentWriteClaim {
            logical_request_id: input.logical_request_id,
            attempt_id: input.attempt_id,
            hash: lineage.hash.to_vec(),
            epoch: lineage.epoch,
            fence: lineage.fence,
            authority: lineage.authority,
            object_key: lineage.object_key.to_owned(),
            body_blake3: input.body_blake3,
            body_size: input.body_size,
            send_not_after: existing.claim.send_not_after,
            hard_not_after: existing.claim.hard_not_after,
        };
        if existing.claim != expected {
            return Err(DomainError::InvalidInput(
                "fragment write attempt identity was reused with a different binding".to_owned(),
            ));
        }
        return match (existing.state, existing.unexpired) {
            (FragmentWriteClaimState::Prepared, true) => {
                Ok(FragmentWriteClaimCreation::Created(existing.claim))
            }
            (state, true) if state.blocks_until_hard_expiry() => Ok(
                FragmentWriteClaimCreation::BlockedUntil(existing.claim.hard_not_after),
            ),
            _ => Err(DomainError::PreconditionRejected {
                reason: "fragment_write_attempt_terminal_or_expired".to_owned(),
                reason_version: 1,
            }),
        };
    }

    if let FragmentWriteClaimBarrier::BlockedUntil(hard_not_after) =
        write_claim_barrier_locked(tx, sequence, lineage.hash, lineage.epoch, lineage.fence).await?
    {
        return Ok(FragmentWriteClaimCreation::BlockedUntil(hard_not_after));
    }

    sequence.enter(LockClass::Fragments)?;
    let body_size = i64::try_from(input.body_size).map_err(|_| {
        DomainError::InvalidInput("fragment write claim body size exceeds i64".to_owned())
    })?;
    let row = tx
        .query_one(
            "WITH claim_clock AS (SELECT clock_timestamp() AS now) \
             INSERT INTO lore_fragment_write_claims ( \
                 logical_request_id, attempt_id, hash, epoch, fence, authority, object_key, \
                 body_blake3, body_size, state, send_not_after, hard_not_after, prepared_at \
             ) \
             SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, \
                    claim_clock.now + ($11::bigint * interval '1 millisecond'), \
                    claim_clock.now + (($11::bigint + $12::bigint) * interval '1 millisecond'), \
                    claim_clock.now \
               FROM claim_clock \
             RETURNING send_not_after, hard_not_after",
            &[
                &input.logical_request_id.as_slice(),
                &input.attempt_id.as_slice(),
                &lineage.hash,
                &lineage.epoch,
                &lineage.fence,
                &lineage.authority.bits(),
                &lineage.object_key,
                &input.body_blake3.as_slice(),
                &body_size,
                &FragmentWriteClaimState::Prepared.bits(),
                &input.send_timeout_millis,
                &input.late_effect_bound_millis,
            ],
        )
        .await
        .map_err(|error| DomainError::from_pg("fragment write claim insert", error))?;
    Ok(FragmentWriteClaimCreation::Created(FragmentWriteClaim {
        logical_request_id: input.logical_request_id,
        attempt_id: input.attempt_id,
        hash: lineage.hash.to_vec(),
        epoch: lineage.epoch,
        fence: lineage.fence,
        authority: lineage.authority,
        object_key: lineage.object_key.to_owned(),
        body_blake3: input.body_blake3,
        body_size: input.body_size,
        send_not_after: row.get("send_not_after"),
        hard_not_after: row.get("hard_not_after"),
    }))
}

/// Inspect existing late-effect barriers while the caller holds the exact
/// lifecycle head lock. Claim creation uses this lineage-scoped check; a repair
/// successor may proceed on a new epoch while the hash-wide inventory retains
/// an older ambiguous target for Phase 6B cleanup.
async fn write_claim_barrier_locked(
    tx: &Transaction<'_>,
    sequence: &mut LockSequence,
    hash: &[u8],
    epoch: i64,
    fence: i64,
) -> Result<FragmentWriteClaimBarrier, DomainError> {
    sequence.enter(LockClass::Fragments)?;
    let blocking_states = [
        FragmentWriteClaimState::Prepared.bits(),
        FragmentWriteClaimState::Sending.bits(),
        FragmentWriteClaimState::Ambiguous.bits(),
    ];
    let rows = tx
        .query(
            "SELECT hard_not_after FROM lore_fragment_write_claims \
              WHERE hash = $1 AND epoch = $2 AND fence = $3 \
                AND state = ANY($4) AND hard_not_after > clock_timestamp() \
              ORDER BY hard_not_after DESC FOR UPDATE",
            &[&hash, &epoch, &fence, &blocking_states.as_slice()],
        )
        .await
        .map_err(|error| DomainError::from_pg("fragment write claim barrier", error))?;
    Ok(rows
        .first()
        .map(|row| FragmentWriteClaimBarrier::BlockedUntil(row.get("hard_not_after")))
        .unwrap_or(FragmentWriteClaimBarrier::Clear))
}

/// Compute one hash's send barrier for the prune loop, and settle any
/// `Prepared` claim whose send window has closed.
///
/// This is the prune path's replacement for [`write_claim_inventory_locked`].
/// That function stays as it is, because obliterate
/// (`capture_obliterate_intent_locked`) needs its hash-wide exact cleanup
/// targets; the prune loop only ever needed the barrier plus its own
/// candidate's row, which it now takes through
/// [`lock_write_claim_identity`].
///
/// # Why this can read without `FOR UPDATE`
///
/// The caller holds this hash's `lore_fragment_lifecycle` row `FOR UPDATE`, and
/// every writer of `lore_fragment_write_claims` takes that head lock first:
/// claim insert, authorization, settlement, this normalization, and the prune
/// deletes. Holding the head is therefore sufficient to serialise this read,
/// the same argument `lock_lease_member_heads` documents for reading epoch
/// dispositions without locking epoch rows. Locking every claim row on the hash
/// adds nothing and lets a prune pass queue behind unrelated traffic.
///
/// This probe is **not** redundant with the plan query's anti-join. The
/// anti-join runs unlocked on a separate pooled connection and is advisory: a
/// hash can gain an active claim between the plan and the head lock. This is
/// the locked check, and it is what makes the delete safe.
///
/// # Why the state list is a SQL literal
///
/// `0, 1, 3` are Prepared, Sending and Ambiguous, and `4` is NoSend. Written as
/// literals, both statements match `lore_fragment_write_claims_barrier`'s
/// partial predicate and use it with `hash` as the index condition. Bound as
/// `$n` parameters, the planner cannot prove partial-index implication, and a
/// generic plan degrades both to a sequential scan of the whole claims table.
/// There is no other index on this table with `hash` leading.
async fn write_claim_barrier_for_prune(
    tx: &Transaction<'_>,
    sequence: &mut LockSequence,
    hash: &[u8],
) -> Result<Option<SystemTime>, DomainError> {
    sequence.enter(LockClass::Fragments)?;
    let database_now: SystemTime = tx
        .query_one("SELECT clock_timestamp()", &[])
        .await
        .map_err(|error| DomainError::from_pg("fragment write prune barrier clock", error))?
        .get(0);
    // Settle every Prepared claim whose send window has closed, exactly as
    // `write_claim_inventory_locked` does row by row. The head lock already
    // serialises this, so one set-based statement is equivalent and takes row
    // locks only on the rows it changes. Prepared (0) becomes NoSend (4).
    //
    // The inventory's `updated != 1` guard (its
    // `fragment_write_claim_inventory_race` rejection) has no counterpart here,
    // and needs none. That guard covers a read-then-CAS pair: the inventory
    // reads a row as Prepared, then updates it by identity, and the guard
    // catches a change in between. This statement reads and writes in one
    // operation, so there is no window for that check to describe. The rejection
    // remains reachable from the inventory itself, which obliterate still calls.
    tx.execute(
        "UPDATE lore_fragment_write_claims SET state = 4, settled_at = $2 \
          WHERE hash = $1 AND state = 0 AND send_not_after <= $2",
        &[&hash, &database_now],
    )
    .await
    .map_err(|error| DomainError::from_pg("expired prepared fragment write claim settle", error))?;
    let rows = tx
        .query(
            "SELECT state, send_not_after, hard_not_after \
               FROM lore_fragment_write_claims \
              WHERE hash = $1 AND state IN (0, 1, 3) \
              ORDER BY logical_request_id, attempt_id",
            &[&hash],
        )
        .await
        .map_err(|error| DomainError::from_pg("fragment write prune barrier", error))?;
    let mut blocked_until: Option<SystemTime> = None;
    for row in rows {
        let state = FragmentWriteClaimState::from_bits(row.get("state"))?;
        // Prepared blocks on its send horizon, Sending and Ambiguous on their
        // hard late-effect horizon. The plan query's anti-join mirrors this
        // split; a uniform `hard_not_after` test would be stricter than the
        // loop and would starve hashes holding a settled-out Prepared row.
        let horizon: Option<SystemTime> = match state {
            FragmentWriteClaimState::Prepared => Some(row.get("send_not_after")),
            FragmentWriteClaimState::Sending | FragmentWriteClaimState::Ambiguous => {
                Some(row.get("hard_not_after"))
            }
            FragmentWriteClaimState::Decisive | FragmentWriteClaimState::NoSend => None,
        };
        if let Some(horizon) = horizon.filter(|horizon| *horizon > database_now) {
            blocked_until = Some(
                blocked_until
                    .map(|current| current.max(horizon))
                    .unwrap_or(horizon),
            );
        }
    }
    Ok(blocked_until)
}

/// Inspect every claim for a hash while the exact lifecycle head is locked.
///
/// This is the Phase 6B cleanup inventory. It is deliberately private and
/// takes a transaction plus lock sequence so it cannot become a race-prone
/// standalone deletion authority. Current-lineage send authorization continues
/// to use exact epoch/fence binding elsewhere.
async fn write_claim_inventory_locked(
    tx: &Transaction<'_>,
    sequence: &mut LockSequence,
    hash: &[u8],
) -> Result<FragmentWriteClaimInventory, DomainError> {
    sequence.enter(LockClass::Fragments)?;
    let database_now: SystemTime = tx
        .query_one("SELECT clock_timestamp()", &[])
        .await
        .map_err(|error| DomainError::from_pg("fragment write inventory clock", error))?
        .get(0);
    let rows = tx
        .query(
            "SELECT logical_request_id, attempt_id, hash, epoch, fence, authority, object_key, \
                    body_blake3, body_size, state, send_not_after, hard_not_after, \
                    hard_not_after > $2 AS unexpired \
               FROM lore_fragment_write_claims \
              WHERE hash = $1 \
              ORDER BY logical_request_id, attempt_id FOR UPDATE",
            &[&hash, &database_now],
        )
        .await
        .map_err(|error| DomainError::from_pg("fragment write claim inventory", error))?;
    let mut blocked_until: Option<SystemTime> = None;
    let mut cleanup_targets = Vec::new();
    for row in rows {
        let locked = decode_locked_write_claim(row)?;
        match locked.state {
            FragmentWriteClaimState::Prepared => {
                if locked.claim.send_not_after > database_now {
                    blocked_until = Some(
                        blocked_until
                            .map(|current| current.max(locked.claim.send_not_after))
                            .unwrap_or(locked.claim.send_not_after),
                    );
                } else {
                    let updated = tx
                        .execute(
                            "UPDATE lore_fragment_write_claims \
                                SET state = $3, settled_at = $4 \
                              WHERE logical_request_id = $1 AND attempt_id = $2 AND state = $5",
                            &[
                                &locked.claim.logical_request_id.as_slice(),
                                &locked.claim.attempt_id.as_slice(),
                                &FragmentWriteClaimState::NoSend.bits(),
                                &database_now,
                                &FragmentWriteClaimState::Prepared.bits(),
                            ],
                        )
                        .await
                        .map_err(|error| {
                            DomainError::from_pg(
                                "expired prepared fragment write claim settle",
                                error,
                            )
                        })?;
                    if updated != 1 {
                        return Err(DomainError::PreconditionRejected {
                            reason: "fragment_write_claim_inventory_race".to_owned(),
                            reason_version: 1,
                        });
                    }
                }
            }
            FragmentWriteClaimState::Sending | FragmentWriteClaimState::Ambiguous
                if locked.claim.hard_not_after > database_now =>
            {
                blocked_until = Some(
                    blocked_until
                        .map(|current| current.max(locked.claim.hard_not_after))
                        .unwrap_or(locked.claim.hard_not_after),
                );
            }
            FragmentWriteClaimState::Sending
            | FragmentWriteClaimState::Ambiguous
            | FragmentWriteClaimState::Decisive => {
                cleanup_targets.push(FragmentWriteCleanupTarget {
                    logical_request_id: locked.claim.logical_request_id,
                    attempt_id: locked.claim.attempt_id,
                    hash: locked.claim.hash,
                    epoch: locked.claim.epoch,
                    fence: locked.claim.fence,
                    authority: locked.claim.authority,
                    object_key: locked.claim.object_key,
                    body_blake3: locked.claim.body_blake3,
                    body_size: locked.claim.body_size,
                });
            }
            FragmentWriteClaimState::NoSend => {}
        }
    }
    Ok(FragmentWriteClaimInventory {
        blocked_until,
        cleanup_targets,
    })
}

fn encode_obliterate_operation(origin: u8) -> [u8; 16] {
    let mut token = [0_u8; 16];
    token[..OBLITERATE_OPERATION_PREFIX.len()].copy_from_slice(&OBLITERATE_OPERATION_PREFIX);
    token[12] = origin;
    token
}

fn decode_obliterate_operation(token: Option<&[u8]>) -> Result<u8, DomainError> {
    let Some(token) = token else {
        return Err(DomainError::NotReady(
            "deleting fragment head has no durable obliterate ownership token".to_owned(),
        ));
    };
    if token.len() != 16
        || token[..OBLITERATE_OPERATION_PREFIX.len()] != OBLITERATE_OPERATION_PREFIX
        || token[13..] != [0_u8; 3]
    {
        return Err(DomainError::NotReady(
            "deleting fragment head has an unknown obliterate ownership token".to_owned(),
        ));
    }
    match token[12] {
        OBLITERATE_ORIGIN_PREPARING_STAGE
        | OBLITERATE_ORIGIN_PREPARING_REMOTE_NORMAL
        | OBLITERATE_ORIGIN_PREPARING_REMOTE_REPAIR
        | OBLITERATE_ORIGIN_STAGED
        | OBLITERATE_ORIGIN_REMOTE
        | OBLITERATE_ORIGIN_MISSING => Ok(token[12]),
        _ => Err(DomainError::NotReady(
            "deleting fragment head has an unknown obliterate origin".to_owned(),
        )),
    }
}

fn obliterate_origin_from_head(head: &FragmentHeadLock) -> Result<u8, DomainError> {
    match head.state {
        FragmentLifecycleState::PreparingStage => Ok(OBLITERATE_ORIGIN_PREPARING_STAGE),
        FragmentLifecycleState::PreparingRemote => match head.active_operation.as_deref() {
            Some(token) if token == DIRECT_WRITE_NORMAL_OPERATION => {
                Ok(OBLITERATE_ORIGIN_PREPARING_REMOTE_NORMAL)
            }
            Some(token) if token == DIRECT_WRITE_REPAIR_OPERATION => {
                Ok(OBLITERATE_ORIGIN_PREPARING_REMOTE_REPAIR)
            }
            Some(_) => Err(DomainError::NotReady(
                "PreparingRemote head has an unknown direct-write lineage token".to_owned(),
            )),
            None => Err(DomainError::NotReady(
                "PreparingRemote head has no direct-write lineage token".to_owned(),
            )),
        },
        FragmentLifecycleState::Staged => Ok(OBLITERATE_ORIGIN_STAGED),
        FragmentLifecycleState::Remote => Ok(OBLITERATE_ORIGIN_REMOTE),
        FragmentLifecycleState::Missing => Ok(OBLITERATE_ORIGIN_MISSING),
        FragmentLifecycleState::DeletingChildren | FragmentLifecycleState::DeletingPayload => {
            decode_obliterate_operation(head.active_operation.as_deref())
        }
        FragmentLifecycleState::Tombstoned => Err(DomainError::PreconditionRejected {
            reason: "fragment_already_tombstoned".to_owned(),
            reason_version: 1,
        }),
    }
}

fn validate_purge_target_key(target: &FragmentPurgeTarget) -> Result<(), DomainError> {
    let canonical = match target.authority {
        EpochAuthority::Staged => target.object_key == staged_epoch_key(&target.hash, target.epoch),
        // A promoted staged epoch legitimately publishes Remote authority at
        // the legacy key even though its epoch is greater than the first
        // publication's. A repair successor is the other canonical Remote
        // shape. No prefix, neighbouring hash, or arbitrary database text is
        // ever eligible for DeleteExact.
        EpochAuthority::Remote => {
            target.object_key == legacy_hash_key(&target.hash)
                || target.object_key == repair_epoch_key(&target.hash, target.epoch)
        }
    };
    if canonical {
        Ok(())
    } else {
        Err(DomainError::NotReady(
            "fragment purge target has a noncanonical object key".to_owned(),
        ))
    }
}

async fn require_claims_write_capability(
    tx: &Transaction<'_>,
    expected_revision: &str,
) -> Result<(), DomainError> {
    let row = tx
        .query_opt(
            "SELECT write_capability, provider_write_authority_revision \
               FROM lore_fragment_schema_state WHERE id = 1",
            &[],
        )
        .await
        .map_err(|error| DomainError::from_pg("obliterate write capability", error))?
        .ok_or_else(|| {
            DomainError::NotReady("SCHEMA-118 capability singleton is absent".to_owned())
        })?;
    let capability = FragmentWriteCapability::decode(
        row.get("write_capability"),
        row.get("provider_write_authority_revision"),
    )?;
    match capability {
        FragmentWriteCapability::ClaimsRequired {
            provider_write_authority_revision,
        } if provider_write_authority_revision == expected_revision => Ok(()),
        FragmentWriteCapability::ClaimsRequired { .. } => Err(DomainError::NotReady(
            "fragment write-authority revision does not match coordinated obliterate activation"
                .to_owned(),
        )),
        FragmentWriteCapability::Optional => Err(DomainError::NotReady(
            "coordinated obliterate requires the write-claims-v1 capability cutover".to_owned(),
        )),
    }
}

async fn owned_obliterate_association_locked(
    tx: &Transaction<'_>,
    ownership: &FragmentObliterateOwnership,
) -> Result<bool, DomainError> {
    let row = tx
        .query_opt(
            "SELECT association_epoch, state FROM lore_fragment_associations \
              WHERE hash = $1 AND repository_id = $2 AND context = $3",
            &[
                &ownership.hash,
                &ownership.repository_id,
                &ownership.context,
            ],
        )
        .await
        .map_err(|error| DomainError::from_pg("owned obliterate association", error))?;
    Ok(row.is_some_and(|row| {
        row.get::<_, i16>("state") == schema::ASSOCIATION_TOMBSTONED
            && row.get::<_, i64>("association_epoch") == ownership.fence
    }))
}

async fn capture_obliterate_intent_locked(
    tx: &Transaction<'_>,
    sequence: &mut LockSequence,
    hash: &[u8],
    repository_id: &[u8],
    context: &[u8],
    head: &FragmentHeadLock,
    provider_write_authority_revision: &str,
) -> Result<FragmentObliterateIntent, DomainError> {
    let phase = match head.state {
        FragmentLifecycleState::DeletingChildren => FragmentObliteratePhase::Children,
        FragmentLifecycleState::DeletingPayload => FragmentObliteratePhase::Payload,
        _ => {
            return Err(DomainError::Internal(
                "obliterate intent capture requires a deleting head".to_owned(),
            ));
        }
    };
    let origin = decode_obliterate_operation(head.active_operation.as_deref())?;
    let inventory = write_claim_inventory_locked(tx, sequence, hash).await?;
    let mut targets = BTreeSet::new();
    for target in inventory.cleanup_targets {
        if target.authority != EpochAuthority::Remote {
            return Err(DomainError::Internal(
                "a provider write claim named non-remote authority".to_owned(),
            ));
        }
        let target = FragmentPurgeTarget {
            hash: target.hash,
            epoch: target.epoch,
            authority: target.authority,
            object_key: target.object_key,
            provider_body_blake3: Some(target.body_blake3),
            provider_body_size: Some(target.body_size),
            provider_claim_fence: Some(target.fence),
        };
        validate_purge_target_key(&target)?;
        targets.insert(target);
    }

    let current = match origin {
        OBLITERATE_ORIGIN_PREPARING_STAGE => {
            let target = FragmentPurgeTarget {
                hash: hash.to_vec(),
                epoch: head.current_epoch,
                authority: EpochAuthority::Staged,
                object_key: staged_epoch_key(hash, head.current_epoch),
                provider_body_blake3: None,
                provider_body_size: None,
                provider_claim_fence: None,
            };
            validate_purge_target_key(&target)?;
            targets.insert(target.clone());
            Some(FragmentObliterateRepresentation {
                target,
                manifest: None,
            })
        }
        OBLITERATE_ORIGIN_PREPARING_REMOTE_NORMAL | OBLITERATE_ORIGIN_PREPARING_REMOTE_REPAIR => {
            None
        }
        OBLITERATE_ORIGIN_STAGED | OBLITERATE_ORIGIN_REMOTE | OBLITERATE_ORIGIN_MISSING => {
            let row = tx
                .query_opt(
                    "SELECT authority, object_key, manifest_id, size_payload, size_content, \
                            decoded_hash, payload_flags, provider_body_blake3, \
                            provider_body_size, provider_claim_fence \
                       FROM lore_fragment_epochs WHERE hash = $1 AND epoch = $2",
                    &[&hash, &head.current_epoch],
                )
                .await
                .map_err(|error| DomainError::from_pg("obliterate current epoch", error))?;
            match row {
                None => {
                    if origin != OBLITERATE_ORIGIN_MISSING {
                        return Err(DomainError::NotReady(
                            "deleting fragment head has no exact current epoch evidence".to_owned(),
                        ));
                    }
                    // An unusable first publication deliberately commits Missing
                    // without inserting an epoch row. A direct Remote attempt is
                    // still named exactly by its durable current-epoch claim. With
                    // no such claim the failed publication was Staged, whose path
                    // is deterministic. Older claims from predecessor epochs do
                    // not suppress that staged target.
                    let current_remote_claim = targets.iter().any(|target| {
                        target.authority == EpochAuthority::Remote
                            && target.epoch == head.current_epoch
                    });
                    if current_remote_claim {
                        None
                    } else {
                        let target = FragmentPurgeTarget {
                            hash: hash.to_vec(),
                            epoch: head.current_epoch,
                            authority: EpochAuthority::Staged,
                            object_key: staged_epoch_key(hash, head.current_epoch),
                            provider_body_blake3: None,
                            provider_body_size: None,
                            provider_claim_fence: None,
                        };
                        validate_purge_target_key(&target)?;
                        targets.insert(target.clone());
                        Some(FragmentObliterateRepresentation {
                            target,
                            manifest: None,
                        })
                    }
                }
                Some(row) => {
                    let authority = EpochAuthority::from_bits(row.get("authority"))?;
                    let body_blake3 = row
                        .get::<_, Option<Vec<u8>>>("provider_body_blake3")
                        .map(|value| fixed_bytes::<32>(value, "epoch provider body digest"))
                        .transpose()?;
                    let body_size = row
                        .get::<_, Option<i64>>("provider_body_size")
                        .map(|value| {
                            u64::try_from(value).map_err(|_| {
                                DomainError::Internal(
                                    "epoch provider body size is negative".to_owned(),
                                )
                            })
                        })
                        .transpose()?;
                    let target = FragmentPurgeTarget {
                        hash: hash.to_vec(),
                        epoch: head.current_epoch,
                        authority,
                        object_key: row.get("object_key"),
                        provider_body_blake3: body_blake3,
                        provider_body_size: body_size,
                        provider_claim_fence: row.get("provider_claim_fence"),
                    };
                    validate_purge_target_key(&target)?;
                    let manifest = FragmentManifest {
                        authority,
                        object_key: target.object_key.clone(),
                        manifest_id: row.get("manifest_id"),
                        size_payload: row.get("size_payload"),
                        size_content: row.get("size_content"),
                        decoded_hash: row.get("decoded_hash"),
                        payload_flags: row.get("payload_flags"),
                    };
                    targets.insert(target.clone());
                    Some(FragmentObliterateRepresentation {
                        target,
                        manifest: Some(manifest),
                    })
                }
            }
        }
        _ => {
            return Err(DomainError::NotReady(
                "deleting fragment head has an unknown obliterate origin".to_owned(),
            ));
        }
    };
    let purge_targets = targets.into_iter().collect::<Vec<_>>();

    // Record which captured targets have immutable epoch evidence. The final
    // commit updates exactly these rows to PURGED; claim-only targets remain in
    // the claim table as their evidence and cannot manufacture an affected-row
    // expectation for an epoch that never published.
    let mut purge_evidence_epochs = Vec::new();
    for target in &purge_targets {
        let body_size = target
            .provider_body_size
            .map(i64::try_from)
            .transpose()
            .map_err(|_| DomainError::Internal("purge target size exceeds i64".to_owned()))?;
        let present = tx
            .query_opt(
                "SELECT 1 FROM lore_fragment_epochs \
                  WHERE hash = $1 AND epoch = $2 AND authority = $3 AND object_key = $4 \
                    AND provider_body_blake3 IS NOT DISTINCT FROM $5 \
                    AND provider_body_size IS NOT DISTINCT FROM $6 \
                    AND provider_claim_fence IS NOT DISTINCT FROM $7",
                &[
                    &target.hash,
                    &target.epoch,
                    &target.authority.bits(),
                    &target.object_key,
                    &target
                        .provider_body_blake3
                        .as_ref()
                        .map(|value| value.as_slice()),
                    &body_size,
                    &target.provider_claim_fence,
                ],
            )
            .await
            .map_err(|error| DomainError::from_pg("obliterate epoch evidence", error))?
            .is_some();
        if present && !purge_evidence_epochs.contains(&target.epoch) {
            purge_evidence_epochs.push(target.epoch);
        }
    }
    purge_evidence_epochs.sort_unstable();
    let metering_present = tx
        .query_opt(
            "SELECT 1 FROM lore_fragment_lifecycle_metering WHERE hash = $1",
            &[&hash],
        )
        .await
        .map_err(|error| DomainError::from_pg("obliterate metering evidence", error))?
        .is_some();

    Ok(FragmentObliterateIntent {
        ownership: FragmentObliterateOwnership {
            hash: hash.to_vec(),
            repository_id: repository_id.to_vec(),
            context: context.to_vec(),
            fence: head.last_fence,
        },
        phase,
        current_epoch: head.current_epoch,
        origin,
        current,
        purge_targets,
        purge_evidence_epochs,
        metering_present,
        blocked_until: inventory.blocked_until,
        provider_write_authority_revision: provider_write_authority_revision.to_owned(),
    })
}

async fn obliterate_blocked_until_locked(
    tx: &Transaction<'_>,
    intent: &FragmentObliterateIntent,
) -> Result<Option<SystemTime>, DomainError> {
    let staged_epochs = intent
        .purge_targets
        .iter()
        .filter(|target| target.authority == EpochAuthority::Staged)
        .map(|target| target.epoch)
        .collect::<Vec<_>>();
    if staged_epochs.is_empty() {
        return Ok(intent.blocked_until);
    }
    let lease_deadline = tx
        .query_one(
            "SELECT max(lease.deadline) AS blocked_until \
               FROM lore_fragment_staged_leases AS lease \
               JOIN lore_fragment_staged_lease_members AS member \
                 ON member.lease_id = lease.lease_id \
              WHERE member.hash = $1 AND member.epoch = ANY($2) \
                AND NOT lease.terminal AND lease.deadline > clock_timestamp()",
            &[&intent.ownership.hash, &staged_epochs],
        )
        .await
        .map_err(|error| DomainError::from_pg("obliterate staged lease barrier", error))?
        .get::<_, Option<SystemTime>>("blocked_until");
    Ok(match (intent.blocked_until, lease_deadline) {
        (Some(claim), Some(lease)) => Some(claim.max(lease)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    })
}

async fn lock_write_claim(
    tx: &Transaction<'_>,
    sequence: &mut LockSequence,
    input: &FragmentWriteClaimInput,
) -> Result<Option<LockedFragmentWriteClaim>, DomainError> {
    lock_write_claim_identity(tx, sequence, &input.logical_request_id, &input.attempt_id).await
}

async fn lock_write_claim_identity(
    tx: &Transaction<'_>,
    sequence: &mut LockSequence,
    logical_request_id: &[u8; 16],
    attempt_id: &[u8; 16],
) -> Result<Option<LockedFragmentWriteClaim>, DomainError> {
    sequence.enter(LockClass::Fragments)?;
    let row = tx
        .query_opt(
            "SELECT logical_request_id, attempt_id, hash, epoch, fence, authority, object_key, \
                    body_blake3, body_size, state, send_not_after, hard_not_after, \
                    hard_not_after > clock_timestamp() AS unexpired \
               FROM lore_fragment_write_claims \
              WHERE logical_request_id = $1 AND attempt_id = $2 FOR UPDATE",
            &[&logical_request_id.as_slice(), &attempt_id.as_slice()],
        )
        .await
        .map_err(|error| DomainError::from_pg("fragment write claim lock", error))?;
    row.map(decode_locked_write_claim).transpose()
}

async fn settle_write_claim_locked(
    tx: &Transaction<'_>,
    sequence: &mut LockSequence,
    claim: &FragmentWriteClaim,
    settlement: FragmentWriteSettlement,
) -> Result<(), DomainError> {
    let Some(locked) =
        lock_write_claim_identity(tx, sequence, &claim.logical_request_id, &claim.attempt_id)
            .await?
    else {
        return Err(DomainError::NotReady(
            "fragment write claim is absent".to_owned(),
        ));
    };
    if locked.claim != *claim {
        return Err(DomainError::InvalidInput(
            "fragment write claim binding does not match durable state".to_owned(),
        ));
    }
    let target = settlement.state();
    if locked.state == target {
        return Ok(());
    }
    let valid_transition = matches!(
        (locked.state, target),
        (
            FragmentWriteClaimState::Prepared,
            FragmentWriteClaimState::NoSend
        ) | (
            FragmentWriteClaimState::Sending,
            FragmentWriteClaimState::Decisive
        ) | (
            FragmentWriteClaimState::Sending,
            FragmentWriteClaimState::Ambiguous
        ) | (
            FragmentWriteClaimState::Sending,
            FragmentWriteClaimState::NoSend
        )
    );
    if !valid_transition {
        return Err(DomainError::PreconditionRejected {
            reason: "fragment_write_claim_invalid_settlement".to_owned(),
            reason_version: 1,
        });
    }
    let updated = tx
        .execute(
            "UPDATE lore_fragment_write_claims \
                SET state = $3, settled_at = clock_timestamp() \
              WHERE logical_request_id = $1 AND attempt_id = $2 AND state = $4",
            &[
                &claim.logical_request_id.as_slice(),
                &claim.attempt_id.as_slice(),
                &target.bits(),
                &locked.state.bits(),
            ],
        )
        .await
        .map_err(|error| DomainError::from_pg("fragment write claim settle", error))?;
    if updated != 1 {
        return Err(DomainError::PreconditionRejected {
            reason: "fragment_write_claim_settlement_race".to_owned(),
            reason_version: 1,
        });
    }
    Ok(())
}

fn decode_locked_write_claim(
    row: tokio_postgres::Row,
) -> Result<LockedFragmentWriteClaim, DomainError> {
    let logical_request_id = fixed_bytes::<16>(
        row.get("logical_request_id"),
        "fragment write logical request id",
    )?;
    let attempt_id = fixed_bytes::<16>(row.get("attempt_id"), "fragment write attempt id")?;
    let body_blake3 = fixed_bytes::<32>(row.get("body_blake3"), "fragment write body digest")?;
    let body_size: i64 = row.get("body_size");
    Ok(LockedFragmentWriteClaim {
        claim: FragmentWriteClaim {
            logical_request_id,
            attempt_id,
            hash: row.get("hash"),
            epoch: row.get("epoch"),
            fence: row.get("fence"),
            authority: EpochAuthority::from_bits(row.get("authority"))?,
            object_key: row.get("object_key"),
            body_blake3,
            body_size: u64::try_from(body_size).map_err(|_| {
                DomainError::Internal("fragment write claim has a negative body size".to_owned())
            })?,
            send_not_after: row.get("send_not_after"),
            hard_not_after: row.get("hard_not_after"),
        },
        state: FragmentWriteClaimState::from_bits(row.get("state"))?,
        unexpired: row.get("unexpired"),
    })
}

fn fixed_bytes<const N: usize>(value: Vec<u8>, field: &str) -> Result<[u8; N], DomainError> {
    value.try_into().map_err(|_| {
        DomainError::Internal(format!(
            "{field} does not have the schema-required {N}-byte width"
        ))
    })
}

fn valid_write_authority_revision(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

/// What a push witness comparison decided, as a value rather than a branch
/// order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PushWitnessChange {
    /// Neither scalar moved. The fast path commits with no fragment-row read.
    Neither,
    /// The association scalar moved, whether or not the lifecycle scalar did
    /// too. Always an abort.
    AssociationMoved,
    /// The lifecycle scalar moved and the association scalar did not. The only
    /// case the bounded fallback may attempt.
    LifecycleOnly,
}

/// Classify one push witness against its captured value.
///
/// # The precedence is the point
///
/// `AssociationMoved` outranks `LifecycleOnly` when **both** scalars moved, and
/// that ordering is load-bearing for the CR-031:266 equivalence allowance
/// rather than a stylistic choice. An obliterate-then-recreate moves both: it
/// tombstones associations (association scalar) and crosses readability
/// (lifecycle scalar). If such a witness were routed to the fallback, the
/// recreated fragment could present content columns equal to the captured
/// epoch's and be accepted as "semantically equivalent" — committing a push
/// against an association set that no longer contains what it required.
///
/// As two positional `if`s this was protected by nothing but a comment: the
/// association branch could be deleted outright with every live push case and
/// every library test still green, because every one of those cases associates
/// before capturing its witness, so that scalar never moves. Making it a value
/// is what lets `an_association_move_outranks_a_lifecycle_move` pin it offline.
fn classify_push_witness(
    captured: PushGenerationWitness,
    current: PushGenerationWitness,
) -> PushWitnessChange {
    if current.content_association_generation != captured.content_association_generation {
        return PushWitnessChange::AssociationMoved;
    }
    if current.fragment_lifecycle_generation != captured.fragment_lifecycle_generation {
        return PushWitnessChange::LifecycleOnly;
    }
    PushWitnessChange::Neither
}

/// Take a share lock on every lease member's head, in sorted hash order, and
/// refuse a head that is gone or on its way out.
///
/// # Why a lock, and why `FOR SHARE`
///
/// The disposition guard this serialises is otherwise a plain unlocked
/// `SELECT` at READ COMMITTED, which nothing orders against `commit_obliterate`
/// — its scope check can pass, obliterate can commit `DISPOSITION_PURGED`, and
/// the lease still lands. Every writer that mutates a `lore_fragment_epochs`
/// disposition for a hash does so while holding that hash's head row
/// `FOR UPDATE`: `commit_obliterate`'s purge and `commit_publication`'s
/// predecessor quarantine are the only two, and both sit after
/// [`lock_fragment_head`]. Holding the head is therefore sufficient to
/// serialise **both** this function's state check and the epoch-disposition
/// check that follows it, without locking epoch rows separately.
///
/// `FOR SHARE` rather than `FOR UPDATE` because concurrent hydration is the
/// normal case: two readers leasing the same staged fragment must not queue
/// behind each other, and share locks are mutually compatible. Only a writer
/// blocks, and only for the few statements a lease acquire runs.
///
/// **Folding the check into the member `INSERT ... SELECT` would not have
/// worked.** A single statement narrows the window but establishes no
/// happens-before: at READ COMMITTED the `SELECT` half takes its snapshot at
/// statement start, so an obliterate committing immediately after that scan is
/// still invisible and the lease still lands. The race is a missing lock, not
/// a missing atomic statement.
///
/// # Lock order
///
/// This is the first and only domain-row class the lease path takes
/// (`LockClass::Fragments`, position 4), and the lease tables themselves hold
/// no position, so nothing here can reach back for an earlier class and no
/// F-032-3 inversion is expressible.
///
/// **That is a structural argument, not a machine-checked one, and an earlier
/// version of this comment overstated it.** It claimed registering with
/// [`LockSequence`] made the ordering "checked rather than asserted". It does
/// not: `enter` rejects only a *downward* move, this path enters exactly one
/// class exactly once, and a fresh sequence has no previous class to be below —
/// so the failure branch is unreachable for every possible input. The
/// registration currently proves nothing.
///
/// It is kept anyway, for the one moment it starts mattering: if this path ever
/// takes a second class, the guard becomes live and catches an inversion for
/// free. Documenting intent and pre-wiring that check is worth a line. What a
/// reader must not do is treat the ordering as verified today and skip
/// re-deriving it by hand when adding that second class.
///
/// **This changes the lease path's standing exemption.** CR-031 recorded the
/// staged-lease transaction as sound outside `LockSequence` *because it took no
/// domain row*. It now takes one, so the exemption's original rationale no
/// longer applies and the registration above replaces it.
///
/// # What this does and does not guarantee
///
/// It guarantees no lease is granted over a fragment already obliterated or
/// mid-deletion. It does **not** make an obliterate honour a lease that is
/// already live — a writer that wins the head lock first proceeds, and
/// draining live readers before a physical purge is Phase 6's, not closed
/// here.
async fn lock_lease_member_heads(
    tx: &Transaction<'_>,
    sequence: &mut LockSequence,
    hashes: &[&[u8]],
) -> Result<(), DomainError> {
    sequence.enter(LockClass::Fragments)?;
    let mut sorted: Vec<&[u8]> = hashes.to_vec();
    sorted.sort_unstable();
    let rows = tx
        .query(
            "SELECT hash, state FROM lore_fragment_lifecycle \
              WHERE hash = ANY($1) ORDER BY hash FOR SHARE",
            &[&sorted],
        )
        .await
        .map_err(|error| DomainError::from_pg("staged lease head lock", error))?;
    let mut locked: BTreeMap<Vec<u8>, FragmentLifecycleState> = BTreeMap::new();
    for row in rows {
        locked.insert(
            row.get("hash"),
            FragmentLifecycleState::from_bits(row.get("state"))?,
        );
    }
    for hash in &sorted {
        // An absent head is refused rather than ignored. `FOR UPDATE`/`FOR
        // SHARE` over zero rows locks nothing, so proceeding here would run
        // unserialised — the trap `lock_fragment_head`'s own doc names.
        let Some(state) = locked.get(*hash) else {
            return Err(DomainError::PreconditionRejected {
                reason: STAGED_LEASE_MEMBER_NOT_STAGED.to_owned(),
                reason_version: 1,
            });
        };
        // The epoch-level `DISPOSITION_PURGED` guard is exactly one epoch deep,
        // and `commit_obliterate` purges only the epoch that was current when
        // it began. A promoted fragment therefore leaves its staged predecessor
        // `QUARANTINED` — admitted by design — and obliterating that fragment
        // purges only the promoted epoch, leaving the staged one still looking
        // leasable. Refusing on the head's state is what closes that, and it
        // costs nothing the promotion case needs: a promoted head is `Remote`
        // and readable.
        if *state == FragmentLifecycleState::Tombstoned || state.is_deleting() {
            return Err(DomainError::PreconditionRejected {
                reason: STAGED_LEASE_MEMBER_NOT_STAGED.to_owned(),
                reason_version: 1,
            });
        }
    }
    Ok(())
}

/// One required fragment whose current epoch is not the one preflight
/// captured.
///
/// Named fields rather than a tuple because the two `i64`s are trivially
/// transposable and a transposition here would compare the wrong pair of epoch
/// rows without failing anything loudly.
struct DivergentEpoch<'a> {
    /// The FragmentId.
    hash: &'a [u8],
    /// The epoch preflight saw.
    captured: i64,
    /// The epoch the head names now.
    current: i64,
}

/// Decide CR-031:266's "semantically equivalent current epoch" for every
/// required fragment whose epoch moved between preflight and the final push.
///
/// # The rule
///
/// Two epochs of one FragmentId are semantically equivalent when their
/// `lore_fragment_epochs` rows describe the **same content**: identical
/// `decoded_hash`, `size_content`, `size_payload`, and `payload_flags`. None of
/// those four columns is ever rewritten after publication — `disposition` and
/// `validated_at` are the only mutable columns on the row, so "the epoch row is
/// immutable" is too strong a claim, but the compared columns are.
///
/// Comparing `decoded_hash` is load-bearing rather than belt-and-braces:
/// nothing in this module enforces that two epochs of one FragmentId decode to
/// the same content, so it cannot be assumed from the hash alone.
///
/// The two epochs may differ in `authority` and `object_key`, and that
/// difference is the whole point — it is exactly a `Staged`->`Remote`
/// promotion, which re-publishes the same bytes under a new epoch because
/// epoch rows are immutable and the remote object is a different
/// representation of the same fragment (see
/// [`PostgresFragmentCoordinator::begin_promotion`]).
///
/// `manifest_id` is deliberately **not** compared. It is a caller-supplied
/// opaque identity for one representation, so a promotion may legitimately
/// carry a new one; requiring equality there would leave the allowance dead in
/// the one case CR-031 names.
///
/// # What still aborts
///
/// Everything else. A repair successor that re-encoded the payload moves
/// `payload_flags` or `size_payload` and is "different". A required fragment
/// with no row at its captured epoch is "different" — that row is retained
/// through quarantine and purge, so its absence means the caller's epoch was
/// never real here. The readability check in the caller runs first and is
/// untouched, so missing, deleting, and tombstoned heads never reach this.
///
/// This is a strict widening of what commits: every set this accepts was
/// previously an `ABORTED` the caller had to re-preflight for, and no set it
/// rejects was previously accepted.
///
/// # Why the allowance is safe, and what it depends on
///
/// The caller aborts unconditionally when the **association** scalar moved,
/// before the count check and long before this runs. That is load-bearing
/// rather than incidental: it is what keeps an obliterate-then-recreate — which
/// tombstones associations and so always moves that scalar — out of reach of
/// this function. Equivalence over content columns alone would not be enough.
///
/// That dependency is no longer positional. This function takes both witnesses
/// and `debug_assert_eq!`s the association scalar itself, so the precondition is
/// an argument it checks rather than an ordering a reader has to notice, and
/// [`classify_push_witness`] makes the precedence a value rather than a branch
/// order.
///
/// # Where each guarantee is actually pinned — measured, not assumed
///
/// An earlier version of this comment claimed the assertion "makes a reordering
/// fail a `cargo test` run instead of only the live tier". **That is false and
/// is retracted.** This function is unreachable without a database, so with the
/// `AssociationMoved` arm stubbed to fall through, `cargo test -p lore-postgres`
/// stays fully green and only the live tier fails — measured both with and
/// without the assertion present. The three guards partition as:
///
/// * [`classify_push_witness`]'s unit tests are the **only** offline pin, and
///   their scope is the classifier itself, not its use.
/// * The live case is what **detects** a consumer that skips the abort arm. It
///   does so with or without the assertion.
/// * This assertion is a live-tier **tripwire**: it fires one frame earlier than
///   the verdict assertion, naming the violated invariant instead of leaving a
///   wrong verdict to be interpreted. Diagnosis, not detection.
///
/// **A release build is fully sufficient without it.** The `AssociationMoved`
/// arm returns `Aborted` unconditionally and no assertion sits in that path, so
/// release enforces the precedence exactly as debug does. Compiling the
/// assertion out costs nothing.
///
/// Quarantine cannot forge equivalence either: a publication quarantines only
/// epochs below the one it publishes, so a readable head's current epoch is
/// never quarantined or purged.
///
/// # Cost
///
/// One extra statement, and only when at least one epoch actually moved. The
/// unchanged fast path and the all-epochs-match fallback issue nothing.
///
/// It takes no lock of its own, and does not need one. The caller already holds
/// `FOR UPDATE` on every head it is asking about, so the `current_epoch` values
/// this statement is keyed on cannot move underneath it; the compared columns
/// are never rewritten; and at READ COMMITTED this statement sees one coherent
/// snapshot of rows that were already committed when the head lock was taken.
/// It therefore adds no lock class and cannot invert F-032-3.
async fn equivalent_epochs(
    tx: &Transaction<'_>,
    captured: PushGenerationWitness,
    current: PushGenerationWitness,
    divergent: &[DivergentEpoch<'_>],
) -> Result<bool, DomainError> {
    // The precondition, checked here rather than left to a reader noticing the
    // caller's branch order. Taking both witnesses turns "the association check
    // happens earlier in the function" from an ordering into an argument this
    // function verifies.
    //
    // This is a live-tier tripwire, NOT offline coverage: reaching this line
    // needs a database, so a consumer that skips the abort arm is detected by
    // the live case either way. What the assertion adds is the diagnosis —
    // it fires one frame before the verdict assertion and names the invariant.
    // See this function's doc for the measurement.
    debug_assert_eq!(
        captured.content_association_generation, current.content_association_generation,
        "equivalent_epochs must never see a witness whose association scalar moved: the fallback \
         revalidates representations, not membership, so an obliterate-then-recreate could present \
         equal content columns and be accepted against an association set that no longer holds it"
    );
    let hashes: Vec<&[u8]> = divergent.iter().map(|item| item.hash).collect();
    let captured: Vec<i64> = divergent.iter().map(|item| item.captured).collect();
    let current: Vec<i64> = divergent.iter().map(|item| item.current).collect();
    let matched: i64 = tx
        .query_one(
            "SELECT count(*)::bigint FROM unnest($1::bytea[], $2::bigint[], $3::bigint[]) \
                    AS required(hash, captured_epoch, current_epoch) \
                    JOIN lore_fragment_epochs AS was \
                      ON was.hash = required.hash AND was.epoch = required.captured_epoch \
                    JOIN lore_fragment_epochs AS now \
                      ON now.hash = required.hash AND now.epoch = required.current_epoch \
              WHERE was.decoded_hash  = now.decoded_hash \
                AND was.size_content  = now.size_content \
                AND was.size_payload  = now.size_payload \
                AND was.payload_flags = now.payload_flags",
            &[&hashes, &captured, &current],
        )
        .await
        .map_err(|error| DomainError::from_pg("push fallback epoch equivalence", error))?
        .get(0);
    // All or nothing: one non-equivalent member aborts the whole push. Compare
    // in `i64` rather than narrowing `matched` to `usize`, so an impossible
    // negative count cannot be flattened into a silent abort.
    Ok(i64::try_from(divergent.len()).is_ok_and(|expected| matched == expected))
}

/// Refuse a wrong-length `lease_id` before any database work.
///
/// [`schema::STAGED_LEASE_ID_LEN`] and the DDL's `octet_length(lease_id) = 16`
/// CHECK are the same bound; this is the typed half, so the caller gets
/// [`DomainError::InvalidInput`] (never retryable, never a partial write)
/// instead of a bare 23514 from the table (INV-EF P2-6).
fn validate_lease_id(lease_id: &[u8]) -> Result<(), DomainError> {
    if lease_id.len() != schema::STAGED_LEASE_ID_LEN {
        return Err(DomainError::InvalidInput(format!(
            "staged lease id must be exactly {} bytes, got {}",
            schema::STAGED_LEASE_ID_LEN,
            lease_id.len()
        )));
    }
    Ok(())
}

/// Refuse a member batch the lease schema cannot represent faithfully.
///
/// `lore_fragment_staged_lease_members` is keyed `(lease_id, hash)`, so a batch
/// repeating one hash at two epochs persists as **one** row while the returned
/// [`StagedReaderLease`] claims both — the second epoch reads as protected and
/// is not, and a faithful retry of the same batch then compares two proposed
/// members against one stored member and is refused as a mismatch. One hash
/// resolves to one epoch per hydration request, so a repeat is a caller defect
/// rather than a shape to accommodate.
///
/// An empty batch is refused for a smaller reason: it publishes a live lease
/// that protects nothing, which a reaper then has to clean. A caller with no
/// staged fragments takes no lease.
fn validate_lease_members(members: &[(Vec<u8>, i64)]) -> Result<(), DomainError> {
    if members.is_empty() {
        return Err(DomainError::InvalidInput(
            "a staged reader lease must cover at least one member".to_owned(),
        ));
    }
    // Bounded because both `LockClass::Fragments` siblings bound their row set
    // and this one did not — a consistency gap, not a measured regression; see
    // `MAX_STAGED_LEASE_MEMBERS`, which records that behaviour at large member
    // counts is unmeasured. Refused here, before any database work, so an
    // over-large batch takes no lock at all.
    if members.len() > MAX_STAGED_LEASE_MEMBERS {
        return Err(DomainError::InvalidInput(format!(
            "a staged reader lease may cover at most {MAX_STAGED_LEASE_MEMBERS} members, got {}; \
             split the hydration across several leases, which protect the same bytes because \
             leases are independent",
            members.len()
        )));
    }
    let mut seen: BTreeSet<&[u8]> = BTreeSet::new();
    for (hash, _) in members {
        if !seen.insert(hash.as_slice()) {
            return Err(DomainError::InvalidInput(format!(
                "staged lease member hash {} appears more than once; the member table is keyed \
                 (lease_id, hash) and cannot hold two epochs for one hash",
                hex_lower(hash)
            )));
        }
    }
    Ok(())
}

/// Resolve a duplicate `acquire_staged_leases` against the lease that already
/// holds that id.
///
/// A faithful replay — same member set, lease not yet terminal — returns the
/// **existing** lease: its original `reader_fence` and `deadline`, not the ones
/// this attempt proposed. Anything else is refused, because it is an id
/// collision rather than a retry. See `acquire_staged_leases`' own doc for why
/// each of the two refusals is the safe choice.
async fn replay_staged_lease(
    tx: &Transaction<'_>,
    lease_id: &[u8],
    members: &[(Vec<u8>, i64)],
) -> Result<StagedReaderLease, DomainError> {
    let Some(row) = tx
        .query_opt(
            "SELECT reader_fence, deadline, terminal FROM lore_fragment_staged_leases \
              WHERE lease_id = $1 FOR UPDATE",
            &[&lease_id],
        )
        .await
        .map_err(|error| DomainError::from_pg("staged lease replay read", error))?
    else {
        // The insert conflicted, so the row existed a statement ago. Only a
        // concurrent reaper can have removed it in between, and a lease this
        // acquire never established is not one it may report as held.
        //
        // Decisive, not retryable, and that is the point. A retryable error
        // here would be re-driven straight back into `acquire_staged_leases`,
        // where the insert now succeeds and publishes a **new live lease under
        // the same id** — turning a just-reaped, possibly released lease back
        // into live protection, which is exactly what
        // `STAGED_LEASE_ALREADY_RELEASED` refuses one statement earlier. The
        // caller's remedy is a new lease id, never a retry of this one.
        return Err(DomainError::PreconditionRejected {
            reason: STAGED_LEASE_VANISHED.to_owned(),
            reason_version: 1,
        });
    };
    if row.get::<_, bool>("terminal") {
        return Err(DomainError::PreconditionRejected {
            reason: STAGED_LEASE_ALREADY_RELEASED.to_owned(),
            reason_version: 1,
        });
    }
    let existing_members = tx
        .query(
            "SELECT hash, epoch FROM lore_fragment_staged_lease_members WHERE lease_id = $1",
            &[&lease_id],
        )
        .await
        .map_err(|error| DomainError::from_pg("staged lease replay members", error))?;
    // Set comparison, not sequence comparison: the caller's batch order is its
    // own business and a reordered retry is still the same lease.
    let existing: BTreeSet<(Vec<u8>, i64)> = existing_members
        .iter()
        .map(|row| (row.get("hash"), row.get("epoch")))
        .collect();
    let proposed: BTreeSet<(Vec<u8>, i64)> = members.iter().cloned().collect();
    if existing != proposed {
        return Err(DomainError::PreconditionRejected {
            reason: STAGED_LEASE_MEMBER_SET_MISMATCH.to_owned(),
            reason_version: 1,
        });
    }
    Ok(StagedReaderLease {
        lease_id: lease_id.to_vec(),
        reader_fence: row.get("reader_fence"),
        deadline: row.get("deadline"),
        // Proven equal as a set just above, so this is the caller's own
        // ordering of the same members the lease holds.
        members: members.to_vec(),
    })
}

/// Allocate one monotonic epoch or fence. Gaps are valid.
async fn next_fence(tx: &Transaction<'_>) -> Result<i64, DomainError> {
    tx.query_one("SELECT nextval('lore_fragment_fence_seq')::bigint", &[])
        .await
        .map_err(|error| DomainError::from_pg("fragment fence allocation", error))
        .map(|row| row.get(0))
}

fn duration_millis(context: &str, duration: Duration) -> Result<i64, DomainError> {
    let millis = duration.as_millis();
    if !(1..=MAX_FRAGMENT_WRITE_CLAIM_DURATION_MILLIS).contains(&millis) {
        return Err(DomainError::InvalidInput(format!(
            "{context} must be between 1 and {MAX_FRAGMENT_WRITE_CLAIM_DURATION_MILLIS} milliseconds"
        )));
    }
    i64::try_from(millis)
        .map_err(|_| DomainError::InvalidInput(format!("{context} exceeds i64 milliseconds")))
}

/// Stamp the head with the fence this operation was issued at, so a delayed
/// commit can tell whether anything linearized in between.
///
/// It deliberately does **not** write `active_operation`. Phase 5 uses that
/// column for the direct-publication lineage token, while the other operations
/// that call this helper have no operation identity in scope. Clearing or
/// replacing the token here would lose a recoverable `PreparingRemote`
/// publication's exact object-key lineage. The naming is deliberate: an
/// earlier `set_active_operation` name claimed a write this function never
/// made.
async fn stamp_operation_fence(
    tx: &Transaction<'_>,
    hash: &[u8],
    fence: i64,
) -> Result<(), DomainError> {
    tx.execute(
        "UPDATE lore_fragment_lifecycle \
            SET last_fence = $2, updated_at = clock_timestamp() WHERE hash = $1",
        &[&hash, &fence],
    )
    .await
    .map_err(|error| DomainError::from_pg("fragment operation fence stamp", error))?;
    Ok(())
}

/// Move one repository's association scalar. The row is already locked by the
/// caller's `lock_repository`, so this takes no new lock class.
/// **PRECONDITION: the caller already holds this repository row `FOR UPDATE`.**
///
/// This takes no `LockSequence::enter`, and that is deliberate rather than an
/// oversight of the kind INV-EF P2-4 flags. Registering here would be *wrong*,
/// not merely redundant: `create_association` reaches this after entering
/// `LockClass::Associations` (position 5), so an `enter(Repository)` at position
/// 1 would be a downward move and `LockSequence` would reject the whole
/// transaction. The row is already held from that method's opening call to
/// `lock_repository`, so this statement acquires nothing new.
///
/// The cost is that the guard cannot see this write. A future caller that reaches
/// it without holding the row gets no error — it gets an unserialised increment.
/// Verify the precondition at any new call site; do not infer it from the fact
/// that the existing ones are fine.
async fn bump_association_generation(
    tx: &Transaction<'_>,
    repository_id: &[u8],
) -> Result<(), DomainError> {
    tx.execute(
        "UPDATE lore_domain_repositories \
            SET content_association_generation = content_association_generation + 1 \
          WHERE repository_id = $1",
        &[&repository_id],
    )
    .await
    .map_err(|error| DomainError::from_pg("association generation bump", error))?;
    Ok(())
}

/// Read, without locking, the repositories a readable/unreadable transition on
/// this hash would have to visit, and bound the set before anything is taken.
///
/// **This must run before the head is locked.** A lifecycle transition updates
/// `lore_domain_repositories`, which is `LockClass::Repository` (position 1),
/// while the head is `LockClass::Fragments` (position 4). Discovering the fanout
/// after taking the head and then reaching back for repository rows is an
/// F-032-3 inversion — and `LockSequence::enter` rejects it, so the whole
/// transition fails rather than deadlocking. Either way the fanout has to be
/// planned first.
///
/// The count check is CR-031's explicit admission bound: a set above
/// [`MAX_LIFECYCLE_GENERATION_FANOUT`] fails **before** any row is locked,
/// rather than taking an unbounded row-lock set inside one transaction.
async fn plan_lifecycle_fanout(
    tx: &Transaction<'_>,
    hash: &[u8],
) -> Result<Vec<Vec<u8>>, DomainError> {
    let rows = tx
        .query(
            "SELECT repository_id FROM lore_fragment_associations \
              WHERE hash = $1 AND state = $2 ORDER BY repository_id",
            &[&hash, &schema::ASSOCIATION_LIVE],
        )
        .await
        .map_err(|error| DomainError::from_pg("lifecycle fanout measure", error))?;
    if rows.len() > MAX_LIFECYCLE_GENERATION_FANOUT {
        return Err(DomainError::PreconditionRejected {
            reason: "lifecycle_generation_fanout_limit".to_owned(),
            reason_version: 1,
        });
    }
    Ok(rows.iter().map(|row| row.get("repository_id")).collect())
}

/// Lock the planned fanout's repository rows, in ascending repository order.
///
/// One row at a time rather than a set-based statement, because Postgres does
/// not fix the lock acquisition order of `UPDATE ... WHERE id = ANY(...)`, and
/// two transitions over an overlapping fanout must meet the overlap in the same
/// sequence.
async fn lock_lifecycle_fanout(
    tx: &Transaction<'_>,
    sequence: &mut LockSequence,
    repositories: &[Vec<u8>],
) -> Result<(), DomainError> {
    for repository_id in repositories {
        sequence.enter(LockClass::Repository)?;
        let locked = tx
            .execute(
                "SELECT 1 FROM lore_domain_repositories WHERE repository_id = $1 FOR UPDATE",
                &[&repository_id],
            )
            .await
            .map_err(|error| DomainError::from_pg("lifecycle fanout repository lock", error))?;
        if locked == 0 {
            // `FOR UPDATE` over zero rows locks nothing, silently. Letting that
            // pass would mean the later set-based update touches fewer rows
            // than were planned, which is precisely the partial fanout CR-031
            // forbids — and the "all or nothing" claim would be false without
            // anything failing.
            //
            // This is damage, not a race: `create_association` refuses when the
            // repository row is absent, and repository identities are
            // tombstoned rather than deleted, so a live association to a
            // nonexistent repository cannot arise from ordinary operation.
            return Err(DomainError::Internal(format!(
                "a live fragment association names repository {} which has no domain row; \
                 the fanout cannot be taken atomically",
                hex_lower(repository_id)
            )));
        }
    }
    Ok(())
}

/// Re-read the live fanout under the head lock and confirm it is still covered
/// by the rows this transaction locked.
///
/// **Every caller must run this, whether or not it goes on to move a scalar.**
/// It used to live inside [`apply_lifecycle_generation`], which
/// `begin_obliterate` calls only under `if was_readable` — so on a non-readable
/// head the growth check was skipped while the association tombstone still ran
/// by predicate over the *current* set. An association created between the plan
/// read and the head lock was then retired by a transaction that had never
/// locked its repository row and never moved its scalar (INV-EF P1-1).
///
/// The set cannot grow once the head row is **actually** held:
/// `create_association` takes the repository row, then the head, then the
/// association row, so a concurrent inserter blocks on the head before it can
/// insert. That guarantee is exactly as strong as the head lock and no stronger,
/// which is why every caller of this helper has already returned on a `None`
/// head — `FOR UPDATE` over an absent row locks nothing (see
/// [`lock_fragment_head`]). It *can* have grown between the plan and the head
/// lock, and a repository that appeared in that window is one this transaction
/// never locked; committing anyway would be the partial fanout CR-031 forbids,
/// so this returns retryable [`DomainError::Contention`].
///
/// Returns the confirmed set, which callers use for **both** the generation
/// bump and the association tombstone, so those two can no longer disagree
/// about which repositories the operation affects.
async fn confirm_lifecycle_fanout(
    tx: &Transaction<'_>,
    hash: &[u8],
    locked: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, DomainError> {
    let current = match plan_lifecycle_fanout(tx, hash).await {
        Ok(current) => current,
        // The re-plan crossing the admission bound is a race, not a caller
        // error: the first plan was under the limit, so the operation was
        // legitimately admitted and the set grew underneath it. Returning the
        // non-retryable `PreconditionRejected` the initial plan uses would turn
        // a retryable window into a hard refusal.
        Err(DomainError::PreconditionRejected { reason, .. }) => {
            return Err(DomainError::Contention(format!(
                "the live-association fanout for this fragment crossed the admission bound \
                 between planning and the head lock ({reason}); retrying re-admits it"
            )));
        }
        Err(other) => return Err(other),
    };
    let held: BTreeSet<&Vec<u8>> = locked.iter().collect();
    if current.iter().any(|id| !held.contains(id)) {
        return Err(DomainError::Contention(format!(
            "the live-association fanout for this fragment grew from {} to {} repositories \
             between planning and the head lock; retrying plans the larger set",
            locked.len(),
            current.len()
        )));
    }
    Ok(current)
}

/// Move the lifecycle scalar for every repository in the confirmed fanout.
///
/// One statement over rows [`confirm_lifecycle_fanout`] has already proved this
/// transaction holds, so a partial fanout is not representable.
async fn apply_lifecycle_generation(
    tx: &Transaction<'_>,
    locked: &[Vec<u8>],
) -> Result<(), DomainError> {
    if locked.is_empty() {
        return Ok(());
    }
    // Bound by `locked`, which this has just proved is a superset of `current`.
    // Writing the already-locked set makes "one statement over rows this
    // transaction holds" literally true rather than true by inference.
    tx.execute(
        "UPDATE lore_domain_repositories \
            SET fragment_lifecycle_generation = fragment_lifecycle_generation + 1 \
          WHERE repository_id = ANY($1)",
        &[&locked],
    )
    .await
    .map_err(|error| DomainError::from_pg("lifecycle generation bump", error))?;
    Ok(())
}

async fn fragment_schema_presence(
    client: &deadpool_postgres::Client,
) -> Result<FragmentSchemaPresence, DomainError> {
    let present: i64 = client
        .query_one(
            "SELECT count(*)::bigint FROM unnest($1::text[]) AS relation \
              WHERE to_regclass(relation) IS NOT NULL",
            &[&schema::FRAGMENT_SCHEMA_RELATIONS.as_slice()],
        )
        .await
        .map_err(|error| DomainError::from_pg("fragment schema probe", error))?
        .get(0);
    Ok(if present == 0 {
        FragmentSchemaPresence::Absent
    } else if present == schema::FRAGMENT_SCHEMA_RELATIONS.len() as i64 {
        FragmentSchemaPresence::Complete
    } else {
        FragmentSchemaPresence::Partial { present }
    })
}

async fn repository_generation_columns_present(
    client: &deadpool_postgres::Client,
) -> Result<bool, DomainError> {
    let present: i64 = client
        .query_one(
            "SELECT count(*)::bigint FROM information_schema.columns \
              WHERE table_name = 'lore_domain_repositories' \
                AND column_name IN ('content_association_generation', \
                                    'fragment_lifecycle_generation')",
            &[],
        )
        .await
        .map_err(|error| DomainError::from_pg("repository generation column probe", error))?
        .get(0);
    Ok(present == 2)
}

/// The legacy bare-hash key, unchanged. A normal first write keeps using it so
/// an existing cell's objects stay addressable and no key migration is implied.
fn legacy_hash_key(hash: &[u8]) -> String {
    hex_lower(hash)
}

/// A server-only immutable key for a repair successor. Never the legacy key:
/// that is what stops a repair from overwriting bytes another epoch's manifest
/// still names.
fn repair_epoch_key(hash: &[u8], epoch: i64) -> String {
    format!("{}.r{epoch}", hex_lower(hash))
}

/// A server-only key for a staged epoch's finalized file.
fn staged_epoch_key(hash: &[u8], epoch: i64) -> String {
    format!("{}.s{epoch}", hex_lower(hash))
}

fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, byte| {
        // Writing to a String is infallible; the Result exists only because
        // `write!` is generic over `fmt::Write`.
        let _ = write!(out, "{byte:02x}");
        out
    })
}

/// A lost commit acknowledgement is `OutcomeUnknown`, never a retry.
fn classify_commit(
    result: Result<(), tokio_postgres::Error>,
    context: &str,
) -> Result<(), DomainError> {
    match result {
        Ok(()) => Ok(()),
        Err(error) => {
            let classified = DomainError::from_pg(context, error);
            match classified {
                DomainError::Transient(message) => Err(DomainError::OutcomeUnknown(message)),
                other => Err(other),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn witness(epoch: i64, state: FragmentLifecycleState, fence: i64) -> EpochWitness {
        EpochWitness {
            hash: vec![7u8; 32],
            epoch,
            state,
            manifest_id: Some(vec![9u8; 32]),
            fence,
        }
    }

    fn head(epoch: i64, state: FragmentLifecycleState, fence: i64) -> FragmentHeadLock {
        FragmentHeadLock {
            current_epoch: epoch,
            state,
            manifest_id: Some(vec![9u8; 32]),
            last_fence: fence,
            active_operation: None,
        }
    }

    #[test]
    fn an_exactly_unchanged_head_matches_its_witness() {
        let captured = witness(4, FragmentLifecycleState::Remote, 11);
        assert!(head(4, FragmentLifecycleState::Remote, 11).matches(&captured));
    }

    #[test]
    fn each_moved_witness_field_independently_fences() {
        let captured = witness(4, FragmentLifecycleState::Remote, 11);
        assert!(
            !head(5, FragmentLifecycleState::Remote, 11).matches(&captured),
            "a moved epoch must fence"
        );
        assert!(
            !head(4, FragmentLifecycleState::Missing, 11).matches(&captured),
            "a moved state must fence"
        );
        assert!(
            !head(4, FragmentLifecycleState::Remote, 12).matches(&captured),
            "a moved fence must fence"
        );
        let mut replaced_manifest = head(4, FragmentLifecycleState::Remote, 11);
        replaced_manifest.manifest_id = Some(vec![1u8; 32]);
        assert!(
            !replaced_manifest.matches(&captured),
            "a replaced manifest at the same epoch must fence"
        );
    }

    #[test]
    fn the_repair_key_is_never_the_legacy_key() {
        // Overwriting the legacy key with repair bytes is forbidden by CR-031's
        // rollback policy, and this is the constructor that makes it
        // impossible rather than merely discouraged.
        let hash = vec![0xabu8; 32];
        assert_ne!(repair_epoch_key(&hash, 9), legacy_hash_key(&hash));
        assert_ne!(staged_epoch_key(&hash, 9), legacy_hash_key(&hash));
        assert_ne!(repair_epoch_key(&hash, 9), staged_epoch_key(&hash, 9));
        // Two repair epochs of the same fragment are distinct keys, so a second
        // repair cannot land on the first one's bytes either.
        assert_ne!(repair_epoch_key(&hash, 9), repair_epoch_key(&hash, 10));
    }

    #[test]
    fn the_legacy_key_is_the_bare_lowercase_hex_hash() {
        // `PostgresImmutableStore::hash_key` derives the object key as bare
        // lowercase hex with no prefix. A normal first write must keep landing
        // on exactly that key or every existing object becomes unreachable.
        assert_eq!(legacy_hash_key(&[0x00, 0x0f, 0xff]), "000fff");
    }

    #[test]
    fn the_fanout_bound_matches_the_push_revalidation_bound() {
        assert_eq!(
            MAX_LIFECYCLE_GENERATION_FANOUT,
            MAX_PUSH_FRAGMENT_REVALIDATIONS
        );
        // CR-031 fixes this at 4,096 for WP-118. A silent change here would
        // move the point at which a push is refused.
        assert_eq!(MAX_PUSH_FRAGMENT_REVALIDATIONS, 4_096);
        // The third per-transaction row budget in `LockClass::Fragments`. All
        // three bound a row-lock acquisition over the same table in the same
        // lock class, so a divergence between them is a claim that one of those
        // acquisitions costs something different — which is a claim that needs
        // a measurement, not a constant edit.
        assert_eq!(MAX_STAGED_LEASE_MEMBERS, MAX_PUSH_FRAGMENT_REVALIDATIONS);
    }

    #[test]
    fn not_provisioned_reads_as_no_lifecycle_evidence_on_every_field() {
        // The INV-EE P0-1 shape: a caller that checks only `lifecycle_enabled`
        // and a caller that checks the whole evidence set must reach the same
        // legacy-route conclusion.
        let readiness = FragmentLifecycleReadiness::not_provisioned();
        assert!(!readiness.provisioned);
        assert!(!readiness.lifecycle_enabled);
        assert!(!readiness.cutover_at_present);
        assert!(!readiness.same_database);
        assert!(!readiness.sequence_headroom);
        assert_eq!(readiness.schema_version, 0);
        assert_eq!(readiness.backfill_state, schema::BACKFILL_NOT_STARTED);
        assert_eq!(readiness.unresolved_rows, 0);
        assert!(!readiness.ready_for_lifecycle());
    }

    #[test]
    fn readiness_fails_closed_on_each_missing_precondition() {
        let ready = FragmentLifecycleReadiness {
            provisioned: true,
            schema_version: schema::FRAGMENT_SCHEMA_VERSION,
            backfill_state: schema::BACKFILL_CUTOVER,
            cutover_at_present: true,
            lifecycle_enabled: false,
            same_database: true,
            sequence_headroom: true,
            unresolved_rows: 0,
            write_capability: FragmentWriteCapability::Optional,
        };
        assert!(ready.ready_for_lifecycle());

        let mut before_cutover = ready.clone();
        before_cutover.backfill_state = schema::BACKFILL_VERIFIED;
        assert!(!before_cutover.ready_for_lifecycle());

        let mut no_marker = ready.clone();
        no_marker.cutover_at_present = false;
        assert!(!no_marker.ready_for_lifecycle());

        let mut other_database = ready.clone();
        other_database.same_database = false;
        assert!(!other_database.ready_for_lifecycle());

        let mut no_headroom = ready.clone();
        no_headroom.sequence_headroom = false;
        assert!(!no_headroom.ready_for_lifecycle());

        let mut damaged = ready.clone();
        damaged.unresolved_rows = 1;
        assert!(!damaged.ready_for_lifecycle());

        let mut unprovisioned = ready;
        unprovisioned.provisioned = false;
        assert!(!unprovisioned.ready_for_lifecycle());
    }

    #[test]
    fn a_fenced_commit_verdict_is_not_a_publication() {
        assert!(CommitVerdict::Published.published());
        assert!(!CommitVerdict::Fenced.published());
    }

    #[test]
    fn a_transition_locks_repository_rows_before_the_head() {
        // The shape every transition path uses: plan the fanout unlocked, lock
        // those repository rows (position 1), then the head (position 4), then
        // associations (position 5).
        let mut sequence = LockSequence::new();
        sequence
            .enter(LockClass::Repository)
            .expect("fanout repository row");
        sequence
            .enter(LockClass::Repository)
            .expect("a second fanout repository row");
        sequence
            .enter(LockClass::Fragments)
            .expect("the lifecycle head");
        sequence
            .enter(LockClass::Associations)
            .expect("association rows");
    }

    #[test]
    fn reaching_back_for_a_repository_row_after_the_head_is_refused() {
        // This is the inversion the first cut of this file shipped: the head
        // was locked, and only then did the fanout reach for repository rows.
        // `LockSequence` rejects it, so it did not deadlock — it failed every
        // readable/unreadable transition on any fragment with a live
        // association, which is every one that matters. Pinned here because it
        // is invisible without a fanout, and cheap to reintroduce.
        let mut sequence = LockSequence::new();
        sequence
            .enter(LockClass::Fragments)
            .expect("the lifecycle head");
        let error = sequence
            .enter(LockClass::Repository)
            .expect_err("a repository row after the head must be refused");
        assert!(matches!(error, DomainError::Internal(_)));
    }

    #[test]
    fn the_two_refusal_reasons_are_distinct_codes() {
        // A caller distinguishes "your required set is too large, nothing was
        // touched, split the push" from "something you require changed, take a
        // fresh preflight". Collapsing them would make the first look retryable
        // in the same way as the second.
        assert_ne!(
            REQUIRED_FRAGMENT_REVALIDATION_LIMIT,
            REQUIRED_FRAGMENT_CHANGED
        );
    }

    fn push_witness(association: i64, lifecycle: i64) -> PushGenerationWitness {
        PushGenerationWitness {
            content_association_generation: association,
            fragment_lifecycle_generation: lifecycle,
        }
    }

    #[test]
    fn an_association_move_outranks_a_lifecycle_move() {
        // THE case. Both scalars moved, which is exactly what an
        // obliterate-then-recreate produces: it tombstones associations and
        // crosses readability. It must abort, never reach the bounded
        // fallback, and never be handed to the equivalence allowance -- a
        // recreated fragment can present identical content columns and would
        // otherwise be accepted as semantically equivalent to an epoch whose
        // association is gone.
        assert_eq!(
            classify_push_witness(push_witness(1, 1), push_witness(2, 2)),
            PushWitnessChange::AssociationMoved,
            "an association move must outrank a simultaneous lifecycle move"
        );
    }

    #[test]
    fn each_push_witness_shape_classifies_to_exactly_one_outcome() {
        assert_eq!(
            classify_push_witness(push_witness(1, 1), push_witness(1, 1)),
            PushWitnessChange::Neither
        );
        assert_eq!(
            classify_push_witness(push_witness(1, 1), push_witness(2, 1)),
            PushWitnessChange::AssociationMoved
        );
        assert_eq!(
            classify_push_witness(push_witness(1, 1), push_witness(1, 2)),
            PushWitnessChange::LifecycleOnly
        );
        // Only `LifecycleOnly` may attempt the fallback. If a fourth shape is
        // ever added, this is where the fallback's precondition has to be
        // re-argued rather than silently widened.
        for (association, lifecycle) in [(1, 1), (2, 1), (1, 2), (2, 2)] {
            let change =
                classify_push_witness(push_witness(1, 1), push_witness(association, lifecycle));
            assert_eq!(
                change == PushWitnessChange::LifecycleOnly,
                association == 1 && lifecycle != 1,
                "({association}, {lifecycle}) classified as {change:?}"
            );
        }
    }

    #[test]
    fn a_lease_id_must_be_exactly_the_schema_length() {
        // Both guards are pure and refuse before any database work, so they
        // belong offline rather than only behind an `#[ignore]` live case.
        assert!(validate_lease_id(&[0u8; schema::STAGED_LEASE_ID_LEN]).is_ok());
        for length in [
            0,
            schema::STAGED_LEASE_ID_LEN - 1,
            schema::STAGED_LEASE_ID_LEN + 1,
        ] {
            assert!(
                matches!(
                    validate_lease_id(&vec![0u8; length]),
                    Err(DomainError::InvalidInput(_))
                ),
                "a {length}-byte lease id must be refused as InvalidInput"
            );
        }
    }

    #[test]
    fn a_lease_member_batch_is_non_empty_and_names_each_hash_once() {
        let first = vec![1u8; 32];
        let second = vec![2u8; 32];
        assert!(validate_lease_members(&[(first.clone(), 4), (second.clone(), 5)]).is_ok());
        assert!(
            matches!(
                validate_lease_members(&[]),
                Err(DomainError::InvalidInput(_))
            ),
            "an empty batch publishes a lease that protects nothing"
        );
        // The member table is keyed (lease_id, hash), so this batch would
        // persist one row while the returned lease claimed two.
        assert!(
            matches!(
                validate_lease_members(&[(first.clone(), 4), (first, 9)]),
                Err(DomainError::InvalidInput(_))
            ),
            "one hash at two epochs must be refused, not silently deduplicated"
        );
    }

    #[test]
    fn a_lease_member_batch_is_bounded_before_any_lock_is_taken() {
        // `lock_lease_member_heads` takes a FOR SHARE row lock per member, so
        // an unbounded batch is an unbounded lock acquisition. Distinct hashes
        // throughout, so this exercises the bound rather than tripping the
        // duplicate guard.
        let batch = |count: usize| -> Vec<(Vec<u8>, i64)> {
            (0..count)
                .map(|index| {
                    let mut hash = vec![0u8; 32];
                    hash[..8].copy_from_slice(&(index as u64).to_be_bytes());
                    (hash, 1)
                })
                .collect()
        };
        assert!(
            validate_lease_members(&batch(MAX_STAGED_LEASE_MEMBERS)).is_ok(),
            "exactly the bound must be admitted; an off-by-one here silently narrows hydration"
        );
        assert!(
            matches!(
                validate_lease_members(&batch(MAX_STAGED_LEASE_MEMBERS + 1)),
                Err(DomainError::InvalidInput(_))
            ),
            "one over the bound must be refused before any database work"
        );
    }

    #[test]
    fn every_staged_lease_refusal_reason_is_a_distinct_code() {
        // These land in a receipt's reason field, so a collision would make two
        // different refusals indistinguishable to the caller that has to decide
        // between retrying with a new id and fixing its batch.
        let reasons = [
            STAGED_LEASE_MEMBER_NOT_STAGED,
            STAGED_LEASE_MEMBER_SET_MISMATCH,
            STAGED_LEASE_ALREADY_RELEASED,
            STAGED_LEASE_VANISHED,
        ];
        let distinct: BTreeSet<&str> = reasons.into_iter().collect();
        assert_eq!(
            distinct.len(),
            reasons.len(),
            "{reasons:?} are not distinct"
        );
    }
}

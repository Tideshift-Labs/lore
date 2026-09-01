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
use std::time::SystemTime;

use deadpool_postgres::Pool;
use deadpool_postgres::Transaction;

use crate::domain::PostgresDomainStore;
use crate::domain::errors::DomainError;
use crate::domain::fragments::schema;
use crate::domain::fragments::states::EpochAuthority;
use crate::domain::fragments::states::FragmentLifecycleState;
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
    /// The head as captured at begin, for post-I/O revalidation. `None` when
    /// this operation created the head.
    pub captured: Option<EpochWitness>,
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

        Ok(FragmentLifecycleReadiness {
            provisioned: true,
            schema_version: row.get("schema_version"),
            backfill_state: row.get("backfill_state"),
            cutover_at_present: cutover_at.is_some(),
            lifecycle_enabled: row.get("lifecycle_enabled"),
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
        client
            .execute(
                "UPDATE lore_fragment_schema_state \
                    SET lifecycle_enabled = true, updated_at = clock_timestamp() \
                  WHERE id = 1",
                &[],
            )
            .await
            .map_err(|error| DomainError::from_pg("fragment lifecycle enable", error))?;
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
        if hashes.is_empty() {
            return Ok(Vec::new());
        }
        let client = self.checkout().await?;
        let rows = client
            .query(
                "SELECT a.hash               AS hash, \
                        a.association_epoch  AS association_epoch, \
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
                   FROM lore_fragment_associations AS a \
                   JOIN lore_domain_repositories   AS r ON r.repository_id = a.repository_id \
                   JOIN lore_fragment_lifecycle    AS l ON l.hash = a.hash \
                   JOIN lore_fragment_epochs       AS e \
                        ON e.hash = l.hash AND e.epoch = l.current_epoch \
                  WHERE a.repository_id = $1 \
                    AND a.context       = $2 \
                    AND a.hash          = ANY($3) \
                    AND a.state         = $4 \
                    AND r.state         = $5 \
                    AND a.repository_generation <= r.generation \
                    AND l.state = ANY($7) \
                    AND l.manifest_id = e.manifest_id \
                    AND e.disposition = $6",
                &[
                    &repository_id,
                    &context,
                    &hashes,
                    &schema::ASSOCIATION_LIVE,
                    &STATE_LIVE,
                    &schema::DISPOSITION_CURRENT_ELIGIBLE,
                    &FragmentLifecycleState::readable_bits().as_slice(),
                ],
            )
            .await
            .map_err(|error| DomainError::from_pg("fragment resolve", error))?;

        let mut readable: BTreeMap<Vec<u8>, FragmentVerdict> = BTreeMap::new();
        for row in rows {
            let hash: Vec<u8> = row.get("hash");
            let state = FragmentLifecycleState::from_bits(row.get("state"))?;
            let authority = EpochAuthority::from_bits(row.get("authority"))?;
            let manifest_id: Vec<u8> = row.get("manifest_id");
            readable.insert(
                hash.clone(),
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
            );
        }

        // Answer in the caller's order, with a verdict for every hash asked
        // about. A missing row is `Absent`, indistinguishable from a fenced or
        // tombstoned one on purpose.
        Ok(hashes
            .iter()
            .map(|hash| FragmentResolution {
                hash: hash.clone(),
                verdict: readable
                    .get(hash)
                    .cloned()
                    .unwrap_or(FragmentVerdict::Absent),
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
    ) -> Result<BeginOutcome, DomainError> {
        self.begin_publication(hash, EpochAuthority::Remote, Some(legacy_object_key))
            .await
    }

    /// Publish a `PreparingStage` intent. Allocates an epoch and fence without
    /// publishing any positive association; the file write, validation, flush,
    /// atomic finalize, and directory durability all happen outside Postgres.
    pub async fn begin_stage(&self, hash: &[u8]) -> Result<BeginOutcome, DomainError> {
        self.begin_publication(hash, EpochAuthority::Staged, None)
            .await
    }

    /// Claim the exact `Missing` epoch, state, and fence for a repair.
    ///
    /// Both explicit repair and put-on-`Missing` come through here: a client
    /// re-offering bytes whose FragmentId matches a `Missing` head is a
    /// first-class repair, which is what preserves today's cheap self-heal
    /// (`store/immutable_store.rs:955-980`) without ever overwriting the legacy
    /// key. The successor takes a greater epoch and its own immutable key.
    pub async fn claim_repair(&self, hash: &[u8]) -> Result<BeginOutcome, DomainError> {
        let mut client = self.checkout().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|error| DomainError::from_pg("repair claim begin", error))?;
        let mut sequence = LockSequence::new();
        let Some(head) = lock_fragment_head(&tx, &mut sequence, hash).await? else {
            return Err(DomainError::PreconditionRejected {
                reason: "fragment_head_absent".to_owned(),
                reason_version: 1,
            });
        };
        if head.state != FragmentLifecycleState::Missing {
            return Ok(BeginOutcome::Fenced(format!(
                "repair requires a Missing head; this one is {}",
                head.state.label()
            )));
        }
        let epoch = next_fence(&tx).await?;
        let fence = next_fence(&tx).await?;
        // Repair never reuses the legacy bare-hash key. A server-only immutable
        // epoch key is the whole reason the predecessor's bytes stay
        // untouched and diagnosable.
        let object_key = repair_epoch_key(hash, epoch);
        stamp_operation_fence(&tx, hash, fence).await?;
        classify_commit(tx.commit().await, "repair claim commit")?;
        Ok(BeginOutcome::Admitted(Box::new(FragmentIntent {
            hash: hash.to_vec(),
            epoch,
            fence,
            object_key,
            authority: EpochAuthority::Remote,
            captured: Some(EpochWitness {
                hash: hash.to_vec(),
                epoch: head.current_epoch,
                state: head.state,
                manifest_id: head.manifest_id,
                fence: head.last_fence,
            }),
        })))
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
    ) -> Result<CommitVerdict, DomainError> {
        self.commit_publication(intent, observation, EpochAuthority::Remote)
            .await
    }

    /// Publish `Staged` plus its manifest, metering, and association
    /// atomically, once the file is finalized and durable.
    pub async fn commit_staged(
        &self,
        intent: &FragmentIntent,
        observation: IoObservation,
    ) -> Result<CommitVerdict, DomainError> {
        self.commit_publication(intent, observation, EpochAuthority::Staged)
            .await
    }

    /// Publish a repair successor by the same head CAS `commit_remote` uses,
    /// quarantining the predecessor epoch rather than overwriting it.
    pub async fn commit_repair(
        &self,
        intent: &FragmentIntent,
        observation: IoObservation,
    ) -> Result<CommitVerdict, DomainError> {
        self.commit_publication(intent, observation, EpochAuthority::Remote)
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
        Ok(BeginOutcome::Admitted(Box::new(FragmentIntent {
            hash: hash.to_vec(),
            epoch,
            fence,
            object_key: legacy_hash_key(hash),
            authority: EpochAuthority::Remote,
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
        Ok(CommitVerdict::Published)
    }

    /// Tombstone one association and move the repository's association scalar.
    pub async fn tombstone_association(
        &self,
        hash: &[u8],
        repository_id: &[u8],
        context: &[u8],
    ) -> Result<CommitVerdict, DomainError> {
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
        Ok(CommitVerdict::Published)
    }

    /// Move a head into the deletion sequence and remove its live associations,
    /// then release everything so the physical purge can run outside Postgres.
    ///
    /// `obliterate` stays the physical takedown primitive. This is the first
    /// half; [`Self::commit_obliterate`] publishes `Tombstoned` only after the
    /// caller proves the version-aware purge completed.
    pub async fn begin_obliterate(&self, hash: &[u8]) -> Result<BeginOutcome, DomainError> {
        let mut client = self.checkout().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|error| DomainError::from_pg("obliterate begin", error))?;
        let mut sequence = LockSequence::new();
        // Obliterate makes a readable head unreadable and removes every live
        // association, so both the repository fanout and the association rows
        // are in play. Repository rows come first (position 1).
        let fanout = plan_lifecycle_fanout(&tx, hash).await?;
        lock_lifecycle_fanout(&tx, &mut sequence, &fanout).await?;
        let Some(head) = lock_fragment_head(&tx, &mut sequence, hash).await? else {
            return Err(DomainError::PreconditionRejected {
                reason: "fragment_head_absent".to_owned(),
                reason_version: 1,
            });
        };
        if head.state == FragmentLifecycleState::Tombstoned {
            return Ok(BeginOutcome::Fenced(
                "the fragment is already tombstoned".to_owned(),
            ));
        }
        let object_key = current_epoch_key(&tx, hash, head.current_epoch)
            .await?
            .unwrap_or_else(|| legacy_hash_key(hash));
        let fence = next_fence(&tx).await?;
        let was_readable = head.state.is_readable();
        tx.execute(
            "UPDATE lore_fragment_lifecycle \
                SET state = $2, manifest_id = NULL, last_fence = $3, \
                    active_operation = NULL, diagnostic_class = 0, \
                    updated_at = clock_timestamp() \
              WHERE hash = $1",
            &[
                &hash,
                &FragmentLifecycleState::DeletingPayload.bits(),
                &fence,
            ],
        )
        .await
        .map_err(|error| DomainError::from_pg("obliterate state update", error))?;
        // Confirmed BEFORE the readability branch and used for everything below.
        //
        // This is INV-EF P1-1. The bump used to run over the plan-time list while
        // the tombstone ran by predicate over the current set, and the only
        // growth check sat inside `apply_lifecycle_generation` — which obliterate
        // calls only when the head was readable. On a non-readable head
        // (`Missing`, `Preparing*`, `Deleting*` are all accepted here; only
        // `Tombstoned` is refused above) an association created between the plan
        // read and the head lock was retired by a transaction that had never
        // locked its repository row and moved no scalar attributable to the
        // removal.
        let confirmed = confirm_lifecycle_fanout(&tx, hash, &fanout).await?;
        if was_readable {
            apply_lifecycle_generation(&tx, &confirmed).await?;
        }
        // Retiring associations moves the association scalar too, for every
        // repository that loses one. Obliterate previously moved only the
        // lifecycle scalar, so a push whose preflight predated an obliterate of
        // content it referenced could see an unchanged association generation
        // and take the fast path. The rows are already locked by the fanout.
        bump_association_generation_many(&tx, &confirmed).await?;
        sequence.enter(LockClass::Associations)?;
        // Scoped to the confirmed repository set rather than every live
        // association on the hash, so the rows this statement retires are
        // exactly the rows whose scalars moved above. A bare
        // `WHERE hash = $1 AND state = LIVE` predicate would silently widen to
        // anything that appeared in the planning window.
        tx.execute(
            "UPDATE lore_fragment_associations \
                SET state = $2, updated_at = clock_timestamp() \
              WHERE hash = $1 AND state = $3 AND repository_id = ANY($4)",
            &[
                &hash,
                &schema::ASSOCIATION_TOMBSTONED,
                &schema::ASSOCIATION_LIVE,
                &confirmed,
            ],
        )
        .await
        .map_err(|error| DomainError::from_pg("obliterate association removal", error))?;
        classify_commit(tx.commit().await, "obliterate begin commit")?;
        Ok(BeginOutcome::Admitted(Box::new(FragmentIntent {
            hash: hash.to_vec(),
            epoch: head.current_epoch,
            fence,
            object_key,
            authority: EpochAuthority::Remote,
            captured: Some(EpochWitness {
                hash: hash.to_vec(),
                epoch: head.current_epoch,
                state: FragmentLifecycleState::DeletingPayload,
                manifest_id: None,
                fence,
            }),
        })))
    }

    /// Publish `Tombstoned`, and only after the caller has proved every
    /// provider version of the exact current-epoch object key is gone.
    ///
    /// The epoch row's disposition becomes `PURGED` in the same transaction, so
    /// a later GC package can tell "proved gone" from "not yet visited" without
    /// re-deriving it.
    pub async fn commit_obliterate(
        &self,
        intent: &FragmentIntent,
    ) -> Result<CommitVerdict, DomainError> {
        let Some(captured) = intent.captured.as_ref() else {
            return Err(DomainError::Internal(
                "obliterate commit needs the witness captured at begin".to_owned(),
            ));
        };
        let mut client = self.checkout().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|error| DomainError::from_pg("obliterate commit begin", error))?;
        let mut sequence = LockSequence::new();
        let Some(head) = lock_fragment_head(&tx, &mut sequence, &intent.hash).await? else {
            return Ok(CommitVerdict::Fenced);
        };
        if !head.matches(captured) {
            return Ok(CommitVerdict::Fenced);
        }
        let fence = next_fence(&tx).await?;
        // `diagnostic_class` is zeroed here as well as at begin. The schema's
        // `lore_fragment_lifecycle_diagnostic_shape` CHECK allows a nonzero
        // class only on a `Missing` head, so relying on begin having zeroed it
        // would make this statement take a 23514 on any path that reaches
        // tombstone from a diagnosed head.
        tx.execute(
            "UPDATE lore_fragment_lifecycle \
                SET state = $2, manifest_id = NULL, last_fence = $3, \
                    active_operation = NULL, diagnostic_class = 0, \
                    updated_at = clock_timestamp() \
              WHERE hash = $1",
            &[
                &intent.hash,
                &FragmentLifecycleState::Tombstoned.bits(),
                &fence,
            ],
        )
        .await
        .map_err(|error| DomainError::from_pg("obliterate tombstone update", error))?;
        tx.execute(
            "UPDATE lore_fragment_epochs SET disposition = $3 \
              WHERE hash = $1 AND epoch = $2",
            &[&intent.hash, &intent.epoch, &schema::DISPOSITION_PURGED],
        )
        .await
        .map_err(|error| DomainError::from_pg("obliterate epoch disposition", error))?;
        tx.execute(
            "DELETE FROM lore_fragment_lifecycle_metering WHERE hash = $1",
            &[&intent.hash],
        )
        .await
        .map_err(|error| DomainError::from_pg("obliterate metering removal", error))?;
        classify_commit(tx.commit().await, "obliterate commit")?;
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
        if !divergent.is_empty() && !equivalent_epochs(tx, &divergent).await? {
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
    ) -> Result<BeginOutcome, DomainError> {
        let mut client = self.checkout().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|error| DomainError::from_pg("publication begin", error))?;
        let mut sequence = LockSequence::new();
        let existing = lock_fragment_head(&tx, &mut sequence, hash).await?;
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
        }
        let epoch = next_fence(&tx).await?;
        let fence = next_fence(&tx).await?;
        let object_key = match legacy_object_key {
            Some(key) => key.to_owned(),
            None => staged_epoch_key(hash, epoch),
        };
        let preparing = match authority {
            EpochAuthority::Staged => FragmentLifecycleState::PreparingStage,
            EpochAuthority::Remote => FragmentLifecycleState::PreparingRemote,
        };
        tx.execute(
            "INSERT INTO lore_fragment_lifecycle ( \
                 hash, current_epoch, state, manifest_id, last_fence, active_operation \
             ) VALUES ($1, $2, $3, NULL, $4, NULL) \
             ON CONFLICT (hash) DO UPDATE \
                SET current_epoch    = EXCLUDED.current_epoch, \
                    state            = EXCLUDED.state, \
                    manifest_id      = NULL, \
                    last_fence       = EXCLUDED.last_fence, \
                    diagnostic_class = 0, \
                    updated_at       = clock_timestamp()",
            &[&hash, &epoch, &preparing.bits(), &fence],
        )
        .await
        .map_err(|error| DomainError::from_pg("publication intent insert", error))?;
        classify_commit(tx.commit().await, "publication begin commit")?;
        Ok(BeginOutcome::Admitted(Box::new(FragmentIntent {
            hash: hash.to_vec(),
            epoch,
            fence,
            object_key,
            authority,
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
    ) -> Result<CommitVerdict, DomainError> {
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
        let Some(head) = lock_fragment_head(&tx, &mut sequence, &intent.hash).await? else {
            return Ok(CommitVerdict::Fenced);
        };
        // The fence this operation was issued at is the head's own fence only
        // while no other operation has touched it. Anything else means a
        // repair, an obliterate, or a competing write linearized in between.
        if head.last_fence != intent.fence {
            return Ok(CommitVerdict::Fenced);
        }
        if head.state.is_deleting() || head.state == FragmentLifecycleState::Tombstoned {
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
                classify_commit(tx.commit().await, "publication missing commit")?;
                return Ok(CommitVerdict::Published);
            }
            IoObservation::Valid(manifest) => manifest,
        };

        let fence = next_fence(&tx).await?;
        // Immutable: a repair successor is a new row at a greater epoch, never
        // an update of an existing one. `DO NOTHING` covers only the exact
        // replay of one operation's own commit.
        tx.execute(
            "INSERT INTO lore_fragment_epochs ( \
                 hash, epoch, authority, object_key, manifest_id, size_payload, size_content, \
                 decoded_hash, payload_flags, fence, validated_at, disposition \
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, clock_timestamp(), $11) \
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
        classify_commit(tx.commit().await, "publication commit")?;
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
            "SELECT current_epoch, state, manifest_id, last_fence \
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
        })
    })
    .transpose()
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
/// F-032-3 inversion is expressible. It is registered with [`LockSequence`]
/// rather than exempted, so that claim is checked rather than asserted.
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
/// The caller aborts unconditionally when the **association** scalar moved, one
/// statement before the count check and long before this runs. That ordering is
/// load-bearing rather than incidental: it is what keeps an obliterate-then-
/// recreate — which tombstones associations and so always moves that scalar —
/// out of reach of this function. Keep the association check ahead of the
/// fallback if this is ever reshuffled; without it, equivalence over content
/// columns alone would not be enough.
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
    divergent: &[DivergentEpoch<'_>],
) -> Result<bool, DomainError> {
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

/// Stamp the head with the fence this operation was issued at, so a delayed
/// commit can tell whether anything linearized in between.
///
/// It deliberately does **not** write `active_operation`. That column is
/// CR-031's "active operation" model field and stays reserved and NULL until
/// Phase 5 plumbs the CR-029 domain operation ID down to this layer; there is
/// no operation identity in scope here to put in it, and writing the fence
/// there would make a diagnostic column lie about what it holds. The naming is
/// deliberate — an earlier `set_active_operation` name claimed a write this
/// function never made.
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

async fn current_epoch_key(
    tx: &Transaction<'_>,
    hash: &[u8],
    epoch: i64,
) -> Result<Option<String>, DomainError> {
    let row = tx
        .query_opt(
            "SELECT object_key FROM lore_fragment_epochs WHERE hash = $1 AND epoch = $2",
            &[&hash, &epoch],
        )
        .await
        .map_err(|error| DomainError::from_pg("fragment epoch key", error))?;
    Ok(row.map(|row| row.get("object_key")))
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

/// Move the association scalar for a whole locked fanout at once.
///
/// Used where one operation retires many associations, so every affected
/// repository's push witness moves with the removal rather than only the
/// caller's own.
/// **PRECONDITION: the caller already holds every one of these repository rows
/// `FOR UPDATE`**, which for its one caller means passing the set returned by
/// [`confirm_lifecycle_fanout`] and nothing else.
///
/// Takes no `LockSequence::enter`, and — as with
/// [`bump_association_generation`] — registering would be rejected rather than
/// merely redundant. `begin_obliterate` reaches this *after* `lock_fragment_head`
/// has advanced the sequence to `LockClass::Fragments` (position 4), so
/// `enter(Repository)` at position 1 would be a downward move and
/// `LockSequence` would fail the transaction. The rows were locked earlier, by
/// `lock_lifecycle_fanout`, before the head.
///
/// An earlier revision of this comment said a second entry would be "harmless
/// because same-class repeats are allowed". That was wrong — by this point the
/// sequence is no longer on `Repository` — and it is the same
/// claim-not-checked-against-the-code failure INV-EF raised as P1-3, committed
/// inside the comment written to close P2-4.
///
/// The guard therefore does not cover this write; the precondition does.
async fn bump_association_generation_many(
    tx: &Transaction<'_>,
    repositories: &[Vec<u8>],
) -> Result<(), DomainError> {
    if repositories.is_empty() {
        return Ok(());
    }
    tx.execute(
        "UPDATE lore_domain_repositories \
            SET content_association_generation = content_association_generation + 1 \
          WHERE repository_id = ANY($1)",
        &[&repositories],
    )
    .await
    .map_err(|error| DomainError::from_pg("association generation bump", error))?;
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

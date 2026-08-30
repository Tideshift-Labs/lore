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
//! # Scope as of the SCHEMA-118 window
//!
//! Phases 2 and 3: schema, readiness, the batched resolver, and the begin/commit
//! pairs with their witnesses and lock order. The provider-consuming halves
//! (Phase 4 onward — repair through the governed client, version-aware physical
//! purge, backfill) wait on WP-114's CD-1/CD-3/CD-4/CD-5 and are not here.

use std::collections::BTreeMap;
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
    pub fn ready_for_lifecycle(&self) -> bool {
        self.provisioned
            && self.schema_version >= 1
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
    AlreadyReadable(Box<FragmentResolution>),
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
}

impl CommitVerdict {
    /// Whether the operation published.
    pub fn published(self) -> bool {
        matches!(self, Self::Published)
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
    /// readable at its captured epoch. The push may commit.
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

/// Reason code for a required fragment that is no longer readable at its
/// captured epoch.
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

        // A readable head whose current epoch has no row, or whose manifest
        // does not match that epoch's, is unresolvable by the resolver's join.
        // It is not a routing question; it is damage that would silently make
        // fragments absent.
        let unresolved_rows: i64 = client
            .query_one(
                "SELECT count(*)::bigint FROM lore_fragment_lifecycle AS l \
                  WHERE NOT EXISTS ( \
                        SELECT 1 FROM lore_fragment_epochs AS e \
                         WHERE e.hash = l.hash AND e.epoch = l.current_epoch) \
                     OR (l.state IN (3, 4) AND NOT EXISTS ( \
                        SELECT 1 FROM lore_fragment_epochs AS e \
                         WHERE e.hash = l.hash AND e.epoch = l.current_epoch \
                           AND e.manifest_id = l.manifest_id))",
                &[],
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
        if readiness.schema_version > schema::FRAGMENT_SCHEMA_VERSION {
            return Err(DomainError::NotReady(format!(
                "cell fragment schema_version {} is newer than this binary's {}; \
                 roll the binary forward before enabling lifecycle routing",
                readiness.schema_version,
                schema::FRAGMENT_SCHEMA_VERSION
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
                    AND a.repository_generation = r.generation \
                    AND l.state IN (3, 4) \
                    AND l.manifest_id = e.manifest_id \
                    AND e.disposition = $6",
                &[
                    &repository_id,
                    &context,
                    &hashes,
                    &schema::ASSOCIATION_LIVE,
                    &STATE_LIVE,
                    &schema::DISPOSITION_CURRENT_ELIGIBLE,
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
        set_active_operation(&tx, hash, fence).await?;
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
        let fence = next_fence(&tx).await?;
        set_active_operation(&tx, hash, fence).await?;
        classify_commit(tx.commit().await, "promotion begin commit")?;
        Ok(BeginOutcome::Admitted(Box::new(FragmentIntent {
            hash: hash.to_vec(),
            // Promotion republishes the SAME epoch under a new authority; it is
            // not a new representation, so it must not consume an epoch.
            epoch: head.current_epoch,
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
    pub async fn commit_promotion(
        &self,
        intent: &FragmentIntent,
        observation: IoObservation,
    ) -> Result<CommitVerdict, DomainError> {
        self.commit_publication(intent, observation, EpochAuthority::Remote)
            .await
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
            // live-associated repository's scalar moves atomically with it.
            bump_lifecycle_generation(&tx, &mut sequence, &witness.hash).await?;
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
        if was_readable {
            bump_lifecycle_generation(&tx, &mut sequence, hash).await?;
        }
        sequence.enter(LockClass::Associations)?;
        tx.execute(
            "UPDATE lore_fragment_associations \
                SET state = $2, updated_at = clock_timestamp() \
              WHERE hash = $1 AND state = $3",
            &[
                &hash,
                &schema::ASSOCIATION_TOMBSTONED,
                &schema::ASSOCIATION_LIVE,
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
        tx.execute(
            "UPDATE lore_fragment_lifecycle \
                SET state = $2, manifest_id = NULL, last_fence = $3, \
                    active_operation = NULL, updated_at = clock_timestamp() \
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
        if current == captured {
            return Ok(PushWitnessVerdict::Unchanged);
        }
        if current.content_association_generation != captured.content_association_generation {
            // The association set itself moved. The fallback revalidates
            // representations, not membership, so it cannot cover this.
            return Ok(PushWitnessVerdict::Aborted {
                reason: REQUIRED_FRAGMENT_CHANGED,
            });
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
        // rule). One set-based query, never a row at a time.
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
        for item in &sorted {
            let Some((epoch, state)) = observed.get(&item.hash) else {
                return Ok(PushWitnessVerdict::Aborted {
                    reason: REQUIRED_FRAGMENT_CHANGED,
                });
            };
            let state = FragmentLifecycleState::from_bits(*state)?;
            if !state.is_readable() || *epoch != item.epoch {
                return Ok(PushWitnessVerdict::Aborted {
                    reason: REQUIRED_FRAGMENT_CHANGED,
                });
            }
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
    /// 256 KiB fragment. Lease maintenance runs in its own transaction and
    /// never co-occurs with a domain lock, which is why the lease row needs no
    /// position in F-032-3.
    pub async fn acquire_staged_leases(
        &self,
        lease_id: &[u8],
        members: &[(Vec<u8>, i64)],
        deadline: SystemTime,
    ) -> Result<StagedReaderLease, DomainError> {
        let mut client = self.checkout().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|error| DomainError::from_pg("staged lease begin", error))?;
        let reader_fence = next_fence(&tx).await?;
        tx.execute(
            "INSERT INTO lore_fragment_staged_leases (lease_id, reader_fence, deadline) \
             VALUES ($1, $2, $3)",
            &[&lease_id, &reader_fence, &deadline],
        )
        .await
        .map_err(|error| DomainError::from_pg("staged lease insert", error))?;
        for (hash, epoch) in members {
            tx.execute(
                "INSERT INTO lore_fragment_staged_lease_members (lease_id, hash, epoch) \
                 VALUES ($1, $2, $3) ON CONFLICT (lease_id, hash) DO NOTHING",
                &[&lease_id, &hash, &epoch],
            )
            .await
            .map_err(|error| DomainError::from_pg("staged lease member insert", error))?;
        }
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
    pub async fn release_staged_lease(&self, lease_id: &[u8]) -> Result<(), DomainError> {
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
                return Ok(BeginOutcome::AlreadyReadable(Box::new(
                    FragmentResolution {
                        hash: hash.to_vec(),
                        verdict: FragmentVerdict::Absent,
                    },
                )));
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
                    bump_lifecycle_generation(&tx, &mut sequence, &intent.hash).await?;
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
            bump_lifecycle_generation(&tx, &mut sequence, &intent.hash).await?;
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

/// Allocate one monotonic epoch or fence. Gaps are valid.
async fn next_fence(tx: &Transaction<'_>) -> Result<i64, DomainError> {
    tx.query_one("SELECT nextval('lore_fragment_fence_seq')::bigint", &[])
        .await
        .map_err(|error| DomainError::from_pg("fragment fence allocation", error))
        .map(|row| row.get(0))
}

async fn set_active_operation(
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
    .map_err(|error| DomainError::from_pg("fragment active operation", error))?;
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

/// Move the lifecycle scalar for **every** repository with a live association
/// to this hash, atomically and in sorted repository order.
///
/// Three separate requirements are met here and each one matters:
///
/// - **Measured before mutated.** The fanout set is read and counted first, and
///   a set above [`MAX_LIFECYCLE_GENERATION_FANOUT`] fails admission rather
///   than taking an unbounded row-lock set inside one transaction.
/// - **Sorted order.** Rows are locked one at a time in ascending repository
///   order rather than by a set-based `UPDATE ... WHERE id IN (...)`, whose
///   lock acquisition order Postgres does not fix. Two transitions over an
///   overlapping fanout therefore acquire the overlap in the same sequence.
/// - **All or nothing.** The update is one statement over the already-locked
///   set inside the caller's transaction, so a partial fanout is not
///   representable.
async fn bump_lifecycle_generation(
    tx: &Transaction<'_>,
    sequence: &mut LockSequence,
    hash: &[u8],
) -> Result<(), DomainError> {
    let rows = tx
        .query(
            "SELECT repository_id FROM lore_fragment_associations \
              WHERE hash = $1 AND state = $2 ORDER BY repository_id",
            &[&hash, &schema::ASSOCIATION_LIVE],
        )
        .await
        .map_err(|error| DomainError::from_pg("lifecycle fanout measure", error))?;
    if rows.is_empty() {
        return Ok(());
    }
    if rows.len() > MAX_LIFECYCLE_GENERATION_FANOUT {
        return Err(DomainError::PreconditionRejected {
            reason: "lifecycle_generation_fanout_limit".to_owned(),
            reason_version: 1,
        });
    }
    let repositories: Vec<Vec<u8>> = rows.iter().map(|row| row.get("repository_id")).collect();
    for repository_id in &repositories {
        sequence.enter(LockClass::Repository)?;
        tx.execute(
            "SELECT 1 FROM lore_domain_repositories WHERE repository_id = $1 FOR UPDATE",
            &[&repository_id],
        )
        .await
        .map_err(|error| DomainError::from_pg("lifecycle fanout repository lock", error))?;
    }
    tx.execute(
        "UPDATE lore_domain_repositories \
            SET fragment_lifecycle_generation = fragment_lifecycle_generation + 1 \
          WHERE repository_id = ANY($1)",
        &[&repositories],
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
}

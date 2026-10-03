// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Store-owned write-behind adapter. No checked-out connection crosses I/O.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Instant;

use lore_fragment_provider::FragmentDrainAttempt;
use lore_fragment_provider::FragmentDrainMaintenanceHandle;
use lore_fragment_provider::FragmentDrainPolicyPin;
use lore_fragment_provider::FragmentDrainReservationInput;
use lore_fragment_provider::FragmentDrainReservationPlan;
use lore_fragment_provider::FragmentDrainWriteReceipt;
use tokio::sync::Mutex;

use super::*;
use crate::domain::fragments::EpochWitness;
use crate::domain::fragments::FragmentDrainCandidate;
use crate::domain::fragments::FragmentDrainCandidateBatch;
use crate::domain::fragments::FragmentStageObserver;
use crate::domain::fragments::StageCleanupIntent;
use crate::domain::fragments::states::FragmentLifecycleState;
use crate::store::write_behind::CapacityVerdict;
use crate::store::write_behind::cleanup::StageFileCandidate;
use crate::store::write_behind::cleanup::StageFileScanner;

#[cfg(all(test, target_os = "linux"))]
#[path = "fragment_write_behind_adapter_tests.rs"]
mod adapter_tests;

#[cfg(test)]
mod observe_trace_tests {
    use super::*;

    #[test]
    fn a_trace_records_completed_steps_in_order_and_names_the_failed_one() {
        let now = Instant::now();
        let mut trace = ObserveTrace::default();
        trace.begin(ObserveStep::PhysicalInventory, now);
        trace.end(
            ObserveStep::PhysicalInventory,
            Duration::from_millis(3),
            true,
        );
        trace.begin(ObserveStep::StagePolicy, now);
        trace.end(ObserveStep::StagePolicy, Duration::from_millis(40), false);
        assert_eq!(
            trace,
            ObserveTrace {
                completed: vec![
                    (ObserveStep::PhysicalInventory, Duration::from_millis(3)),
                    (ObserveStep::StagePolicy, Duration::from_millis(40)),
                ],
                in_flight: None,
                failed: Some(ObserveStep::StagePolicy),
            }
        );
    }

    #[test]
    fn a_step_that_never_returned_stays_in_flight() {
        let now = Instant::now();
        let mut trace = ObserveTrace::default();
        trace.begin(ObserveStep::StageLedger, now);
        assert_eq!(trace.in_flight, Some((ObserveStep::StageLedger, now)));
        assert!(trace.completed.is_empty());
        assert_eq!(trace.failed, None);
    }
}

#[cfg(all(test, unix))]
mod source_tests {
    use uuid::Uuid;

    use super::*;
    use crate::domain::PostgresDomainStore;
    use crate::domain::fragments::StageReservationInput;
    use crate::pool::TlsConfig;
    use crate::store::write_behind::WriteBehindSettings;
    use crate::store::write_behind::WriteBehindWatermarks;

    #[tokio::test]
    #[ignore = "requires owned LORE_TEST_PG_URL and Unix staging filesystem"]
    async fn orphan_temp_cleanup_is_confined_and_replayed_without_double_refund() {
        let url = std::env::var("LORE_TEST_PG_URL").expect("owned Postgres URL");
        let domain = PostgresDomainStore::connect(&url, 4, &TlsConfig::default())
            .await
            .unwrap();
        let coordinator = domain.fragment_coordinator();
        let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .unwrap();
        let connection_task = lore_base::lore_spawn!(async move {
            connection.await.unwrap();
        });
        client.batch_execute("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='object_dispatch_retention_maintenance') THEN CREATE ROLE object_dispatch_retention_maintenance; END IF; END $$").await.unwrap();
        coordinator.bootstrap().await.unwrap();
        client
            .batch_execute("SET SESSION AUTHORIZATION object_dispatch_retention_maintenance")
            .await
            .unwrap();
        client.execute("SELECT stage_policy_publish_v1('fixture-cell','fixture-policy-v1',decode(repeat('aa',32),'hex'),1073741824,100000,1073741824,100000,60000,4102444800000)", &[]).await.unwrap();
        client
            .batch_execute("RESET SESSION AUTHORIZATION")
            .await
            .unwrap();
        let root = std::env::temp_dir().join(format!("lore-orphan-cleanup-{}", Uuid::now_v7()));
        std::fs::create_dir(&root).unwrap();
        let stage = WriteBehindStage::open(WriteBehindSettings {
            root: root.clone(),
            watermarks: WriteBehindWatermarks {
                low_bytes: 10_000_000,
                high_bytes: 20_000_000,
                hard_bytes: 30_000_000,
                low_count: 1000,
                high_count: 2000,
                hard_count: 3000,
                min_free_bytes: 0,
            },
            drain_stale_after: Duration::from_secs(60),
            sample_interval: Duration::from_secs(3600),
            stage_io_wait: crate::store::write_behind::DEFAULT_STAGE_IO_WAIT,
        })
        .unwrap();
        let hash = [0xf1; 32];
        let key = format!("{}.s9000", hex::encode(hash));
        let temporary = root.join("incoming").join(format!("{key}.tmp"));
        std::fs::write(&temporary, b"orphan temp").unwrap();
        let intent = coordinator
            .begin_stage_cleanup(&hash, 9000)
            .await
            .unwrap()
            .expect("genuine orphan reclaim seal");
        let charged = coordinator.observe_stage().await.unwrap();
        assert_eq!(
            (charged.resident_bytes, charged.resident_files),
            (262144, 1)
        );
        let incoming = root.join("incoming");
        let retained = root.join("incoming-retained");
        let external = root.with_extension("external");
        std::fs::create_dir(&external).unwrap();
        let sentinel = external.join(format!("{key}.tmp"));
        std::fs::write(&sentinel, b"external sentinel").unwrap();
        std::fs::rename(&incoming, &retained).unwrap();
        std::os::unix::fs::symlink(&external, &incoming).unwrap();
        assert!(stage.purge_placement(intent.target()).is_err());
        assert_eq!(std::fs::read(&sentinel).unwrap(), b"external sentinel");
        assert_eq!(coordinator.observe_stage().await.unwrap().resident_files, 1);
        std::fs::remove_file(&incoming).unwrap();
        std::fs::rename(&retained, &incoming).unwrap();
        stage.purge_placement(intent.target()).unwrap();
        assert!(
            !temporary.exists(),
            "temp-only cleanup needs no shard directory"
        );
        coordinator.commit_stage_cleanup(&intent).await.unwrap();
        let purged = coordinator.observe_stage().await.unwrap();
        assert_eq!(
            (
                purged.resident_bytes,
                purged.resident_files,
                purged.metadata_bytes,
                purged.metadata_rows
            ),
            (0, 0, 256, 1)
        );
        std::fs::write(&temporary, b"late residue").unwrap();
        let retry = coordinator
            .begin_stage_cleanup(&hash, 9000)
            .await
            .unwrap()
            .expect("compact tombstone retains cleanup authority");
        stage.purge_placement(retry.target()).unwrap();
        coordinator.commit_stage_cleanup(&retry).await.unwrap();
        coordinator.commit_stage_cleanup(&retry).await.unwrap();
        let replay = coordinator.observe_stage().await.unwrap();
        assert_eq!(
            (
                replay.resident_bytes,
                replay.resident_files,
                replay.metadata_bytes,
                replay.metadata_rows
            ),
            (0, 0, 256, 1)
        );
        assert!(!temporary.exists());
        std::fs::remove_dir_all(root).unwrap();
        std::fs::remove_dir_all(external).unwrap();
        drop(client);
        connection_task.await.unwrap();
    }

    #[tokio::test]
    #[ignore = "requires owned LORE_TEST_PG_URL and Unix staging filesystem"]
    async fn source_validation_round_trips_raw_lz4_zstd_and_refuses_corrupt_or_missing_bytes() {
        let url = std::env::var("LORE_TEST_PG_URL").expect("owned Postgres URL");
        let domain = PostgresDomainStore::connect(&url, 4, &TlsConfig::default())
            .await
            .unwrap();
        let coordinator = domain.fragment_coordinator();
        let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .unwrap();
        let connection_task = lore_base::lore_spawn!(async move {
            connection.await.unwrap();
        });
        client.batch_execute("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='object_dispatch_retention_maintenance') THEN CREATE ROLE object_dispatch_retention_maintenance; END IF; END $$").await.unwrap();
        coordinator.bootstrap().await.unwrap();
        client
            .batch_execute("SET SESSION AUTHORIZATION object_dispatch_retention_maintenance")
            .await
            .unwrap();
        client.execute("SELECT stage_policy_publish_v1('fixture-cell','fixture-policy-v1',decode(repeat('aa',32),'hex'),1073741824,100000,1073741824,100000,60000,4102444800000)", &[]).await.unwrap();
        client
            .batch_execute("RESET SESSION AUTHORIZATION")
            .await
            .unwrap();
        let root = std::env::temp_dir().join(format!("lore-source-validation-{}", Uuid::now_v7()));
        std::fs::create_dir(&root).unwrap();
        let stage = WriteBehindStage::open(WriteBehindSettings {
            root: root.clone(),
            watermarks: WriteBehindWatermarks {
                low_bytes: 10_000_000,
                high_bytes: 20_000_000,
                hard_bytes: 30_000_000,
                low_count: 1000,
                high_count: 2000,
                hard_count: 3000,
                min_free_bytes: 0,
            },
            drain_stale_after: Duration::from_secs(60),
            sample_interval: Duration::from_secs(3600),
            stage_io_wait: crate::store::write_behind::DEFAULT_STAGE_IO_WAIT,
        })
        .unwrap();
        for mode in [
            lore_storage::CompressionMode::NoCompression,
            lore_storage::CompressionMode::Lz4,
            lore_storage::CompressionMode::Zstd,
        ] {
            let decoded = format!("source validation {mode:?} ")
                .repeat(256)
                .into_bytes();
            let address = Address {
                context: Context::default(),
                hash: Hash::from(blake3::hash(&decoded).as_bytes().as_slice()),
            };
            let original = Fragment {
                flags: FragmentFlags::PayloadLocalCachePriority.into(),
                size_payload: decoded.len() as u32,
                size_content: decoded.len() as u64,
            };
            let (fragment, bytes) = if matches!(mode, lore_storage::CompressionMode::NoCompression)
            {
                (original, Bytes::from(decoded.clone()))
            } else {
                lore_storage::compress(original, &decoded, mode).unwrap()
            };
            let BeginOutcome::Admitted(intent) = coordinator
                .begin_stage(
                    address.hash.data(),
                    StageReservationInput {
                        size_payload: bytes.len() as u64,
                        original_flags: fragment.flags,
                    },
                )
                .await
                .unwrap()
            else {
                panic!("fresh stage");
            };
            stage
                .stage(
                    address.hash.data(),
                    intent.epoch,
                    &intent.object_key,
                    &bytes,
                )
                .await
                .unwrap();
            let manifest = PostgresImmutableStore::key_manifest(
                &intent.object_key,
                address,
                fragment,
                &bytes,
                EpochAuthority::Staged,
            )
            .unwrap();
            assert_eq!(
                coordinator
                    .commit_staged(&intent, IoObservation::Valid(manifest))
                    .await
                    .unwrap(),
                CommitVerdict::Published
            );
            let source = coordinator
                .staged_drain_candidates(FragmentDrainCandidateBatch::new(32).unwrap())
                .await
                .unwrap()
                .into_iter()
                .find(|row| row.hash() == address.hash.data())
                .unwrap();
            let verified = FragmentWriteBehindHandle::verify_staged_source(
                &coordinator,
                &stage,
                source.clone(),
            )
            .await
            .unwrap();
            assert_eq!(verified.bytes, bytes);
            assert_eq!(
                verified.fragment.flags, fragment.flags,
                "all original flags survive source capture"
            );
            // Deterministically place lineage movement between real file
            // validation and admission, the gap a concurrent actor can hit.
            client
                .execute(
                    "UPDATE lore_fragment_lifecycle SET last_fence=last_fence+1 WHERE hash=$1",
                    &[&address.hash.data().as_slice()],
                )
                .await
                .unwrap();
            let claim = FragmentWriteClaimInput::new(
                *Uuid::now_v7().as_bytes(),
                *Uuid::now_v7().as_bytes(),
                *blake3::hash(&bytes).as_bytes(),
                bytes.len() as u64,
                Duration::from_secs(2),
                Duration::from_secs(3),
            )
            .unwrap();
            assert!(
                matches!(
                    coordinator
                        .begin_promotion(&verified.source, claim)
                        .await
                        .unwrap(),
                    BeginOutcome::Fenced(_)
                ),
                "a validated old digest cannot authorize a moved source"
            );
            let count: i64 = client
                .query_one(
                    "SELECT count(*) FROM lore_fragment_write_claims WHERE hash=$1",
                    &[&address.hash.data().as_slice()],
                )
                .await
                .unwrap()
                .get(0);
            assert_eq!(count, 0);
            // Renew the witness after the deliberate fence movement so the
            // following refusals discriminate disk corruption and absence.
            let source = coordinator
                .staged_drain_candidates(FragmentDrainCandidateBatch::new(32).unwrap())
                .await
                .unwrap()
                .into_iter()
                .find(|row| row.hash() == address.hash.data())
                .unwrap();
            FragmentWriteBehindHandle::verify_staged_source(&coordinator, &stage, source.clone())
                .await
                .unwrap();
            let path = root
                .join("staged")
                .join(&intent.object_key[..2])
                .join(&intent.object_key[2..4])
                .join(&intent.object_key);
            std::fs::write(&path, vec![0x5a; bytes.len()]).unwrap();
            assert!(
                FragmentWriteBehindHandle::verify_staged_source(
                    &coordinator,
                    &stage,
                    source.clone()
                )
                .await
                .is_err(),
                "same-length corruption cannot reach promotion"
            );
            std::fs::remove_file(path).unwrap();
            assert!(
                FragmentWriteBehindHandle::verify_staged_source(&coordinator, &stage, source)
                    .await
                    .is_err(),
                "missing source cannot reach promotion"
            );
        }
        std::fs::remove_dir_all(root).unwrap();
        drop(client);
        connection_task.await.unwrap();
    }
}

struct CleanupState {
    cursor: Option<(Vec<u8>, i64)>,
    scanner: Arc<std::sync::Mutex<StageFileScanner>>,
    scan: Option<tokio::task::JoinHandle<Result<Vec<StageFileCandidate>, StoreError>>>,
    purge: Option<tokio::task::JoinHandle<Result<StageCleanupIntent, StoreError>>>,
}

/// Actual completed work, independent of the duration of a whole batch.
#[derive(Clone, Copy, Default)]
pub struct WriteBehindActivity {
    pub drain_loop: Option<Instant>,
    pub drain_progress: Option<Instant>,
    pub cleanup_loop: Option<Instant>,
    pub cleanup_progress: Option<Instant>,
}

/// A completed stage walk: completion time, bytes, files, unknown entries.
type StagePhysical = (Instant, u64, u64, u64);
/// One stage inventory step's retained scanner and whether it completed a walk.
type StageInventoryTask = tokio::task::JoinHandle<Result<(StageFileScanner, bool), StoreError>>;

/// The step in flight, whether it starts a walk, and the latest stage ledger
/// read when it was issued.
type PendingStageStep = (StageInventoryTask, bool, Option<(u64, u64)>);

/// A completed stage walk older than this is not compared, as before.
const STAGE_PHYSICAL_MAX_AGE: Duration = Duration::from_secs(300);

struct PhysicalInventory {
    scanner: Option<StageFileScanner>,
    task: Option<PendingStageStep>,
    /// Completed walks and the ledger each is compared with. See
    /// [`lore_fragment_provider::WalkLedgerBound`] for why one later read is not
    /// enough.
    walk: lore_fragment_provider::WalkLedgerBound<StagePhysical>,
}

impl Default for PhysicalInventory {
    fn default() -> Self {
        Self {
            scanner: Some(StageFileScanner::default()),
            task: None,
            walk: lore_fragment_provider::WalkLedgerBound::default(),
        }
    }
}

/// One sub-step of [`FragmentWriteBehindHandle::observe`], in call order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObserveStep {
    /// Collect the finished stage walk step and issue the next one.
    PhysicalInventory,
    /// Re-read the pinned stage policy.
    StagePolicy,
    /// The stage ledger read.
    StageLedger,
    /// The spool observation, which waits for one spool walk step.
    SpoolObserve,
    /// Bind the latest completed stage walk to the ledger read.
    BindInventory,
}

impl ObserveStep {
    /// The name used in logs and as the metric attribute.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::PhysicalInventory => "physical_inventory",
            Self::StagePolicy => "stage_policy",
            Self::StageLedger => "stage_ledger",
            Self::SpoolObserve => "spool_observe",
            Self::BindInventory => "bind_inventory",
        }
    }
}

/// Step timings of the latest `observe()` attempt.
///
/// Kept on the handle, not returned, so a caller whose deadline cancelled the
/// attempt can still read which step it was waiting on and for how long.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObserveTrace {
    /// Steps that returned, in order, with how long each took.
    pub completed: Vec<(ObserveStep, Duration)>,
    /// The step that started and has not returned: still running, or its
    /// future was dropped by a caller's deadline.
    pub in_flight: Option<(ObserveStep, Instant)>,
    /// The step that returned an error.
    pub failed: Option<ObserveStep>,
}

impl ObserveTrace {
    fn begin(&mut self, step: ObserveStep, at: Instant) {
        self.in_flight = Some((step, at));
    }

    fn end(&mut self, step: ObserveStep, elapsed: Duration, ok: bool) {
        self.in_flight = None;
        self.completed.push((step, elapsed));
        if !ok {
            self.failed = Some(step);
        }
    }
}

pub struct WriteBehindObservation {
    pub pending_files: u64,
    pub pending_bytes: u64,
    pub stage_bytes: u64,
    pub stage_files: u64,
    pub spool_bytes: u64,
    pub spool_files: u64,
    pub oldest_pending_age: Option<Duration>,
    pub cleanup_backlog: u64,
    pub roots_usable: bool,
    pub capacity_available: bool,
    /// Why `capacity_available` holds or fails. Observability only; the
    /// verdict above is `capacity.failing.is_empty()`.
    pub capacity: CapacityEvidence,
}

/// Each `capacity_available` predicate, evaluated separately, plus the ages of
/// the two physical inventories it compared against the ledger.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CapacityEvidence {
    /// The names of every failing predicate, in evaluation order.
    pub failing: Vec<&'static str>,
    /// Age of the last completed stage walk when the predicate was evaluated.
    pub stage_inventory_age: Option<Duration>,
    /// Age of the last completed spool walk when the predicate was evaluated.
    pub spool_inventory_age: Option<Duration>,
    pub stage_physical_bytes: Option<u64>,
    pub stage_physical_files: Option<u64>,
    /// The ledger the stage walk was compared with: the larger of the reads
    /// before the walk started and after it completed.
    pub stage_ledger_bytes: u64,
    pub stage_ledger_files: u64,
    pub spool_physical_bytes: Option<u64>,
    pub spool_physical_files: Option<u64>,
    /// The ledger the spool walk was compared with, bound the same way.
    pub spool_ledger_bytes: u64,
    pub spool_ledger_files: u64,
    pub available_bytes: Option<u64>,
}

impl CapacityEvidence {
    /// The same conjunction `observe` has always computed, split so each
    /// failing conjunct is named. The verdict must not change here.
    fn evaluate(
        stage_metadata_full: bool,
        stage_physical: Option<(Instant, u64, u64, u64)>,
        stage_ledger: (u64, u64),
        spool: &lore_fragment_provider::FragmentDrainObservation,
        min_free_bytes: u64,
    ) -> Self {
        let (stage_ledger_bytes, stage_ledger_files) = stage_ledger;
        let mut failing = Vec::new();
        if stage_metadata_full {
            failing.push("stage_metadata_full");
        }
        if spool.metadata_full {
            failing.push("spool_metadata_full");
        }
        match stage_physical {
            None => failing.push("stage_inventory_missing"),
            Some((_, bytes, files, unknown)) => {
                if unknown != 0 {
                    failing.push("stage_unknown_entries");
                }
                if bytes > stage_ledger_bytes {
                    failing.push("stage_bytes_over_ledger");
                }
                if files > stage_ledger_files {
                    failing.push("stage_files_over_ledger");
                }
            }
        }
        let (spool_ledger_bytes, spool_ledger_files) = spool.physical_ledger_bound();
        match spool.physical_spool_bytes {
            None => failing.push("spool_bytes_inventory_missing"),
            Some(bytes) if bytes > spool_ledger_bytes => failing.push("spool_bytes_over_ledger"),
            Some(_) => {}
        }
        match spool.physical_spool_files {
            None => failing.push("spool_files_inventory_missing"),
            Some(files) if files > spool_ledger_files => failing.push("spool_files_over_ledger"),
            Some(_) => {}
        }
        match spool.available_bytes {
            None => failing.push("free_space_unknown"),
            Some(free) if free < min_free_bytes => failing.push("free_space_below_minimum"),
            Some(_) => {}
        }
        Self {
            failing,
            stage_inventory_age: stage_physical.map(|(at, _, _, _)| at.elapsed()),
            spool_inventory_age: spool.physical_spool_age,
            stage_physical_bytes: stage_physical.map(|(_, bytes, _, _)| bytes),
            stage_physical_files: stage_physical.map(|(_, _, files, _)| files),
            stage_ledger_bytes,
            stage_ledger_files,
            spool_physical_bytes: spool.physical_spool_bytes,
            spool_physical_files: spool.physical_spool_files,
            spool_ledger_bytes,
            spool_ledger_files,
            available_bytes: spool.available_bytes,
        }
    }

    /// Classify the failing predicates for staging admission.
    ///
    /// Only a physical inventory above its ledger bound is a reconciliation
    /// disagreement that can clear by itself, as the walk and the ledger catch
    /// up. Everything else refuses at once:
    ///
    /// - a full metadata budget, free space below the minimum, or free space
    ///   that cannot be read, because more staging makes each worse;
    /// - a missing inventory (no completed walk, a failed walk, or one older than
    ///   five minutes), because there is then no physical evidence to reconcile,
    ///   only its absence, and a wedged walk must not look like a transient;
    /// - unknown stage entries, because no ledger charges a foreign or malformed
    ///   file and waiting does not remove it.
    pub fn verdict(&self) -> CapacityVerdict {
        if self.failing.is_empty() {
            CapacityVerdict::Available
        } else if self
            .failing
            .iter()
            .all(|name| RECONCILING_PREDICATES.contains(name))
        {
            CapacityVerdict::Reconciling
        } else {
            CapacityVerdict::Unavailable
        }
    }
}

/// The snapshot-vs-ledger predicates staging admission gives a time budget.
const RECONCILING_PREDICATES: [&str; 4] = [
    "stage_bytes_over_ledger",
    "stage_files_over_ledger",
    "spool_bytes_over_ledger",
    "spool_files_over_ledger",
];

/// Most promotions one drain pass runs at once, whatever the configuration.
pub const MAX_DRAIN_CONCURRENCY: usize = 8;

/// The default is one promotion at a time. Parallel promotions drained the
/// spool faster but added foreground commit/push latency on the shared domain
/// pool (row 77), so they are opt-in through `[write_behind] worker_concurrency`.
pub const DEFAULT_DRAIN_CONCURRENCY: usize = 1;

/// The keyset cursor and the per-hash retry cooldown. Locked only for short
/// bookkeeping, never across a promotion (row 77).
struct DrainState {
    cursor: Vec<u8>,
    cooldown: BTreeMap<Vec<u8>, (Instant, u32)>,
}

/// One concurrent promotion's retained file tasks. A promotion holds its slot
/// for its whole run.
#[derive(Default)]
struct DrainSlot {
    // A cancelled wait never forgets an unfinished syscall or starts another.
    writer: Option<
        tokio::task::JoinHandle<
            Result<FragmentDrainWriteReceipt, lore_fragment_provider::FragmentProviderError>,
        >,
    >,
    reader: Option<tokio::task::JoinHandle<Result<VerifiedStagedBody, StoreError>>>,
}

impl DrainSlot {
    /// Collect the retained tasks that finished. False while one still runs:
    /// the slot starts no promotion until its syscall returns.
    async fn settle(&mut self) -> bool {
        if let Some(reader) = self.reader.as_mut() {
            if !reader.is_finished() {
                return false;
            }
            let _ = reader.await;
            self.reader = None;
        }
        if let Some(writer) = self.writer.as_mut() {
            if !writer.is_finished() {
                return false;
            }
            let _ = writer.await;
            self.writer = None;
        }
        true
    }

    /// Whether a timed-out file task is still retained here.
    fn retains_task(&self) -> bool {
        self.reader.is_some() || self.writer.is_some()
    }
}

type HeldDrainSlot = tokio::sync::OwnedMutexGuard<DrainSlot>;

type JoinedPromotion =
    Result<(Vec<u8>, Result<bool, StoreError>, HeldDrainSlot), tokio::task::JoinError>;

pub struct FragmentWriteBehindHandle {
    coordinator: PostgresFragmentCoordinator,
    /// The observer's two reads, on the domain connection reserved for it
    /// ([`crate::domain::PostgresDomainStore::fragment_stage_observer`]).
    /// Only `observe()` uses it.
    observer: FragmentStageObserver,
    provider: Arc<FragmentProviderEntry>,
    stage: Arc<WriteBehindStage>,
    drain: FragmentDrainCapability,
    maintenance: FragmentDrainMaintenanceHandle,
    policy: FragmentDrainPolicyPin,
    send_timeout: Duration,
    late_effect_bound: Duration,
    /// Held for one whole drain pass, so passes never overlap.
    pass: Mutex<()>,
    state: Mutex<DrainState>,
    /// [`MAX_DRAIN_CONCURRENCY`] slots; a pass uses the first
    /// [`Self::drain_concurrency`] of them.
    slots: Vec<Arc<Mutex<DrainSlot>>>,
    drain_concurrency: std::sync::atomic::AtomicUsize,
    cleanup: Mutex<CleanupState>,
    inventory: Mutex<PhysicalInventory>,
    activity: std::sync::Mutex<WriteBehindActivity>,
    observe_trace: std::sync::Mutex<ObserveTrace>,
}

impl PostgresImmutableStore {
    pub async fn create_write_behind_handle(
        &self,
        root: PathBuf,
        cell_id: String,
        revision: String,
        digest: [u8; 32],
        observer: FragmentStageObserver,
    ) -> Result<Arc<FragmentWriteBehindHandle>, StoreError> {
        let FragmentLifecycleRoute::Coordinated {
            coordinator,
            provider,
            late_effect_bound,
            ..
        } = &self.fragment_route
        else {
            return Err(StoreError::internal("write-behind requires governed route"));
        };
        let stage = self
            .write_behind
            .clone()
            .ok_or_else(|| StoreError::internal("write-behind stage missing"))?;
        coordinator
            .verify_stage_policy(&cell_id, &revision, &digest)
            .await
            .map_err(domain_store_err)?;
        let (bytes, files) = stage.hard_limits();
        coordinator
            .verify_stage_capacity(bytes, files)
            .await
            .map_err(domain_store_err)?;
        let policy = FragmentDrainPolicyPin {
            cell_id,
            revision,
            digest,
        };
        let (drain, maintenance) = provider
            .drain_handles(root, policy.clone(), self.io_timeout, self.io_timeout)
            .await
            .map_err(provider_store_err)?;
        let scanner = Arc::new(std::sync::Mutex::new(StageFileScanner::default()));
        Ok(Arc::new(FragmentWriteBehindHandle {
            coordinator: coordinator.clone(),
            observer,
            provider: provider.clone(),
            stage,
            drain,
            maintenance,
            policy,
            send_timeout: self.io_timeout,
            late_effect_bound: *late_effect_bound,
            pass: Mutex::new(()),
            state: Mutex::new(DrainState {
                cursor: Vec::new(),
                cooldown: BTreeMap::new(),
            }),
            slots: (0..MAX_DRAIN_CONCURRENCY)
                .map(|_| Arc::new(Mutex::new(DrainSlot::default())))
                .collect(),
            drain_concurrency: std::sync::atomic::AtomicUsize::new(DEFAULT_DRAIN_CONCURRENCY),
            cleanup: Mutex::new(CleanupState {
                cursor: None,
                scanner,
                scan: None,
                purge: None,
            }),
            inventory: Mutex::new(PhysicalInventory::default()),
            activity: std::sync::Mutex::new(WriteBehindActivity::default()),
            observe_trace: std::sync::Mutex::new(ObserveTrace::default()),
        }))
    }
}

/// Private and produced only after checking the exact durable source manifest.
struct VerifiedStagedBody {
    source: FragmentDrainCandidate,
    address: Address,
    fragment: Fragment,
    bytes: Bytes,
}

impl FragmentWriteBehindHandle {
    pub fn activity(&self) -> WriteBehindActivity {
        *self
            .activity
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }

    fn record_drain_activity(&self, promoted: bool) {
        let mut activity = self
            .activity
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        activity.drain_loop = Some(Instant::now());
        if promoted {
            activity.drain_progress = activity.drain_loop;
        }
    }

    fn record_cleanup_activity(&self, cleaned: bool) {
        let mut activity = self
            .activity
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        activity.cleanup_loop = Some(Instant::now());
        if cleaned {
            activity.cleanup_progress = activity.cleanup_loop;
        }
    }

    /// Advance inventory independently of slow cleanup/provider operations.
    /// One retained job owns the scanner and an I/O permit until actual syscall
    /// completion; cancellation cannot start a second scanner on a wedged root.
    ///
    /// Collects a finished step and issues the next one. The step issued here
    /// runs concurrently with this observation's ledger read, so it is bound to
    /// the previous read, and a walk it completes is bound by a later read; see
    /// [`Self::bind_stage_inventory`].
    async fn physical_inventory(&self) -> Result<(), StoreError> {
        let mut state = self.inventory.lock().await;
        if let Some((task, started, before)) = state.task.as_mut()
            && task.is_finished()
        {
            let (started, before) = (*started, *before);
            let result = task.await;
            state.task = None;
            if let Ok(Ok((scanner, completed))) = result {
                let walk = completed.then(|| scanner.physical_observation()).flatten();
                state.walk.record_step(before, started, walk);
                state.scanner = Some(scanner);
            } else {
                state.walk.record_failure();
                state.scanner = Some(StageFileScanner::default());
                return Err(StoreError::from(SlowDown));
            }
        }
        if state.task.is_none() {
            let permit = self
                .stage
                .root()
                .try_io_permit(crate::store::write_behind::StageIoPath::Inventory)
                .map_err(|error| error.store_error())?;
            let mut scanner = state
                .scanner
                .take()
                .ok_or_else(|| StoreError::internal("physical inventory scanner missing"))?;
            let started = !scanner.walk_in_progress();
            let before = state.walk.last_ledger();
            let stage = self.stage.clone();
            let task = lore_base::lore_spawn_blocking!("stage-physical-inventory", move || {
                let _permit = permit;
                let previous = scanner.physical_observation().map(|(at, _, _, _)| at);
                // Up to 4096 entries per observer tick, with the scanner's own
                // depth/handle bound. Cleanup keeps its separate candidate cursor.
                // It stops at a completion, so a step starts at most one walk.
                for _ in 0..16 {
                    let _ = scanner
                        .scan(&stage, 256)
                        .map_err(|error| error.store_error())?;
                    if scanner.physical_observation().map(|(at, _, _, _)| at) != previous {
                        return Ok((scanner, true));
                    }
                }
                Ok((scanner, false))
            });
            state.task = Some((task, started, before));
        }
        Ok(())
    }

    /// Record the stage ledger read taken after [`Self::physical_inventory`],
    /// and return the latest completed walk with the ledger it must not exceed.
    async fn bind_stage_inventory(
        &self,
        ledger: (u64, u64),
    ) -> Option<(StagePhysical, (u64, u64))> {
        let mut state = self.inventory.lock().await;
        state.walk.record_ledger(ledger);
        state
            .walk
            .current()
            .filter(|((at, _, _, _), _)| at.elapsed() < STAGE_PHYSICAL_MAX_AGE)
    }

    pub fn mode(&self) -> StagingMode {
        self.stage.mode()
    }
    pub fn note_drain_heartbeat(&self) {
        self.stage.note_drain_heartbeat();
    }
    pub fn note_worker_stopped(&self) {
        self.stage.note_worker_stopped();
    }
    pub fn note_observation_unknown(&self) {
        self.stage.note_observation_unknown();
    }

    /// Step timings of the latest `observe()` attempt, including one a caller's
    /// deadline cancelled.
    pub fn observe_trace(&self) -> ObserveTrace {
        self.observe_trace
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    fn with_trace(&self, update: impl FnOnce(&mut ObserveTrace)) {
        update(
            &mut self
                .observe_trace
                .lock()
                .unwrap_or_else(|error| error.into_inner()),
        );
    }

    /// Run one `observe()` step and record how long it took. A step whose
    /// future is dropped stays `in_flight`.
    async fn observe_step<T>(
        &self,
        step: ObserveStep,
        future: impl std::future::Future<Output = Result<T, StoreError>>,
    ) -> Result<T, StoreError> {
        let started = Instant::now();
        self.with_trace(|trace| trace.begin(step, started));
        let result = future.await;
        self.with_trace(|trace| trace.end(step, started.elapsed(), result.is_ok()));
        result
    }

    pub async fn observe(&self) -> Result<WriteBehindObservation, StoreError> {
        self.with_trace(|trace| *trace = ObserveTrace::default());
        self.stage.note_observation_unknown();
        self.observe_step(ObserveStep::PhysicalInventory, self.physical_inventory())
            .await?;
        // Both database reads go to the reserved observer connection, never the
        // shared domain pool (row 76).
        self.observe_step(ObserveStep::StagePolicy, async {
            self.observer
                .verify_stage_policy(
                    &self.policy.cell_id,
                    &self.policy.revision,
                    &self.policy.digest,
                )
                .await
                .map_err(domain_store_err)
        })
        .await?;
        let observation = self
            .observe_step(ObserveStep::StageLedger, async {
                self.observer
                    .observe_stage()
                    .await
                    .map_err(domain_store_err)
            })
            .await?;
        let spool = self
            .observe_step(ObserveStep::SpoolObserve, async {
                self.maintenance.observe().await.map_err(provider_store_err)
            })
            .await?;
        let charged_bytes = positive(observation.resident_bytes)?;
        let charged_files = positive(observation.resident_files)?;
        let bound = self
            .observe_step(ObserveStep::BindInventory, async {
                Ok(self
                    .bind_stage_inventory((charged_bytes, charged_files))
                    .await)
            })
            .await?;
        let stage_physical = bound.map(|(walk, _)| walk);
        let capacity = CapacityEvidence::evaluate(
            observation.metadata_full,
            stage_physical,
            bound.map_or((charged_bytes, charged_files), |(_, ledger)| ledger),
            &spool,
            self.stage.min_free_bytes(),
        );
        let capacity_available = capacity.failing.is_empty();
        self.stage.note_capacity(capacity.verdict());
        let stage_bytes = charged_bytes.max(stage_physical.map_or(0, |(_, bytes, _, _)| bytes));
        let stage_files = charged_files.max(stage_physical.map_or(0, |(_, _, files, _)| files));
        self.stage.note_occupancy(stage_bytes, stage_files);
        self.stage
            .note_pending_staged(observation.pending_files != 0);
        Ok(WriteBehindObservation {
            pending_files: positive(observation.pending_files)?,
            pending_bytes: positive(observation.pending_bytes)?,
            stage_bytes,
            stage_files,
            spool_bytes: spool
                .spool_bytes
                .max(spool.physical_spool_bytes.unwrap_or(0)),
            spool_files: spool
                .spool_files
                .max(spool.physical_spool_files.unwrap_or(0)),
            oldest_pending_age: observation
                .oldest_pending
                .and_then(|t| SystemTime::now().duration_since(t).ok()),
            cleanup_backlog: positive(observation.cleanup_backlog)?
                .saturating_add(spool.cleanup_backlog),
            roots_usable: self.stage.snapshot().root_available && spool.roots_usable,
            capacity_available,
            capacity,
        })
    }

    /// How many promotions one drain pass runs at once.
    pub fn drain_concurrency(&self) -> usize {
        self.drain_concurrency
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Override the default drain concurrency
    /// ([`DEFAULT_DRAIN_CONCURRENCY`]). Clamped to `1..=MAX_DRAIN_CONCURRENCY`.
    pub fn set_drain_concurrency(&self, concurrency: usize) {
        self.drain_concurrency.store(
            concurrency.clamp(1, MAX_DRAIN_CONCURRENCY),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// Promote up to `batch` staged fragments, at most
    /// [`Self::drain_concurrency`] at once (row 77).
    ///
    /// Each promotion runs in its own task on its own slot. The cursor and
    /// cooldown lock is taken only for bookkeeping, never across a promotion.
    /// Candidates in one batch are distinct hashes, and passes never overlap,
    /// so one replica never runs two promotions of one fragment; across
    /// replicas the claim barrier and the promotion fence still decide.
    /// Cancelling the pass aborts its tasks; a slot keeps any file task that
    /// was still running, and the next pass will not reuse that slot until the
    /// task returns.
    pub async fn drain_pass(self: &Arc<Self>, batch: u32) -> Result<u32, StoreError> {
        let _pass = self.pass.lock().await;
        let mut free = Vec::new();
        for slot in self.slots.iter().take(self.drain_concurrency()) {
            // A locked slot belongs to a task of a cancelled pass that is still
            // being torn down. A slot whose file task outlived its wait keeps the
            // sole handle until the syscall returns; its claim expires in SQL.
            let Ok(mut slot) =
                tokio::time::timeout(self.send_timeout, slot.clone().lock_owned()).await
            else {
                continue;
            };
            if slot.settle().await {
                free.push(slot);
            }
        }
        if free.is_empty() {
            return Err(StoreError::from(SlowDown));
        }
        let bound = FragmentDrainCandidateBatch::new(batch).map_err(domain_store_err)?;
        let cursor = self.state.lock().await.cursor.clone();
        let mut candidates = self
            .coordinator
            .staged_drain_candidates_after(bound, &cursor)
            .await
            .map_err(domain_store_err)?;
        if candidates.is_empty() && !cursor.is_empty() {
            self.state.lock().await.cursor.clear();
            candidates = self
                .coordinator
                .staged_drain_candidates_after(bound, &[])
                .await
                .map_err(domain_store_err)?;
        }
        {
            let now = Instant::now();
            self.state.lock().await.cooldown.retain(|_, (until, _)| {
                now.saturating_duration_since(*until) < Duration::from_secs(300)
            });
        }
        let mut promoted = 0;
        let mut running = tokio::task::JoinSet::new();
        for source in candidates {
            let hash = source.hash().to_vec();
            {
                let mut state = self.state.lock().await;
                state.cursor = hash.clone();
                if state
                    .cooldown
                    .get(&hash)
                    .is_some_and(|(until, _)| *until > Instant::now())
                {
                    continue;
                }
            }
            while free.is_empty() {
                let Some(joined) = running.join_next().await else {
                    break;
                };
                self.settle_promotion(joined, &mut promoted, &mut free)
                    .await;
            }
            // Every slot retains a file task that has not returned.
            let Some(slot) = free.pop() else {
                break;
            };
            let handle = self.clone();
            lore_base::lore_spawn!(running, async move {
                let mut slot = slot;
                let result = handle.promote(source, &mut slot).await;
                (hash, result, slot)
            });
        }
        while let Some(joined) = running.join_next().await {
            self.settle_promotion(joined, &mut promoted, &mut free)
                .await;
        }
        Ok(promoted)
    }

    /// Account for one finished promotion and return its slot to the pass.
    async fn settle_promotion(
        &self,
        joined: JoinedPromotion,
        promoted: &mut u32,
        free: &mut Vec<HeldDrainSlot>,
    ) {
        let Ok((hash, result, slot)) = joined else {
            // A panicked promotion: its slot guard is gone with it.
            self.record_drain_activity(false);
            tracing::warn!("fragment promotion task failed");
            return;
        };
        match result {
            Ok(true) => {
                *promoted += 1;
                self.record_drain_activity(true);
                self.state.lock().await.cooldown.remove(&hash);
            }
            Ok(false) => self.record_drain_activity(false),
            Err(error) => {
                let mut state = self.state.lock().await;
                // Bounded memory; the keyset still advances when cooling down.
                if state.cooldown.len() >= 1024 {
                    state.cooldown.clear();
                }
                let tries = state
                    .cooldown
                    .get(&hash)
                    .map_or(1, |(_, n)| n.saturating_add(1));
                let delay = Duration::from_secs((1u64 << tries.min(5)).min(30));
                state.cooldown.insert(hash, (Instant::now() + delay, tries));
                tracing::warn!("fragment promotion deferred: {error}");
            }
        }
        // A slot still holding a timed-out file task sits out the rest of the pass.
        if !slot.retains_task() {
            free.push(slot);
        }
    }

    async fn verify_source(
        &self,
        source: FragmentDrainCandidate,
        slot: &mut DrainSlot,
    ) -> Result<VerifiedStagedBody, StoreError> {
        let coordinator = self.coordinator.clone();
        let stage = self.stage.clone();
        slot.reader = Some(lore_base::lore_spawn!("fragment-drain-read", async move {
            Self::verify_staged_source(&coordinator, &stage, source).await
        }));
        let reader = slot
            .reader
            .as_mut()
            .ok_or_else(|| StoreError::internal("source reader missing"))?;
        match tokio::time::timeout(self.send_timeout, reader).await {
            Ok(result) => {
                slot.reader = None;
                result.map_err(|_error| StoreError::from(SlowDown))?
            }
            Err(_) => Err(StoreError::from(SlowDown)),
        }
    }

    async fn verify_staged_source(
        coordinator: &PostgresFragmentCoordinator,
        stage: &WriteBehindStage,
        source: FragmentDrainCandidate,
    ) -> Result<VerifiedStagedBody, StoreError> {
        let bytes = match stage
            .read_staged(source.hash(), source.epoch(), source.object_key())
            .await
        {
            StagedRead::Found(bytes) => bytes,
            StagedRead::Unavailable(error) => return Err(error.store_error()),
            StagedRead::Absent => {
                Self::diagnose(coordinator, &source, MissingDiagnostic::Absent).await?;
                return Err(StoreError::from(SlowDown));
            }
        };
        let address = Address {
            context: Context::default(),
            hash: Hash::from(source.hash()),
        };
        let fragment = Fragment {
            flags: source.original_flags(),
            size_payload: u32::try_from(source.size_payload())
                .map_err(|_error| StoreError::internal("staged payload size"))?,
            size_content: positive(source.size_content())?,
        };
        let manifest = PostgresImmutableStore::key_manifest(
            source.object_key(),
            address,
            fragment,
            &bytes,
            EpochAuthority::Staged,
        )?;
        let matches = manifest.manifest_id == source.manifest_id()
            && manifest.decoded_hash == source.decoded_hash()
            && manifest.payload_flags == source.payload_flags()
            && bytes.len() as u64 == source.size_payload();
        if !matches {
            Self::diagnose(coordinator, &source, MissingDiagnostic::Corrupt).await?;
            return Err(StoreError::internal("staged manifest mismatch"));
        }
        if let Err(diagnostic) = PostgresImmutableStore::validate_candidate(
            address.hash,
            &manifest,
            fragment,
            bytes.clone(),
        ) {
            Self::diagnose(coordinator, &source, diagnostic).await?;
            return Err(StoreError::internal("staged semantic validation failed"));
        }
        Ok(VerifiedStagedBody {
            source,
            address,
            fragment,
            bytes,
        })
    }

    async fn diagnose(
        coordinator: &PostgresFragmentCoordinator,
        source: &FragmentDrainCandidate,
        diagnostic: MissingDiagnostic,
    ) -> Result<(), StoreError> {
        let witness = EpochWitness {
            hash: source.hash().to_vec(),
            epoch: source.epoch(),
            state: FragmentLifecycleState::Staged,
            manifest_id: Some(source.manifest_id().to_vec()),
            fence: source.last_fence(),
        };
        coordinator
            .mark_missing(&witness, diagnostic)
            .await
            .map_err(domain_store_err)?;
        Ok(())
    }

    async fn promote(
        &self,
        source: FragmentDrainCandidate,
        slot: &mut DrainSlot,
    ) -> Result<bool, StoreError> {
        crate::domain::fragments::failpoint!("drain.source.entry").map_err(domain_store_err)?;
        let verified = self.verify_source(source, slot).await?;
        let logical = uuid::Uuid::now_v7();
        let attempt = uuid::Uuid::now_v7();
        let input = FragmentWriteClaimInput::new(
            *logical.as_bytes(),
            *attempt.as_bytes(),
            *blake3::hash(&verified.bytes).as_bytes(),
            verified.bytes.len() as u64,
            self.send_timeout,
            self.late_effect_bound,
        )
        .map_err(domain_store_err)?;
        // Row 77: begin and authorize run on one connection, so the promotion
        // waits for the shared domain pool twice rather than three times.
        // `send_promotion` releases it before the provider PUT.
        let held = self
            .coordinator
            .holding_connection()
            .await
            .map_err(domain_store_err)?;
        let intent = match held
            .begin_promotion(&verified.source, input)
            .await
            .map_err(domain_store_err)?
        {
            BeginOutcome::Admitted(intent) => intent,
            _ => return Ok(false),
        };
        let result = self.send_promotion(&intent, &verified, held, slot).await;
        match result {
            Ok((manifest, settlement)) => {
                let committed = self
                    .coordinator
                    .commit_promotion(&intent, IoObservation::Valid(manifest.clone()), settlement)
                    .await;
                match committed {
                    Ok(CommitVerdict::Published) => Ok(true),
                    Ok(_) => Ok(false),
                    Err(error) => {
                        // A lost commit response is resolved against the exact
                        // successor. Never repeat PUT to discover publication.
                        let current = self
                            .coordinator
                            .capture_current_readable_epoch(&intent.hash)
                            .await
                            .map_err(domain_store_err)?;
                        if current.is_some_and(|w| {
                            w.epoch == intent.epoch
                                && w.manifest_id.as_ref() == Some(&manifest.manifest_id)
                        }) {
                            Ok(true)
                        } else {
                            Err(domain_store_err(error))
                        }
                    }
                }
            }
            Err(error) => {
                // Coordinator distinguishes Prepared/NoSend from Sending and
                // preserves the late-effect barrier for ambiguous attempts.
                self.coordinator
                    .commit_promotion(
                        &intent,
                        IoObservation::Unusable(MissingDiagnostic::Absent),
                        FragmentWriteSettlement::NoSend,
                    )
                    .await
                    .map_err(domain_store_err)?;
                Err(error)
            }
        }
    }

    async fn send_promotion(
        &self,
        intent: &crate::domain::fragments::FragmentIntent,
        body: &VerifiedStagedBody,
        held: PostgresFragmentCoordinator,
        slot: &mut DrainSlot,
    ) -> Result<(FragmentManifest, FragmentWriteSettlement), StoreError> {
        let claim = intent
            .write_claim()
            .ok_or_else(|| StoreError::internal("promotion claim missing"))?;
        let mut plan = FragmentDrainReservationPlan::new(FragmentDrainReservationInput {
            logical_request_id: uuid::Uuid::from_bytes(*claim.logical_request_id()),
            attempt_id: uuid::Uuid::from_bytes(*claim.attempt_id()),
            upload_id: uuid::Uuid::now_v7(),
            spool_object_id: uuid::Uuid::now_v7(),
            upload_fence: positive(claim.fence())?,
            source_hash: body.address.hash.to_string(),
            source_epoch: positive(body.source.epoch())?,
            source_manifest: body
                .source
                .manifest_id()
                .try_into()
                .map_err(|_error| StoreError::internal("source manifest width"))?,
            remote_epoch: positive(intent.epoch)?,
            remote_fence: positive(intent.fence)?,
            object_key: intent.object_key.clone(),
            body_digest: *claim.body_blake3(),
            body_size: claim.body_size(),
            send_not_after_ms: system_time_millis(claim.send_not_after())?,
            hard_not_after_ms: system_time_millis(claim.hard_not_after())?,
        });
        let mut reservation_result = self.drain.reserve_spool(&mut plan).await;
        for _ in 0..2 {
            if !matches!(
                &reservation_result,
                Err(
                    lore_fragment_provider::FragmentProviderError::DrainAuthority(
                        lore_fragment_provider::FragmentDrainAuthorityError::Unavailable
                            // Rolled back for certain; the same descriptor is safe to replay.
                            | lore_fragment_provider::FragmentDrainAuthorityError::Contended
                    )
                )
            ) {
                break;
            }
            // The plan retains its exact accepted descriptor across uncertain
            // database outcomes. A retry must not mint another quota identity.
            reservation_result = self.drain.reserve_spool(&mut plan).await;
        }
        let reservation = reservation_result.map_err(provider_store_err)?;
        let budget_pin = reservation.budget_pin().clone();
        let bytes = body.bytes.clone();
        // The reservation is retained with the receipt so ready derives all
        // identifiers from the exact accepted descriptor.
        let reservation = Arc::new(reservation);
        let writer_reservation = reservation.clone();
        slot.writer = Some(lore_base::lore_spawn_blocking!(
            "fragment-drain-spool",
            move || writer_reservation.write_body(&bytes)
        ));
        let handle = slot
            .writer
            .as_mut()
            .ok_or_else(|| StoreError::internal("spool writer missing"))?;
        let written = tokio::time::timeout(self.send_timeout, handle).await;
        let receipt = match written {
            Ok(joined) => {
                slot.writer = None;
                joined
                    .map_err(|_error| StoreError::from(SlowDown))?
                    .map_err(provider_store_err)?
            }
            Err(_) => return Err(StoreError::from(SlowDown)),
        };
        let ready = self
            .drain
            .mark_spool_ready(&reservation, &receipt)
            .await
            .map_err(provider_store_err)?;
        let logical = uuid::Uuid::from_bytes(*claim.logical_request_id()).to_string();
        let mut ledger =
            FragmentAttemptLedger::new(self.provider.boundary().provider_boundary_id(), &logical)
                .map_err(provider_store_err)?;
        let authorized = held
            .authorize_write_claim(claim)
            .await
            .map_err(domain_store_err)?;
        // Never across the provider PUT: a stalled send must not keep a shared
        // domain connection.
        drop(held);
        let request = FragmentDrainAttempt {
            logical_request_id: logical,
            attempt_id: uuid::Uuid::from_bytes(*claim.attempt_id()).to_string(),
            attempt_ordinal: 1,
            deadline_unix_ms: system_time_millis(claim.send_not_after())?,
            budget_pin,
            object_key: intent.object_key.clone(),
            metadata: to_object_metadata(&body.fragment).into_iter().collect(),
            claim_body_blake3: *claim.body_blake3(),
            claim_body_size: claim.body_size(),
        };
        let execution = tokio::time::timeout(
            authorized.send_budget(),
            self.drain
                .attempt_drain(&mut ledger, request, &ready, &body.bytes),
        )
        .await;
        let (settlement, created) = match execution {
            Ok(Ok(execution)) => (
                match execution.outcome {
                    ProviderAttemptOutcome::Decisive => FragmentWriteSettlement::Decisive,
                    ProviderAttemptOutcome::Ambiguous => FragmentWriteSettlement::Ambiguous,
                },
                execution.response == FragmentTransportResponse::PutCreated,
            ),
            Ok(Err(error))
                if error.disposition()
                    == lore_fragment_provider::FragmentProviderDisposition::OutcomeUnknown =>
            {
                (FragmentWriteSettlement::Ambiguous, false)
            }
            Ok(Err(error)) => return Err(provider_store_err(error)),
            Err(_) => (FragmentWriteSettlement::Ambiguous, false),
        };
        if created && settlement == FragmentWriteSettlement::Decisive {
            return Ok((
                PostgresImmutableStore::key_manifest(
                    &intent.object_key,
                    body.address,
                    body.fragment,
                    &body.bytes,
                    EpochAuthority::Remote,
                )?,
                settlement,
            ));
        }
        // Adopt the actual representation, including an equivalent alternate
        // encoding. Its own metadata bounds its decoder before semantic compare.
        let remote = tokio::time::timeout(
            self.send_timeout,
            self.provider.get(
                &FragmentGetAttempt {
                    logical_request_id: uuid::Uuid::now_v7().to_string(),
                    attempt_id: uuid::Uuid::now_v7().to_string(),
                    attempt_ordinal: 1,
                },
                &FragmentGetOperation {
                    object_key: intent.object_key.clone(),
                },
            ),
        )
        .await
        .map_err(|_error| StoreError::from(SlowDown))?
        .map_err(provider_store_err)?;
        if let (ProviderAttemptOutcome::Decisive, FragmentGetResponse::Found { bytes, metadata }) =
            (remote.outcome, remote.response)
        {
            let metadata = metadata.into_iter().collect();
            let fragment = from_object_metadata(Some(&metadata))
                .map_err(|_error| StoreError::internal("remote metadata invalid"))?;
            let bytes = Bytes::from(bytes);
            PostgresImmutableStore::validate_put_candidate(
                body.address,
                fragment,
                &bytes,
                "promotion adoption",
            )?;
            if fragment.size_content != body.fragment.size_content
                || fragment.flags & CONTENT_STRUCTURE_MASK
                    != body.fragment.flags & CONTENT_STRUCTURE_MASK
            {
                return Err(StoreError::internal("remote fragment semantics conflict"));
            }
            return Ok((
                PostgresImmutableStore::key_manifest(
                    &intent.object_key,
                    body.address,
                    fragment,
                    &bytes,
                    EpochAuthority::Remote,
                )?,
                settlement,
            ));
        }
        Err(StoreError::from(SlowDown))
    }

    pub async fn cleanup_pass(&self, batch: u32) -> Result<u32, StoreError> {
        let mut state = self.cleanup.lock().await;
        let mut cleaned = 0;
        if let Some(task) = state.purge.as_mut() {
            if !task.is_finished() {
                return Err(StoreError::from(SlowDown));
            }
            let result = task.await;
            state.purge = None;
            self.coordinator
                .commit_stage_cleanup(&result.map_err(|_error| StoreError::from(SlowDown))??)
                .await
                .map_err(domain_store_err)?;
            cleaned += 1;
            self.record_cleanup_activity(true);
        }
        let candidates = self
            .coordinator
            .stage_cleanup_candidates(
                state.cursor.as_ref().map(|(h, e)| (h.as_slice(), *e)),
                batch,
            )
            .await
            .map_err(domain_store_err)?;
        if candidates.is_empty() {
            state.cursor = None;
        }
        for (hash, epoch) in candidates {
            state.cursor = Some((hash.clone(), epoch));
            if let Some(intent) = self
                .coordinator
                .begin_stage_cleanup(&hash, epoch)
                .await
                .map_err(domain_store_err)?
            {
                self.purge_stage(&mut state, intent, None).await?;
                cleaned += 1;
                self.record_cleanup_activity(true);
            }
        }
        if state.scan.is_none() {
            let scanner = state.scanner.clone();
            let stage = self.stage.clone();
            state.scan = Some(lore_base::lore_spawn_blocking!(
                "stage-inventory",
                move || {
                    scanner
                        .lock()
                        .map_err(|_error| StoreError::from(SlowDown))?
                        .scan(&stage, batch as usize)
                        .map_err(|e| e.store_error())
                }
            ));
        }
        let task = state
            .scan
            .as_mut()
            .ok_or_else(|| StoreError::internal("stage inventory task missing"))?;
        let files = match tokio::time::timeout(self.send_timeout, task).await {
            Ok(result) => {
                state.scan = None;
                result.map_err(|_error| StoreError::from(SlowDown))??
            }
            Err(_) => return Err(StoreError::from(SlowDown)),
        };
        for file in files {
            if let Some(intent) = self
                .coordinator
                .begin_stage_cleanup(&file.hash, file.epoch)
                .await
                .map_err(domain_store_err)?
            {
                self.purge_stage(&mut state, intent, Some(file)).await?;
                cleaned += 1;
                self.record_cleanup_activity(true);
            }
        }
        // Keep expiry cleanup bounded, but surface completed physical work
        // between items rather than after an entire slow spool batch.
        for _ in 0..batch {
            let removed = self
                .maintenance
                .cleanup_pass(1)
                .await
                .map_err(provider_store_err)?;
            cleaned += removed;
            self.record_cleanup_activity(removed > 0);
        }
        Ok(cleaned)
    }

    async fn purge_stage(
        &self,
        state: &mut CleanupState,
        intent: StageCleanupIntent,
        file: Option<StageFileCandidate>,
    ) -> Result<(), StoreError> {
        let stage = self.stage.clone();
        state.purge = Some(lore_base::lore_spawn_blocking!(
            "stage-reclaim",
            move || {
                stage
                    .purge_placement(intent.target())
                    .map_err(|e| e.store_error())?;
                if let Some(file) = file {
                    stage
                        .purge_candidate(&file, intent.target())
                        .map_err(|e| e.store_error())?;
                }
                Ok(intent)
            }
        ));
        let task = state
            .purge
            .as_mut()
            .ok_or_else(|| StoreError::internal("stage purge task missing"))?;
        let intent = match tokio::time::timeout(self.send_timeout, task).await {
            Ok(result) => {
                state.purge = None;
                result.map_err(|_error| StoreError::from(SlowDown))??
            }
            Err(_) => return Err(StoreError::from(SlowDown)),
        };
        self.coordinator
            .commit_stage_cleanup(&intent)
            .await
            .map_err(domain_store_err)
    }
}

fn positive(value: i64) -> Result<u64, StoreError> {
    u64::try_from(value).map_err(|_error| StoreError::internal("negative write-behind observation"))
}

#[cfg(test)]
mod capacity_evidence_tests {
    use std::time::Duration;
    use std::time::Instant;

    use lore_fragment_provider::FragmentDrainObservation;

    use super::CapacityEvidence;

    const MIN_FREE: u64 = 64;

    fn healthy_spool() -> FragmentDrainObservation {
        FragmentDrainObservation {
            spool_bytes: 100,
            spool_files: 10,
            cleanup_backlog: 0,
            roots_usable: true,
            metadata_full: false,
            superseded_pending: 0,
            available_bytes: Some(MIN_FREE),
            physical_spool_bytes: Some(100),
            physical_spool_files: Some(10),
            physical_spool_age: Some(Duration::from_millis(1_500)),
            physical_spool_ledger: None,
        }
    }

    fn healthy_stage(at: Instant) -> Option<(Instant, u64, u64, u64)> {
        Some((at, 200, 20, 0))
    }

    fn evaluate(
        stage_metadata_full: bool,
        stage_physical: Option<(Instant, u64, u64, u64)>,
        spool: &FragmentDrainObservation,
    ) -> CapacityEvidence {
        CapacityEvidence::evaluate(
            stage_metadata_full,
            stage_physical,
            (200, 20),
            spool,
            MIN_FREE,
        )
    }

    #[test]
    fn a_reconciled_cell_names_no_failing_predicate() {
        let evidence = evaluate(false, healthy_stage(Instant::now()), &healthy_spool());
        assert!(evidence.failing.is_empty(), "{:?}", evidence.failing);
    }

    /// One case per conjunct: each must fail alone and report exactly its name.
    #[test]
    fn each_predicate_reports_its_own_name() {
        let now = Instant::now();
        let mut cases: Vec<(&str, CapacityEvidence)> = Vec::new();
        cases.push((
            "stage_metadata_full",
            evaluate(true, healthy_stage(now), &healthy_spool()),
        ));
        let mut spool = healthy_spool();
        spool.metadata_full = true;
        cases.push((
            "spool_metadata_full",
            evaluate(false, healthy_stage(now), &spool),
        ));
        cases.push((
            "stage_inventory_missing",
            evaluate(false, None, &healthy_spool()),
        ));
        cases.push((
            "stage_unknown_entries",
            evaluate(false, Some((now, 200, 20, 1)), &healthy_spool()),
        ));
        cases.push((
            "stage_bytes_over_ledger",
            evaluate(false, Some((now, 201, 20, 0)), &healthy_spool()),
        ));
        cases.push((
            "stage_files_over_ledger",
            evaluate(false, Some((now, 200, 21, 0)), &healthy_spool()),
        ));
        let mut spool = healthy_spool();
        spool.physical_spool_bytes = None;
        cases.push((
            "spool_bytes_inventory_missing",
            evaluate(false, healthy_stage(now), &spool),
        ));
        let mut spool = healthy_spool();
        spool.physical_spool_bytes = Some(101);
        cases.push((
            "spool_bytes_over_ledger",
            evaluate(false, healthy_stage(now), &spool),
        ));
        let mut spool = healthy_spool();
        spool.physical_spool_files = None;
        cases.push((
            "spool_files_inventory_missing",
            evaluate(false, healthy_stage(now), &spool),
        ));
        let mut spool = healthy_spool();
        spool.physical_spool_files = Some(11);
        cases.push((
            "spool_files_over_ledger",
            evaluate(false, healthy_stage(now), &spool),
        ));
        let mut spool = healthy_spool();
        spool.available_bytes = None;
        cases.push((
            "free_space_unknown",
            evaluate(false, healthy_stage(now), &spool),
        ));
        let mut spool = healthy_spool();
        spool.available_bytes = Some(MIN_FREE - 1);
        cases.push((
            "free_space_below_minimum",
            evaluate(false, healthy_stage(now), &spool),
        ));
        for (name, evidence) in cases {
            assert_eq!(evidence.failing, vec![name], "case {name}");
        }
    }

    /// Equal to the ledger is reconciled; only strictly larger fails, as before.
    #[test]
    fn a_physical_inventory_equal_to_its_ledger_passes() {
        let mut spool = healthy_spool();
        spool.available_bytes = Some(MIN_FREE);
        let evidence = evaluate(false, Some((Instant::now(), 200, 20, 0)), &spool);
        assert!(evidence.failing.is_empty(), "{:?}", evidence.failing);
    }

    #[test]
    fn both_inventory_ages_and_both_sides_of_each_comparison_are_reported() {
        let completed = Instant::now() - Duration::from_secs(7);
        let mut spool = healthy_spool();
        spool.physical_spool_bytes = Some(150);
        let evidence = evaluate(false, Some((completed, 180, 19, 0)), &spool);
        assert_eq!(evidence.failing, vec!["spool_bytes_over_ledger"]);
        let stage_age = evidence.stage_inventory_age.expect("stage age");
        assert!(stage_age >= Duration::from_secs(7), "{stage_age:?}");
        assert!(stage_age < Duration::from_secs(60), "{stage_age:?}");
        assert_eq!(
            evidence.spool_inventory_age,
            Some(Duration::from_millis(1_500))
        );
        assert_eq!(evidence.stage_physical_bytes, Some(180));
        assert_eq!(evidence.stage_physical_files, Some(19));
        assert_eq!(
            (evidence.stage_ledger_bytes, evidence.stage_ledger_files),
            (200, 20)
        );
        assert_eq!(evidence.spool_physical_bytes, Some(150));
        assert_eq!(
            (evidence.spool_ledger_bytes, evidence.spool_ledger_files),
            (100, 10)
        );
        assert_eq!(evidence.available_bytes, Some(MIN_FREE));
    }

    /// The verdict must equal the single conjunction `observe` computed before
    /// the predicates were split out, over every boundary of every input.
    #[test]
    fn the_verdict_matches_the_original_conjunction_on_every_boundary() {
        let now = Instant::now();
        let options = |values: [u64; 3]| [None, Some(values[0]), Some(values[1]), Some(values[2])];
        for stage_full in [false, true] {
            for spool_full in [false, true] {
                for stage in [
                    None,
                    Some((now, 200, 20, 0)),
                    Some((now, 201, 20, 0)),
                    Some((now, 200, 21, 0)),
                    Some((now, 199, 19, 1)),
                ] {
                    for spool_bytes in options([99, 100, 101]) {
                        for spool_files in options([9, 10, 11]) {
                            for free in options([0, MIN_FREE - 1, MIN_FREE]) {
                                let spool = FragmentDrainObservation {
                                    metadata_full: spool_full,
                                    physical_spool_bytes: spool_bytes,
                                    physical_spool_files: spool_files,
                                    available_bytes: free,
                                    ..healthy_spool()
                                };
                                let original = !stage_full
                                    && !spool.metadata_full
                                    && stage.is_some_and(|(_, bytes, files, unknown)| {
                                        unknown == 0 && bytes <= 200 && files <= 20
                                    })
                                    && spool
                                        .physical_spool_bytes
                                        .is_some_and(|bytes| bytes <= spool.spool_bytes)
                                    && spool
                                        .physical_spool_files
                                        .is_some_and(|files| files <= spool.spool_files)
                                    && spool.available_bytes.is_some_and(|free| free >= MIN_FREE);
                                let evidence = evaluate(stage_full, stage, &spool);
                                assert_eq!(evidence.failing.is_empty(), original, "{evidence:?}");
                            }
                        }
                    }
                }
            }
        }
    }

    /// INV-FT row 67: the spool walk is compared with its own ledger bound, not
    /// the current read. The 2026-09-28 sample: 118 bodies walked, 116 in the
    /// read taken after a cleanup burst, 118 in the read before the walk.
    #[test]
    fn the_spool_walk_is_compared_with_its_bound_not_the_current_read() {
        let mut spool = healthy_spool();
        spool.spool_bytes = 8_492_370;
        spool.spool_files = 116;
        spool.physical_spool_bytes = Some(8_750_269);
        spool.physical_spool_files = Some(118);
        spool.physical_spool_ledger = Some((8_750_269, 118));
        let evidence = evaluate(false, healthy_stage(Instant::now()), &spool);
        assert!(evidence.failing.is_empty(), "{:?}", evidence.failing);
        assert_eq!(
            (evidence.spool_ledger_bytes, evidence.spool_ledger_files),
            (8_750_269, 118),
            "the evidence names the side it compared"
        );
        spool.physical_spool_ledger = Some((8_750_268, 118));
        let evidence = evaluate(false, healthy_stage(Instant::now()), &spool);
        assert_eq!(evidence.failing, vec!["spool_bytes_over_ledger"]);
    }

    /// Staging's budget covers only the snapshot-vs-ledger predicates.
    #[test]
    fn only_over_ledger_predicates_are_reconciling() {
        use crate::store::write_behind::CapacityVerdict;
        let now = Instant::now();
        assert_eq!(
            evaluate(false, healthy_stage(now), &healthy_spool()).verdict(),
            CapacityVerdict::Available
        );
        let mut spool = healthy_spool();
        spool.physical_spool_bytes = Some(101);
        spool.physical_spool_files = Some(11);
        assert_eq!(
            evaluate(false, Some((now, 201, 21, 0)), &spool).verdict(),
            CapacityVerdict::Reconciling,
            "all four over-ledger predicates together are still reconciling"
        );
        let hard: Vec<(&str, CapacityEvidence)> = vec![
            (
                "stage_metadata_full",
                evaluate(true, healthy_stage(now), &spool),
            ),
            ("stage_inventory_missing", evaluate(false, None, &spool)),
            (
                "stage_unknown_entries",
                evaluate(false, Some((now, 201, 21, 1)), &spool),
            ),
            (
                "spool_metadata_full",
                evaluate(
                    false,
                    healthy_stage(now),
                    &FragmentDrainObservation {
                        metadata_full: true,
                        ..spool
                    },
                ),
            ),
            (
                "spool_bytes_inventory_missing",
                evaluate(
                    false,
                    healthy_stage(now),
                    &FragmentDrainObservation {
                        physical_spool_bytes: None,
                        ..spool
                    },
                ),
            ),
            (
                "spool_files_inventory_missing",
                evaluate(
                    false,
                    healthy_stage(now),
                    &FragmentDrainObservation {
                        physical_spool_files: None,
                        ..spool
                    },
                ),
            ),
            (
                "free_space_unknown",
                evaluate(
                    false,
                    healthy_stage(now),
                    &FragmentDrainObservation {
                        available_bytes: None,
                        ..spool
                    },
                ),
            ),
            (
                "free_space_below_minimum",
                evaluate(
                    false,
                    healthy_stage(now),
                    &FragmentDrainObservation {
                        available_bytes: Some(MIN_FREE - 1),
                        ..spool
                    },
                ),
            ),
        ];
        for (name, evidence) in hard {
            assert!(evidence.failing.contains(&name), "{name}: {evidence:?}");
            assert_eq!(
                evidence.verdict(),
                CapacityVerdict::Unavailable,
                "{name} beside reconciling predicates still refuses at once"
            );
        }
    }

    #[test]
    fn a_missing_inventory_reports_no_age() {
        let mut spool = healthy_spool();
        spool.physical_spool_age = None;
        let evidence = evaluate(false, None, &spool);
        assert_eq!(evidence.stage_inventory_age, None);
        assert_eq!(evidence.spool_inventory_age, None);
    }
}

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
use crate::domain::fragments::StageCleanupIntent;
use crate::domain::fragments::states::FragmentLifecycleState;
use crate::store::write_behind::cleanup::StageFileCandidate;
use crate::store::write_behind::cleanup::StageFileScanner;

#[cfg(all(test, target_os = "linux"))]
#[path = "fragment_write_behind_adapter_tests.rs"]
mod adapter_tests;

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

struct PhysicalInventory {
    scanner: Option<StageFileScanner>,
    task: Option<tokio::task::JoinHandle<Result<StageFileScanner, StoreError>>>,
    observation: Option<(Instant, u64, u64, u64)>,
}

impl Default for PhysicalInventory {
    fn default() -> Self {
        Self {
            scanner: Some(StageFileScanner::default()),
            task: None,
            observation: None,
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
}

struct DrainState {
    cursor: Vec<u8>,
    cooldown: BTreeMap<Vec<u8>, (Instant, u32)>,
    // A cancelled wait never forgets an unfinished syscall or starts another.
    writer: Option<
        tokio::task::JoinHandle<
            Result<FragmentDrainWriteReceipt, lore_fragment_provider::FragmentProviderError>,
        >,
    >,
    reader: Option<tokio::task::JoinHandle<Result<VerifiedStagedBody, StoreError>>>,
}

pub struct FragmentWriteBehindHandle {
    coordinator: PostgresFragmentCoordinator,
    provider: Arc<FragmentProviderEntry>,
    stage: Arc<WriteBehindStage>,
    drain: FragmentDrainCapability,
    maintenance: FragmentDrainMaintenanceHandle,
    policy: FragmentDrainPolicyPin,
    send_timeout: Duration,
    late_effect_bound: Duration,
    state: Mutex<DrainState>,
    cleanup: Mutex<CleanupState>,
    inventory: Mutex<PhysicalInventory>,
    activity: std::sync::Mutex<WriteBehindActivity>,
}

impl PostgresImmutableStore {
    pub async fn create_write_behind_handle(
        &self,
        root: PathBuf,
        cell_id: String,
        revision: String,
        digest: [u8; 32],
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
            provider: provider.clone(),
            stage,
            drain,
            maintenance,
            policy,
            send_timeout: self.io_timeout,
            late_effect_bound: *late_effect_bound,
            state: Mutex::new(DrainState {
                cursor: Vec::new(),
                cooldown: BTreeMap::new(),
                writer: None,
                reader: None,
            }),
            cleanup: Mutex::new(CleanupState {
                cursor: None,
                scanner,
                scan: None,
                purge: None,
            }),
            inventory: Mutex::new(PhysicalInventory::default()),
            activity: std::sync::Mutex::new(WriteBehindActivity::default()),
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
    async fn physical_inventory(&self) -> Result<Option<(Instant, u64, u64, u64)>, StoreError> {
        let mut state = self.inventory.lock().await;
        if let Some(task) = state.task.as_mut()
            && task.is_finished()
        {
            let result = task.await;
            state.task = None;
            if let Ok(Ok(scanner)) = result {
                state.observation = scanner.physical_observation();
                state.scanner = Some(scanner);
            } else {
                state.observation = None;
                state.scanner = Some(StageFileScanner::default());
                return Err(StoreError::from(SlowDown));
            }
        }
        if state.task.is_none() {
            let permit = self
                .stage
                .root()
                .try_io_permit()
                .map_err(|error| error.store_error())?;
            let mut scanner = state
                .scanner
                .take()
                .ok_or_else(|| StoreError::internal("physical inventory scanner missing"))?;
            let stage = self.stage.clone();
            state.task = Some(lore_base::lore_spawn_blocking!(
                "stage-physical-inventory",
                move || {
                    let _permit = permit;
                    let previous = scanner.physical_observation().map(|(at, _, _, _)| at);
                    // Up to 4096 entries per observer tick, with the scanner's own
                    // depth/handle bound. Cleanup keeps its separate candidate cursor.
                    for _ in 0..16 {
                        let _ = scanner
                            .scan(&stage, 256)
                            .map_err(|error| error.store_error())?;
                        if scanner.physical_observation().map(|(at, _, _, _)| at) != previous {
                            break;
                        }
                    }
                    Ok(scanner)
                }
            ));
        }
        Ok(state
            .observation
            .filter(|(at, _, _, _)| at.elapsed() < Duration::from_secs(300)))
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

    pub async fn observe(&self) -> Result<WriteBehindObservation, StoreError> {
        self.stage.note_observation_unknown();
        let stage_physical = self.physical_inventory().await?;
        self.coordinator
            .verify_stage_policy(
                &self.policy.cell_id,
                &self.policy.revision,
                &self.policy.digest,
            )
            .await
            .map_err(domain_store_err)?;
        let observation = self
            .coordinator
            .observe_stage()
            .await
            .map_err(domain_store_err)?;
        let spool = self
            .maintenance
            .observe()
            .await
            .map_err(provider_store_err)?;
        let charged_bytes = positive(observation.resident_bytes)?;
        let charged_files = positive(observation.resident_files)?;
        let capacity_available = !observation.metadata_full
            && !spool.metadata_full
            && stage_physical.is_some_and(|(_, bytes, files, unknown)| {
                unknown == 0 && bytes <= charged_bytes && files <= charged_files
            })
            && spool
                .physical_spool_bytes
                .is_some_and(|bytes| bytes <= spool.spool_bytes)
            && spool
                .physical_spool_files
                .is_some_and(|files| files <= spool.spool_files)
            && spool
                .available_bytes
                .is_some_and(|free| free >= self.stage.min_free_bytes());
        self.stage.note_capacity(capacity_available);
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
        })
    }

    pub async fn drain_pass(&self, batch: u32) -> Result<u32, StoreError> {
        let mut state = self.state.lock().await;
        if let Some(reader) = state.reader.as_mut() {
            if !reader.is_finished() {
                return Err(StoreError::from(SlowDown));
            }
            let _ = reader.await;
            state.reader = None;
        }
        // A prior task may have been cancelled while the filesystem was blocked.
        // Keep its sole handle until completion; its old claim expires in SQL.
        if let Some(writer) = state.writer.as_mut() {
            if !writer.is_finished() {
                return Err(StoreError::from(SlowDown));
            }
            let _ = writer.await;
            state.writer = None;
        }
        let bound = FragmentDrainCandidateBatch::new(batch).map_err(domain_store_err)?;
        let mut candidates = self
            .coordinator
            .staged_drain_candidates_after(bound, &state.cursor)
            .await
            .map_err(domain_store_err)?;
        if candidates.is_empty() && !state.cursor.is_empty() {
            state.cursor.clear();
            candidates = self
                .coordinator
                .staged_drain_candidates_after(bound, &[])
                .await
                .map_err(domain_store_err)?;
        }
        let mut promoted = 0;
        let now = Instant::now();
        state.cooldown.retain(|_, (until, _)| {
            now.saturating_duration_since(*until) < Duration::from_secs(300)
        });
        for source in candidates {
            state.cursor = source.hash().to_vec();
            if state
                .cooldown
                .get(source.hash())
                .is_some_and(|(until, _)| *until > Instant::now())
            {
                continue;
            }
            let hash = source.hash().to_vec();
            match self.promote(source, &mut state).await {
                Ok(true) => {
                    promoted += 1;
                    self.record_drain_activity(true);
                    state.cooldown.remove(&hash);
                }
                Ok(false) => self.record_drain_activity(false),
                Err(error) => {
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
                    if state.writer.is_some() || state.reader.is_some() {
                        break;
                    }
                }
            }
        }
        Ok(promoted)
    }

    async fn verify_source(
        &self,
        source: FragmentDrainCandidate,
        state: &mut DrainState,
    ) -> Result<VerifiedStagedBody, StoreError> {
        let coordinator = self.coordinator.clone();
        let stage = self.stage.clone();
        state.reader = Some(lore_base::lore_spawn!("fragment-drain-read", async move {
            Self::verify_staged_source(&coordinator, &stage, source).await
        }));
        let reader = state
            .reader
            .as_mut()
            .ok_or_else(|| StoreError::internal("source reader missing"))?;
        match tokio::time::timeout(self.send_timeout, reader).await {
            Ok(result) => {
                state.reader = None;
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
        state: &mut DrainState,
    ) -> Result<bool, StoreError> {
        crate::domain::fragments::failpoint!("drain.source.entry").map_err(domain_store_err)?;
        let verified = self.verify_source(source, state).await?;
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
        let intent = match self
            .coordinator
            .begin_promotion(&verified.source, input)
            .await
            .map_err(domain_store_err)?
        {
            BeginOutcome::Admitted(intent) => intent,
            _ => return Ok(false),
        };
        let result = self.send_promotion(&intent, &verified, state).await;
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
        state: &mut DrainState,
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
        state.writer = Some(lore_base::lore_spawn_blocking!(
            "fragment-drain-spool",
            move || writer_reservation.write_body(&bytes)
        ));
        let handle = state
            .writer
            .as_mut()
            .ok_or_else(|| StoreError::internal("spool writer missing"))?;
        let written = tokio::time::timeout(self.send_timeout, handle).await;
        let receipt = match written {
            Ok(joined) => {
                state.writer = None;
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
        let authorized = self
            .coordinator
            .authorize_write_claim(claim)
            .await
            .map_err(domain_store_err)?;
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

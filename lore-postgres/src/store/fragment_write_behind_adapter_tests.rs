// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Real adapter + real SQL/limiter/spool; only the authorized transport is scripted.
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use lore_fragment_provider::CellProviderBoundary;
use lore_fragment_provider::FragmentDatabaseIdentity;
use lore_fragment_provider::FragmentDirectPutPort;
use lore_fragment_provider::FragmentDirectPutRequest;
use lore_fragment_provider::FragmentDispatchRuntimeConfig;
use lore_fragment_provider::FragmentDispatchTls;
use lore_fragment_provider::FragmentGetExchange;
use lore_fragment_provider::FragmentGetPort;
use lore_fragment_provider::FragmentGetRequest;
use lore_fragment_provider::FragmentProcessPoolInventory;
use lore_fragment_provider::FragmentTransportExchange;
use lore_fragment_provider::FragmentTransportPort;
use lore_fragment_provider::FragmentTransportRequest;
use lore_fragment_provider::InFlightChargeBound;
use lore_fragment_provider::InFlightPutBound;
use lore_fragment_provider::ProviderCapabilities;
use uuid::Uuid;

use super::*;
use crate::domain::PostgresDomainStore;
use crate::pool::TlsConfig;
use crate::store::write_behind::WriteBehindSettings;
use crate::store::write_behind::WriteBehindWatermarks;

#[derive(Clone, Copy, Debug)]
enum PutResult {
    Created,
    Exists,
    Ambiguous,
    Timeout,
}

#[derive(Clone)]
struct Port {
    result: PutResult,
    body: Bytes,
    remote: FragmentGetResponse,
    puts: Arc<AtomicUsize>,
    gets: Arc<AtomicUsize>,
}

impl FragmentTransportPort for Port {
    fn issue<'a>(
        &'a self,
        _: FragmentTransportRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = FragmentTransportExchange> + Send + 'a>> {
        Box::pin(async {
            panic!("drain must never issue HEAD/LIST/DELETE or another provider operation")
        })
    }
}

impl FragmentDirectPutPort for Port {
    fn issue_direct_put<'a>(
        &'a self,
        request: FragmentDirectPutRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = FragmentTransportExchange> + Send + 'a>> {
        Box::pin(async move {
            assert_eq!(
                request.body(),
                Some(self.body.as_ref()),
                "transport sees exactly the validated durable source"
            );
            assert_eq!(request.blake3(), Some(blake3::hash(&self.body).as_bytes()));
            self.puts.fetch_add(1, Ordering::SeqCst);
            let (outcome, response) = match self.result {
                PutResult::Created => (
                    ProviderAttemptOutcome::Decisive,
                    FragmentTransportResponse::PutCreated,
                ),
                PutResult::Exists => (
                    ProviderAttemptOutcome::Decisive,
                    FragmentTransportResponse::PutPreconditionFailed,
                ),
                PutResult::Ambiguous => (
                    ProviderAttemptOutcome::Ambiguous,
                    FragmentTransportResponse::AmbiguousFailure,
                ),
                PutResult::Timeout => std::future::pending().await,
            };
            FragmentTransportExchange {
                outcome,
                provider_requests_issued: 1,
                response,
            }
        })
    }
}

impl FragmentGetPort for Port {
    fn issue_get<'a>(
        &'a self,
        _: FragmentGetRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = FragmentGetExchange> + Send + 'a>> {
        Box::pin(async move {
            self.gets.fetch_add(1, Ordering::SeqCst);
            FragmentGetExchange {
                outcome: ProviderAttemptOutcome::Decisive,
                provider_requests_issued: 1,
                response: self.remote.clone(),
            }
        })
    }
}

struct Fixture {
    handle: Arc<FragmentWriteBehindHandle>,
    admin: tokio_postgres::Client,
    address: Address,
    source_epoch: i64,
    root: PathBuf,
    port: Port,
    _connection: tokio_util::task::AbortOnDropHandle<()>,
}

impl Fixture {
    async fn open(result: PutResult, remote: FragmentGetResponse, payload: Bytes) -> Self {
        Self::open_with_commit_loss(result, remote, payload, false).await
    }

    async fn open_with_commit_loss(
        result: PutResult,
        remote: FragmentGetResponse,
        payload: Bytes,
        lose_commit_ack: bool,
    ) -> Self {
        if lose_commit_ack {
            assert!(crate::domain::fragments::failpoints_compiled());
            assert_eq!(
                std::env::var("LORE_FRAGMENT_FAILPOINTS").unwrap(),
                "publication.commit.settled=unknown",
                "runner must set the process-wide failpoint before startup"
            );
        }
        let helper = std::env::var("LORE_TEST_ADAPTER_SETUP_BIN")
            .expect("runner must build the test-only dispatch setup example");
        let setup = std::process::Command::new(helper)
            .output()
            .expect("start fixture helper");
        assert!(
            setup.status.success(),
            "fixture setup failed: {}",
            String::from_utf8_lossy(&setup.stderr)
        );
        let setup: serde_json::Value = serde_json::from_slice(&setup.stdout).expect("fixture JSON");
        let url = std::env::var("LORE_TEST_PG_URL").expect("fresh disposable PostgreSQL URL");
        let domain = PostgresDomainStore::connect(&url, 1, &TlsConfig::default())
            .await
            .unwrap();
        let coordinator = domain.fragment_coordinator();
        coordinator.bootstrap().await.unwrap();
        let (admin, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .unwrap();
        let connection =
            tokio_util::task::AbortOnDropHandle::new(lore_base::lore_spawn!(async move {
                connection.await.unwrap();
            }));
        let digest: [u8; 32] = hex::decode(setup["digest"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let expiry = setup["expiry"].as_i64().unwrap();
        admin
            .batch_execute("SET SESSION AUTHORIZATION object_dispatch_retention_maintenance")
            .await
            .unwrap();
        admin.query_one("SELECT stage_policy_publish_v1('adapter-cell','adapter-policy-v1',$1,30000000,3000,100000000,10000,60000,$2)", &[&&digest[..], &expiry]).await.unwrap();
        admin
            .batch_execute("RESET SESSION AUTHORIZATION")
            .await
            .unwrap();
        let port = Port {
            result,
            body: payload.clone(),
            remote,
            puts: Arc::new(AtomicUsize::new(0)),
            gets: Arc::new(AtomicUsize::new(0)),
        };
        let provider = Arc::new(
            FragmentProviderEntry::connect(
                FragmentDispatchRuntimeConfig {
                    postgres_url: format!(
                        "{}{}sslmode=disable",
                        url.replacen("://postgres@", "://object_dispatch_retention_runtime@", 1,),
                        if url.contains('?') { "&" } else { "?" }
                    ),
                    expected_database_identity: FragmentDatabaseIdentity::new(
                        setup["system"].as_str().unwrap(),
                        setup["oid"].as_u64().unwrap() as u32,
                    )
                    .unwrap(),
                    process_pool_inventory: FragmentProcessPoolInventory {
                        immutable_pool_max: 4,
                        mutable_pool_max: 1,
                        lock_pool_max: 1,
                        domain_pool_max: 4,
                        dispatch_pool_max: 2,
                        relay_pool_max: 0,
                    }
                    .validate()
                    .unwrap(),
                    connect_timeout: Duration::from_secs(5),
                    acquire_timeout: Duration::from_secs(5),
                    statement_timeout: Duration::from_secs(5),
                    lock_timeout: Duration::from_secs(2),
                    tls: FragmentDispatchTls::Disabled,
                },
                CellProviderBoundary::new(
                    "adapter-boundary",
                    "adapter-fragments",
                    "us-east-1",
                    "minio",
                )
                .unwrap(),
                ProviderCapabilities::none(),
                InFlightPutBound::new(2, Duration::from_secs(1)).unwrap(),
                InFlightChargeBound::new(2, Duration::from_secs(1)).unwrap(),
                port.clone(),
            )
            .await
            .unwrap(),
        );
        let root = std::env::temp_dir().join(format!("lore-adapter-{}", Uuid::now_v7()));
        std::fs::create_dir(&root).unwrap();
        let stage_root = root.join("stage");
        let spool_root = root.join("spool");
        std::fs::create_dir(&stage_root).unwrap();
        std::fs::create_dir(&spool_root).unwrap();
        let stage = WriteBehindStage::open(WriteBehindSettings {
            root: stage_root,
            watermarks: WriteBehindWatermarks {
                low_bytes: 10000000,
                high_bytes: 20000000,
                hard_bytes: 30000000,
                low_count: 1000,
                high_count: 2000,
                hard_count: 3000,
                min_free_bytes: 0,
            },
            drain_stale_after: Duration::from_secs(60),
            sample_interval: Duration::from_secs(3600),
        })
        .unwrap();
        let s3_config = aws_sdk_s3::config::Builder::new()
            .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
            .region(aws_sdk_s3::config::Region::new("us-east-1"))
            .build();
        let store = PostgresImmutableStore {
            pool: crate::pool::build_pool(&url, 4, &TlsConfig::default()).unwrap(),
            s3: S3Impl::new(
                aws_sdk_s3::Client::from_conf(s3_config),
                Duration::from_secs(30),
                None,
            ),
            bucket: "unused-test-transport".into(),
            instruments: crate::metrics::Instruments::new("adapter-test"),
            fragment_route: FragmentLifecycleRoute::Legacy,
            staged_epoch_cleanup: None,
            write_behind: Some(stage.clone()),
            io_timeout: Duration::from_secs(3),
        }
        .with_fragment_lifecycle(
            coordinator.clone(),
            provider,
            BudgetPin {
                revision: "adapter-budget-v1".into(),
                fence: 1,
            },
            Duration::from_secs(5),
            None,
        );
        let handle = store
            .create_write_behind_handle(
                spool_root,
                "adapter-cell".into(),
                "adapter-policy-v1".into(),
                digest,
            )
            .await
            .unwrap();
        let address = Address {
            context: Context::default(),
            hash: Hash::from(blake3::hash(&payload).as_bytes().as_slice()),
        };
        let fragment = raw_fragment(&payload);
        let stage_result = store
            .put_staged(&coordinator, &stage, address, fragment, payload)
            .await;
        let source = if lose_commit_ack {
            assert!(
                stage_result.is_err(),
                "the same failpoint also loses the fixture's staging acknowledgement"
            );
            let staged = coordinator.capture_current_readable_epoch_for_authority(address.hash.data(), EpochAuthority::Staged).await.unwrap().expect("setup staging actually committed despite the deliberately lost acknowledgement");
            assert_eq!(staged.state, FragmentLifecycleState::Staged);
            staged
        } else {
            stage_result.unwrap()
        };
        Self {
            handle,
            admin,
            address,
            source_epoch: source.epoch,
            root,
            port,
            _connection: connection,
        }
    }

    async fn current(&self) -> EpochWitness {
        if let Some(remote) = self
            .handle
            .coordinator
            .capture_current_readable_epoch(self.address.hash.data())
            .await
            .unwrap()
        {
            return remote;
        }
        self.handle
            .coordinator
            .capture_current_readable_epoch_for_authority(
                self.address.hash.data(),
                EpochAuthority::Staged,
            )
            .await
            .unwrap()
            .expect("current readable staged or remote authority")
    }

    async fn claim_state(&self) -> i16 {
        self.admin
            .query_one(
                "SELECT state FROM lore_fragment_write_claims WHERE hash=$1",
                &[&self.address.hash.data().as_slice()],
            )
            .await
            .unwrap()
            .get(0)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn raw_fragment(payload: &[u8]) -> Fragment {
    Fragment {
        flags: 0,
        size_payload: payload.len() as u32,
        size_content: payload.len() as u64,
    }
}

fn payload() -> Bytes {
    Bytes::from("adapter semantic payload repeated ".repeat(512))
}

fn remote(fragment: Fragment, bytes: &[u8]) -> FragmentGetResponse {
    FragmentGetResponse::Found {
        bytes: bytes.to_vec(),
        metadata: to_object_metadata(&fragment).into_iter().collect(),
    }
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn adapter_created_put_publishes_once_and_uses_real_reservation_and_claim() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    assert_eq!(fixture.handle.drain_pass(8).await.unwrap(), 1);
    let current = fixture.current().await;
    assert_eq!(current.state, FragmentLifecycleState::Remote);
    assert!(current.epoch > fixture.source_epoch);
    assert_eq!(fixture.claim_state().await, 2, "decisive settled claim");
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.port.gets.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.handle.drain_pass(8).await.unwrap(), 0);
    assert_eq!(
        fixture.port.puts.load(Ordering::SeqCst),
        1,
        "published fragment cannot be resent"
    );
    let rows: i64 = fixture
        .admin
        .query_one(
            "SELECT count(*) FROM object_store_retention.object_dispatch_spool_objects",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(rows, 1, "one accepted physical reservation");
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn adapter_precondition_adopts_actual_alternate_compression_manifest() {
    let payload = payload();
    let (compressed, bytes) = lore_storage::compress(
        raw_fragment(&payload),
        &payload,
        lore_storage::CompressionMode::Zstd,
    )
    .unwrap();
    let fixture = Fixture::open(PutResult::Exists, remote(compressed, &bytes), payload).await;
    assert_eq!(fixture.handle.drain_pass(8).await.unwrap(), 1);
    let current = fixture.current().await;
    assert_eq!(current.state, FragmentLifecycleState::Remote);
    let object_key: String = fixture
        .admin
        .query_one(
            "SELECT object_key FROM lore_fragment_write_claims WHERE hash=$1",
            &[&fixture.address.hash.data().as_slice()],
        )
        .await
        .unwrap()
        .get(0);
    let expected = PostgresImmutableStore::key_manifest(
        &object_key,
        fixture.address,
        compressed,
        &bytes,
        EpochAuthority::Remote,
    )
    .unwrap();
    assert_eq!(
        current.manifest_id,
        Some(expected.manifest_id),
        "publish the observed encoding, not the sent raw representation"
    );
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.port.gets.load(Ordering::SeqCst), 1);
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn adapter_corrupt_remote_readback_keeps_staged_source_and_late_effect_barrier() {
    let payload = payload();
    let corrupt = vec![0x5a; payload.len()];
    let fixture = Fixture::open(
        PutResult::Ambiguous,
        remote(raw_fragment(&payload), &corrupt),
        payload,
    )
    .await;
    assert_eq!(fixture.handle.drain_pass(8).await.unwrap(), 0);
    let current = fixture.current().await;
    assert_eq!(current.state, FragmentLifecycleState::Staged);
    assert_eq!(current.epoch, fixture.source_epoch);
    assert_eq!(
        fixture.claim_state().await,
        3,
        "a sent request remains ambiguous even if readback is corrupt"
    );
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.port.gets.load(Ordering::SeqCst), 1);
    assert!(
        fixture
            .handle
            .coordinator
            .staged_drain_candidates(FragmentDrainCandidateBatch::new(8).unwrap())
            .await
            .unwrap()
            .is_empty(),
        "hard horizon excludes another writer"
    );
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn adapter_timeout_reads_back_without_repeating_the_put() {
    let payload = payload();
    let fixture = Fixture::open(
        PutResult::Timeout,
        remote(raw_fragment(&payload), &payload),
        payload,
    )
    .await;
    assert_eq!(
        fixture.handle.drain_pass(8).await.unwrap(),
        1,
        "bounded timeout must reconcile the object already present"
    );
    assert_eq!(
        fixture.current().await.state,
        FragmentLifecycleState::Remote
    );
    assert_eq!(
        fixture.claim_state().await,
        3,
        "publication preserves ambiguity about the late provider effect"
    );
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.port.gets.load(Ordering::SeqCst), 1);
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn adapter_timeout_before_object_effect_keeps_source_and_send_barrier() {
    let fixture = Fixture::open(PutResult::Timeout, FragmentGetResponse::NotFound, payload()).await;
    assert_eq!(fixture.handle.drain_pass(8).await.unwrap(), 0);
    assert_eq!(
        fixture.current().await.state,
        FragmentLifecycleState::Staged
    );
    assert_eq!(fixture.current().await.epoch, fixture.source_epoch);
    assert_eq!(fixture.claim_state().await, 3);
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.port.gets.load(Ordering::SeqCst), 1);
    assert!(
        fixture
            .handle
            .coordinator
            .staged_drain_candidates(FragmentDrainCandidateBatch::new(8).unwrap())
            .await
            .unwrap()
            .is_empty(),
        "absent readback does not erase the late-effect horizon"
    );
    assert_eq!(fixture.handle.drain_pass(8).await.unwrap(), 0);
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn adapter_valid_bytes_with_conflicting_content_flags_cannot_replace_staged_authority() {
    let payload = payload();
    let mut conflicting = raw_fragment(&payload);
    conflicting.flags = FragmentFlags::PayloadRevisionState.bits();
    let address = Address {
        context: Context::default(),
        hash: Hash::from(blake3::hash(&payload).as_bytes().as_slice()),
    };
    PostgresImmutableStore::validate_put_candidate(
        address,
        conflicting,
        &payload,
        "valid semantic-conflict fixture",
    )
    .expect("conflicting content flags still form a valid independently decodable fragment");
    let fixture = Fixture::open(PutResult::Exists, remote(conflicting, &payload), payload).await;
    assert_eq!(fixture.handle.drain_pass(8).await.unwrap(), 0);
    assert_eq!(
        fixture.current().await.state,
        FragmentLifecycleState::Staged
    );
    assert_eq!(fixture.current().await.epoch, fixture.source_epoch);
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.port.gets.load(Ordering::SeqCst), 1);
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn adapter_corrupt_staged_source_creates_neither_claim_nor_provider_request() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    let hash = fixture.address.hash.to_string();
    let key = format!("{hash}.s{}", fixture.source_epoch);
    let path = fixture
        .root
        .join("stage/staged")
        .join(&key[..2])
        .join(&key[2..4])
        .join(&key);
    std::fs::write(path, vec![0x5a; fixture.port.body.len()]).unwrap();
    assert_eq!(fixture.handle.drain_pass(8).await.unwrap(), 0);
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 0);
    assert_eq!(fixture.port.gets.load(Ordering::SeqCst), 0);
    let claims: i64 = fixture
        .admin
        .query_one(
            "SELECT count(*) FROM lore_fragment_write_claims WHERE hash=$1",
            &[&fixture.address.hash.data().as_slice()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(claims, 0, "source validation precedes claim admission");
    let spools: i64 = fixture
        .admin
        .query_one(
            "SELECT count(*) FROM object_store_retention.object_dispatch_spool_objects",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(spools, 0, "source validation precedes spool reservation");
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn adapter_cleanup_recovers_after_finished_purge_and_scan_tasks_panic() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    let purge = lore_base::lore_spawn_blocking!(
        "test-cleanup-purge-panic",
        move || -> Result<StageCleanupIntent, StoreError> { panic!("injected purge worker panic") }
    );
    tokio::time::timeout(Duration::from_secs(3), async {
        while !purge.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("panic worker terminates");
    fixture.handle.cleanup.lock().await.purge = Some(purge);
    assert!(fixture.handle.cleanup_pass(8).await.is_err());
    assert!(
        fixture.handle.cleanup.lock().await.purge.is_none(),
        "failed completed task is consumed"
    );
    assert_eq!(
        fixture.handle.cleanup_pass(8).await.unwrap(),
        0,
        "next pass uses real SQL and filesystem without polling the failed task again"
    );

    let scan = lore_base::lore_spawn_blocking!(
        "test-cleanup-scan-panic",
        move || -> Result<Vec<StageFileCandidate>, StoreError> {
            panic!("injected scan worker panic")
        }
    );
    tokio::time::timeout(Duration::from_secs(3), async {
        while !scan.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("panic worker terminates");
    fixture.handle.cleanup.lock().await.scan = Some(scan);
    assert!(fixture.handle.cleanup_pass(8).await.is_err());
    assert!(
        fixture.handle.cleanup.lock().await.scan.is_none(),
        "failed completed scan is consumed"
    );
    assert_eq!(fixture.handle.cleanup_pass(8).await.unwrap(), 0);
    assert_eq!(
        fixture.current().await.state,
        FragmentLifecycleState::Staged,
        "cleanup never purges the readable source"
    );
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 0);
}

#[cfg(feature = "failure_generator")]
#[tokio::test]
#[ignore = "requires isolated process with publication.commit.settled=unknown and owned adapter fixture"]
async fn adapter_lost_publication_ack_rereads_exact_successor_without_another_put() {
    let fixture = Fixture::open_with_commit_loss(
        PutResult::Created,
        FragmentGetResponse::NotFound,
        payload(),
        true,
    )
    .await;
    assert_eq!(
        fixture.handle.drain_pass(8).await.unwrap(),
        1,
        "unknown commit response must resolve against the exact committed successor"
    );
    let current = fixture.current().await;
    assert_eq!(current.state, FragmentLifecycleState::Remote);
    assert!(current.epoch > fixture.source_epoch);
    assert_eq!(fixture.claim_state().await, 2);
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.port.gets.load(Ordering::SeqCst),
        0,
        "publication loss is reconciled from SQL rather than by another provider request"
    );
    assert_eq!(fixture.handle.drain_pass(8).await.unwrap(), 0);
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 1);
}

#[cfg(feature = "failure_generator")]
#[path = "fragment_write_behind_cleanup_tests.rs"]
mod cleanup_fault_tests;

#[path = "fragment_write_behind_progress_tests.rs"]
mod progress_tests;

#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn adapter_malformed_compressed_readback_is_bounded_and_preserves_staged_authority() {
    let body = payload();
    let (compressed, encoded) = lore_storage::compress(
        raw_fragment(&body),
        &body,
        lore_storage::CompressionMode::Zstd,
    )
    .unwrap();
    let mut corrupt = encoded.to_vec();
    corrupt[0] ^= 0xff;
    assert_eq!(
        corrupt.len(),
        compressed.size_payload as usize,
        "metadata length stays valid so semantic verification reaches the decoder"
    );
    let fixture = Fixture::open(PutResult::Ambiguous, remote(compressed, &corrupt), body).await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), fixture.handle.drain_pass(1))
            .await
            .expect("corrupt compressed GET must return within the bounded adapter attempt")
            .unwrap(),
        0
    );
    assert_eq!(
        fixture.current().await.state,
        FragmentLifecycleState::Staged
    );
    assert_eq!(fixture.current().await.epoch, fixture.source_epoch);
    assert_eq!(fixture.claim_state().await, 3);
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.port.gets.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.handle.drain_pass(1).await.unwrap(), 0);
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn adapter_drain_progresses_while_foreground_gets_share_the_provider_budget() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    let provider = fixture.handle.provider.clone();
    let completed = Arc::new(AtomicUsize::new(0));
    let traffic_completed = completed.clone();
    let traffic = tokio_util::task::AbortOnDropHandle::new(lore_base::lore_spawn!(async move {
        loop {
            let exchange = provider
                .get(
                    &FragmentGetAttempt {
                        logical_request_id: Uuid::now_v7().to_string(),
                        attempt_id: Uuid::now_v7().to_string(),
                        attempt_ordinal: 1,
                    },
                    &FragmentGetOperation {
                        object_key: "foreground-contention".into(),
                    },
                )
                .await;
            if exchange.is_ok() {
                traffic_completed.fetch_add(1, Ordering::SeqCst);
            }
            tokio::task::yield_now().await;
        }
    }));
    tokio::time::timeout(Duration::from_secs(5), async {
        while completed.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("foreground traffic must obtain actual budget and enter transport");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), fixture.handle.drain_pass(1))
            .await
            .expect("drain must progress before ongoing foreground traffic stops")
            .unwrap(),
        1
    );
    assert_eq!(
        fixture.current().await.state,
        FragmentLifecycleState::Remote
    );
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 1);
    assert!(fixture.port.gets.load(Ordering::SeqCst) > 0);
    assert!(completed.load(Ordering::SeqCst) > 0);
    assert!(
        !traffic.is_finished(),
        "foreground loop remains active through publication"
    );
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn adapter_stalled_put_releases_the_single_domain_connection_and_survives_task_abort() {
    let fixture = Fixture::open(PutResult::Timeout, FragmentGetResponse::NotFound, payload()).await;
    let handle = fixture.handle.clone();
    let running = lore_base::lore_spawn!(async move { handle.drain_pass(1).await });
    tokio::time::timeout(Duration::from_secs(2), async {
        while fixture.port.puts.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("provider PUT entered");
    let witness = tokio::time::timeout(Duration::from_millis(500), fixture.current())
        .await
        .expect("a stalled provider call must not retain the sole domain checkout");
    assert_eq!(witness.state, FragmentLifecycleState::Staged);
    assert_eq!(witness.epoch, fixture.source_epoch);
    running.abort();
    assert!(running.await.unwrap_err().is_cancelled());
    assert_eq!(fixture.handle.drain_pass(1).await.unwrap(), 0);
    assert_eq!(
        fixture.port.puts.load(Ordering::SeqCst),
        1,
        "cancellation preserves the sending barrier"
    );
    assert_eq!(fixture.current().await.epoch, fixture.source_epoch);
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn adapter_observer_completes_inventory_across_more_than_one_bounded_scan() {
    let body = payload();
    let expected_bytes = body.len() as u64;
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, body).await;
    let historical = fixture.root.join("stage").join("staged").join("historical");
    std::fs::create_dir_all(&historical).unwrap();
    for index in 0..4097 {
        std::fs::create_dir(historical.join(format!("{index:04x}"))).unwrap();
    }
    let first = fixture.handle.observe().await.unwrap();
    assert!(
        !first.capacity_available,
        "partial inventory cannot certify capacity"
    );
    let complete = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let observed = fixture.handle.observe().await.unwrap();
            if observed.capacity_available {
                break observed;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("resumable inventory must finish despite historical directories");
    assert_eq!(complete.pending_files, 1);
    assert_eq!(complete.stage_files, 1);
    assert_eq!(complete.stage_bytes, expected_bytes);
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 0);
}

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
use crate::domain::DomainPoolLayout;
use crate::domain::PostgresDomainStore;
use crate::pool::TlsConfig;
use crate::store::write_behind::WriteBehindSettings;
use crate::store::write_behind::WriteBehindWatermarks;

/// The observer interval the fixture's reserved connection is bounded by: the
/// server's default.
const OBSERVE_INTERVAL: Duration = Duration::from_secs(1);

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
    /// More fragments a test staged beside `body`.
    extra_bodies: Arc<std::sync::Mutex<Vec<Bytes>>>,
    /// How long each PUT stays in flight, in milliseconds.
    put_delay_ms: Arc<AtomicUsize>,
    in_flight: Arc<AtomicUsize>,
    max_in_flight: Arc<AtomicUsize>,
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
            let body = request.body().expect("a drain PUT carries a body");
            let staged = body == self.body.as_ref()
                || self
                    .extra_bodies
                    .lock()
                    .unwrap()
                    .iter()
                    .any(|extra| extra.as_ref() == body);
            assert!(
                staged,
                "transport sees exactly the validated durable source"
            );
            assert_eq!(request.blake3(), Some(blake3::hash(body).as_bytes()));
            self.puts.fetch_add(1, Ordering::SeqCst);
            let in_flight = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_in_flight.fetch_max(in_flight, Ordering::SeqCst);
            let delay = self.put_delay_ms.load(Ordering::SeqCst);
            if delay > 0 {
                tokio::time::sleep(Duration::from_millis(delay as u64)).await;
            }
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
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
    store: PostgresImmutableStore,
    stage: Arc<WriteBehindStage>,
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
        // One shared domain connection, as before, plus the observer's own.
        let domain = PostgresDomainStore::connect_with_layout(
            &url,
            2,
            &TlsConfig::default(),
            DomainPoolLayout::ReserveObserver {
                observe_interval: OBSERVE_INTERVAL,
            },
        )
        .await
        .unwrap();
        let coordinator = domain.fragment_coordinator();
        let observer = domain
            .fragment_stage_observer()
            .expect("a reserving store has a stage observer");
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
            extra_bodies: Arc::new(std::sync::Mutex::new(Vec::new())),
            put_delay_ms: Arc::new(AtomicUsize::new(0)),
            in_flight: Arc::new(AtomicUsize::new(0)),
            max_in_flight: Arc::new(AtomicUsize::new(0)),
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
            stage_io_wait: crate::store::write_behind::DEFAULT_STAGE_IO_WAIT,
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
            cancel_withdrawals: CancelWithdrawals::new(CANCEL_WITHDRAW_PERMITS),
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
                observer,
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
            store,
            stage,
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

/// Row 79: a promotion holds no domain connection across its spool reserve,
/// write and ready steps. `begin_promotion`, `authorize_write_claim` and
/// `commit_promotion` each take their own short checkout, so a promotion makes
/// three; row 77's held connection made two and sat idle through the spool
/// I/O. The pass's candidate read is the fourth.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn adapter_promotion_checks_out_separately_for_begin_authorize_and_commit() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    let before = fixture.handle.coordinator.acquired_for_test();
    assert_eq!(fixture.handle.drain_pass(8).await.unwrap(), 1);
    assert_eq!(
        fixture.handle.coordinator.acquired_for_test() - before,
        4,
        "one candidate read plus three promotion checkouts"
    );
    assert_eq!(
        fixture.current().await.state,
        FragmentLifecycleState::Remote
    );
}

impl Fixture {
    /// Stage `count` more distinct fragments beside the fixture's own, and let
    /// the port accept their bodies.
    async fn stage_more(&self, tag: &str, count: usize) -> Vec<Address> {
        let mut addresses = Vec::new();
        for ordinal in 0..count {
            let bytes = Bytes::from(format!("{tag} payload {ordinal} repeated ").repeat(512));
            let address = Address {
                context: Context::default(),
                hash: Hash::from(blake3::hash(&bytes).as_bytes().as_slice()),
            };
            self.port.extra_bodies.lock().unwrap().push(bytes.clone());
            let staged = self
                .store
                .put_staged(
                    &self.handle.coordinator,
                    &self.stage,
                    address,
                    raw_fragment(&bytes),
                    bytes,
                )
                .await
                .unwrap();
            assert_eq!(staged.state, FragmentLifecycleState::Staged);
            addresses.push(address);
        }
        addresses
    }

    async fn state_of(&self, address: Address) -> FragmentLifecycleState {
        self.handle
            .coordinator
            .capture_current_readable_epoch(address.hash.data())
            .await
            .unwrap()
            .map_or(FragmentLifecycleState::Staged, |witness| witness.state)
    }
}

/// Row 77: a pass runs at most `drain_concurrency` promotions at once, and
/// does run that many. The fixture's provider admits two PUTs at once, so a
/// bound of 1 that the pass ignored would show 2 here.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn adapter_parallel_drain_respects_its_concurrency_bound() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    fixture.port.put_delay_ms.store(300, Ordering::SeqCst);
    let first = fixture.stage_more("serial", 2).await;
    // The default is the smaller of 4 and the shared domain pool, which is
    // one connection in this fixture, so a fresh handle is serial.
    assert_eq!(fixture.handle.drain_concurrency(), 1);
    assert_eq!(fixture.handle.drain_pass(8).await.unwrap(), 3);
    assert_eq!(fixture.port.max_in_flight.load(Ordering::SeqCst), 1);

    fixture.port.max_in_flight.store(0, Ordering::SeqCst);
    let second = fixture.stage_more("parallel", 4).await;
    fixture.handle.set_drain_concurrency(2);
    assert_eq!(fixture.handle.drain_pass(8).await.unwrap(), 4);
    assert_eq!(
        fixture.port.max_in_flight.load(Ordering::SeqCst),
        2,
        "two promotions were in their PUT at once"
    );
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 7);
    for address in first.into_iter().chain(second) {
        assert_eq!(
            fixture.state_of(address).await,
            FragmentLifecycleState::Remote
        );
    }
    // Out of range is clamped, never zero.
    fixture.handle.set_drain_concurrency(0);
    assert_eq!(fixture.handle.drain_concurrency(), 1);
    fixture.handle.set_drain_concurrency(usize::MAX);
    assert_eq!(fixture.handle.drain_concurrency(), MAX_DRAIN_CONCURRENCY);
}

/// Row 77: parallel promotion never sends one fragment twice, even when two
/// passes are started at once on one handle.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn adapter_parallel_drain_promotes_each_fragment_once() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    fixture.port.put_delay_ms.store(100, Ordering::SeqCst);
    let staged = fixture.stage_more("once", 5).await;
    fixture.handle.set_drain_concurrency(4);
    let before = Instant::now();
    let (left, right) = tokio::join!(fixture.handle.drain_pass(8), fixture.handle.drain_pass(8));
    assert_eq!(left.unwrap() + right.unwrap(), 6);
    let activity = fixture.handle.activity();
    assert!(activity.drain_progress.is_some_and(|at| at >= before));
    assert!(activity.drain_loop >= activity.drain_progress);
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 6);
    assert_eq!(fixture.handle.drain_pass(8).await.unwrap(), 0);
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 6);
    for address in staged {
        assert_eq!(
            fixture.state_of(address).await,
            FragmentLifecycleState::Remote
        );
    }
    let claims: i64 = fixture
        .admin
        .query_one(
            "SELECT count(*) FROM lore_fragment_write_claims WHERE state = 2",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(claims, 6, "one decisive claim per fragment");
}

/// Row 77: under parallelism the drain still records progress only when a
/// promotion publishes (the case above checks that it does). A pass whose
/// sends all fail leaves the progress clock alone and returns 0, which is
/// what the server's `drain_not_progressing` accounting reads.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn adapter_parallel_drain_records_no_progress_when_every_send_fails() {
    let fixture = Fixture::open(
        PutResult::Ambiguous,
        FragmentGetResponse::NotFound,
        payload(),
    )
    .await;
    fixture.stage_more("failing", 3).await;
    fixture.handle.set_drain_concurrency(4);
    assert_eq!(fixture.handle.drain_pass(8).await.unwrap(), 0);
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 4);
    assert!(
        fixture.handle.activity().drain_progress.is_none(),
        "no publication, no progress"
    );
    // Each failed hash cools down; the next pass sends nothing and still
    // records no progress.
    assert_eq!(fixture.handle.state.lock().await.cooldown.len(), 4);
    assert_eq!(fixture.handle.drain_pass(8).await.unwrap(), 0);
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 4);
    assert!(fixture.handle.activity().drain_progress.is_none());
}

/// A put refused for staging I/O capacity must leave no live preparation.
/// Otherwise every retry of that hash is fenced until `prepare_ttl` runs out,
/// which turned transient capacity refusals into 30 s commit stalls live.
/// Every slot stays held here, so the put's wait budget runs out first.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn adapter_capacity_refused_put_leaves_no_preparation_that_fences_the_retry() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    let bytes = Bytes::from("capacity refused payload repeated ".repeat(512));
    let address = Address {
        context: Context::default(),
        hash: Hash::from(blake3::hash(&bytes).as_bytes().as_slice()),
    };
    let permits = std::iter::from_fn(|| {
        fixture
            .stage
            .root()
            .try_io_permit(crate::store::write_behind::StageIoPath::Put)
            .ok()
    })
    .take(64)
    .collect::<Vec<_>>();
    assert!(
        !permits.is_empty(),
        "the fixture holds every staging I/O permit"
    );
    let refused = fixture
        .store
        .put_staged(
            &fixture.handle.coordinator,
            &fixture.stage,
            address,
            raw_fragment(&bytes),
            bytes.clone(),
        )
        .await;
    assert!(
        matches!(&refused, Err(error) if error.is_slow_down()),
        "capacity refusal is retryable backpressure"
    );
    for table in [
        "lore_fragment_lifecycle",
        "lore_fragment_epochs",
        "lore_fragment_stage_custody",
    ] {
        let rows: i64 = fixture
            .admin
            .query_one(
                &format!("SELECT count(*) FROM {table} WHERE hash=$1"),
                &[&address.hash.data().as_slice()],
            )
            .await
            .unwrap()
            .get(0);
        assert_eq!(rows, 0, "a refused put writes no {table} row");
    }
    drop(permits);
    let retried = fixture
        .store
        .put_staged(
            &fixture.handle.coordinator,
            &fixture.stage,
            address,
            raw_fragment(&bytes),
            bytes,
        )
        .await
        .expect("the retry is admitted at once, not fenced by the refused attempt");
    assert_eq!(retried.state, FragmentLifecycleState::Staged);
}

/// Row 76: the observer's policy and ledger reads use the domain connection
/// reserved for it. With every shared domain connection held, `observe()`
/// still answers; before the reservation it queued behind them and missed its
/// 1 s budget.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn adapter_observe_answers_with_every_shared_domain_connection_held() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    // The fixture's shared domain pool has one connection; hold it.
    let held = fixture.handle.coordinator.checkout_for_test().await;
    let shared_checkouts = fixture.handle.coordinator.acquired_for_test();
    let observed = tokio::time::timeout(Duration::from_secs(2), fixture.handle.observe())
        .await
        .expect("observe() must not wait for the shared domain pool");
    observed.expect("observe() succeeds on its reserved connection");
    assert_eq!(
        fixture.handle.coordinator.acquired_for_test(),
        shared_checkouts,
        "observe() took no shared domain connection"
    );
    drop(held);
}

/// Row 76 review: the reserved connection cancels a statement just under the
/// observer interval, so a read the observer gave up on cannot run into the
/// next attempt. The shared pool keeps the server default.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn adapter_observer_connection_times_out_statements_inside_the_interval() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    assert_eq!(
        fixture.handle.observer.statement_timeout_for_test().await,
        "900ms"
    );
    assert_eq!(
        fixture
            .handle
            .coordinator
            .statement_timeout_for_test()
            .await,
        "0"
    );
}

/// Row 76 review: a read blocked on the server (here behind an exclusive lock
/// on the policy table) fails the observation at the statement timeout and
/// does not wedge later attempts. The attempt the observer abandons leaves its
/// read running on the one connection; the next attempt's health check finds
/// that connection busy and replaces it. Without the statement timeout and the
/// health check, every later attempt queued behind the blocked read forever.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn adapter_observe_fails_inside_its_budget_on_a_blocked_read_and_recovers() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    fixture
        .handle
        .observe()
        .await
        .expect("baseline observation");
    fixture
        .admin
        .batch_execute("BEGIN; LOCK TABLE lore_fragment_stage_policy IN ACCESS EXCLUSIVE MODE")
        .await
        .unwrap();
    let abandoned =
        tokio::time::timeout(Duration::from_millis(200), fixture.handle.observe()).await;
    assert!(abandoned.is_err(), "the policy read blocks behind the lock");
    let blocked = tokio::time::timeout(OBSERVE_INTERVAL * 2, fixture.handle.observe())
        .await
        .expect("a blocked read ends at the statement timeout, not never");
    assert!(blocked.is_err(), "a blocked read is a failed observation");
    fixture.admin.batch_execute("ROLLBACK").await.unwrap();
    tokio::time::timeout(OBSERVE_INTERVAL, fixture.handle.observe())
        .await
        .expect("observe() answers inside its budget once the lock is gone")
        .expect("observe() succeeds once the lock is gone");
}

/// Row 76 review: a terminated observer backend costs at most the attempt that
/// finds it. That attempt answers inside the budget either way, and the next
/// one succeeds on a replacement connection.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn adapter_observe_recovers_after_its_backend_is_terminated() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    let terminated_pid = fixture.handle.observer.backend_pid_for_test().await;
    let terminated: bool = fixture
        .admin
        .query_one("SELECT pg_terminate_backend($1)", &[&terminated_pid])
        .await
        .unwrap()
        .get(0);
    assert!(terminated, "the observer backend was terminated");
    let _either = tokio::time::timeout(OBSERVE_INTERVAL, fixture.handle.observe())
        .await
        .expect("the attempt that finds the dead connection answers inside the budget");
    tokio::time::timeout(OBSERVE_INTERVAL, fixture.handle.observe())
        .await
        .expect("the next attempt answers inside the budget")
        .expect("the next attempt succeeds on a replacement connection");
    assert_ne!(
        fixture.handle.observer.backend_pid_for_test().await,
        terminated_pid,
        "the dead connection was replaced"
    );
}

/// Row 76: a put that finds every staging I/O slot taken waits for one to free
/// instead of answering `SlowDown`, whose client backoff grows to 10 s.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn adapter_put_waits_for_a_staging_slot_freed_inside_its_budget() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    let bytes = Bytes::from("slot wait payload repeated ".repeat(512));
    let address = Address {
        context: Context::default(),
        hash: Hash::from(blake3::hash(&bytes).as_bytes().as_slice()),
    };
    let mut permits = std::iter::from_fn(|| {
        fixture
            .stage
            .root()
            .try_io_permit(crate::store::write_behind::StageIoPath::Put)
            .ok()
    })
    .take(64)
    .collect::<Vec<_>>();
    assert!(
        !permits.is_empty(),
        "the fixture holds every staging I/O permit"
    );
    let put = fixture.store.put_staged(
        &fixture.handle.coordinator,
        &fixture.stage,
        address,
        raw_fragment(&bytes),
        bytes.clone(),
    );
    let release = async {
        tokio::time::sleep(Duration::from_millis(200)).await;
        permits.pop();
    };
    let (staged, ()) = tokio::join!(put, release);
    let staged = staged.expect("a slot freed inside the wait budget admits the put");
    assert_eq!(staged.state, FragmentLifecycleState::Staged);
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

#[path = "fragment_write_behind_withdraw_tests.rs"]
mod withdraw_tests;

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

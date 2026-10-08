// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use lore_base::error::SlowDown;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Fragment;
use lore_base::types::Hash;
use lore_base::types::Partition;
use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::locks::VerifiedLockOwner;
use lore_postgres::domain::receipts::ReceiptKey;
use lore_postgres::pool::TlsConfig;
use lore_proto::BranchPushRequest;
use lore_revision::branch;
use lore_revision::branch::DEFAULT_HISTORY_STEP_SIZE;
use lore_revision::lore::BranchId;
use lore_revision::lore::RepositoryId;
use lore_revision::node::Node;
use lore_revision::node::NodeFlags;
use lore_revision::node::ROOT_NODE;
use lore_revision::repository;
use lore_revision::repository::RepositoryContext;
use lore_revision::state::State;
use lore_server::domain::DomainContext;
use lore_server::grpc::domain_operation_metadata::DomainOperationMetadata;
use lore_server::grpc::get_write_token;
use lore_server::grpc::handlers::branch_push::*;
use lore_server::grpc::handlers::push_lock_guard;
use lore_server::grpc::handlers::push_lock_guard::PushLockEnforcement;
use lore_server::grpc::server::RevisionListAcceleration;
use lore_server::hooks::Hook;
use lore_server::hooks::HookContext;
use lore_server::hooks::HookDispatcher;
use lore_server::hooks::HookError;
use lore_server::hooks::HookPoint;
use lore_server::lock::store::LocalLockStore;
use lore_storage::ImmutableStore;
use lore_storage::StoreError;
use lore_storage::StoreGetData;
use lore_storage::StoreMatchResult;
use lore_storage::StoreObliterateStats;
use lore_storage::hash::hash_string;
use lore_storage::local::immutable_store::ImmutableStoreSettings;
use lore_storage::local::immutable_store::LocalImmutableStore;
use lore_telemetry::InstrumentProvider;
use lore_transport::grpc::REPOSITORY_ID_KEY;
use opentelemetry::metrics::Meter;
use opentelemetry::metrics::MeterProvider as _;
use opentelemetry_sdk::metrics::InMemoryMetricExporter;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::metrics::data::AggregatedMetrics;
use opentelemetry_sdk::metrics::data::MetricData;
use rand::random;
use tokio::sync::mpsc;
use tonic::Code;
use tonic::Request;
use tonic::metadata::MetadataValue;
use tonic::transport::server::TcpConnectInfo;
use uuid::Uuid;

use crate::notification::testing::MockNotificationSender;
use crate::store::test_support::test_store_create;

// FORK-LOCAL (Tideshift): the governed (Postgres domain) push/create cases.
mod governed_tests;

struct RecordingInstrumentProvider {
    meter_provider: SdkMeterProvider,
    exporter: InMemoryMetricExporter,
}

impl RecordingInstrumentProvider {
    fn new() -> Self {
        let exporter = InMemoryMetricExporter::default();
        let meter_provider = SdkMeterProvider::builder()
            .with_periodic_exporter(exporter.clone())
            .build();
        Self {
            meter_provider,
            exporter,
        }
    }

    fn counter_value(&self, name: &str) -> u64 {
        self.meter_provider
            .force_flush()
            .expect("metric flush should succeed");
        let expected_name = format!("{}.{}", self.namespace(), name);
        let values: Vec<u64> = self
            .exporter
            .get_finished_metrics()
            .expect("metrics should be exported")
            .iter()
            .flat_map(|resource| resource.scope_metrics())
            .flat_map(|scope| scope.metrics())
            .filter(|metric| metric.name() == expected_name)
            .map(|metric| match metric.data() {
                AggregatedMetrics::U64(MetricData::Sum(sum)) => {
                    sum.data_points().map(|point| point.value()).sum()
                }
                data => panic!("expected u64 sum metric, got {data:?}"),
            })
            .collect();
        assert_eq!(
            values.len(),
            1,
            "expected exactly one exported {expected_name} metric"
        );
        values[0]
    }
}

#[tokio::test]
#[ignore = "run with lore-postgres/tests/run-lock-fencing-live.ps1"]
async fn real_witness_capture_precedes_both_cr019_bypass_conditions() {
    let url = std::env::var("LORE_TEST_PG_URL")
        .expect("the checked-in live runner must provide PostgreSQL");
    let store = Arc::new(
        PostgresDomainStore::connect(&url, 2, &TlsConfig::default())
            .await
            .expect("connect domain store"),
    );
    let coordinator = Arc::new(store.lock_coordinator());
    coordinator
        .bootstrap()
        .await
        .expect("install isolated SCHEMA-117 fixture");

    let (direct, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .expect("connect direct fixture client");
    lore_base::lore_spawn!(async move {
        if let Err(error) = connection.await {
            eprintln!("push witness fixture connection error: {error}");
        }
    });
    let repository_id: RepositoryId = random();
    let branch_id: BranchId = random();
    let repository_bytes = repository_id.as_ref().to_vec();
    let branch_bytes = branch_id.as_ref().to_vec();
    let hash = random::<[u8; 32]>().to_vec();
    direct.execute(
        "INSERT INTO lore_domain_repositories(repository_id,state,generation,name,metadata_hash,default_branch_id,creation_fingerprint_version,creation_fingerprint,created_at) VALUES($1,0,1,'witness-fixture',$2,$3,1,$4,clock_timestamp())",
        &[&repository_bytes, &hash, &branch_bytes, &hash],
    ).await.expect("insert repository fixture");
    direct.execute(
        "INSERT INTO lore_domain_branches(repository_id,branch_id,repository_generation,state,generation,name,metadata_hash,latest_hash,creation_fingerprint_version,creation_fingerprint,created_at) VALUES($1,$2,1,0,1,'main',$3,$3,1,$3,clock_timestamp())",
        &[&repository_bytes, &branch_bytes, &hash],
    ).await.expect("insert branch fixture and namespace");

    let context = Arc::new(DomainContext::new_with_lock_coordinator(
        store,
        false,
        coordinator.clone(),
    ));

    // CR-019 disabled: a missing namespace remains observable before the
    // admitted-none legacy return. Moving capture below that return would
    // make this incorrectly succeed with None.
    let missing_branch: BranchId = random();
    let disabled = prepare_governed_push(
        Some(&context),
        None,
        repository_id,
        missing_branch,
        random(),
        false,
        false,
    )
    .await;
    let disabled = match disabled {
        Err(status) => status,
        Ok(_) => panic!("missing namespace must fail before the CR-019-disabled bypass"),
    };
    assert_eq!(disabled.code(), Code::FailedPrecondition);

    // Capture a concrete witness, then drive the real CR-019 no-foreign-
    // locks guard. The bogus revision and absent local branch would fail
    // if that guard tried to diff instead of taking its early return.
    let operation_id = Uuid::now_v7();
    let admitted = lore_server::domain::AdmittedOperation {
        key: ReceiptKey {
            verified_issuer: "https://issuer.example".to_owned(),
            authenticated_subject: "wp117-pusher".to_owned(),
            tenant_scope_key: vec![7; 16],
            operation_id,
        },
        source: lore_server::domain::AdmissionSource::Carried(Box::new(DomainOperationMetadata {
            operation_id,
            fingerprint_version: 1,
            fingerprint: vec![8; 32],
            prepare_token: [9; 32],
            mediated_scope: None,
            claim_witness: None,
        })),
    };
    let governed = prepare_governed_push(
        Some(&context),
        Some(admitted),
        repository_id,
        branch_id,
        random(),
        false,
        false,
    )
    .await
    .expect("capture before CR-019 empty-query return")
    .expect("admitted push carries its witness");
    assert_eq!(governed.lock_witness.repository_lock_generation, 1);
    assert_eq!(governed.lock_witness.branch_lock_generation, 1);
    assert_eq!(
        governed
            .lock_witness
            .branch_lock_namespace_last_applied_fence,
        0
    );

    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("create CR-019 stores");
    let repository = Arc::new(RepositoryContext::new_server_context(
        immutable_store,
        mutable_store,
        repository_id,
    ));
    let enforcement = PushLockEnforcement {
        lock_store: Arc::new(LocalLockStore::default()),
        issuer_policy: push_lock_guard::LockOwnerIssuerPolicy::Pinned(
            "https://issuer.example".to_owned(),
        ),
    };
    let pusher = VerifiedLockOwner {
        verified_issuer: "https://issuer.example".to_owned(),
        authenticated_subject: "wp117-pusher".to_owned(),
    };
    let bogus_revision = Hash::hash_buffer(b"never serialized for wp117 bypass fixture");
    Box::pin(LORE_CONTEXT.scope(execution, async move {
        push_lock_guard::enforce_push_locks(
            repository,
            &enforcement,
            branch_id,
            bogus_revision,
            &pusher,
        )
        .await
        .expect("real CR-019 empty-lock guard must take its early return");
    }))
    .await;
}

impl InstrumentProvider for RecordingInstrumentProvider {
    fn namespace(&self) -> &'static str {
        "test"
    }

    fn meter(&self) -> Meter {
        self.meter_provider.meter(self.namespace())
    }
}

struct RecordingPostHook {
    sender: mpsc::UnboundedSender<()>,
}

#[async_trait]
impl Hook for RecordingPostHook {
    fn name(&self) -> &'static str {
        "recording-post"
    }

    fn hook_points(&self) -> &'static [HookPoint] {
        &[HookPoint::BranchPush]
    }

    async fn post_handler(&self, _ctx: &HookContext) -> Result<(), HookError> {
        self.sender
            .send(())
            .expect("post-hook observation receiver dropped");
        Ok(())
    }
}

async fn create_root_branch(repository_context: &Arc<RepositoryContext>, name: &str) -> BranchId {
    let write_token = get_write_token();
    lore_revision::branch::create(
        repository_context.clone(),
        &write_token,
        BranchId::from(uuid::Uuid::now_v7()),
        name,
        branch::default_category(),
        "test-creator",
        1,
        vec![],
        false,
        false,
    )
    .await
    .expect("Could not create root branch")
}

async fn build_revision(repository_context: &Arc<RepositoryContext>) -> Hash {
    let state = State::new();
    state.set_revision_number(1);
    state
        .serialize(repository_context.clone(), &get_write_token())
        .await
        .expect("Failed to serialize state")
}

fn make_request(
    repository: RepositoryId,
    branch: BranchId,
    revision: Hash,
) -> Request<BranchPushRequest> {
    let mut request = Request::new(BranchPushRequest {
        branch: branch.into(),
        revision: revision.into(),
        force: false,
        fast_forward_merge: false,
    });
    request.metadata_mut().insert_bin(
        REPOSITORY_ID_KEY,
        tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()),
    );
    request
}

#[tokio::test]
#[ignore = "needs disposable live Postgres via LORE_TEST_PG_URL; run with -- --ignored --test-threads=1"]
async fn enforcing_cell_rejects_before_legacy_branch_push_body() {
    let Some(domain) = lore_server::domain::test_support::configured_enforcing_context().await
    else {
        panic!("LORE_TEST_PG_URL must be set; a skipped live case is NOT RUN, never a pass");
    };
    let repository = random::<RepositoryId>();
    let (immutable_store, mutable_store, _) = test_store_create().await.expect("test stores");
    let notification = Arc::new(MockNotificationSender::new());
    let hooks = HookDispatcher::empty();
    let instruments = RecordingInstrumentProvider::new();
    let error = handler(
        make_request(repository, BranchId::default(), Hash::default()),
        immutable_store,
        mutable_store,
        notification,
        &hooks,
        DEFAULT_HISTORY_STEP_SIZE,
        RevisionListAcceleration::default(),
        &instruments,
        None,
        Some(&domain),
    )
    .await
    .expect_err("enforcement must reject missing operation carriage at entry");
    assert_eq!(error.code(), Code::InvalidArgument);
}

async fn create_test_branch(repository: &Arc<RepositoryContext>) -> BranchId {
    let branch_id = BranchId::from(uuid::Uuid::now_v7());
    let write_token = get_write_token();
    branch::create(
        repository.clone(),
        &write_token,
        branch_id,
        "test-branch",
        branch::default_category(),
        "creator",
        1,
        vec![],
        false,
        false,
    )
    .await
    .expect("create branch");
    branch_id
}

async fn serialize_revision(
    repository: &Arc<RepositoryContext>,
    branch: BranchId,
    parent_self: Hash,
    parent_other: Hash,
    revision_number: u64,
) -> Arc<State> {
    let write_token = get_write_token();
    let mut metadata = lore_revision::metadata::Metadata::new();
    metadata.set_branch(branch).expect("set branch");
    let metadata_hash = metadata
        .serialize(repository.clone())
        .await
        .expect("serialize metadata");

    let state = State::new();
    state.set_parent_self(parent_self);
    if !parent_other.is_zero() {
        state.set_parent_other(parent_other);
    }
    state.set_revision_number(revision_number);
    state.set_metadata_hash(metadata_hash);
    state
        .serialize(repository.clone(), &write_token)
        .await
        .expect("serialize state");
    state
}

/// A revision whose metadata names `payload`, so the walk collects an address
/// it never reads.
async fn serialize_revision_naming_a_payload(
    repository: &Arc<RepositoryContext>,
    branch: BranchId,
    payload: Address,
) -> Arc<State> {
    let write_token = get_write_token();
    let mut metadata = lore_revision::metadata::Metadata::new();
    metadata.set_branch(branch).expect("set branch");
    metadata
        .set_address("build-artifact", payload)
        .expect("set the payload address");
    let metadata_hash = metadata
        .serialize(repository.clone())
        .await
        .expect("serialize metadata");

    let state = State::new();
    state.set_parent_self(Hash::default());
    state.set_revision_number(1);
    state.set_metadata_hash(metadata_hash);
    state
        .serialize(repository.clone(), &write_token)
        .await
        .expect("serialize state");
    state
}

/// A revision holding one file, so its state references node and name
/// fragments the walk has to read.
async fn serialize_revision_with_a_file(
    repository: &Arc<RepositoryContext>,
    branch: BranchId,
) -> Arc<State> {
    let write_token = get_write_token();
    let mut metadata = lore_revision::metadata::Metadata::new();
    metadata.set_branch(branch).expect("set branch");
    let metadata_hash = metadata
        .serialize(repository.clone())
        .await
        .expect("serialize metadata");

    let state = State::new();
    state.set_parent_self(Hash::default());
    state.set_revision_number(1);
    state.set_metadata_hash(metadata_hash);
    state
        .node_add(
            repository.clone(),
            ROOT_NODE,
            Node {
                flags: NodeFlags::File.bits(),
                name_hash: lore_storage::hash::hash_string("file.txt"),
                ..Default::default()
            },
            "file.txt",
        )
        .await
        .expect("node_add");
    state
        .serialize(repository.clone(), &write_token)
        .await
        .expect("serialize state");
    state
}

/// Copy the fragment at `hash` alone, leaving everything it references absent
/// in `target`.
async fn hand_over_fragment(
    source: &Arc<dyn lore_storage::ImmutableStore>,
    target: &Arc<dyn lore_storage::ImmutableStore>,
    repository: RepositoryId,
    hash: Hash,
) {
    let address = Address::zero_context_hash(hash);
    let data = source
        .clone()
        .get(repository, address)
        .await
        .expect("read the fragment to hand over");
    target
        .clone()
        .put(repository, address, data.fragment, data.payload, false)
        .await
        .expect("hand over the fragment");
}

/// Push revisions `numbers`, chained from `parent`. Returns the pushed
/// signatures oldest-first.
async fn push_linear_revisions(
    repository: &Arc<RepositoryContext>,
    branch: BranchId,
    parent: Hash,
    numbers: std::ops::RangeInclusive<u64>,
) -> Vec<Hash> {
    let mut parent = parent;
    let mut signatures = Vec::new();
    for number in numbers {
        let state = serialize_revision(repository, branch, parent, Hash::default(), number).await;
        parent = push(
            repository.clone(),
            branch,
            state.revision(),
            true,
            true,
            false,
            DEFAULT_HISTORY_STEP_SIZE,
            RevisionListAcceleration::default(),
        )
        .await
        .expect("push revision")
        .revision;
        signatures.push(parent);
    }
    signatures
}

/// Push a merge revision whose `parent_other` carries a much higher
/// revision number, so the branch's revision number jumps to
/// `other_revision_number + 1` and skips the numbers in between.
async fn push_jump_revision(
    repository: &Arc<RepositoryContext>,
    branch: BranchId,
    parent: Hash,
    other_revision_number: u64,
) -> (Hash, u64) {
    let other = serialize_revision(
        repository,
        branch,
        Hash::default(),
        Hash::default(),
        other_revision_number,
    )
    .await;
    let state = serialize_revision(
        repository,
        branch,
        parent,
        other.revision(),
        0, /* rewritten */
    )
    .await;

    let result = push(
        repository.clone(),
        branch,
        state.revision(),
        true,
        true,
        false,
        DEFAULT_HISTORY_STEP_SIZE,
        RevisionListAcceleration::default(),
    )
    .await
    .expect("push jump revision");
    (result.revision, result.revision_number)
}

/// Read the revision sealed at `boundary`, or `None` when unsealed.
async fn load_step_key(
    repository: &Arc<RepositoryContext>,
    branch: BranchId,
    boundary: u64,
) -> Option<Hash> {
    let (key, key_type) = branch::revision_step_key(
        repository::SALT_LORE,
        repository.id,
        branch,
        boundary,
        DEFAULT_HISTORY_STEP_SIZE,
    );
    repository
        .clone()
        .read_mutable_store()
        .load(repository.id, key, key_type)
        .await
        .ok()
        .filter(|revision| !revision.is_zero())
}

mod extract_client_ip {
    use super::*;

    #[test]
    fn use_x_forwarded_when_available() {
        let mut req = Request::new(());

        let xff_metadata_value: MetadataValue<_> = "10.0.0.1, 10.0.0.2".parse().unwrap();
        req.metadata_mut()
            .insert("x-forwarded-for", xff_metadata_value);

        // set remote address to make sure it's NOT used in presence of the XFF header
        let peer_addr = SocketAddr::from(([192, 168, 1, 42], 4242));
        req.extensions_mut().insert(TcpConnectInfo {
            local_addr: None,
            remote_addr: Some(peer_addr),
        });

        assert_eq!(
            extract_client_ip(&req),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
        );
    }

    #[test]
    fn dont_use_xff_when_it_contains_invalid_value() {
        let mut req = Request::new(());

        let xff_metadata_value: MetadataValue<_> = "10.0.0.lol, 10.0.0.wat".parse().unwrap();
        req.metadata_mut()
            .insert("x-forwarded-for", xff_metadata_value);

        let peer_addr = SocketAddr::from(([192, 168, 1, 42], 4242));
        req.extensions_mut().insert(TcpConnectInfo {
            local_addr: None,
            remote_addr: Some(peer_addr),
        });

        assert_eq!(
            extract_client_ip(&req),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)))
        );
    }

    #[test]
    fn still_uses_last_ip_when_xff_contains_invalid_value_in_chain() {
        let mut req = Request::new(());

        let xff_metadata_value: MetadataValue<_> =
            "10.0.0.lol, 10.0.0.wat, 10.0.0.42".parse().unwrap();
        req.metadata_mut()
            .insert("x-forwarded-for", xff_metadata_value);

        let peer_addr = SocketAddr::from(([192, 168, 1, 42], 4242));
        req.extensions_mut().insert(TcpConnectInfo {
            local_addr: None,
            remote_addr: Some(peer_addr),
        });

        assert_eq!(
            extract_client_ip(&req),
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 42)))
        );
    }

    #[test]
    fn fallback_to_remote_addr() {
        let mut req = Request::new(());

        let peer_addr = SocketAddr::from(([192, 168, 1, 42], 31415));
        req.extensions_mut().insert(TcpConnectInfo {
            local_addr: None,
            remote_addr: Some(peer_addr),
        });

        assert_eq!(
            extract_client_ip(&req),
            Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)))
        );
    }
}

mod push {
    use super::*;

    #[tokio::test]
    async fn push_unknown_revision_returns_not_found() {
        let repository_id = random::<RepositoryId>();
        let branch_id = BranchId::from(uuid::Uuid::now_v7());

        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution.clone(), async move {
            let repository_context = Arc::new(RepositoryContext::new_server_context(
                immutable_store,
                mutable_store,
                repository_id,
            ));

            let write_token = get_write_token();
            branch::create(
                repository_context.clone(),
                &write_token,
                branch_id,
                "test-branch",
                branch::personal_category(),
                "test-creator",
                1,
                vec![],
                false,
                false,
            )
            .await
            .expect("Failed to create branch");

            // A hash with no corresponding state data in the immutable store
            let nonexistent_revision = random::<Hash>();

            let result = push(
                repository_context,
                branch_id,
                nonexistent_revision,
                true,
                true,
                false,
                DEFAULT_HISTORY_STEP_SIZE,
                RevisionListAcceleration::default(),
            )
            .await;

            let Err(status) = result else {
                panic!("an unknown revision cannot be pushed");
            };
            assert_eq!(status.code(), Code::NotFound);
            let error = lore_transport::ProtocolError::from(status);
            assert!(error.is_not_found(), "{error:?}");
        }))
        .await;
    }

    /// A fragment the walk cannot read is named as an address the caller
    /// reconstructs. Both detections share a code, so the message is what
    /// pins which one this reaches.
    #[tokio::test]
    async fn a_fragment_the_walk_cannot_read_names_its_address() {
        let repository_id = random::<RepositoryId>();

        let (peer_store, peer_mutable, execution) =
            test_store_create().await.expect("Failed to create stores");
        let (store, mutable_store, _) = test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let peer = Arc::new(RepositoryContext::new_server_context(
                peer_store.clone(),
                peer_mutable,
                repository_id,
            ));
            let repository = Arc::new(RepositoryContext::new_server_context(
                store.clone(),
                mutable_store,
                repository_id,
            ));

            let branch = create_test_branch(&repository).await;
            let state = serialize_revision_with_a_file(&peer, branch).await;

            hand_over_fragment(&peer_store, &store, repository_id, state.revision()).await;

            let Err(status) = push(
                repository,
                branch,
                state.revision(),
                true,
                true,
                false,
                DEFAULT_HISTORY_STEP_SIZE,
                RevisionListAcceleration::default(),
            )
            .await
            else {
                panic!("a revision missing its fragments cannot be pushed");
            };

            assert_eq!(status.code(), Code::FailedPrecondition);
            assert!(
                status
                    .message()
                    .starts_with("Failed to collect new fragments"),
                "{}",
                status.message()
            );
            let error = lore_transport::ProtocolError::from(status);
            assert!(error.is_address_not_found(), "{error:?}");
        }))
        .await;
    }

    /// A fragment the store answers as absent is named the same way, so the
    /// two paths that detect it report one condition.
    ///
    /// The revision and the blob holding its metadata are both handed over,
    /// since the walk reads both. What stays absent is the payload that
    /// metadata names, which the walk collects without reading, so the store
    /// query is what detects it.
    #[tokio::test]
    async fn a_fragment_the_store_reports_absent_names_its_address() {
        let repository_id = random::<RepositoryId>();

        let (peer_store, peer_mutable, execution) =
            test_store_create().await.expect("Failed to create stores");
        let (store, mutable_store, _) = test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let peer = Arc::new(RepositoryContext::new_server_context(
                peer_store.clone(),
                peer_mutable,
                repository_id,
            ));
            let repository = Arc::new(RepositoryContext::new_server_context(
                store.clone(),
                mutable_store,
                repository_id,
            ));

            let branch = create_test_branch(&repository).await;
            let payload = Address::zero_context_hash(Hash::from([0xabu8; 32]));
            let state = serialize_revision_naming_a_payload(&peer, branch, payload).await;
            hand_over_fragment(&peer_store, &store, repository_id, state.revision()).await;
            hand_over_fragment(&peer_store, &store, repository_id, state.metadata_hash()).await;

            let Err(status) = push(
                repository,
                branch,
                state.revision(),
                true,
                true,
                false,
                DEFAULT_HISTORY_STEP_SIZE,
                RevisionListAcceleration::default(),
            )
            .await
            else {
                panic!("a revision missing a payload its metadata names cannot be pushed");
            };

            assert_eq!(status.code(), Code::FailedPrecondition);
            assert_eq!(
                status.message(),
                format!("Missing fragment '{payload}'"),
                "the absent payload has to be the fragment named"
            );
            let error = lore_transport::ProtocolError::from(status);
            assert!(error.is_address_not_found(), "{error:?}");
        }))
        .await;
    }

    /// A merge whose second parent the store cannot answer for is refused as the
    /// missing fragment it is.
    ///
    /// The merge and the blob holding its metadata are handed over, so what stays
    /// absent is the line the merge joins. That parent carries what the merge is
    /// verified against, so it is read rather than only queried, and the read has to
    /// report the address as a missing fragment like the query does.
    #[tokio::test]
    async fn a_merge_missing_its_other_parent_names_that_address() {
        let repository_id = random::<RepositoryId>();

        let (peer_store, peer_mutable, execution) =
            test_store_create().await.expect("Failed to create stores");
        let (store, mutable_store, _) = test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let peer = Arc::new(RepositoryContext::new_server_context(
                peer_store.clone(),
                peer_mutable,
                repository_id,
            ));
            let repository = Arc::new(RepositoryContext::new_server_context(
                store.clone(),
                mutable_store,
                repository_id,
            ));

            let branch = create_test_branch(&repository).await;
            let other =
                serialize_revision(&peer, branch, Hash::default(), Hash::default(), 1).await;
            let merge =
                serialize_revision(&peer, branch, Hash::default(), other.revision(), 2).await;

            hand_over_fragment(&peer_store, &store, repository_id, merge.revision()).await;
            hand_over_fragment(&peer_store, &store, repository_id, merge.metadata_hash()).await;

            let Err(status) = push(
                repository,
                branch,
                merge.revision(),
                true,
                true,
                false,
                DEFAULT_HISTORY_STEP_SIZE,
                RevisionListAcceleration::default(),
            )
            .await
            else {
                panic!("a merge missing the line it joins cannot be pushed");
            };

            assert_eq!(status.code(), Code::FailedPrecondition);
            assert_eq!(
                status.message(),
                format!(
                    "Missing fragment '{}'",
                    Address::zero_context_hash(other.revision())
                ),
                "the absent parent has to be the fragment named"
            );
            let error = lore_transport::ProtocolError::from(status);
            assert!(error.is_address_not_found(), "{error:?}");
        }))
        .await;
    }

    /// A merge is verified against its second parent as well as its first, so a
    /// second parent the store cannot walk refuses the push.
    ///
    /// That parent and the blob holding its metadata are handed over, leaving the tree
    /// it names absent. The merge itself holds no file, so collecting it against its
    /// first parent reads nothing of that tree: what reaches it is the collection
    /// against the second parent, which is the one this covers.
    #[tokio::test]
    async fn a_merge_is_verified_against_the_tree_of_its_other_parent() {
        let repository_id = random::<RepositoryId>();

        let (peer_store, peer_mutable, execution) =
            test_store_create().await.expect("Failed to create stores");
        let (store, mutable_store, _) = test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let peer = Arc::new(RepositoryContext::new_server_context(
                peer_store.clone(),
                peer_mutable,
                repository_id,
            ));
            let repository = Arc::new(RepositoryContext::new_server_context(
                store.clone(),
                mutable_store,
                repository_id,
            ));

            let branch = create_test_branch(&repository).await;
            let other = serialize_revision_with_a_file(&peer, branch).await;
            let merge =
                serialize_revision(&peer, branch, Hash::default(), other.revision(), 2).await;

            for hash in [
                merge.revision(),
                merge.metadata_hash(),
                other.revision(),
                other.metadata_hash(),
            ] {
                hand_over_fragment(&peer_store, &store, repository_id, hash).await;
            }

            let Err(status) = push(
                repository,
                branch,
                merge.revision(),
                true,
                true,
                false,
                DEFAULT_HISTORY_STEP_SIZE,
                RevisionListAcceleration::default(),
            )
            .await
            else {
                panic!("a merge whose other parent cannot be walked cannot be pushed");
            };

            assert_eq!(status.code(), Code::FailedPrecondition);
            assert!(
                status
                    .message()
                    .starts_with("Failed to collect new fragments"),
                "{}",
                status.message()
            );
            let error = lore_transport::ProtocolError::from(status);
            assert!(error.is_address_not_found(), "{error:?}");
        }))
        .await;
    }

    #[tokio::test]
    async fn linear_history_seals_a_boundary_only_once_the_head_moves_past_it() {
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let repository = Arc::new(RepositoryContext::new_server_context(
                immutable_store,
                mutable_store,
                random::<RepositoryId>(),
            ));
            let branch = create_test_branch(&repository).await;

            let chain = push_linear_revisions(&repository, branch, Hash::default(), 1..=100).await;

            // Revision 100 is the head, so segment 100 is still the open one.
            assert_eq!(load_step_key(&repository, branch, 100).await, None);

            push_linear_revisions(&repository, branch, chain[99], 101..=101).await;

            // Now the head has moved past 100, sealing it with revision 100.
            assert_eq!(
                load_step_key(&repository, branch, 100).await,
                Some(chain[99])
            );
            // Nothing above the head may be sealed.
            assert_eq!(load_step_key(&repository, branch, 200).await, None);
        }))
        .await;
    }

    #[tokio::test]
    async fn linear_history_seals_each_boundary_with_its_own_highest_revision() {
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let repository = Arc::new(RepositoryContext::new_server_context(
                immutable_store,
                mutable_store,
                random::<RepositoryId>(),
            ));
            let branch = create_test_branch(&repository).await;

            let chain = push_linear_revisions(&repository, branch, Hash::default(), 1..=250).await;

            assert_eq!(
                load_step_key(&repository, branch, 100).await,
                Some(chain[99])
            );
            assert_eq!(
                load_step_key(&repository, branch, 200).await,
                Some(chain[199])
            );
            // Segment 300 holds the head at 250 and stays open.
            assert_eq!(load_step_key(&repository, branch, 300).await, None);
        }))
        .await;
    }

    /// A jump seals the boundaries between the two revisions and no
    /// others. The segment the new revision lands in stays open, since the
    /// revisions above it do not exist yet.
    #[tokio::test]
    async fn jump_seals_the_crossed_boundary_and_not_the_one_it_landed_in() {
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let repository = Arc::new(RepositoryContext::new_server_context(
                immutable_store,
                mutable_store,
                random::<RepositoryId>(),
            ));
            let branch = create_test_branch(&repository).await;

            let chain = push_linear_revisions(&repository, branch, Hash::default(), 1..=99).await;
            let (_, revision_number) =
                push_jump_revision(&repository, branch, chain[98], 104).await;
            assert_eq!(revision_number, 105);

            // Boundary 100 is the only one crossed, answered by revision 99.
            assert_eq!(
                load_step_key(&repository, branch, 100).await,
                Some(chain[98])
            );
            // Segment 200 contains the new head at 105 and is still open.
            assert_eq!(load_step_key(&repository, branch, 200).await, None);
            assert_eq!(load_step_key(&repository, branch, 300).await, None);
        }))
        .await;
    }

    #[tokio::test]
    async fn jump_seals_every_boundary_it_skipped_over() {
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution, async move {
            let repository = Arc::new(RepositoryContext::new_server_context(
                immutable_store,
                mutable_store,
                random::<RepositoryId>(),
            ));
            let branch = create_test_branch(&repository).await;

            let chain = push_linear_revisions(&repository, branch, Hash::default(), 1..=150).await;
            assert_eq!(
                load_step_key(&repository, branch, 100).await,
                Some(chain[99])
            );

            let (_, revision_number) =
                push_jump_revision(&repository, branch, chain[149], 399).await;
            assert_eq!(revision_number, 400);

            // 150 -> 400 skips 200 and 300; both are answered by revision 150,
            // the highest revision numbered at or below them.
            assert_eq!(
                load_step_key(&repository, branch, 200).await,
                Some(chain[149])
            );
            assert_eq!(
                load_step_key(&repository, branch, 300).await,
                Some(chain[149])
            );
            // The boundary already sealed before the jump is left alone.
            assert_eq!(
                load_step_key(&repository, branch, 100).await,
                Some(chain[99])
            );
            // Segment 400 holds the new head, and 500 was never reached.
            assert_eq!(load_step_key(&repository, branch, 400).await, None);
            assert_eq!(load_step_key(&repository, branch, 500).await, None);
        }))
        .await;
    }
}

#[tokio::test]
async fn no_op_push_does_not_repeat_notification_or_post_hook() {
    let repository = random::<RepositoryId>();
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");

    let (notification_tx, mut notification_rx) = mpsc::unbounded_channel();
    let notification_observer = notification_tx.clone();
    let mut notification_sender = MockNotificationSender::new();
    notification_sender
        .expect_branch_pushed()
        .times(1)
        .returning(move |_, _, _, _, _| {
            notification_observer
                .send(())
                .expect("notification observation receiver dropped");
        });
    let notification_sender = Arc::new(notification_sender);
    let instrument_provider = RecordingInstrumentProvider::new();

    Box::pin(LORE_CONTEXT.scope(execution.clone(), async move {
        let repository_context = Arc::new(RepositoryContext::new_server_context(
            immutable_store.clone(),
            mutable_store.clone(),
            repository,
        ));
        let main = create_root_branch(&repository_context, "main").await;
        let revision = build_revision(&repository_context).await;

        let (hook_tx, mut hook_rx) = mpsc::unbounded_channel();
        let hook_dispatcher = HookDispatcher::from_hooks_default(vec![(
            "recording-post".to_string(),
            Box::new(RecordingPostHook { sender: hook_tx }),
        )]);

        let first = handler(
            make_request(repository, main, revision),
            immutable_store.clone(),
            mutable_store.clone(),
            notification_sender.clone(),
            &hook_dispatcher,
            DEFAULT_HISTORY_STEP_SIZE,
            lore_server::grpc::server::RevisionListAcceleration::default(),
            &instrument_provider,
            None,
            None,
        )
        .await
        .expect("first push should succeed");
        assert!(first.into_inner().success);
        notification_rx
            .recv()
            .await
            .expect("advancing push should publish a notification");
        hook_rx
            .recv()
            .await
            .expect("advancing push should dispatch a post-hook");

        let repeated = handler(
            make_request(repository, main, revision),
            immutable_store.clone(),
            mutable_store.clone(),
            notification_sender.clone(),
            &hook_dispatcher,
            DEFAULT_HISTORY_STEP_SIZE,
            lore_server::grpc::server::RevisionListAcceleration::default(),
            &instrument_provider,
            None,
            None,
        )
        .await
        .expect("no-op re-push should succeed");
        assert!(repeated.into_inner().success);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), notification_rx.recv())
                .await
                .is_err(),
            "no-op re-push published a notification"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(100), hook_rx.recv())
                .await
                .is_err(),
            "no-op re-push dispatched a post-hook"
        );
        assert_eq!(
            instrument_provider.counter_value("num_branches_pushed"),
            1,
            "only the advancing push should increment num_branches_pushed"
        );
        drop(notification_tx);
    }))
    .await;
}

/// Wraps a real, in-memory `LocalImmutableStore` and, once armed, returns
/// `StoreError::SlowDown` from every `query()` call. Delegates everything
/// else straight through, so a repository's states can be built normally
/// before the fault is armed. Mirrors the fixture pattern in
/// `lore-revision/tests/state.rs`.
struct SlowDownQueryStore {
    inner: Arc<LocalImmutableStore>,
    armed: AtomicBool,
}

impl SlowDownQueryStore {
    fn wrapping(inner: Arc<LocalImmutableStore>) -> Arc<Self> {
        Arc::new(Self {
            inner,
            armed: AtomicBool::new(false),
        })
    }

    fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }
}

#[async_trait]
impl ImmutableStore for SlowDownQueryStore {
    async fn query(
        self: Arc<Self>,
        partition: Partition,
        addresses: &[Address],
        results: &mut [StoreMatchResult],
    ) -> Result<(), StoreError> {
        if self.armed.load(Ordering::SeqCst) {
            return Err(StoreError::from(SlowDown));
        }
        self.inner
            .clone()
            .query(partition, addresses, results)
            .await
    }

    async fn get_metadata(
        self: Arc<Self>,
        partition: Partition,
        address: Address,
    ) -> Result<StoreGetData, StoreError> {
        self.inner.clone().get_metadata(partition, address).await
    }

    async fn get(
        self: Arc<Self>,
        partition: Partition,
        address: Address,
    ) -> Result<StoreGetData, StoreError> {
        self.inner.clone().get(partition, address).await
    }

    async fn put(
        self: Arc<Self>,
        partition: Partition,
        address: Address,
        fragment: Fragment,
        payload: Option<Bytes>,
        force: bool,
    ) -> Result<(), StoreError> {
        self.inner
            .clone()
            .put(partition, address, fragment, payload, force)
            .await
    }

    async fn obliterate(
        self: Arc<Self>,
        partition: Partition,
        address: Address,
        stats: Arc<StoreObliterateStats>,
    ) -> Result<(), StoreError> {
        self.inner
            .clone()
            .obliterate(partition, address, stats)
            .await
    }

    async fn evict(
        self: Arc<Self>,
        max_capacity: usize,
        sync_data: bool,
        sink: Option<lore_storage::gc_event::GcEventSinkRef>,
    ) -> Result<usize, StoreError> {
        self.inner
            .clone()
            .evict(max_capacity, sync_data, sink)
            .await
    }

    async fn compact(
        self: Arc<Self>,
        max_size: usize,
        at: Option<usize>,
        sync_data: bool,
        sink: Option<lore_storage::gc_event::GcEventSinkRef>,
    ) -> Result<Option<usize>, StoreError> {
        self.inner
            .clone()
            .compact(max_size, at, sync_data, sink)
            .await
    }

    async fn compact_resume_at(self: Arc<Self>) -> Option<usize> {
        self.inner.clone().compact_resume_at().await
    }

    async fn stop_gc(self: Arc<Self>, terminate: bool) {
        self.inner.clone().stop_gc(terminate).await;
    }

    fn max_query_batch(&self) -> Option<usize> {
        self.inner.max_query_batch()
    }

    async fn flush(self: Arc<Self>, sync_data: bool) -> Result<(), StoreError> {
        self.inner.clone().flush(sync_data).await
    }

    async fn verify(self: Arc<Self>, heal: bool) -> Result<(), StoreError> {
        self.inner.clone().verify(heal).await
    }

    async fn copy(
        self: Arc<Self>,
        source_partition: Partition,
        source_address: Address,
        destination_partition: Partition,
        destination_context: Context,
        durable: bool,
    ) -> Result<(), StoreError> {
        self.inner
            .clone()
            .copy(
                source_partition,
                source_address,
                destination_partition,
                destination_context,
                durable,
            )
            .await
    }
}

#[tokio::test]
async fn verify_fragments_maps_slow_down_to_resource_exhausted() {
    // Reproduces the mismatch this CR fixed: without `.filter_slow_down()?`
    // on the `collect_new_fragments` call inside `verify_fragments`, a
    // `StateError::SlowDown` fell through to the generic `warn_map_err`
    // below it and surfaced as `Status::internal(..)` — the wrong gRPC
    // code for a condition the client should back off and retry on, and
    // inconsistent with the `exist_batch` verification loop a few dozen
    // lines below, which already maps its own SlowDown to
    // `Status::resource_exhausted(..)`.
    let (_immutable_store, mutable_store, execution) =
        crate::store::test_support::test_store_create()
            .await
            .expect("Failed to create stores");
    let repository_id: Context = rand::random();

    let status = LORE_CONTEXT
        .scope(execution.clone(), async move {
            let real_store = LocalImmutableStore::new(None, ImmutableStoreSettings::default())
                .await
                .expect("Failed to create store");
            let fault_store = SlowDownQueryStore::wrapping(real_store);

            let repository = Arc::new(RepositoryContext::new_server_context(
                fault_store.clone(),
                mutable_store.clone(),
                repository_id.into(),
            ));

            let write_token = get_write_token();

            let parent_state = Arc::new(State::new());
            let name = "test-node";
            let node = Node {
                name_hash: hash_string(name),
                ..Default::default()
            };
            parent_state
                .node_add(repository.clone(), ROOT_NODE, node, name)
                .await
                .expect("Failed to add node");
            let parent_signature = parent_state
                .serialize(repository.clone(), &write_token)
                .await
                .expect("Failed to serialize parent state");
            let parent_state = State::deserialize(repository.clone(), parent_signature)
                .await
                .expect("Failed to deserialize parent state");

            // A second, differing state so `verify_fragments` actually has
            // something to query (an unmodified diff never reaches the
            // store).
            let other_name = "other-test-node";
            let other_node = Node {
                name_hash: hash_string(other_name),
                ..Default::default()
            };
            let state = Arc::new(State::new());
            state
                .node_add(repository.clone(), ROOT_NODE, other_node, other_name)
                .await
                .expect("Failed to add node");
            let signature = state
                .serialize(repository.clone(), &write_token)
                .await
                .expect("Failed to serialize state");
            let state = State::deserialize(repository.clone(), signature)
                .await
                .expect("Failed to deserialize state");

            fault_store.arm();

            verify_fragments(repository, parent_state, None, state).await
        })
        .await
        .expect_err("Expected verify_fragments to surface a SlowDown as an error status");

    assert_eq!(
        status.code(),
        tonic::Code::ResourceExhausted,
        "Expected a SlowDown out of collect_new_fragments to map to \
         resource_exhausted (matching the exist_batch verification loop), \
         got: {status:?}"
    );
}

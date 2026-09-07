// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! WP118 single real server, clean initialization and authenticated released-shaped RPCs.
//! ReBAC is a test double; no platform ACL/create-claim or actual released CLI proof.
#![allow(dead_code)] // Read-only shared authentication fixtures expose additional case helpers.
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use lore_server::auth::jwk::JWKServiceSettings;
use lore_server::domain::operator::DomainCommand;
use lore_server::domain::operator::run;
use lore_server::settings::AuthSettings;
use lore_server::settings::LockStoreSettings;
use lore_server::settings::Settings;
use lore_storage::Address;
use lore_storage::Context;
use lore_storage::Hash;
use lore_storage::ImmutableStore;
use lore_storage::Partition;
const REVISION: &str = "clean-init-test-writer-v1";
#[path = "common/clean_init_dispatch.rs"]
mod dispatch;
#[path = "common/clean_init_fixture.rs"]
mod fixture;
#[path = "common/clean_init_rpc_create.rs"]
mod rpc_create;
#[path = "common/clean_init_rpc_store.rs"]
mod rpc_store;
// Reuse authentication and wire clients without launching/editing the WP109 harness.
#[path = "../../lore-integration-tests/tests/active_active_two_process_support/carriage.rs"]
mod carriage;
#[path = "../../lore-integration-tests/tests/active_active_two_process_support/client.rs"]
mod client;
#[path = "../../lore-integration-tests/tests/active_active_two_process_support/jwks.rs"]
mod jwks;
#[path = "../../lore-integration-tests/tests/active_active_two_process_support/rebac_stub/mod.rs"]
mod rebac_stub;
struct Env {
    jwks_json: PathBuf,
    jwt_private_key: PathBuf,
    jwt_kid: String,
    jwt_issuer: String,
    jwt_audience: String,
}
mod backend {
    pub struct SharedBackend {
        pub domain: std::sync::Arc<lore_postgres::domain::PostgresDomainStore>,
    }
}
fn port() -> u16 {
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
#[tokio::test]
#[ignore = "owned PostgreSQL/MinIO and one real loreserver; run run-clean-init-single-server-rpc-live.ps1"]
async fn clean_initialized_single_server_authenticates_upload_push_read_and_receipt() {
    tokio::time::timeout(Duration::from_secs(180), run_case(false, 0))
        .await
        .expect("single-server RPC proof deadline");
}
#[tokio::test]
#[ignore = "owned PostgreSQL/MinIO and one real loreserver; run run-clean-init-single-server-rpc-live.ps1"]
async fn clean_initialized_single_server_v0_create_upload_push_read_and_receipt() {
    tokio::time::timeout(Duration::from_secs(180), run_case(true, 0))
        .await
        .expect("single-server v0 proof deadline");
}
#[tokio::test]
#[ignore = "owned RPC fixture; run run-clean-init-single-server-rpc-live.ps1"]
async fn create_first_metadata_throttle_is_resource_exhausted_without_publication() {
    tokio::time::timeout(Duration::from_secs(180), run_case(false, 1))
        .await
        .unwrap();
}
#[tokio::test]
#[ignore = "owned RPC fixture; run run-clean-init-single-server-rpc-live.ps1"]
async fn create_second_metadata_throttle_is_resource_exhausted_without_publication() {
    tokio::time::timeout(Duration::from_secs(180), run_case(false, 2))
        .await
        .unwrap();
}
#[tokio::test]
#[ignore = "owned RPC fixture; run run-clean-init-single-server-rpc-live.ps1"]
async fn applied_create_replay_missing_metadata_returns_aborted_and_keeps_receipt() {
    tokio::time::timeout(Duration::from_secs(180), run_case(false, 3))
        .await
        .unwrap();
}
async fn run_case(v0: bool, refusal: u8) {
    let fixture = fixture::Fixture::new().await;
    fixture.initialize().await.unwrap();
    dispatch::install(&fixture.url).await;
    let domain = Arc::new(fixture.store().await);
    let backend = backend::SharedBackend {
        domain: domain.clone(),
    };
    let keys = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../lorehub/docker/test-fixtures");
    let auth = Env {
        jwks_json: keys.join("jwks.json"),
        jwt_private_key: keys.join("jwt-private-key.pem"),
        jwt_kid: "lorehub-test-key-1".into(),
        jwt_issuer: "https://wp118-single.invalid".into(),
        jwt_audience: "lore-storage".into(),
    };
    let jwks = jwks::JwksServer::start(port(), &auth.jwks_json).await;
    let stub = rebac_stub::RebacStub::start(&auth, port()).await;
    let minter = jwks::TokenMinter::from_env(&auth);
    let writer = uuid::Uuid::now_v7().to_string();
    let outsider = uuid::Uuid::now_v7().to_string();
    let token = minter.mint(&writer);
    let authn = minter.mint_authn(&writer);
    let grpc_port = port();
    let http_port = port();
    let directory = tempfile::tempdir().unwrap();
    let mut config: toml::Value = toml::from_str(include_str!("../config/default.toml")).unwrap();
    config["immutable_store"]["mode"] = "postgres".into();
    config["mutable_store"]["mode"] = "postgres".into();
    config["lock_store"]["mode"] = "postgres".into();
    for name in ["immutable_store", "mutable_store"] {
        config[name]["local"].as_table_mut().unwrap().insert(
            "path".into(),
            directory
                .path()
                .join(name)
                .to_string_lossy()
                .to_string()
                .into(),
        );
    }
    config["server"]["quic"]["enabled"] = false.into();
    config["server"]["grpc"]["host"] = "127.0.0.1".into();
    config["server"]["grpc"]["port"] = (grpc_port as i64).into();
    config["server"]["http"]["host"] = "127.0.0.1".into();
    config["server"]["http"]["port"] = (http_port as i64).into();
    config["server"].as_table_mut().unwrap().insert("auth".into(),toml::from_str(&format!("jwt_issuer={:?}\njwt_audience=[{:?}]\nenforce_write_permission=true\n[jwk]\nendpoint={:?}",auth.jwt_issuer,auth.jwt_audience,jwks.url())).unwrap());
    config.as_table_mut().unwrap().insert(
        "environment".into(),
        toml::from_str(&format!("[endpoint]\nauth_url={:?}", stub.url())).unwrap(),
    );
    config.as_table_mut().unwrap().insert(
        "plugins".into(),
        toml::Value::try_from(&fixture.settings.plugins).unwrap(),
    );
    config["plugins"].as_table_mut().unwrap().insert(
        "remote".into(),
        toml::from_str("cell_id='wp118-single-rpc'").unwrap(),
    );
    let pool = lore_postgres::pool::build_pool(&fixture.url, 1, &Default::default()).unwrap();
    let authority = pool.get().await.unwrap();
    lore_postgres::domain::outbox::stamp_cutover(&**authority, "wp118-single-rpc")
        .await
        .unwrap();
    let pg: tokio_postgres::Config = fixture.url.parse().unwrap();
    config["plugins"]["postgres"]["fragment_provider"]["dispatch_postgres_url"] = format!(
        "postgresql://object_dispatch_retention_runtime@localhost:{}/{}?sslmode=require",
        pg.get_ports()[0],
        pg.get_dbname().unwrap()
    )
    .into();
    config["plugins"]["postgres"]["fragment_provider"]["dispatch_ca_cert_path"] =
        std::env::var("LORE_TEST_CLEAN_INIT_CA_PATH")
            .unwrap()
            .into();
    config["plugins"]["postgres"]["fragment_provider"]["dispatch_lock_timeout_millis"] =
        1000.into();
    for field in [
        "dispatch_connect_timeout_millis",
        "dispatch_acquire_timeout_millis",
        "dispatch_statement_timeout_millis",
    ] {
        config["plugins"]["postgres"]["fragment_provider"][field] = 5000.into();
    }
    config.as_table_mut().unwrap().insert(
        "notification".into(),
        toml::from_str("mode='local'").unwrap(),
    );
    config.as_table_mut().unwrap().insert(
        "outbox_relay".into(),
        toml::from_str("enabled=false").unwrap(),
    );
    std::fs::write(
        directory.path().join("local.toml"),
        toml::to_string(&config).unwrap(),
    )
    .unwrap();
    let log_path = PathBuf::from(std::env::var("LORE_TEST_SINGLE_RPC_LOG").unwrap());
    let log = std::fs::File::create(&log_path).unwrap();
    let mut command =
        std::process::Command::new(std::env::var("LORE_TEST_SINGLE_RPC_SERVER").unwrap());
    command
        .args([
            "--config",
            directory.path().to_str().unwrap(),
            "--env",
            "local",
        ])
        .env_remove("LORE_FRAGMENT_FAILPOINTS")
        .stdout(log.try_clone().unwrap())
        .stderr(log);
    let mut child = ServerChild(command.spawn().unwrap());
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "server exited: {}",
            std::fs::read_to_string(&log_path).unwrap()
        );
        if reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .unwrap()
            .get(format!("http://127.0.0.1:{http_port}/health_check"))
            .send()
            .await
            .is_ok_and(|r| r.status().is_success())
            && tokio::net::TcpStream::connect(("127.0.0.1", grpc_port))
                .await
                .is_ok()
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "startup timed out: {}",
            std::fs::read_to_string(&log_path).unwrap()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let endpoint = format!("http://127.0.0.1:{grpc_port}");
    let repository = *uuid::Uuid::now_v7().as_bytes();
    let branch = *uuid::Uuid::now_v7().as_bytes();
    let prepared =
        rpc_create::prepare(&backend, minter.issuer(), &writer, &repository, &branch, v0).await;
    if refusal == 1 || refusal == 2 {
        // Consume real grants through ordinary PUT. Each absent-repo PUT uploads an
        // unassociated representation, so the published write budget honestly drains.
        let rpc = rpc_store::RpcStore {
            endpoint: endpoint.clone(),
            token: token.clone(),
            uploads: Default::default(),
        };
        let consumed = if refusal == 1 { 7 } else { 6 };
        for index in 0..consumed {
            rpc.assert_put_refused(
                Partition::from(Context::from(repository)),
                bytes::Bytes::from(format!("budget-drain-{index}")),
            )
            .await;
        }
        assert_eq!(authority.query_one("SELECT count(*) FROM object_store_retention.object_dispatch_provider_charge_grants", &[]).await.unwrap().get::<_, i64>(0), consumed);
        let error = rpc_create::send_result(&endpoint, &token, &repository, &branch, &prepared, v0)
            .await
            .unwrap_err();
        assert_eq!(error.code(), tonic::Code::ResourceExhausted, "{error}");
        assert_eq!(
            error.message(),
            if refusal == 1 {
                "Repository metadata upload requires retry"
            } else {
                "Default branch metadata upload requires retry"
            }
        );
        for table in [
            "lore_domain_repositories",
            "lore_domain_branches",
            "lore_fragment_associations",
            "lore_outbox_events",
        ] {
            assert_eq!(
                authority
                    .query_one(&format!("SELECT count(*) FROM {table}"), &[])
                    .await
                    .unwrap()
                    .get::<_, i64>(0),
                0,
                "{table}: serializer refusal precedes domain publication"
            );
        }
        let row = authority
            .query_one(
                "SELECT state,outcome FROM lore_domain_operation_receipts WHERE operation_id=$1",
                &[&prepared.operation_id.as_bytes().as_slice()],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, i16>(0), 0);
        assert_eq!(row.get::<_, Option<i16>>(1), None);
        assert_eq!(authority.query_one("SELECT count(*) FROM object_store_retention.object_dispatch_provider_charge_grants", &[]).await.unwrap().get::<_,i64>(0), 7);
        return;
    } // Even a prepared create does not authorize the ordinary public PUT route for this absent repo.
    rpc_store::RpcStore {
        endpoint: endpoint.clone(),
        token: token.clone(),
        uploads: Default::default(),
    }
    .assert_absent_repository_put_refused(Partition::from(Context::from(repository)))
    .await;
    assert_eq!(
        authority
            .query_one(
                "SELECT count(*) FROM lore_fragment_associations WHERE repository_id=$1",
                &[&repository.as_slice()]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    let created_metadata =
        rpc_create::send(&endpoint, &token, &repository, &branch, &prepared, v0).await;
    stub.grant(&repository, &writer, rebac_stub::policy::Role::Developer);
    let rpc = Arc::new(rpc_store::RpcStore {
        endpoint: endpoint.clone(),
        token: token.clone(),
        uploads: Default::default(),
    });
    let pointers = authority.query_one("SELECT r.metadata_hash,b.metadata_hash FROM lore_domain_repositories r JOIN lore_domain_branches b USING(repository_id) WHERE r.repository_id=$1", &[&repository.as_slice()]).await.unwrap();
    assert_eq!(pointers.get::<_, Vec<u8>>(0), created_metadata);
    for index in 0..2 {
        let hash: Vec<u8> = pointers.get(index);
        let fetched = rpc
            .clone()
            .get(
                Partition::from(Context::from(repository)),
                Address {
                    hash: Hash::from(hash.as_slice()),
                    context: Context::default(),
                },
            )
            .await
            .unwrap();
        assert!(
            !fetched.payload.as_ref().unwrap().is_empty(),
            "each published metadata pointer must be fetchable through RPC"
        );
    }
    if refusal == 3 {
        let original_events: Vec<(String, String)> = authority
            .query(
                "SELECT event_id::text,event_kind FROM lore_outbox_events ORDER BY event_id",
                &[],
            )
            .await
            .unwrap()
            .iter()
            .map(|row| (row.get(0), row.get(1)))
            .collect();
        let row = authority
            .query_one(
                "SELECT object_key FROM lore_fragment_epochs WHERE hash=$1",
                &[&created_metadata],
            )
            .await
            .unwrap();
        let key: String = row.get(0);
        // Damage only the owned bucket. Current GET must fail while durable SQL
        // publication and its Applied receipt remain authoritative.
        fixture
            .s3
            .sdk_client()
            .delete_object()
            .bucket(&fixture.bucket)
            .key(&key)
            .send()
            .await
            .unwrap();
        assert!(
            fixture
                .s3
                .sdk_client()
                .get_object()
                .bucket(&fixture.bucket)
                .key(&key)
                .send()
                .await
                .is_err()
        );
        tokio::time::sleep(Duration::from_millis(5)).await;

        let error =
            rpc_create::send_result(&endpoint, &token, &repository, &branch, &prepared, false)
                .await
                .unwrap_err();
        assert_eq!(error.code(), tonic::Code::Aborted, "{error}");
        assert_eq!(
            error.message(),
            "Repository creation is applied, but its metadata could not be read; reconcile the attempt receipt and repository before retrying"
        );
        let row = authority
            .query_one(
                "SELECT state,outcome FROM lore_domain_operation_receipts WHERE operation_id=$1",
                &[&prepared.operation_id.as_bytes().as_slice()],
            )
            .await
            .unwrap();
        assert_eq!(row.get::<_, i16>(0), 1);
        assert_eq!(row.get::<_, Option<i16>>(1), Some(0));
        assert_eq!(
            authority
                .query_one(
                    "SELECT metadata_hash FROM lore_domain_repositories WHERE repository_id=$1",
                    &[&repository.as_slice()]
                )
                .await
                .unwrap()
                .get::<_, Vec<u8>>(0),
            created_metadata
        );
        assert_eq!(
            authority
                .query_one(
                    "SELECT count(*) FROM lore_fragment_associations WHERE repository_id=$1",
                    &[&repository.as_slice()]
                )
                .await
                .unwrap()
                .get::<_, i64>(0),
            2
        );
        assert_eq!(
            authority
                .query_one("SELECT count(*) FROM lore_outbox_events WHERE event_kind <> 'fragment.lifecycle_generation_advanced'", &[])
                .await
                .unwrap()
                .get::<_, i64>(0),
            4
        );
        let mut expected_hashes =
            vec![pointers.get::<_, Vec<u8>>(0), pointers.get::<_, Vec<u8>>(1)];
        expected_hashes.sort();
        let bound_hashes: Vec<Vec<u8>> = authority
            .query(
                "SELECT hash FROM lore_fragment_associations WHERE repository_id=$1 ORDER BY hash",
                &[&repository.as_slice()],
            )
            .await
            .unwrap()
            .iter()
            .map(|row| row.get(0))
            .collect();
        assert_eq!(
            bound_hashes, expected_hashes,
            "no speculative replay representation may become associated"
        );
        let retained_events: Vec<(String,String)> = authority.query("SELECT event_id::text,event_kind FROM lore_outbox_events WHERE event_kind <> 'fragment.lifecycle_generation_advanced' ORDER BY event_id", &[]).await.unwrap().iter().map(|row| (row.get(0),row.get(1))).collect();
        assert_eq!(
            retained_events, original_events,
            "replay preserves every original create and association event identity"
        );
        let event = authority.query_one("SELECT aggregate_kind,aggregate_id,aggregate_version FROM lore_outbox_events WHERE event_kind='fragment.lifecycle_generation_advanced'", &[]).await.unwrap();
        assert_eq!(event.get::<_, String>(0), "fragment_lifecycle");
        assert_eq!(event.get::<_, Vec<u8>>(1), repository);
        let generation: i64 = authority.query_one("SELECT fragment_lifecycle_generation FROM lore_domain_repositories WHERE repository_id=$1", &[&repository.as_slice()]).await.unwrap().get(0);
        assert_eq!(
            event.get::<_, Vec<u8>>(2),
            (generation as u64).to_be_bytes()
        );
        assert_eq!(
            authority
                .query_one(
                    "SELECT state FROM lore_fragment_lifecycle WHERE hash=$1",
                    &[&created_metadata]
                )
                .await
                .unwrap()
                .get::<_, i16>(0),
            lore_postgres::domain::fragments::FragmentLifecycleState::Missing.bits()
        );
        return;
    }
    let before_retry = authority.query_one("SELECT (SELECT count(*) FROM lore_fragment_associations WHERE repository_id=$1),(SELECT count(*) FROM lore_outbox_events)", &[&repository.as_slice()]).await.unwrap();
    // v1 regenerates the metadata timestamp, so this is a real later speculative upload.
    tokio::time::sleep(Duration::from_millis(5)).await;
    let replay_metadata =
        rpc_create::send(&endpoint, &token, &repository, &branch, &prepared, v0).await;
    assert_eq!(replay_metadata, created_metadata);
    let after_retry = authority.query_one("SELECT (SELECT count(*) FROM lore_fragment_associations WHERE repository_id=$1),(SELECT count(*) FROM lore_outbox_events)", &[&repository.as_slice()]).await.unwrap();
    assert_eq!(before_retry.get::<_, i64>(0), 2);
    assert_eq!(before_retry.get::<_, i64>(1), 4);
    assert_eq!(after_retry.get::<_, i64>(0), before_retry.get::<_, i64>(0));
    assert_eq!(after_retry.get::<_, i64>(1), before_retry.get::<_, i64>(1));
    let grants_before_upload: i64 = authority
        .query_one(
            "SELECT count(*) FROM object_store_retention.object_dispatch_provider_charge_grants",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    let mutable = Arc::new(
        lore_postgres::store::mutable_store::PostgresMutableStore::connect(
            &fixture.url,
            2,
            &lore_postgres::pool::TlsConfig::default(),
        )
        .await
        .unwrap(),
    );
    let context = Arc::new(
        lore_revision::repository::RepositoryContext::new_server_context(
            rpc.clone(),
            mutable,
            repository.into(),
        ),
    );
    let execution = Arc::new(lore_revision::interface::ExecutionContext::new_server(
        Default::default(),
        lore_revision::relay::EventDispatcher::no_dispatch(),
        writer.clone(),
    ));
    let candidate = lore_base::runtime::LORE_CONTEXT
        .scope(execution, async {
            let state = lore_revision::state::State::new();
            state.set_parent_self(Hash::default());
            state.set_revision_number(1);
            state
                .serialize(context, &lore_server::grpc::get_write_token())
                .await
                .unwrap()
        })
        .await;
    let uploaded = rpc.uploads.lock().unwrap().clone();
    assert!(
        !uploaded.is_empty(),
        "serialization must actually upload through RPC"
    );
    let attempt = uuid::Uuid::now_v7();
    let grants_after_upload: i64 = authority
        .query_one(
            "SELECT count(*) FROM object_store_retention.object_dispatch_provider_charge_grants",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        grants_after_upload,
        grants_before_upload + uploaded.len() as i64
    );
    client::branch_push_no_carriage(
        endpoint.clone(),
        &token,
        Some(&authn),
        &repository,
        &branch,
        candidate.as_ref(),
        attempt,
    )
    .await
    .unwrap();
    assert_eq!(
        stub.authorized_count(&writer, "branch.push", &repository),
        1
    );
    let receipt = client::attempt_receipt_get(endpoint.clone(), &token, attempt)
        .await
        .unwrap();
    use lore_proto::lore::domain::v1::DomainOperationOutcome;
    use lore_proto::lore::domain::v1::DomainOperationReceiptStatus;
    assert_eq!(
        receipt.status,
        DomainOperationReceiptStatus::Committed as i32
    );
    assert_eq!(receipt.outcome, DomainOperationOutcome::Applied as i32);
    assert_eq!(receipt.method, "branch.push");
    let absent = client::attempt_receipt_get(endpoint.clone(), &minter.mint(&outsider), attempt)
        .await
        .unwrap();
    assert_eq!(absent.status, DomainOperationReceiptStatus::NotFound as i32);
    assert!(absent.method.is_empty());
    let refusal = client::branch_push_no_carriage(
        endpoint.clone(),
        &minter.mint(&outsider),
        Some(&minter.mint_authn(&outsider)),
        &repository,
        &branch,
        candidate.as_ref(),
        uuid::Uuid::now_v7(),
    )
    .await
    .unwrap_err();
    assert_eq!(
        refusal.code(),
        tonic::Code::PermissionDenied,
        "underprivileged direct push must be denied"
    );
    let tip: Vec<u8> = authority
        .query_one(
            "SELECT latest_hash FROM lore_domain_branches WHERE repository_id=$1 AND branch_id=$2",
            &[&repository.as_slice(), &branch.as_slice()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(tip, candidate.as_ref());
    assert_eq!(
        authority
            .query_one(
                "SELECT count(*) FROM lore_outbox_events WHERE event_kind='branch.pushed'",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1
    );
    let evidence=authority.query_one("SELECT l.state, EXISTS(SELECT 1 FROM lore_fragment_associations a WHERE a.hash=l.hash AND repository_id=$2 AND context=$3), (SELECT count(*) FROM lore_fragment_write_claims w WHERE w.hash=l.hash AND state=2) FROM lore_fragment_lifecycle l WHERE l.hash=$1",&[&candidate.as_ref(),&repository.as_slice(),&[0u8;16].as_slice()]).await.unwrap();
    assert_eq!(evidence.get::<_, i16>(0), 4);
    assert!(evidence.get::<_, bool>(1));
    assert_eq!(evidence.get::<_, i64>(2), 1);
    let grants: i64 = authority
        .query_one(
            "SELECT count(*) FROM object_store_retention.object_dispatch_provider_charge_grants",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        grants,
        grants_after_upload + 1,
        "push performs one governed metadata HEAD"
    );
    let classes = authority.query("SELECT attempt_class,traffic_class,count(*) FROM object_store_retention.object_dispatch_provider_charge_grants GROUP BY attempt_class,traffic_class ORDER BY attempt_class", &[]).await.unwrap();
    assert_eq!(classes.len(), 2);
    let linked_heads: i64 = authority.query_one("SELECT count(*) FROM object_store_retention.object_dispatch_provider_charge_grants g JOIN lore_fragment_write_claims w ON w.logical_request_id=uuid_send(g.logical_request_id) AND w.attempt_id=uuid_send(g.attempt_id) WHERE g.attempt_class=2", &[]).await.unwrap().get(0);
    assert_eq!(
        linked_heads, 0,
        "a metadata HEAD is governed read traffic, not a write claim"
    );
    assert_eq!(
        (
            classes[0].get::<_, i16>(0),
            classes[0].get::<_, i16>(1),
            classes[0].get::<_, i64>(2)
        ),
        (2, 3, 1),
        "one HeadObject/Read grant"
    );
    assert_eq!(
        (
            classes[1].get::<_, i16>(0),
            classes[1].get::<_, i16>(1),
            classes[1].get::<_, i64>(2)
        ),
        (4, 2, grants_after_upload),
        "each remaining grant is PutObject/Write"
    );
    let partition = Partition::from(Context::from(repository));
    let address = Address {
        hash: candidate,
        context: Context::default(),
    };
    let read = rpc.clone().get(partition, address).await.unwrap();
    let expected = &uploaded
        .iter()
        .find(|(a, _)| *a == address)
        .expect("candidate uploaded through RPC")
        .1;
    assert_eq!(
        read.payload.as_ref(),
        Some(expected),
        "RPC GET returns exact uploaded candidate bytes"
    );
    let mut result = [Default::default()];
    rpc.query(partition, &[address], &mut result).await.unwrap();
    assert_eq!(result[0].match_made, lore_storage::StoreMatch::MatchFull);
    assert_eq!(authority.query_one("SELECT count(*) FROM object_store_retention.object_dispatch_provider_charge_grants",&[]).await.unwrap().get::<_,i64>(0),grants);
    assert_eq!(
        authority
            .query_one("SELECT count(*) FROM lore_fragments", &[])
            .await
            .unwrap()
            .get::<_, i64>(0),
        0,
        "all content must use coordinated associations"
    );
    assert!(
        domain
            .fragment_coordinator()
            .push_membership_enabled()
            .await
            .unwrap()
    );
    drop(child);
}

// Native executable has no shim descendants. Reap before fixture tempfiles disappear,
// including assertion unwinds; the async runtime is not needed for this cleanup.
struct ServerChild(std::process::Child);
impl Drop for ServerChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

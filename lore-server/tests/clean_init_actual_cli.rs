// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! WP118 actual CLI happy path against one clean initialized server.
//! ReBAC/exchange are test doubles. This uses the current fork CLI binary and
//! does not prove platform ACL/create-claim policy or outcome-unknown recovery.
#![allow(dead_code)] // Shared authentication fixtures expose additional case helpers.
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

const REVISION: &str = "clean-init-test-writer-v1";
#[path = "common/actual_cli_dispatch.rs"]
mod dispatch;
#[path = "common/clean_init_fixture.rs"]
mod fixture;
#[path = "common/clean_init_rpc_create.rs"]
mod rpc_create;

// Reuse authentication and wire clients without launching the WP109 two-process tier.
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
#[path = "common/actual_cli_auth.rs"]
mod actual_cli_auth;
#[path = "common/actual_cli_process.rs"]
mod actual_cli_process;
#[tokio::test]
#[ignore = "owned initialized PostgreSQL/MinIO, real server and CLI; run-clean-init-actual-cli-live.ps1"]
async fn actual_cli_login_clone_commit_push_and_fresh_clone_readback() {
    tokio::time::timeout(Duration::from_secs(300), run_cli_case())
        .await
        .expect("actual CLI proof deadline");
}
async fn run_cli_case() {
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
    let stub =
        rebac_stub::RebacStub::start_with_authn_hosts(&auth, port(), &["localhost".into()]).await;
    let minter = jwks::TokenMinter::from_env(&auth);
    let writer = uuid::Uuid::now_v7().to_string();

    let token = minter.mint(&writer);

    let repository = *uuid::Uuid::now_v7().as_bytes();
    let branch = *uuid::Uuid::now_v7().as_bytes();
    let exchange = actual_cli_auth::AuthServer::start(
        stub.url(),
        minter.issuer(),
        &writer,
        &repository,
        &auth.jwt_private_key,
        port(),
    )
    .await;
    exchange.assert_permission_refusals().await;
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
    config["server"]["auth"]["jwt_audience"] = toml::Value::Array(vec![
        "lore-storage".into(),
        "commit0-cli".into(),
        "localhost".into(),
    ]);
    config.as_table_mut().unwrap().insert(
        "environment".into(),
        toml::from_str(&format!("[endpoint]\nauth_url={:?}", exchange.url.as_str())).unwrap(),
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
        .env(
            "SSL_CERT_FILE",
            std::env::var("LORE_TEST_CLEAN_INIT_CA_PATH").unwrap(),
        )
        .env_remove("SSL_CERT_DIR")
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

    let prepared = rpc_create::prepare(
        &backend,
        minter.issuer(),
        &writer,
        &repository,
        &branch,
        false,
    )
    .await;
    rpc_create::send(&endpoint, &token, &repository, &branch, &prepared, false).await;
    stub.grant(&repository, &writer, rebac_stub::policy::Role::Developer);
    let remote = format!("grpc://localhost:{grpc_port}");
    let repo_hex = repository
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let clone_url = format!("{remote}/{repo_hex}");
    let workspace = directory.path().join("first");
    let second = directory.path().join("second");
    let mut cli = actual_cli_process::Cli::new(directory.path(), &exchange);
    cli.run(
        "login",
        &[
            "auth",
            "login",
            &remote,
            "--token",
            &exchange.authn,
            "--token-type",
            "lore",
            "--auth-url",
            &exchange.url,
        ],
        directory.path(),
        "auth-first",
    )
    .await;
    cli.run(
        "clone",
        &["clone", &clone_url, workspace.to_str().unwrap()],
        directory.path(),
        "auth-first",
    )
    .await;
    let bytes = b"actual CLI governed provider upload and fresh readback\n";
    std::fs::write(workspace.join("proof.txt"), bytes).unwrap();
    cli.run("stage", &["stage", "--scan", "."], &workspace, "auth-first")
        .await;
    let before: i64 = authority
        .query_one(
            "SELECT count(*) FROM object_store_retention.object_dispatch_provider_charge_grants",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    cli.run(
        "commit",
        &["commit", "WP118 actual CLI proof"],
        &workspace,
        "auth-first",
    )
    .await;
    let push_output = cli.run("push", &["push"], &workspace, "auth-first").await;
    let after: i64 = authority
        .query_one(
            "SELECT count(*) FROM object_store_retention.object_dispatch_provider_charge_grants",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(
        after > before && after <= 64,
        "CLI commit/push must consume bounded real governed grants"
    );
    let tip: Vec<u8> = authority
        .query_one(
            "SELECT latest_hash FROM lore_domain_branches WHERE repository_id=$1 AND branch_id=$2",
            &[&repository.as_slice(), &branch.as_slice()],
        )
        .await
        .unwrap()
        .get(0);
    assert!(tip.iter().any(|b| *b != 0));
    let tip_hex = tip.iter().map(|b| format!("{b:02x}")).collect::<String>();
    assert!(
        push_output.contains(&tip_hex),
        "CLI success must name the authoritative committed branch tip"
    );
    let event=authority.query_one("SELECT repository_id,aggregate_id,payload FROM lore_outbox_events WHERE event_kind='branch.pushed'",&[]).await.unwrap();
    assert_eq!(event.get::<_, Vec<u8>>(0), repository);
    assert_eq!(event.get::<_, Vec<u8>>(1), branch);
    let payload: serde_json::Value = serde_json::from_slice(&event.get::<_, Vec<u8>>(2)).unwrap();
    assert_eq!(payload["new_latest_hash"], tip_hex);
    assert!(
        authority
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM lore_fragment_write_claims WHERE hash=$1 AND state=2)",
                &[&tip]
            )
            .await
            .unwrap()
            .get::<_, bool>(0)
    );
    let receipts = authority.query("SELECT state,outcome,client_attempt_id FROM lore_domain_operation_receipts WHERE method='branch.push'",&[]).await.unwrap();
    println!("CLI branch.push receipt rows: {}", receipts.len());
    assert_eq!(
        receipts.len(),
        1,
        "one CLI push must have one authoritative receipt"
    );
    let receipt = &receipts[0];
    assert_eq!(receipt.get::<_, i16>(0), 1);
    assert_eq!(receipt.get::<_, Option<i16>>(1), Some(0));
    let attempt: Vec<u8> = receipt.get(2);
    let observed = client::attempt_receipt_get(
        endpoint.clone(),
        &exchange.authz,
        uuid::Uuid::from_slice(&attempt).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(
        observed.outcome,
        lore_proto::lore::domain::v1::DomainOperationOutcome::Applied as i32
    );
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
    assert_eq!(authority.query_one("SELECT count(*) FROM lore_fragment_associations a LEFT JOIN lore_fragment_lifecycle l USING(hash) WHERE a.repository_id=$1 AND (a.state<>0 OR l.state IS DISTINCT FROM 4)",&[&repository.as_slice()]).await.unwrap().get::<_,i64>(0),0);
    assert!(authority.query_one("SELECT EXISTS(SELECT 1 FROM lore_fragment_associations WHERE hash=$1 AND repository_id=$2)",&[&tip,&repository.as_slice()]).await.unwrap().get::<_,bool>(0));
    let exchanges_before = exchange.exchanges.lock().unwrap().len();
    assert!(exchanges_before > 0, "real CLI must invoke exchange");
    cli.run(
        "second-login",
        &[
            "auth",
            "login",
            &remote,
            "--token",
            &exchange.authn,
            "--token-type",
            "lore",
            "--auth-url",
            &exchange.url,
        ],
        directory.path(),
        "auth-second",
    )
    .await;
    cli.run(
        "second-clone",
        &["clone", &clone_url, second.to_str().unwrap()],
        directory.path(),
        "auth-second",
    )
    .await;
    cli.run("second-sync", &["sync"], &second, "auth-second")
        .await;
    assert_eq!(std::fs::read(second.join("proof.txt")).unwrap(), bytes);
    let exchanges_after = exchange.exchanges.lock().unwrap().len();
    assert!(
        exchanges_after > exchanges_before,
        "fresh auth store must exchange independently"
    );
    assert!(
        exchange.permission_checks.lock().unwrap().len() >= 2,
        "both actual clones must authorize exact repository reads"
    );
    let direct = exchange.direct_bearers.lock().unwrap();
    assert!(!direct.is_empty());
    assert!(
        direct
            .iter()
            .all(|token| token == &exchange.authn && token != &exchange.authz)
    );
    println!(
        "CLI proof: {exchanges_before} exchanges before fresh clone, {exchanges_after} total; {} direct authorization callbacks; provider grants {before}->{after}",
        direct.len()
    );
    drop(child);
}

struct ServerChild(std::process::Child);
impl Drop for ServerChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

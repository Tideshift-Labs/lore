// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! SERVER-only CR-039 operator coverage: the `loreserver domain
//! upgrade-fragments` verb, and one end-to-end run of the actual compiled
//! binary against a disposable revision-4 clean cell. No MinIO/S3 fixture is
//! needed -- the upgrade is offline and database-only.

use std::time::Duration;

use async_trait::async_trait;
use clap::Parser;
use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::backfill::BranchFacts;
use lore_postgres::domain::backfill::DomainBackfill;
use lore_postgres::domain::backfill::DomainBackfillSource;
use lore_postgres::domain::backfill::OrphanKey;
use lore_postgres::domain::backfill::RepositoryFacts;
use lore_postgres::domain::errors::DomainError;
use lore_postgres::domain::fragments::initialization::CleanCellInitialization;
use lore_postgres::domain::fragments::initialization::CleanCellInitializationOutcome;
use lore_postgres::domain::fragments::schema;
use lore_postgres::domain::locks::BackfillIssuerMap;
use lore_postgres::pool::TlsConfig;
use lore_postgres::pool::build_pool;
use lore_server::auth::jwk::JWKServiceSettings;
use lore_server::domain::operator::DomainCommand;
use lore_server::domain::operator::run;
use lore_server::server::Cli;
use lore_server::settings::AuthSettings;
use lore_server::settings::LockStoreSettings;
use lore_server::settings::Settings;
use tokio_postgres::Client;

#[test]
fn upgrade_fragments_cli_parses_and_carries_the_confirmation_flag() {
    assert!(Cli::try_parse_from(["loreserver", "domain", "upgrade-fragments"]).is_ok());
    let parsed = Cli::try_parse_from([
        "loreserver",
        "domain",
        "upgrade-fragments",
        "--confirm-replicas-stopped",
        "--json",
    ])
    .unwrap();
    let debug = format!("{:?}", parsed.command);
    assert!(debug.contains("UpgradeFragments"));
    assert!(debug.contains("confirm_replicas_stopped: true"));
    assert!(debug.contains("json: true"));
}

#[tokio::test]
async fn operator_requires_explicit_replica_confirmation_before_connecting() {
    let settings: Settings = toml::from_str(include_str!("../config/default.toml")).unwrap();
    let error = run(
        &DomainCommand::UpgradeFragments {
            confirm_replicas_stopped: false,
            json: true,
        },
        &settings,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("--confirm-replicas-stopped"));
}

async fn client(url: &str) -> Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("connect direct assertion client");
    lore_base::lore_spawn!(async move {
        if let Err(error) = connection.await {
            eprintln!("direct postgres connection error: {error}");
        }
    });
    client
}

fn postgres_only_settings(url: &str) -> Settings {
    let mut settings: Settings = toml::from_str(include_str!("../config/default.toml")).unwrap();
    settings.immutable_store.mode = "postgres".into();
    settings.mutable_store.mode = "postgres".into();
    settings.lock_store = Some(LockStoreSettings {
        mode: "postgres".into(),
    });
    settings.server.auth = Some(AuthSettings {
        jwk: Some(JWKServiceSettings {
            endpoint: "https://issuer.invalid/jwks".into(),
        }),
        jwt_audience: None,
        jwt_issuer: Some("https://issuer.invalid".into()),
        enforce_write_permission: true,
    });
    let plugin = format!("url = {url:?}\npool_max = 4\ndomain_pool_max = 4\n");
    settings
        .plugins
        .insert("postgres".into(), toml::from_str(&plugin).unwrap());
    settings
}

struct EmptySource;

#[async_trait]
impl DomainBackfillSource for EmptySource {
    async fn list_repositories(&self) -> Result<Vec<RepositoryFacts>, DomainError> {
        Ok(vec![])
    }
    async fn list_branches(&self, _: &[u8]) -> Result<Vec<BranchFacts>, DomainError> {
        unreachable!()
    }
    async fn snapshot_token(&self, _: &[u8]) -> Result<Vec<u8>, DomainError> {
        unreachable!()
    }
    async fn orphan_projection_keys(&self) -> Result<Vec<OrphanKey>, DomainError> {
        Ok(vec![])
    }
}

/// Build a real clean cell through the domain/lock cutover and
/// `initialize_empty` path (reaching revision 6), then downgrade it in place
/// to the exact revision-4 shape a `dae71dfc` cell has -- mirroring
/// `lore-postgres`'s own `domain_fragment_schema_upgrade.rs` fixture. Armed
/// directly rather than through `DomainCommand::Cutover`: that command also
/// opens the real Postgres immutable store, which needs a live S3 endpoint
/// CR-039's upgrade itself does not (it is offline and database-only).
async fn revision4_clean_cell(url: &str) {
    client(url)
        .await
        .batch_execute(include_str!("../../lore-postgres/migrations/0001_init.sql"))
        .await
        .unwrap();
    let store = PostgresDomainStore::connect(url, 4, &TlsConfig::default())
        .await
        .unwrap();
    store.lock_coordinator().bootstrap().await.unwrap();
    store.fragment_coordinator().bootstrap().await.unwrap();
    let pool = build_pool(url, 2, &TlsConfig::default()).unwrap();
    let backfill = DomainBackfill::new(&pool, &EmptySource);
    assert_eq!(backfill.run().await.unwrap(), 0);
    let verified = backfill.verify().await.unwrap();
    assert!(verified.passed());
    backfill.complete(&verified).await.unwrap();
    store
        .lock_coordinator()
        .backfill(&BackfillIssuerMap::new())
        .await
        .unwrap();
    store
        .lock_coordinator()
        .enable_fencing(false)
        .await
        .unwrap();
    store.enable_enforcement().await.unwrap();
    let coordinator = store.fragment_coordinator();
    let input = CleanCellInitialization::new(
        "cr-039-operator-fixture".into(),
        "cr-039-operator-writer-v1".into(),
    )
    .unwrap();
    assert_eq!(
        coordinator.initialize_empty(&input).await.unwrap(),
        CleanCellInitializationOutcome::Initialized
    );
    let direct = client(url).await;
    direct
        .batch_execute(
            "ALTER TABLE lore_fragment_schema_state DISABLE TRIGGER lore_clean_state_permanent; \
             DROP TABLE IF EXISTS lore_fragment_stage_custody, lore_fragment_stage_usage, \
                 lore_fragment_stage_policy CASCADE; \
             DROP FUNCTION IF EXISTS stage_policy_publish_v1, stage_policy_verify_v1, \
                 stage_policy_rotate_v1; \
             DROP INDEX IF EXISTS lore_fragment_stage_custody_cleanup, \
                 lore_fragment_stage_drain_recovery; \
             UPDATE lore_fragment_schema_state SET schema_version = 4, updated_at = clock_timestamp() \
                 WHERE id = 1; \
             ALTER TABLE lore_fragment_schema_state ENABLE ALWAYS TRIGGER lore_clean_state_permanent;",
        )
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn real_loreserver_binary_upgrades_a_revision_4_clean_cell_and_emits_parseable_json() {
    let url = std::env::var("LORE_TEST_PG_URL").expect("isolated empty PostgreSQL required");
    let settings = postgres_only_settings(&url);
    revision4_clean_cell(&url).await;

    let directory = tempfile::tempdir().unwrap();
    let mut config: toml::Value = toml::from_str(include_str!("../config/default.toml")).unwrap();
    config["mutable_store"]["mode"] = "postgres".into();
    config["immutable_store"]["mode"] = "postgres".into();
    config["server"].as_table_mut().unwrap().insert(
        "auth".into(),
        toml::from_str::<toml::Value>(
            "jwt_issuer = 'https://issuer.invalid'\nenforce_write_permission = true\n[jwk]\nendpoint = 'https://issuer.invalid/jwks'",
        )
        .unwrap(),
    );
    config.as_table_mut().unwrap().insert(
        "plugins".into(),
        toml::Value::try_from(&settings.plugins).unwrap(),
    );
    std::fs::write(
        directory.path().join("local.toml"),
        toml::to_string(&config).unwrap(),
    )
    .unwrap();

    // Without the confirmation flag, the real binary refuses before connecting.
    let mut refused = tokio::process::Command::new(env!("CARGO_BIN_EXE_loreserver"));
    refused.args([
        "--config",
        directory.path().to_str().unwrap(),
        "domain",
        "upgrade-fragments",
        "--json",
    ]);
    refused.kill_on_drop(true);
    let refusal = tokio::time::timeout(Duration::from_secs(30), refused.output())
        .await
        .expect("refusal must not hang")
        .unwrap();
    assert!(!refusal.status.success());
    assert!(
        String::from_utf8_lossy(&refusal.stderr).contains("--confirm-replicas-stopped"),
        "stderr={}",
        String::from_utf8_lossy(&refusal.stderr)
    );

    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_loreserver"));
    command.args([
        "--config",
        directory.path().to_str().unwrap(),
        "domain",
        "upgrade-fragments",
        "--confirm-replicas-stopped",
        "--json",
    ]);
    command.kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(45), command.output())
        .await
        .expect("operator process must finish")
        .unwrap();
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    let report: serde_json::Value = stdout
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|value| value["status"] == "upgraded")
        .expect("CLI must emit an upgraded JSON report");
    assert_eq!(report["from_schema_version"], 4);
    assert_eq!(report["schema_version"], schema::FRAGMENT_SCHEMA_VERSION);
    assert_eq!(report["restart_required"], true);

    let store = PostgresDomainStore::connect(&url, 4, &TlsConfig::default())
        .await
        .unwrap();
    assert!(
        store
            .fragment_coordinator()
            .readiness()
            .await
            .unwrap()
            .ready_for_lifecycle()
    );

    // A rerun of the real binary reports already_current and stays green.
    let mut rerun = tokio::process::Command::new(env!("CARGO_BIN_EXE_loreserver"));
    rerun.args([
        "--config",
        directory.path().to_str().unwrap(),
        "domain",
        "upgrade-fragments",
        "--confirm-replicas-stopped",
        "--json",
    ]);
    rerun.kill_on_drop(true);
    let rerun_output = tokio::time::timeout(Duration::from_secs(45), rerun.output())
        .await
        .expect("rerun must not hang")
        .unwrap();
    assert!(rerun_output.status.success());
    let rerun_stdout = String::from_utf8(rerun_output.stdout).unwrap();
    let rerun_report: serde_json::Value = rerun_stdout
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find(|value| value["status"] == "already_current")
        .expect("CLI must emit an already_current JSON report on rerun");
    assert_eq!(rerun_report["restart_required"], false);
}

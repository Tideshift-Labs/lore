// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Shared owned PostgreSQL/MinIO operator fixture for integration and private construction tests.
use std::time::Duration;

use lore_aws::clients::AwsClientBuilder;
use lore_aws::clients::HttpClientSettings;
use lore_aws::clients::TimeoutConfig;
use lore_aws::s3::S3Impl;
use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::pool::TlsConfig;

use super::AuthSettings;
use super::DomainCommand;
use super::JWKServiceSettings;
use super::LockStoreSettings;
use super::REVISION;
use super::Settings;
use super::run;
pub(super) struct Fixture {
    pub(super) settings: Settings,
    pub(super) url: String,
    pub(super) bucket: String,
    pub(super) s3: S3Impl,
}

impl Fixture {
    pub(super) async fn new() -> Self {
        let url = std::env::var("LORE_TEST_PG_URL").expect("isolated empty PostgreSQL required");
        let endpoint = std::env::var("LORE_TEST_S3_ENDPOINT").expect("owned MinIO required");
        let bucket = format!("clean-init-{}", uuid::Uuid::new_v4().simple());
        let builder = AwsClientBuilder::builder()
            .with_http_settings(&HttpClientSettings::default())
            .maybe_endpoint(Some(endpoint.clone()))
            .maybe_region(Some("us-east-1".into()))
            .with_timeout_config(
                TimeoutConfig::builder()
                    .operation_timeout(Duration::from_secs(10))
                    .build(),
            )
            .build_config()
            .await
            .s3_with_path_style(true);
        let s3 = builder.build().await.unwrap();
        s3.sdk_client()
            .create_bucket()
            .bucket(&bucket)
            .send()
            .await
            .unwrap();
        let mut settings: Settings =
            toml::from_str(include_str!("../../config/default.toml")).unwrap();
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
        let plugin = format!(
            "url = {url:?}\npool_max = 4\ndomain_pool_max = 4\n[object_store]\nbucket = {bucket:?}\nendpoint_url = {endpoint:?}\nregion = \"us-east-1\"\nforce_path_style = true\ntimeout_millis = 5000\n"
        );
        settings
            .plugins
            .insert("postgres".into(), toml::from_str(&plugin).unwrap());
        // This is the supported prerequisite path, including its real immutable metadata source.
        run(
            &DomainCommand::Cutover {
                dry_run: false,
                force_release_legacy_locks: false,
                legacy_lock_issuer: vec![],
                json: true,
            },
            &settings,
        )
        .await
        .unwrap();
        let provider = format!(
            r#"
enabled = true
dispatch_postgres_url = "postgresql://dispatcher@127.0.0.1/cell?sslmode=require"
dispatch_ca_cert_path = "unused-by-offline-initializer.pem"
dispatch_pool_max = 2
dispatch_connect_timeout_millis = 1000
dispatch_acquire_timeout_millis = 1000
dispatch_statement_timeout_millis = 2000
dispatch_lock_timeout_millis = 3000
provider_late_effect_bound_millis = 60000
provider_boundary_id = "cell.clean-init"
endpoint_host = "127.0.0.1"
region = "us-east-1"
budget_revision = "test-budget-v1"
budget_fence = 1
provider_write_authority_revision = "{REVISION}"
"#
        );
        settings
            .plugins
            .get_mut("postgres")
            .unwrap()
            .as_table_mut()
            .unwrap()
            .insert(
                "fragment_provider".into(),
                toml::from_str(&provider).unwrap(),
            );
        Self {
            settings,
            url,
            bucket,
            s3,
        }
    }

    pub(super) async fn initialize(&self) -> anyhow::Result<()> {
        run(
            &DomainCommand::InitializeFragments {
                provider_write_authority_revision: REVISION.into(),
                confirm_legacy_writers_excluded: true,
                json: true,
            },
            &self.settings,
        )
        .await
    }

    pub(super) async fn store(&self) -> PostgresDomainStore {
        PostgresDomainStore::connect(&self.url, 2, &TlsConfig::default())
            .await
            .unwrap()
    }

    pub(super) async fn assert_dark(&self) {
        let store = self.store().await;
        let coordinator = store.fragment_coordinator();
        assert!(!coordinator.readiness().await.unwrap().lifecycle_enabled);
        assert!(!coordinator.push_membership_enabled().await.unwrap());
    }
}

// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! SERVER-only operator integration on owned PostgreSQL and MinIO fixtures.
//! Uses the actual domain operator and namespace inspector, without a serving process.

use std::time::Duration;

use aws_sdk_s3::types::BucketVersioningStatus;
use aws_sdk_s3::types::VersioningConfiguration;
use clap::Parser;
use lore_server::auth::jwk::JWKServiceSettings;
use lore_server::domain::operator::DomainCommand;
use lore_server::domain::operator::run;
use lore_server::server::Cli;
use lore_server::settings::AuthSettings;
use lore_server::settings::LockStoreSettings;
use lore_server::settings::Settings;

const REVISION: &str = "clean-init-test-writer-v1";

#[test]
fn namespace_identity_binds_every_routing_field_but_not_timeout_policy() {
    use lore_postgres::store::immutable_store::ObjectStoreSettings;
    use lore_postgres::store::immutable_store::clean_namespace::clean_namespace_identity;
    let base = ObjectStoreSettings {
        bucket: "owned-bucket".into(),
        endpoint_url: Some("http://127.0.0.1:9000".into()),
        region: Some("us-east-1".into()),
        force_path_style: true,
        slow_operation_threshold_millis: 1000,
        timeout_millis: 5000,
        validate_bucket_on_startup: true,
    };
    let identity = clean_namespace_identity(&base).unwrap();
    for field in 0..4 {
        let mut changed = base.clone();
        match field {
            0 => changed.bucket.push('x'),
            1 => changed.endpoint_url = Some("http://127.0.0.1:9001".into()),
            2 => changed.region = Some("us-west-2".into()),
            _ => changed.force_path_style = false,
        }
        assert_ne!(clean_namespace_identity(&changed).unwrap(), identity);
    }
    let mut policy = base.clone();
    policy.timeout_millis += 1;
    policy.slow_operation_threshold_millis += 1;
    policy.validate_bucket_on_startup = false;
    assert_eq!(clean_namespace_identity(&policy).unwrap(), identity);
    for invalid in 0..3 {
        let mut changed = base.clone();
        match invalid {
            0 => changed.endpoint_url = None,
            1 => changed.region = None,
            _ => changed.bucket.clear(),
        }
        assert!(clean_namespace_identity(&changed).is_err());
    }
}

#[path = "common/clean_init_fixture.rs"]
mod fixture;
use fixture::Fixture;

#[test]
fn initialize_fragments_cli_requires_authority_revision_and_carries_exclusion_attestation() {
    assert!(Cli::try_parse_from(["loreserver", "domain", "initialize-fragments"]).is_err());
    let parsed = Cli::try_parse_from([
        "loreserver",
        "domain",
        "initialize-fragments",
        "--provider-write-authority-revision",
        REVISION,
        "--confirm-legacy-writers-excluded",
        "--json",
    ])
    .unwrap();
    let debug = format!("{:?}", parsed.command);
    assert!(debug.contains("InitializeFragments"));
    assert!(debug.contains("confirm_legacy_writers_excluded: true"));
    assert!(debug.contains(REVISION));
}

#[tokio::test]
async fn operator_requires_explicit_legacy_writer_exclusion_before_connecting() {
    let settings: Settings = toml::from_str(include_str!("../config/default.toml")).unwrap();
    let error = run(
        &DomainCommand::InitializeFragments {
            provider_write_authority_revision: REVISION.into(),
            confirm_legacy_writers_excluded: false,
            json: true,
        },
        &settings,
    )
    .await
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("--confirm-legacy-writers-excluded")
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL and owned MinIO required"]
async fn real_loreserver_binary_initializes_and_emits_parseable_json() {
    let fixture = Fixture::new().await;
    let directory = tempfile::tempdir().unwrap();
    let mut config: toml::Value = toml::from_str(include_str!("../config/default.toml")).unwrap();
    config["mutable_store"]["mode"] = "postgres".into();
    config["immutable_store"]["mode"] = "postgres".into();
    config.as_table_mut().unwrap().insert(
        "lock_store".into(),
        toml::from_str::<toml::Value>("mode = 'postgres'").unwrap(),
    );
    config["server"].as_table_mut().unwrap().insert("auth".into(), toml::from_str::<toml::Value>("jwt_issuer = 'https://issuer.invalid'\nenforce_write_permission = true\n[jwk]\nendpoint = 'https://issuer.invalid/jwks'").unwrap());
    config.as_table_mut().unwrap().insert(
        "plugins".into(),
        toml::Value::try_from(&fixture.settings.plugins).unwrap(),
    );
    std::fs::write(
        directory.path().join("local.toml"),
        toml::to_string(&config).unwrap(),
    )
    .unwrap();
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_loreserver"));
    command.args([
        "--config",
        directory.path().to_str().unwrap(),
        "domain",
        "initialize-fragments",
        "--provider-write-authority-revision",
        REVISION,
        "--confirm-legacy-writers-excluded",
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
        .find(|value| value["status"] == "initialized")
        .expect("CLI must emit initialized JSON report");
    assert_eq!(report["provider_write_authority_revision"], REVISION);
    assert_eq!(report["legacy_writers_excluded_attested"], true);
    assert!(
        fixture
            .store()
            .await
            .fragment_coordinator()
            .readiness()
            .await
            .unwrap()
            .ready_for_lifecycle()
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL and owned MinIO required"]
async fn actual_operator_initializes_empty_cell_and_reruns_after_later_upload() {
    let fixture = Fixture::new().await;
    fixture.assert_dark().await;
    fixture.initialize().await.unwrap();
    let store = fixture.store().await;
    let readiness = store.fragment_coordinator().readiness().await.unwrap();
    assert!(readiness.ready_for_lifecycle());
    assert!(readiness.clean_initialized);
    assert_eq!(readiness.backfill_state, 0);
    assert!(
        store
            .fragment_coordinator()
            .push_membership_enabled()
            .await
            .unwrap()
    );
    let s3 = fixture.s3.sdk_client();
    s3.put_object()
        .bucket(&fixture.bucket)
        .key("later-upload")
        .body(bytes::Bytes::from_static(b"preserve-me").into())
        .send()
        .await
        .unwrap();
    fixture.initialize().await.unwrap();
    let object = s3
        .get_object()
        .bucket(&fixture.bucket)
        .key("later-upload")
        .send()
        .await
        .unwrap();
    assert_eq!(
        object.body.collect().await.unwrap().into_bytes().as_ref(),
        b"preserve-me"
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL and owned MinIO required"]
async fn object_outside_fragment_keyspace_refuses_and_is_not_deleted() {
    let fixture = Fixture::new().await;
    let s3 = fixture.s3.sdk_client();
    s3.put_object()
        .bucket(&fixture.bucket)
        .key("unrelated/hidden-prefix/object")
        .body(bytes::Bytes::from_static(b"existing").into())
        .send()
        .await
        .unwrap();
    let error = fixture.initialize().await.unwrap_err();
    assert!(
        error.to_string().contains("bucket contains objects"),
        "{error:#}"
    );
    fixture.assert_dark().await;
    assert_eq!(
        s3.get_object()
            .bucket(&fixture.bucket)
            .key("unrelated/hidden-prefix/object")
            .send()
            .await
            .unwrap()
            .body
            .collect()
            .await
            .unwrap()
            .into_bytes()
            .as_ref(),
        b"existing"
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL and owned MinIO required"]
async fn incomplete_multipart_upload_refuses_without_aborting_it() {
    let fixture = Fixture::new().await;
    let s3 = fixture.s3.sdk_client();
    let upload = s3
        .create_multipart_upload()
        .bucket(&fixture.bucket)
        .key("pending")
        .send()
        .await
        .unwrap();
    assert!(
        s3.list_objects_v2()
            .bucket(&fixture.bucket)
            .send()
            .await
            .unwrap()
            .contents()
            .is_empty()
    );
    let error = fixture.initialize().await.unwrap_err();
    assert!(
        error.to_string().contains("incomplete multipart uploads"),
        "{error:#}"
    );
    fixture.assert_dark().await;
    let remaining = s3
        .list_multipart_uploads()
        .bucket(&fixture.bucket)
        .send()
        .await
        .unwrap();
    assert_eq!(remaining.uploads().len(), 1);
    assert_eq!(remaining.uploads()[0].upload_id(), upload.upload_id());
}

#[tokio::test]
#[ignore = "isolated PostgreSQL and owned MinIO required"]
async fn enabled_and_suspended_versioning_refuse_even_without_current_objects() {
    let fixture = Fixture::new().await;
    let s3 = fixture.s3.sdk_client();
    for status in [
        BucketVersioningStatus::Enabled,
        BucketVersioningStatus::Suspended,
    ] {
        s3.put_bucket_versioning()
            .bucket(&fixture.bucket)
            .versioning_configuration(VersioningConfiguration::builder().status(status).build())
            .send()
            .await
            .unwrap();
        assert!(
            s3.list_objects_v2()
                .bucket(&fixture.bucket)
                .send()
                .await
                .unwrap()
                .contents()
                .is_empty()
        );
        let error = fixture.initialize().await.unwrap_err();
        assert!(
            error.to_string().contains("versioning never enabled"),
            "{error:#}"
        );
        fixture.assert_dark().await;
    }
}

#[tokio::test]
#[ignore = "isolated PostgreSQL and owned MinIO required"]
async fn hidden_version_and_delete_marker_are_preserved_when_initialization_refuses() {
    let fixture = Fixture::new().await;
    let s3 = fixture.s3.sdk_client();
    s3.put_bucket_versioning()
        .bucket(&fixture.bucket)
        .versioning_configuration(
            VersioningConfiguration::builder()
                .status(BucketVersioningStatus::Enabled)
                .build(),
        )
        .send()
        .await
        .unwrap();
    s3.put_object()
        .bucket(&fixture.bucket)
        .key("hidden")
        .body(bytes::Bytes::from_static(b"retained-version").into())
        .send()
        .await
        .unwrap();
    s3.delete_object()
        .bucket(&fixture.bucket)
        .key("hidden")
        .send()
        .await
        .unwrap();
    assert!(
        s3.list_objects_v2()
            .bucket(&fixture.bucket)
            .send()
            .await
            .unwrap()
            .contents()
            .is_empty()
    );
    let before = s3
        .list_object_versions()
        .bucket(&fixture.bucket)
        .send()
        .await
        .unwrap();
    assert_eq!(before.versions().len(), 1);
    assert_eq!(before.delete_markers().len(), 1);
    assert!(
        fixture
            .initialize()
            .await
            .unwrap_err()
            .to_string()
            .contains("versioning never enabled")
    );
    fixture.assert_dark().await;
    let after = s3
        .list_object_versions()
        .bucket(&fixture.bucket)
        .send()
        .await
        .unwrap();
    assert_eq!(
        after.versions()[0].version_id(),
        before.versions()[0].version_id()
    );
    assert_eq!(
        after.delete_markers()[0].version_id(),
        before.delete_markers()[0].version_id()
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL and owned MinIO required"]
async fn actual_operator_upgrades_inactive_v2_schema_and_reruns_exactly() {
    let fixture = Fixture::new().await;
    let pool = lore_postgres::pool::build_pool(
        &fixture.url,
        1,
        &lore_postgres::pool::TlsConfig::default(),
    )
    .unwrap();
    let direct = pool.get().await.unwrap();
    direct
        .batch_execute(include_str!("common/fragment_schema_v2.sql"))
        .await
        .unwrap();
    let old=direct.query_one("SELECT schema_version, EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema='public' AND table_name='lore_fragment_schema_state' AND column_name='clean_initialized_at') FROM lore_fragment_schema_state",&[]).await.unwrap();
    assert_eq!(old.get::<_, i64>(0), 2);
    assert!(
        !old.get::<_, bool>(1),
        "fixture must actually predate clean initialization columns"
    );
    fixture.initialize().await.unwrap();
    let state = direct
        .query_one(
            "SELECT row_to_json(s)::text FROM lore_fragment_schema_state s",
            &[],
        )
        .await
        .unwrap()
        .get::<_, String>(0);
    let readiness = fixture
        .store()
        .await
        .fragment_coordinator()
        .readiness()
        .await
        .unwrap();
    assert!(readiness.clean_initialized && readiness.ready_for_lifecycle());
    assert!(
        fixture
            .store()
            .await
            .fragment_coordinator()
            .push_membership_enabled()
            .await
            .unwrap()
    );
    fixture.initialize().await.unwrap();
    assert_eq!(
        direct
            .query_one(
                "SELECT row_to_json(s)::text FROM lore_fragment_schema_state s",
                &[]
            )
            .await
            .unwrap()
            .get::<_, String>(0),
        state
    );
}

#[tokio::test]
async fn namespace_configuration_refusal_has_a_typed_class_without_provider_source() {
    use std::error::Error;

    use lore_postgres::store::immutable_store::clean_namespace::CleanNamespaceError;
    use lore_postgres::store::immutable_store::clean_namespace::CleanObjectNamespaceInspector;
    let mut object = lore_postgres::store::immutable_store::ObjectStoreSettings {
        bucket: "fixture".into(),
        endpoint_url: Some("http://localhost:1".into()),
        region: Some("us-east-1".into()),
        force_path_style: true,
        slow_operation_threshold_millis: 1000,
        timeout_millis: 5000,
        validate_bucket_on_startup: false,
    };
    object.timeout_millis = 0;
    let error = match CleanObjectNamespaceInspector::connect(object).await {
        Ok(_) => panic!("zero timeout must refuse before provider I/O"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        CleanNamespaceError::InvalidConfiguration(_)
    ));
    assert!(error.source().is_none());
}

#[tokio::test]
#[ignore = "isolated PostgreSQL and owned MinIO required"]
async fn namespace_provider_failure_preserves_source_distinct_from_refusal() {
    use std::error::Error;

    use lore_postgres::store::immutable_store::clean_namespace::CleanNamespaceError;
    use lore_postgres::store::immutable_store::clean_namespace::CleanObjectNamespaceInspector;
    let fixture = Fixture::new().await;
    let mut object = lore_postgres::store::immutable_store::ObjectStoreSettings {
        bucket: fixture.bucket.clone(),
        endpoint_url: Some(std::env::var("LORE_TEST_S3_ENDPOINT").unwrap()),
        region: Some("us-east-1".into()),
        force_path_style: true,
        slow_operation_threshold_millis: 1000,
        timeout_millis: 5000,
        validate_bucket_on_startup: false,
    };
    object.bucket = format!("missing-{}", uuid::Uuid::new_v4().simple());
    object.validate_bucket_on_startup = false;
    let inspector = CleanObjectNamespaceInspector::connect(object)
        .await
        .unwrap();
    let error = inspector.attest_unversioned().await.unwrap_err();
    assert!(matches!(
        &error,
        CleanNamespaceError::Inspection {
            operation: "bucket versioning",
            ..
        }
    ));
    assert!(error.source().is_some(), "provider SDK cause must survive");
    fixture.assert_dark().await;
    fixture
        .s3
        .sdk_client()
        .put_object()
        .bucket(&fixture.bucket)
        .key("present")
        .body(bytes::Bytes::from_static(b"existing").into())
        .send()
        .await
        .unwrap();
    let error = fixture.initialize().await.unwrap_err();
    let refusal = error
        .downcast_ref::<CleanNamespaceError>()
        .expect("operator anyhow context must preserve typed cause");
    assert!(matches!(refusal, CleanNamespaceError::ObjectsPresent));
    assert!(refusal.source().is_none());
    fixture.assert_dark().await;
}

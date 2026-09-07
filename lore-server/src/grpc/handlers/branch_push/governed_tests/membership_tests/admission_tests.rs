// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Actual activated-cell handler admission, without an operation prepare.

use super::*;

async fn watched_rows(direct: &Client) -> Vec<String> {
    let mut rows = Vec::new();
    for table in [
        "lore_domain_branches",
        "lore_mutable",
        "lore_domain_operation_receipts",
        "lore_outbox_events",
    ] {
        rows.push(direct.query_one(&format!("SELECT coalesce(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text)::text, '[]') FROM {table} t"), &[]).await.unwrap().get(0));
    }
    rows
}

async fn missing_carriage(v1: bool) {
    let url = pg_url().expect("isolated PostgreSQL required");
    let fixture = Fixture::new(&url).await;
    fixture
        .store
        .pause
        .store(false, std::sync::atomic::Ordering::SeqCst);
    let direct = direct_client(&url).await;
    // The runtime fixture bootstraps the domain schema. Maintenance also needs
    // the legacy relations, even when no old writer has populated them.
    direct
        .batch_execute(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../lore-postgres/migrations/0001_init.sql"
        )))
        .await
        .unwrap();
    direct.batch_execute("UPDATE lore_domain_schema_state SET backfill_state=3, cutover_at=clock_timestamp(), enforcement_enabled=true;
        UPDATE lore_domain_lock_schema_state SET backfill_state=2, cutover_at=clock_timestamp(), sequence_headroom_fence=1, fencing_enabled=true;
        UPDATE lore_fragment_schema_state SET backfill_state=3, residue_classified=true, cutover_at=clock_timestamp(), sequence_headroom_fence=1, lifecycle_enabled=true,
        write_capability=1, provider_write_authority_revision='admission-test', write_claims_required_at=clock_timestamp()").await.unwrap();
    fixture
        .immutable
        .coordinator
        .activate_push_membership()
        .await
        .unwrap();
    assert!(
        fixture
            .immutable
            .coordinator
            .push_membership_enabled()
            .await
            .unwrap()
    );
    let before = watched_rows(&direct).await;
    let mut request = Request::new(BranchPushRequest {
        branch: BranchId::from(fixture.branch).into(),
        revision: fixture.revision.into(),
        force: false,
        fast_forward_merge: false,
    });
    request.metadata_mut().insert_bin(
        REPOSITORY_ID_KEY,
        BinaryMetadataValue::from_bytes(&fixture.repository),
    );
    request.extensions_mut().insert(fixture.token.clone());
    for header in [OPERATION_ID_KEY, FINGERPRINT_KEY, PREPARE_TOKEN_KEY] {
        assert!(request.metadata().get_bin(header).is_none());
    }
    let notifications: Arc<dyn NotificationSender> = Arc::new(MockNotificationSender::new());
    let hooks = HookDispatcher::from_hooks_default(Vec::new());
    let result = tokio::time::timeout(Duration::from_secs(15), async {
        if v1 {
            let (metadata, extensions, body) = request.into_parts();
            let request = Request::from_parts(
                metadata,
                extensions,
                lore_proto::lore::revision::v1::BranchPushRequest {
                    id: body.branch,
                    revision_signature: body.revision,
                    force: body.force,
                    fast_forward_merge: body.fast_forward_merge,
                },
            );
            crate::grpc::revision::v1::branch_push::handler(
                request,
                fixture.immutable.clone(),
                fixture.mutable.clone(),
                notifications,
                &hooks,
                branch::DEFAULT_HISTORY_STEP_SIZE,
                RevisionListAcceleration::default(),
                &TestInstrumentProvider,
                None,
                Some(&fixture.domain),
            )
            .await
            .map(|_| ())
        } else {
            handler(
                request,
                fixture.immutable.clone(),
                fixture.mutable.clone(),
                notifications,
                &hooks,
                branch::DEFAULT_HISTORY_STEP_SIZE,
                RevisionListAcceleration::default(),
                &TestInstrumentProvider,
                None,
                Some(&fixture.domain),
            )
            .await
            .map(|_| ())
        }
    })
    .await
    .expect("handler must refuse missing carriage promptly");
    let error = result.expect_err("active cell must reject absent operation carriage");
    assert_eq!(error.code(), Code::InvalidArgument);
    assert_eq!(
        error.message(),
        format!("missing required domain-operation header {OPERATION_ID_KEY}")
    );
    assert!(
        fixture.store.captured.lock().unwrap().is_none(),
        "must not reach governed publication"
    );
    assert_eq!(
        watched_rows(&direct).await,
        before,
        "no tip, projection, receipt, or outbox mutation"
    );
    let context = Arc::new(RepositoryContext::new_server_context(
        fixture.immutable.clone(),
        fixture.mutable.clone(),
        fixture.repository.into(),
    ));
    assert_eq!(
        branch::load_latest(context, fixture.branch.into())
            .await
            .unwrap(),
        Hash::default(),
        "must not fall back to ungoverned publication"
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn v0_activated_membership_rejects_missing_carriage_without_publication() {
    missing_carriage(false).await;
}

#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn v1_activated_membership_rejects_missing_carriage_without_publication() {
    missing_carriage(true).await;
}

async fn startup_fixture(
    active: bool,
    immutable_mode: &str,
) -> anyhow::Result<crate::domain::ConfiguredDomainContext> {
    let url = pg_url().expect("isolated PostgreSQL required");
    let fixture = Fixture::new(&url).await;
    let direct = direct_client(&url).await;
    // The runtime fixture bootstraps the domain schema. Maintenance also needs
    // the legacy relations, even when no old writer has populated them.
    direct
        .batch_execute(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../lore-postgres/migrations/0001_init.sql"
        )))
        .await
        .unwrap();
    direct.batch_execute("UPDATE lore_domain_schema_state SET backfill_state=3, residue_classified=true, cutover_at=clock_timestamp(), enforcement_enabled=true;
        UPDATE lore_domain_lock_schema_state SET backfill_state=2, cutover_at=clock_timestamp(), sequence_headroom_fence=1, fencing_enabled=true;
        UPDATE lore_fragment_schema_state SET backfill_state=3, residue_classified=true, cutover_at=clock_timestamp(), sequence_headroom_fence=1, lifecycle_enabled=true,
        write_capability=1, provider_write_authority_revision='admission-test', write_claims_required_at=clock_timestamp()").await.unwrap();

    if active {
        fixture
            .immutable
            .coordinator
            .activate_push_membership()
            .await
            .unwrap();
    }
    let mut settings: crate::settings::Settings = toml::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/config/default.toml"
    )))
    .unwrap();
    settings.mutable_store.mode = "postgres".into();
    settings.immutable_store.mode = immutable_mode.into();
    settings.lock_store.as_mut().unwrap().mode = "postgres".into();
    settings.server.auth = Some(crate::settings::AuthSettings {
        jwk: Some(crate::auth::jwk::JWKServiceSettings {
            endpoint: "https://issuer.example/.well-known/jwks.json".into(),
        }),
        jwt_audience: None,
        jwt_issuer: Some("https://issuer.example".into()),
        enforce_write_permission: true,
    });
    settings.plugins.insert(
        "postgres".into(),
        toml::from_str(&format!("url = {url:?}\npool_max = 2\ndomain_pool_max = 2")).unwrap(),
    );
    crate::domain::configure_domain_context(&settings).await
}

#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn active_membership_startup_rejects_non_postgres_immutable_authority() {
    let error = startup_fixture(true, "local")
        .await
        .err()
        .expect("mixed authority must refuse startup");
    assert_eq!(
        error.to_string(),
        "fragment push protocol requires immutable_store.mode = 'postgres'"
    );
}

#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn active_membership_startup_attaches_colocated_postgres_authority() {
    let configured = startup_fixture(true, "postgres").await.unwrap();
    let context = configured.context.unwrap();
    assert!(context.fragment_coordinator().is_some());
    assert!(context.lock_coordinator().is_some());
}

#[tokio::test]
#[ignore = "isolated PostgreSQL required"]
async fn dark_membership_startup_preserves_mixed_store_configuration() {
    let configured = startup_fixture(false, "local").await.unwrap();
    let context = configured.context.unwrap();
    assert!(context.fragment_coordinator().is_none());
    assert!(context.lock_coordinator().is_some());
}

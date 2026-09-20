// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Paired policy rotation against real authority state, without a running server.
#![cfg(target_os = "linux")]

use std::sync::Arc;
use std::time::Duration;

use lore_object_dispatch::dispatch_client::DispatchDatabaseIdentity;
use lore_object_dispatch::dispatch_pool::DispatchConnectionBudget;
use lore_object_dispatch::dispatch_pool::DispatchPoolConfig;
use lore_object_dispatch::dispatch_pool::DispatchPoolRole;
use lore_object_dispatch::dispatch_pool::DispatchRuntimePool;
use lore_object_dispatch::dispatch_pool::DispatchTlsMode;
use lore_object_dispatch::drain_policy::DrainClient;
use lore_object_dispatch::drain_policy::DrainDescriptor;
use lore_object_dispatch::drain_policy::DrainPolicy;
use lore_object_dispatch::drain_policy::hex;
use lore_object_dispatch::spool::SpoolLayout;
use lore_object_dispatch::spool::SpoolObjectKey;
use lore_object_dispatch::spool::SpoolObjectKind;
use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::fragments::BeginOutcome;
use lore_postgres::domain::fragments::StageReservationInput;
use lore_postgres::pool::TlsConfig;
use tokio_util::task::AbortOnDropHandle;
use uuid::Uuid;

struct Fixture {
    admin: tokio_postgres::Client,
    _connection: AbortOnDropHandle<()>,
    domain: PostgresDomainStore,
    maintenance: DrainClient,
    runtime: DrainClient,
    policy: DrainPolicy,
}

impl Fixture {
    async fn open() -> Self {
        let helper =
            std::env::var("LORE_TEST_ADAPTER_SETUP_BIN").expect("supported fixture helper");
        let setup = std::process::Command::new(helper).output().unwrap();
        assert!(
            setup.status.success(),
            "{}",
            String::from_utf8_lossy(&setup.stderr)
        );
        let setup: serde_json::Value = serde_json::from_slice(&setup.stdout).unwrap();
        let url = std::env::var("LORE_TEST_PG_URL").expect("fresh owned PostgreSQL database");
        assert!(url.starts_with("postgresql://postgres@"));
        let domain = PostgresDomainStore::connect(&url, 2, &TlsConfig::default())
            .await
            .unwrap();
        domain.fragment_coordinator().bootstrap().await.unwrap();
        let (admin, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .unwrap();
        let connection = AbortOnDropHandle::new(lore_base::lore_spawn!(async move {
            connection.await.unwrap();
        }));
        let identity = DispatchDatabaseIdentity::new(
            setup["system"].as_str().unwrap().parse().unwrap(),
            u32::try_from(setup["oid"].as_u64().unwrap()).unwrap(),
        )
        .unwrap();
        let client = |role: DispatchPoolRole| {
            let pool = DispatchRuntimePool::new(DispatchPoolConfig {
                postgres_url: format!(
                    "{}?sslmode=disable",
                    url.replacen("://postgres@", &format!("://{}@", role.role_name()), 1)
                ),
                role,
                expected_database_identity: identity,
                pool_max: 1,
                connect_timeout: Duration::from_secs(5),
                acquire_timeout: Duration::from_secs(5),
                statement_timeout: Duration::from_secs(5),
                lock_timeout: Duration::from_secs(5),
                tls: DispatchTlsMode::Disabled,
                budget: DispatchConnectionBudget::new(1, 1, 0, 2, 1, 0).unwrap(),
            })
            .unwrap();
            DrainClient::new(Arc::new(pool))
        };
        let maintenance = client(DispatchPoolRole::Maintenance);
        let runtime = client(DispatchPoolRole::Runtime);
        let digest =
            lore_object_dispatch::drain_policy::decode_digest(setup["digest"].as_str().unwrap())
                .unwrap();
        let (policy, _, _, _) = runtime
            .read(
                "adapter-boundary",
                "adapter-cell",
                "adapter-policy-v1",
                &digest,
            )
            .await
            .unwrap();
        maintenance.configure(&policy, true).await.unwrap();
        Self {
            admin,
            _connection: connection,
            domain,
            maintenance,
            runtime,
            policy,
        }
    }

    async fn now(&self) -> u64 {
        u64::try_from(
            self.admin
                .query_one(
                    "SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint",
                    &[],
                )
                .await
                .unwrap()
                .get::<_, i64>(0),
        )
        .unwrap()
    }

    async fn wait_until(&self, deadline: u64) {
        tokio::time::timeout(Duration::from_secs(10), async {
            while self.now().await <= deadline {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("real database deadline elapsed");
    }

    async fn next(&self, revision: &str) -> DrainPolicy {
        let mut policy = self.policy.clone();
        policy.revision = revision.into();
        policy.expires_at_ms = self.now().await + 3_600_000;
        policy
    }

    async fn assert_pin(&self, policy: &DrainPolicy, valid: bool) {
        assert_eq!(
            self.runtime
                .read(
                    &policy.boundary,
                    &policy.cell,
                    &policy.revision,
                    &policy.digest().unwrap()
                )
                .await
                .is_ok(),
            valid
        );
        assert_eq!(
            self.domain
                .fragment_coordinator()
                .verify_stage_policy(&policy.cell, &policy.revision, &policy.digest().unwrap(),)
                .await
                .is_ok(),
            valid
        );
    }

    async fn snapshot(&self) -> String {
        self.admin.query_one(
            "SELECT jsonb_build_object(
              'dispatch', (SELECT jsonb_agg(to_jsonb(t) ORDER BY boundary,cell) FROM object_store_retention.drain_policies t),
              'stage', (SELECT jsonb_agg(to_jsonb(t)) FROM lore_fragment_stage_policy t),
              'dispatch_usage', (SELECT jsonb_agg(to_jsonb(t) ORDER BY provider_boundary_id,scope_kind,scope_id,quota_class) FROM object_store_retention.object_dispatch_quota_usage t),
              'dispatch_metadata', (SELECT jsonb_agg(jsonb_build_array(metadata_bytes,metadata_rows) ORDER BY boundary,cell) FROM object_store_retention.drain_policies),
              'stage_usage', (SELECT jsonb_agg(to_jsonb(t)) FROM lore_fragment_stage_usage t),
              'stage_custody', (SELECT jsonb_agg(to_jsonb(t) ORDER BY hash,epoch) FROM lore_fragment_stage_custody t),
              'spool', (SELECT jsonb_agg(to_jsonb(t) ORDER BY spool_id) FROM object_store_retention.drain_spool_custody t)
            )::text", &[],
        ).await.unwrap().get(0)
    }

    async fn reserve(&self, policy: &DrainPolicy) -> DrainDescriptor {
        let (_, allocation_revision, allocation_fence, allocation_expiry_ms) = self
            .runtime
            .read(
                &policy.boundary,
                &policy.cell,
                &policy.revision,
                &policy.digest().unwrap(),
            )
            .await
            .unwrap();
        let now = self.now().await;
        let logical_request_id = Uuid::now_v7();
        let attempt_id = Uuid::now_v7();
        let layout =
            SpoolLayout::new(std::env::temp_dir().join("rotation-authority-only-spool")).unwrap();
        let paths = layout
            .derive_paths(&SpoolObjectKey {
                provider_boundary_id: policy.boundary.clone(),
                logical_request_id: logical_request_id.to_string(),
                attempt_id: attempt_id.to_string(),
                kind: SpoolObjectKind::Put,
            })
            .unwrap();
        let body = b"rotation";
        let descriptor = DrainDescriptor {
            policy_revision: policy.revision.clone(),
            policy_digest: hex(&policy.digest().unwrap()),
            boundary: policy.boundary.clone(),
            cell: policy.cell.clone(),
            service: policy.service.clone(),
            logical_request_id,
            attempt_id,
            upload_id: Uuid::now_v7(),
            spool_object_id: Uuid::now_v7(),
            upload_fence: 1,
            source_hash: hex(blake3::hash(body).as_bytes()),
            source_epoch: 1,
            source_manifest: hex(&[0x31; 32]),
            remote_epoch: 2,
            remote_fence: 3,
            object_key: "rotation-target".into(),
            body_digest: hex(blake3::hash(body).as_bytes()),
            body_size: body.len() as u64,
            send_not_after_ms: now + 100,
            hard_not_after_ms: now + 200,
            prepared_ttl_ms: policy.maximum_ttl_ms,
            max_chunk_bytes: 262_144,
            allocation_revision,
            allocation_fence,
            allocation_expiry_ms,
            boundary_digest: hex(paths.boundary_binding().boundary_blake3()),
            boundary_token: paths.boundary_binding().boundary_token().to_owned(),
            observation_digest: hex(&paths.observation_binding_blake3()),
        };
        self.runtime.reserve(&descriptor).await.unwrap();
        descriptor
    }
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL with genuine BLAKE3 and the dispatch fixture helper"]
async fn paired_rotation_succeeds_before_and_after_expiry_and_old_pins_fail() {
    let fixture = Fixture::open().await;
    let mut short = fixture.next("rotation-001").await;
    short.expires_at_ms = fixture.now().await + 1500;
    fixture
        .maintenance
        .rotate(
            &short,
            &fixture.policy.revision,
            &fixture.policy.digest().unwrap(),
        )
        .await
        .unwrap();
    fixture.assert_pin(&short, true).await;
    fixture.assert_pin(&fixture.policy, false).await;
    fixture.wait_until(short.expires_at_ms).await;
    fixture.assert_pin(&short, false).await;
    let next = fixture.next("rotation-002").await;
    fixture
        .maintenance
        .rotate(&next, &short.revision, &short.digest().unwrap())
        .await
        .unwrap();
    fixture.assert_pin(&next, true).await;
    fixture.assert_pin(&short, false).await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL with genuine BLAKE3 and the dispatch fixture helper"]
async fn paired_rotation_requires_maintenance_exact_cas_and_monotonic_revision() {
    let fixture = Fixture::open().await;
    let next = fixture.next("rotation-001").await;
    let before = fixture.snapshot().await;
    assert!(
        fixture
            .runtime
            .rotate(
                &next,
                &fixture.policy.revision,
                &fixture.policy.digest().unwrap()
            )
            .await
            .is_err()
    );
    for (revision, digest) in [
        ("wrong-old", fixture.policy.digest().unwrap()),
        (fixture.policy.revision.as_str(), [0x55; 32]),
    ] {
        assert!(
            fixture
                .maintenance
                .rotate(&next, revision, &digest)
                .await
                .is_err()
        );
        assert_eq!(fixture.snapshot().await, before);
    }
    assert!(
        fixture
            .maintenance
            .rotate(
                &fixture.policy,
                &fixture.policy.revision,
                &fixture.policy.digest().unwrap()
            )
            .await
            .is_err()
    );
    let mut changed = fixture.policy.clone();
    changed.stage.max_files += 1;
    assert!(
        fixture.maintenance.configure(&changed, true).await.is_err(),
        "publish cannot overwrite a revision"
    );
    assert_eq!(fixture.snapshot().await, before);
    fixture
        .maintenance
        .rotate(
            &next,
            &fixture.policy.revision,
            &fixture.policy.digest().unwrap(),
        )
        .await
        .unwrap();
    let committed = fixture.snapshot().await;
    // The first result is deliberately not used to decide whether to retry.
    // Exact replay uses the original predecessor after both authorities committed.
    fixture
        .maintenance
        .rotate(
            &next,
            &fixture.policy.revision,
            &fixture.policy.digest().unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        fixture.snapshot().await,
        committed,
        "lost-reply replay changes no state"
    );
    for (revision, digest) in [
        ("wrong-predecessor", fixture.policy.digest().unwrap()),
        (fixture.policy.revision.as_str(), [0x66; 32]),
    ] {
        assert!(
            fixture
                .maintenance
                .rotate(&next, revision, &digest)
                .await
                .is_err()
        );
        assert_eq!(
            fixture.snapshot().await,
            committed,
            "exact current policy still requires its saved predecessor"
        );
    }
    let mut conflicting = next.clone();
    conflicting.stage.max_files += 1;
    assert!(
        fixture
            .maintenance
            .rotate(
                &conflicting,
                &fixture.policy.revision,
                &fixture.policy.digest().unwrap()
            )
            .await
            .is_err()
    );
    assert!(
        fixture
            .maintenance
            .rotate(&fixture.policy, &next.revision, &next.digest().unwrap())
            .await
            .is_err(),
        "reused older revision refuses"
    );
    assert_eq!(fixture.snapshot().await, committed);
    let numeric = fixture.next("rotation-2").await;
    fixture
        .maintenance
        .rotate(&numeric, &next.revision, &next.digest().unwrap())
        .await
        .unwrap();
    let lexical_older = fixture.next("rotation-10").await;
    assert!(
        fixture
            .maintenance
            .rotate(
                &lexical_older,
                &numeric.revision,
                &numeric.digest().unwrap()
            )
            .await
            .is_err()
    );
    let unicode = fixture.next("rotation-ä").await;
    fixture
        .maintenance
        .rotate(&unicode, &numeric.revision, &numeric.digest().unwrap())
        .await
        .unwrap();
    let ascii_older = fixture.next("rotation-z").await;
    assert!(
        fixture
            .maintenance
            .rotate(&ascii_older, &unicode.revision, &unicode.digest().unwrap())
            .await
            .is_err()
    );
    fixture.assert_pin(&unicode, true).await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL with genuine BLAKE3 and the dispatch fixture helper"]
async fn paired_rotation_refuses_active_stage_and_rolls_back_dispatch_changes() {
    let fixture = Fixture::open().await;
    let next = fixture.next("rotation-001").await;
    for table in [
        "object_store_retention.drain_policies",
        "public.lore_fragment_stage_policy",
    ] {
        fixture
            .admin
            .batch_execute(&format!("BEGIN; LOCK TABLE {table} IN ACCESS SHARE MODE"))
            .await
            .unwrap();
        let refused = tokio::time::timeout(
            Duration::from_secs(1),
            fixture.maintenance.rotate(
                &next,
                &fixture.policy.revision,
                &fixture.policy.digest().unwrap(),
            ),
        )
        .await;
        fixture.admin.batch_execute("ROLLBACK").await.unwrap();
        assert!(
            refused
                .expect("NOWAIT must not wait for the five-second lock timeout")
                .is_err()
        );
    }
    fixture
        .admin
        .batch_execute("UPDATE lore_fragment_stage_policy SET revision='diverged-stage-pin'")
        .await
        .unwrap();
    let divergent = fixture.snapshot().await;
    assert!(
        fixture
            .maintenance
            .rotate(
                &next,
                &fixture.policy.revision,
                &fixture.policy.digest().unwrap()
            )
            .await
            .is_err()
    );
    assert_eq!(fixture.snapshot().await, divergent);
    fixture
        .admin
        .execute(
            "UPDATE lore_fragment_stage_policy SET revision=$1",
            &[&fixture.policy.revision],
        )
        .await
        .unwrap();
    assert!(matches!(
        fixture
            .domain
            .fragment_coordinator()
            .begin_stage(
                &[0x41; 32],
                StageReservationInput {
                    size_payload: 8,
                    original_flags: 0,
                }
            )
            .await
            .unwrap(),
        BeginOutcome::Admitted(_)
    ));
    let before = fixture.snapshot().await;
    let next = fixture.next("rotation-001").await;
    assert!(
        fixture
            .maintenance
            .rotate(
                &next,
                &fixture.policy.revision,
                &fixture.policy.digest().unwrap()
            )
            .await
            .is_err()
    );
    assert_eq!(
        fixture.snapshot().await,
        before,
        "stage refusal rolls back the paired dispatch mutation"
    );
    fixture.assert_pin(&fixture.policy, true).await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL with genuine BLAKE3 and the dispatch fixture helper"]
async fn paired_rotation_refuses_live_spool_then_preserves_compact_markers_and_usage() {
    let fixture = Fixture::open().await;
    let mut short = fixture.next("rotation-001").await;
    short.maximum_ttl_ms = 1000;
    short.expires_at_ms = fixture.now().await + 5000;
    fixture
        .maintenance
        .rotate(
            &short,
            &fixture.policy.revision,
            &fixture.policy.digest().unwrap(),
        )
        .await
        .unwrap();
    let descriptor = fixture.reserve(&short).await;
    let second_descriptor = fixture.reserve(&short).await;
    let before = fixture.snapshot().await;
    let next = fixture.next("rotation-002").await;
    assert!(
        fixture
            .maintenance
            .rotate(&next, &short.revision, &short.digest().unwrap())
            .await
            .is_err()
    );
    assert_eq!(fixture.snapshot().await, before);
    fixture
        .wait_until(second_descriptor.hard_not_after_ms + short.maximum_ttl_ms + 100)
        .await;
    let cleanup = fixture
        .runtime
        .claim_cleanup(descriptor.spool_object_id)
        .await
        .unwrap();
    fixture.runtime.release_cleanup(&cleanup).await.unwrap();
    let second_cleanup = fixture
        .runtime
        .claim_cleanup(second_descriptor.spool_object_id)
        .await
        .unwrap();
    fixture
        .runtime
        .release_cleanup(&second_cleanup)
        .await
        .unwrap();
    let coordinator = fixture.domain.fragment_coordinator();
    let orphan = coordinator
        .begin_stage_cleanup(&[0x42; 32], 71)
        .await
        .unwrap()
        .unwrap();
    coordinator.commit_stage_cleanup(&orphan).await.unwrap();
    let second_orphan = coordinator
        .begin_stage_cleanup(&[0x43; 32], 72)
        .await
        .unwrap()
        .unwrap();
    coordinator
        .commit_stage_cleanup(&second_orphan)
        .await
        .unwrap();
    let before: serde_json::Value = serde_json::from_str(&fixture.snapshot().await).unwrap();
    assert_eq!(before["spool"].as_array().unwrap().len(), 2);
    assert_eq!(before["stage_custody"].as_array().unwrap().len(), 2);
    for stage in [false, true] {
        let mut too_small = next.clone();
        if stage {
            too_small.stage.max_metadata_rows = 1;
        } else {
            too_small.metadata_max_rows = 1;
        }
        assert!(
            fixture
                .maintenance
                .rotate(&too_small, &short.revision, &short.digest().unwrap())
                .await
                .is_err()
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&fixture.snapshot().await).unwrap(),
            before
        );
    }
    fixture
        .maintenance
        .rotate(&next, &short.revision, &short.digest().unwrap())
        .await
        .unwrap();
    let after: serde_json::Value = serde_json::from_str(&fixture.snapshot().await).unwrap();
    for name in [
        "stage_usage",
        "stage_custody",
        "spool",
        "dispatch_usage",
        "dispatch_metadata",
    ] {
        assert_eq!(after[name], before[name], "rotation preserves {name}");
    }
    fixture.runtime.release_cleanup(&cleanup).await.unwrap();
    coordinator.commit_stage_cleanup(&orphan).await.unwrap();
    let replayed: serde_json::Value = serde_json::from_str(&fixture.snapshot().await).unwrap();
    for name in [
        "stage_usage",
        "stage_custody",
        "spool",
        "dispatch_usage",
        "dispatch_metadata",
    ] {
        assert_eq!(
            replayed[name], after[name],
            "old cleanup replay cannot refund twice"
        );
    }
    fixture.wait_until(short.expires_at_ms).await;
    assert!(fixture.now().await < next.expires_at_ms);
    fixture.runtime.release_cleanup(&cleanup).await.unwrap();
    fixture
        .runtime
        .release_cleanup(&second_cleanup)
        .await
        .unwrap();
    let compacted: serde_json::Value = serde_json::from_str(&fixture.snapshot().await).unwrap();
    assert!(
        compacted["spool"]
            .as_array()
            .unwrap()
            .iter()
            .all(|row| row["state"] == 4 && row["descriptor"].is_null())
    );
    assert_eq!(
        compacted["dispatch_usage"], after["dispatch_usage"],
        "compaction does not refund live quota again"
    );
    fixture.runtime.release_cleanup(&cleanup).await.unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&fixture.snapshot().await).unwrap(),
        compacted
    );
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL with genuine BLAKE3 and the dispatch fixture helper"]
async fn paired_rotation_rolls_back_stage_when_dispatch_update_fails() {
    let fixture = Fixture::open().await;
    let before = fixture.snapshot().await;
    fixture.admin.batch_execute(
        "CREATE FUNCTION public.rotation_test_refuse_update() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN IF (SELECT revision FROM public.lore_fragment_stage_policy WHERE singleton)='rotation-001' THEN RAISE EXCEPTION 'TEST_AFTER_STAGE_ROTATION'; END IF; RETURN NEW; END $$;
         CREATE TRIGGER rotation_test_refuse_update BEFORE UPDATE ON object_store_retention.drain_policies FOR EACH ROW EXECUTE FUNCTION public.rotation_test_refuse_update();"
    ).await.unwrap();
    let next = fixture.next("rotation-001").await;
    assert!(
        fixture
            .maintenance
            .rotate(
                &next,
                &fixture.policy.revision,
                &fixture.policy.digest().unwrap()
            )
            .await
            .is_err()
    );
    assert_eq!(
        fixture.snapshot().await,
        before,
        "dispatch failure after stage update rolls back both authorities"
    );
    fixture.assert_pin(&fixture.policy, true).await;
    fixture.assert_pin(&next, false).await;
    fixture.admin.batch_execute("DROP TRIGGER rotation_test_refuse_update ON object_store_retention.drain_policies; DROP FUNCTION public.rotation_test_refuse_update();").await.unwrap();
    fixture
        .maintenance
        .rotate(
            &next,
            &fixture.policy.revision,
            &fixture.policy.digest().unwrap(),
        )
        .await
        .unwrap();
    fixture.assert_pin(&next, true).await;
}

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_object_dispatch::DispatchTlsMode;
use lore_object_dispatch::cell_budget_configure::BudgetAction;
use lore_object_dispatch::cell_budget_configure::BudgetConfigureError;
use lore_object_dispatch::cell_budget_configure::BudgetPredecessor;
use lore_object_dispatch::cell_budget_configure::LEGACY_LOCAL_BUDGET_REVISION;
use lore_object_dispatch::cell_budget_configure::LOCAL_BUDGET_REVISION;
use lore_object_dispatch::cell_budget_configure::LocalBudgetConfiguration;
use lore_object_dispatch::cell_budget_configure::configure_budget;
use uuid::Uuid;
#[path = "common/budget_configuration.rs"]
mod configuration;
#[path = "common/budget_fixture.rs"]
mod fixture;
use fixture::BudgetFixture;

async fn config(f: &BudgetFixture) -> LocalBudgetConfiguration {
    let now: i64 = f
        .admin
        .query_one("SELECT object_store_retention.clock_unix_ms_v1()", &[])
        .await
        .unwrap()
        .get(0);
    configuration::config(f.system_identifier, f.database_oid, now)
}

async fn apply(
    f: &BudgetFixture,
    c: &LocalBudgetConfiguration,
    action: BudgetAction,
) -> Result<lore_object_dispatch::cell_budget_configure::BudgetReceipt, BudgetConfigureError> {
    configure_budget(
        c,
        &f.maintenance_url(),
        DispatchTlsMode::PinnedRootCa(f.pem.clone()),
        action,
    )
    .await
}

async fn charge(f: &BudgetFixture, c: &LocalBudgetConfiguration, count: usize) {
    let (runtime, _connection) = fixture::connect(
        &f.base
            .replace("postgres@", "object_dispatch_retention_runtime@"),
        &f.pem,
    )
    .await;
    for _ in 0..count {
        let sql = format!(
            "BEGIN ISOLATION LEVEL SERIALIZABLE; SELECT (object_store_retention.object_store_dispatch_charge_provider_attempt_v1('object-store-dispatch-budget-limiter-v1', '{}', 1::smallint, 1::smallint, 1::bigint::object_store_retention.uint64, '{}', {}::bigint::object_store_retention.uint64, '{}'::uuid, '{}'::uuid, 1, (floor(extract(epoch FROM clock_timestamp())*1000)+10000)::bigint, ARRAY[1,2]::smallint[])).result_code AS verdict",
            c.provider_boundary_id,
            c.allocation_revision,
            c.allocation_fence,
            Uuid::now_v7(),
            Uuid::now_v7()
        );
        let rows = runtime.simple_query(&sql).await.unwrap();
        let verdict = rows.iter().find_map(|row| match row {
            tokio_postgres::SimpleQueryMessage::Row(row) => row.get("verdict"),
            _ => None,
        });
        assert_eq!(verdict, Some("GRANTED"));
        runtime.batch_execute("COMMIT").await.unwrap();
    }
}

#[tokio::test]
#[ignore = "requires the owned TLS PostgreSQL runner"]
async fn live_budget_publish_verify_replay_preserves_depletion() {
    let f = BudgetFixture::new().await;
    let c = config(&f).await;
    assert_eq!(
        apply(&f, &c, BudgetAction::Publish).await.unwrap().result,
        "PUBLISHED"
    );
    charge(&f, &c, 1).await;
    let before = f.snapshot().await;
    assert_ne!(before, "[]");
    assert_eq!(
        apply(&f, &c, BudgetAction::Verify).await.unwrap().result,
        "VERIFIED"
    );
    assert_eq!(
        f.snapshot().await,
        before,
        "verify must roll back all changes"
    );
    assert_eq!(
        apply(&f, &c, BudgetAction::Publish).await.unwrap().result,
        "REPLAY"
    );
    assert_eq!(
        f.snapshot().await,
        before,
        "startup replay must not refill spent budget"
    );
}

#[tokio::test]
#[ignore = "requires the owned TLS PostgreSQL runner"]
async fn live_budget_exact_binding_drift_and_absence_refuse() {
    let f = BudgetFixture::new().await;
    let c = config(&f).await;
    assert_eq!(
        apply(&f, &c, BudgetAction::Verify).await.unwrap_err(),
        BudgetConfigureError::NotPublished
    );
    assert_eq!(
        f.snapshot().await,
        "[]",
        "verify of absent config cannot publish it"
    );
    apply(&f, &c, BudgetAction::Publish).await.unwrap();
    let before = f.snapshot().await;
    for field in ["providerEndpoint", "providerBucket", "evidenceReference"] {
        let mut value = serde_json::to_value(&c).unwrap();
        value[field] = serde_json::json!(if field == "providerEndpoint" {
            "http://localhost:9000"
        } else {
            "other"
        });
        let changed =
            LocalBudgetConfiguration::from_json(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(
            apply(&f, &changed, BudgetAction::Verify).await.unwrap_err(),
            BudgetConfigureError::AuthorityRefused,
            "{field}"
        );
        assert_eq!(f.snapshot().await, before);
    }
    let mut expired = c.clone();
    expired.issued_at_unix_ms -= 180_000;
    expired.hard_expires_at_unix_ms -= 180_000;
    assert_eq!(
        apply(&f, &expired, BudgetAction::Verify).await.unwrap_err(),
        BudgetConfigureError::InvalidConfiguration
    );
}

#[tokio::test]
#[ignore = "requires the owned TLS PostgreSQL runner"]
async fn live_budget_wrong_role_tls_and_database_identity_refuse() {
    let f = BudgetFixture::new().await;
    let c = config(&f).await;
    for url in [
        &f.base,
        &f.base
            .replace("postgres@", "object_dispatch_retention_runtime@"),
    ] {
        assert_eq!(
            configure_budget(
                &c,
                url,
                DispatchTlsMode::PinnedRootCa(f.pem.clone()),
                BudgetAction::Publish
            )
            .await
            .unwrap_err(),
            BudgetConfigureError::ConnectionRefused
        );
    }
    assert_eq!(
        configure_budget(
            &c,
            &f.maintenance_url(),
            DispatchTlsMode::Disabled,
            BudgetAction::Publish
        )
        .await
        .unwrap_err(),
        BudgetConfigureError::ConnectionRefused
    );
    assert_eq!(
        configure_budget(
            &c,
            &f.maintenance_url(),
            DispatchTlsMode::PinnedRootCa("invalid CA".into()),
            BudgetAction::Publish
        )
        .await
        .unwrap_err(),
        BudgetConfigureError::ConnectionRefused
    );
    let mut wrong = c.clone();
    wrong.database_oid += 1;
    assert_eq!(
        apply(&f, &wrong, BudgetAction::Publish).await.unwrap_err(),
        BudgetConfigureError::ConnectionRefused
    );
    assert_eq!(f.snapshot().await, "[]");
}

#[tokio::test]
#[ignore = "requires the owned TLS PostgreSQL runner"]
async fn live_budget_renewal_carries_depletion_without_reset() {
    let f = BudgetFixture::new().await;
    let c = config(&f).await;
    let receipt = apply(&f, &c, BudgetAction::Publish).await.unwrap();
    charge(&f, &c, 60).await;
    let before = f.snapshot().await;
    let mut successor = c.clone();
    successor.allocation_revision = "budget-v2".into();
    successor.allocation_fence = 2;
    successor.hard_expires_at_unix_ms += 60_000;
    successor.predecessor = Some(BudgetPredecessor {
        allocation_fence: 1,
        disposition_id: receipt.disposition_id,
        disposition_digest: receipt.disposition_digest,
        envelope_digest: receipt.envelope_digest,
    });
    assert_eq!(
        apply(&f, &successor, BudgetAction::Verify)
            .await
            .unwrap_err(),
        BudgetConfigureError::NotPublished
    );
    assert_eq!(
        f.snapshot().await,
        before,
        "unpublished successor verify rolls back carry-forward"
    );
    apply(&f, &successor, BudgetAction::Publish).await.unwrap();
    let depleted: bool = f.admin.query_one("SELECT available_scaled < 100 * 60000 FROM object_store_retention.object_dispatch_budget_bucket_state WHERE cap_class=1 AND allocation_fence=2", &[]).await.unwrap().get(0);
    assert!(
        depleted,
        "renewal carries depletion from actual grants instead of resetting to full"
    );
    assert_eq!(
        apply(&f, &successor, BudgetAction::Verify)
            .await
            .unwrap()
            .result,
        "VERIFIED"
    );
}

#[tokio::test]
#[ignore = "requires the owned TLS PostgreSQL runner"]
async fn live_budget_legacy_replay_and_v2_successor_preserve_old_identity_and_depletion() {
    let f = BudgetFixture::new().await;
    let mut legacy = config(&f).await;
    legacy.schema_revision = LEGACY_LOCAL_BUDGET_REVISION.into();
    // Use the pre-V2 derivation independently of the operator. Ensure this fixture exercises
    // the legacy non-V7 shape, irrespective of the database identity and current clock.
    let (old_id, old_disposition, old_envelope) = (0..100)
        .find_map(|nonce| {
            legacy.evidence_reference = format!("legacy UUID compatibility fixture {nonce}");
            let canonical = serde_json::to_vec(&legacy).unwrap();
            let core = blake3::derive_key("Commit0 local development budget core v1", &canonical);
            let disposition =
                blake3::derive_key("Commit0 local development no-cache disposition v1", &core);
            let id = Uuid::from_bytes(disposition[..16].try_into().unwrap());
            (id.get_version_num() != 7).then(|| {
                let envelope = blake3::derive_key(
                    "Commit0 local development budget envelope v1",
                    &disposition,
                );
                (
                    id.to_string(),
                    blake3::Hash::from(disposition).to_hex().to_string(),
                    blake3::Hash::from(envelope).to_hex().to_string(),
                )
            })
        })
        .expect("fixture must contain an actual non-V7 predecessor");
    let receipt = apply(&f, &legacy, BudgetAction::Publish).await.unwrap();
    assert_eq!(receipt.result, "PUBLISHED");
    assert_eq!(receipt.disposition_id, old_id);
    assert_eq!(receipt.disposition_digest, old_disposition);
    assert_eq!(receipt.envelope_digest, old_envelope);
    charge(&f, &legacy, 60).await;
    let buckets_before = f.snapshot().await;
    let old_row_sql = "SELECT to_jsonb(c)::text FROM object_store_retention.object_dispatch_budget_configurations c WHERE allocation_fence=1";
    let old_row: String = f.admin.query_one(old_row_sql, &[]).await.unwrap().get(0);
    for (action, result) in [
        (BudgetAction::Publish, "REPLAY"),
        (BudgetAction::Verify, "VERIFIED"),
        (BudgetAction::Reconcile, "RECONCILED"),
    ] {
        let replay = apply(&f, &legacy, action).await.unwrap();
        assert_eq!(replay.result, result);
        assert_eq!(replay.disposition_id, old_id);
        assert_eq!(replay.disposition_digest, old_disposition);
        assert_eq!(replay.envelope_digest, old_envelope);
        assert_eq!(f.snapshot().await, buckets_before);
        assert_eq!(
            f.admin
                .query_one(old_row_sql, &[])
                .await
                .unwrap()
                .get::<_, String>(0),
            old_row
        );
    }
    let mut successor = config(&f).await;
    successor.schema_revision = LOCAL_BUDGET_REVISION.into();
    successor.allocation_revision = "budget-v2".into();
    successor.allocation_fence = 2;
    successor.predecessor = Some(BudgetPredecessor {
        allocation_fence: 1,
        disposition_id: old_id.clone(),
        disposition_digest: old_disposition.clone(),
        envelope_digest: old_envelope.clone(),
    });
    assert_eq!(
        apply(&f, &successor, BudgetAction::Verify)
            .await
            .unwrap_err(),
        BudgetConfigureError::NotPublished
    );
    assert_eq!(f.snapshot().await, buckets_before);
    let next = apply(&f, &successor, BudgetAction::Publish).await.unwrap();
    assert_eq!(next.result, "PUBLISHED");
    let id = Uuid::parse_str(&next.disposition_id).unwrap();
    assert_eq!(id.get_version_num(), 7);
    assert_eq!(id.get_variant(), uuid::Variant::RFC4122);
    assert_eq!(
        &id.as_bytes()[..6],
        &successor.issued_at_unix_ms.to_be_bytes()[2..]
    );
    assert_eq!(
        f.admin
            .query_one(old_row_sql, &[])
            .await
            .unwrap()
            .get::<_, String>(0),
        old_row
    );
    let prior_buckets: String = f.admin.query_one("SELECT jsonb_agg(to_jsonb(s) ORDER BY cap_class)::text FROM object_store_retention.object_dispatch_budget_bucket_state s WHERE allocation_fence=1", &[]).await.unwrap().get(0);
    assert_eq!(prior_buckets, buckets_before);
    let stored = f.admin.query_one("SELECT predecessor_disposition_id::text, encode(predecessor_disposition_digest, 'hex'), encode(expected_prior_head_digest, 'hex'), expected_prior_head_revision::text, disposition_id::text FROM object_store_retention.object_dispatch_budget_configurations WHERE allocation_fence=2", &[]).await.unwrap();
    assert_eq!(stored.get::<_, String>(0), old_id);
    assert_eq!(stored.get::<_, String>(1), old_disposition);
    assert_eq!(stored.get::<_, String>(2), old_envelope);
    assert_eq!(stored.get::<_, String>(3), "1");
    assert_eq!(stored.get::<_, String>(4), next.disposition_id);
    let depleted: bool = f.admin.query_one("SELECT available_scaled < 100 * 60000 FROM object_store_retention.object_dispatch_budget_bucket_state WHERE cap_class=1 AND allocation_fence=2", &[]).await.unwrap().get(0);
    assert!(depleted, "V1-to-V2 renewal must carry the spent budget");
    let after = f.snapshot().await;
    for action in [
        BudgetAction::Publish,
        BudgetAction::Verify,
        BudgetAction::Reconcile,
    ] {
        let replay = apply(&f, &successor, action).await.unwrap();
        assert_eq!(replay.disposition_id, next.disposition_id);
        assert_eq!(replay.disposition_digest, next.disposition_digest);
        assert_eq!(replay.envelope_digest, next.envelope_digest);
        assert_eq!(f.snapshot().await, after);
    }
}

#[tokio::test]
#[ignore = "requires the owned TLS PostgreSQL runner and a real 60 second expiry"]
async fn live_budget_expired_reconcile_is_read_only_and_allows_successor() {
    let f = BudgetFixture::new().await;
    let mut c = config(&f).await;
    c.schema_revision = LEGACY_LOCAL_BUDGET_REVISION.into();
    c.hard_expires_at_unix_ms = c.issued_at_unix_ms + 60_000;
    assert_eq!(
        apply(&f, &c, BudgetAction::Reconcile).await.unwrap_err(),
        BudgetConfigureError::NotPublished
    );
    assert_eq!(f.snapshot().await, "[]");
    apply(&f, &c, BudgetAction::Publish).await.unwrap();
    let before = f.snapshot().await;
    tokio::time::timeout(std::time::Duration::from_secs(70), async {
        loop {
            let now: i64 = f
                .admin
                .query_one("SELECT object_store_retention.clock_unix_ms_v1()", &[])
                .await
                .unwrap()
                .get(0);
            if now >= c.hard_expires_at_unix_ms {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    })
    .await
    .expect("real database expiry");
    assert_eq!(
        apply(&f, &c, BudgetAction::Verify).await.unwrap_err(),
        BudgetConfigureError::InvalidConfiguration
    );
    let receipt = apply(&f, &c, BudgetAction::Reconcile).await.unwrap();
    assert_eq!(receipt.result, "RECONCILED");
    assert!(receipt.expired);
    assert_eq!(f.snapshot().await, before);
    let mut wrong = c.clone();
    wrong.provider_bucket = "other".into();
    assert_eq!(
        apply(&f, &wrong, BudgetAction::Reconcile)
            .await
            .unwrap_err(),
        BudgetConfigureError::AuthorityRefused
    );
    assert_eq!(f.snapshot().await, before);
    let mut successor = config(&f).await;
    successor.allocation_revision = "budget-v2".into();
    successor.allocation_fence = 2;
    successor.predecessor = Some(BudgetPredecessor {
        allocation_fence: receipt.allocation_fence,
        disposition_id: receipt.disposition_id,
        disposition_digest: receipt.disposition_digest,
        envelope_digest: receipt.envelope_digest,
    });
    assert_eq!(
        apply(&f, &successor, BudgetAction::Publish)
            .await
            .unwrap()
            .result,
        "PUBLISHED"
    );
    assert!(
        !apply(&f, &successor, BudgetAction::Verify)
            .await
            .unwrap()
            .expired
    );
}

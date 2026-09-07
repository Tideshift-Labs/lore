// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Real startup construction must bind the initialized object namespace before dispatch setup.

use lore_postgres::domain::fragments::FragmentProcessPoolInventory;

use super::FragmentProviderActivation;
use super::connect_immutable_store;
use crate::auth::jwk::JWKServiceSettings;
use crate::domain::operator::DomainCommand;
use crate::domain::operator::run;
use crate::settings::AuthSettings;
use crate::settings::LockStoreSettings;
use crate::settings::Settings;

const REVISION: &str = "clean-init-test-writer-v1";

#[path = "clean_init_fixture.rs"]
mod fixture;

#[tokio::test]
#[ignore = "isolated PostgreSQL and owned MinIO required"]
async fn normal_construction_attests_clean_namespace_before_dispatch_setup() {
    let fixture = fixture::Fixture::new().await;
    fixture.assert_dark().await;
    fixture.initialize().await.unwrap();
    let store = fixture.store().await;
    let base = fixture.settings.plugins.get("postgres").unwrap();
    let inventory = FragmentProcessPoolInventory {
        immutable_pool_max: 4,
        mutable_pool_max: 4,
        lock_pool_max: 4,
        domain_pool_max: 4,
        dispatch_pool_max: 2,
    }
    .validate()
    .unwrap();
    let alternative_bucket = format!("clean-init-alternate-{}", uuid::Uuid::new_v4().simple());
    assert_ne!(alternative_bucket, fixture.bucket);
    fixture
        .s3
        .sdk_client()
        .create_bucket()
        .bucket(&alternative_bucket)
        .send()
        .await
        .unwrap();
    for changed in [false, true] {
        let mut config = base.clone();
        if changed {
            config["object_store"]["bucket"] = alternative_bucket.clone().into();
        }
        let activation = FragmentProviderActivation::new(
            store.fragment_coordinator(),
            inventory,
            store.identity().clone(),
        );
        let error = match connect_immutable_store(&config, Some(activation)).await {
            Ok(_) => panic!("fixture's missing dispatch CA must prevent activation"),
            Err(error) => error.to_string(),
        };
        if changed {
            assert!(
                error.contains("clean fragment namespace attestation failed"),
                "{error}"
            );
            assert!(
                !error.contains("dispatch_ca_cert_path"),
                "namespace mismatch must win: {error}"
            );
        } else {
            // Positive control reaches the next actual constructor step. This does not
            // claim a fully serving cell or a valid dispatch/TLS configuration.
            assert!(
                error.contains("could not read dispatch_ca_cert_path"),
                "{error}"
            );
        }
    }
    let pool = lore_postgres::pool::build_pool(
        &fixture.url,
        1,
        &lore_postgres::pool::TlsConfig::default(),
    )
    .unwrap();
    pool.get()
        .await
        .unwrap()
        .batch_execute("ALTER TABLE lore_fragment_state DISABLE TRIGGER lore_clean_legacy_fence")
        .await
        .unwrap();
    let activation = FragmentProviderActivation::new(
        store.fragment_coordinator(),
        inventory,
        store.identity().clone(),
    );
    let error = match connect_immutable_store(base, Some(activation)).await {
        Ok(_) => panic!("damaged clean fence must prevent startup"),
        Err(error) => error.to_string(),
    };
    assert!(
        error.contains("Failed to read fragment lifecycle readiness")
            && error.contains("permanent fence"),
        "{error}"
    );
}

#[path = "clean_init_dispatch.rs"]
mod dispatch;

#[tokio::test]
#[ignore = "isolated PostgreSQL and owned MinIO required"]
async fn clean_initialized_normal_provider_upload_query_read_and_grants_are_live() {
    use std::sync::Arc;

    use lore_storage::Address;
    use lore_storage::Context;
    use lore_storage::Fragment;
    use lore_storage::ImmutableStore;
    use lore_storage::Partition;
    use lore_storage::StoreMatch;
    use lore_storage::StoreMatchResult;
    use lore_storage::hash_slice;
    let fixture = fixture::Fixture::new().await;
    fixture.initialize().await.unwrap();
    dispatch::install(&fixture.url).await;
    let domain = fixture.store().await;
    let repository = create_repository(&domain).await;
    let mut config = fixture.settings.plugins["postgres"].clone();
    let parsed: tokio_postgres::Config = fixture.url.parse().unwrap();
    let dispatch_url = format!(
        "postgresql://object_dispatch_retention_runtime@localhost:{}/{}?sslmode=require",
        parsed.get_ports()[0],
        parsed.get_dbname().unwrap()
    );
    config["fragment_provider"]["dispatch_postgres_url"] = dispatch_url.into();
    config["fragment_provider"]["dispatch_ca_cert_path"] =
        std::env::var("LORE_TEST_CLEAN_INIT_CA_PATH")
            .expect("runner pinned CA")
            .into();
    config["fragment_provider"]["dispatch_connect_timeout_millis"] = 5000.into();
    config["fragment_provider"]["dispatch_acquire_timeout_millis"] = 5000.into();
    config["fragment_provider"]["dispatch_statement_timeout_millis"] = 5000.into();
    config["fragment_provider"]["dispatch_lock_timeout_millis"] = 1000.into();
    let inventory = FragmentProcessPoolInventory {
        immutable_pool_max: 4,
        mutable_pool_max: 4,
        lock_pool_max: 4,
        domain_pool_max: 4,
        dispatch_pool_max: 2,
    }
    .validate()
    .unwrap();
    let activation = FragmentProviderActivation::new(
        domain.fragment_coordinator(),
        inventory,
        domain.identity().clone(),
    );
    let immutable = Arc::new(
        connect_immutable_store(&config, Some(activation))
            .await
            .expect("normal provider construction must fully succeed"),
    );
    let pool = lore_postgres::pool::build_pool(
        &fixture.url,
        1,
        &lore_postgres::pool::TlsConfig::default(),
    )
    .unwrap();
    let direct = pool.get().await.unwrap();
    let initial_grants: i64 = direct
        .query_one(
            "SELECT count(*) FROM object_store_retention.object_dispatch_provider_charge_grants",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        initial_grants, 0,
        "constructor's separately audited versioning probe does not charge a provider operation"
    );
    let payload = bytes::Bytes::from_static(b"clean initialized governed provider roundtrip");
    let hash = hash_slice(&payload);
    let context = Context::from(*uuid::Uuid::now_v7().as_bytes());
    let address = Address { hash, context };
    let partition = Partition::from(Context::from(repository));
    let fragment = Fragment {
        flags: 0,
        size_payload: payload.len() as u32,
        size_content: payload.len() as u64,
    };
    immutable
        .clone()
        .put(partition, address, fragment, Some(payload.clone()), false)
        .await
        .expect("coordinated PUT");
    let grants_after_put: i64 = direct
        .query_one(
            "SELECT count(*) FROM object_store_retention.object_dispatch_provider_charge_grants",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(grants_after_put, initial_grants + 1, "one direct PUT grant");
    let lifecycle=direct.query_one("SELECT state, EXISTS(SELECT 1 FROM lore_fragment_associations WHERE hash=$1 AND repository_id=$2 AND context=$3) FROM lore_fragment_lifecycle WHERE hash=$1",&[&hash.data().as_slice(),&repository.as_slice(),&context.data().as_slice()]).await.unwrap();
    assert_eq!(
        lifecycle.get::<_, i16>(0),
        4,
        "Remote lifecycle established by actual PUT"
    );
    assert!(
        lifecycle.get::<_, bool>(1),
        "published association belongs to exact repository/context"
    );
    assert!(
        domain
            .fragment_coordinator()
            .push_membership_enabled()
            .await
            .unwrap()
    );
    let mut matches = [StoreMatchResult::default()];
    immutable
        .clone()
        .query(partition, &[address], &mut matches)
        .await
        .expect("coordinated query");
    assert_eq!(matches[0].match_made, StoreMatch::MatchFull);
    let (read_fragment, read_payload) = immutable
        .clone()
        .get(partition, address)
        .await
        .expect("coordinated GET")
        .into_payload()
        .unwrap();
    assert_eq!(read_payload, payload);
    assert_eq!(read_fragment.size_payload, fragment.size_payload);
    assert_eq!(direct.query_one("SELECT count(*) FROM object_store_retention.object_dispatch_provider_charge_grants",&[]).await.unwrap().get::<_,i64>(0),grants_after_put,"query and fragment GET do not mint charge grants");
    assert_eq!(
        direct
            .query_one(
                "SELECT count(*) FROM lore_fragment_write_claims WHERE state=2",
                &[]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1,
        "actual direct write claim settled decisive"
    );
    // Completed operator rerun must still recognize the initialized namespace after governed data.
    fixture.initialize().await.unwrap();
    assert_eq!(
        immutable
            .get(partition, address)
            .await
            .unwrap()
            .into_payload()
            .unwrap()
            .1,
        payload
    );
}

async fn create_repository(store: &lore_postgres::domain::PostgresDomainStore) -> [u8; 16] {
    use lore_postgres::domain::coordinator::DomainTransactionStore;
    use lore_postgres::domain::coordinator::GovernedOperation;
    use lore_postgres::domain::coordinator::RepositoryCreateInput;
    use lore_postgres::domain::receipts::OperationBinding;
    use lore_postgres::domain::receipts::PrepareResult;
    use lore_postgres::domain::receipts::ReceiptKey;
    let elapsed = store
        .domain_operation_clock_get()
        .await
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let key = ReceiptKey {
        verified_issuer: "https://clean-init.invalid".into(),
        authenticated_subject: "clean-init-fixture".into(),
        tenant_scope_key: vec![5; 16],
        operation_id: uuid::Uuid::new_v7(uuid::Timestamp::from_unix(
            uuid::NoContext,
            elapsed.as_secs(),
            elapsed.subsec_nanos(),
        )),
    };
    let binding = OperationBinding {
        method: "lore.domain.v1.test/CleanInitRepositoryCreate".into(),
        scope: vec![5; 16],
        fingerprint_version: 1,
        fingerprint: vec![6; 32],
        canonical_intent_digest: vec![7; 32],
    };
    let PrepareResult::Prepared { token, .. } = store
        .domain_operation_prepare(&key, &binding, None, None)
        .await
        .unwrap()
    else {
        panic!("repository create receipt must prepare")
    };
    let repository = *uuid::Uuid::now_v7().as_bytes();
    let input = RepositoryCreateInput {
        repository_id: repository.to_vec(),
        name: "clean-init-roundtrip".into(),
        metadata_hash: vec![1; 32],
        default_branch_id: uuid::Uuid::now_v7().as_bytes().to_vec(),
        default_branch_name: "main".into(),
        default_branch_metadata_hash: vec![2; 32],
        default_branch_latest_hash: vec![3; 32],
        creation_fingerprint: vec![4; 32],
        creation_fingerprint_version: 1,
        projection: vec![],
        events: vec![],
    };
    let result = store
        .repository_create(
            &GovernedOperation {
                key,
                binding,
                prepare_token: token,
            },
            &input,
        )
        .await
        .unwrap();
    assert_eq!(
        result.outcome,
        lore_postgres::domain::errors::DomainOutcome::Applied
    );
    repository
}

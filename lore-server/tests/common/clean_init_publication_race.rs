// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Post-COMMIT lifecycle race with the actual governed provider and ordinary PUT.
use std::sync::Arc;

use lore_storage::Address;
use lore_storage::Context;
use lore_storage::Fragment;
use lore_storage::ImmutableStore;
use lore_storage::Partition;
use lore_storage::hash_slice;

use super::*;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "isolated failure_generator process; run-fragment-clean-init-live.ps1 -PublicationRaceOnly"]
async fn ordinary_put_after_committed_upload_loses_readable_epoch_and_returns_slow_down() {
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
        relay_pool_max: 0,
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
    let payload = bytes::Bytes::from_static(b"publication settled race actual provider payload");
    let hash = hash_slice(&payload);
    let address = Address {
        hash,
        context: Context::default(),
    };
    let gate = std::path::PathBuf::from(std::env::var("LORE_FRAGMENT_FAILPOINT_DIR").unwrap());
    assert_eq!(
        std::env::var("LORE_FRAGMENT_FAILPOINTS").unwrap(),
        "publication.commit.settled=pause"
    );
    let hold = gate.join("publication.commit.settled.hold");
    let reached = gate.join("publication.commit.settled.reached");
    std::fs::write(&hold, b"owned race gate").unwrap();
    struct Release(std::path::PathBuf);
    impl Drop for Release {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let release = Release(hold);
    let operation = lore_base::lore_spawn!("ordinary-put-settled-race", async move {
        immutable
            .put(
                Partition::from(Context::from(repository)),
                address,
                Fragment {
                    flags: 0,
                    size_payload: payload.len() as u32,
                    size_content: payload.len() as u64,
                },
                Some(payload),
                true,
            )
            .await
    });
    let operation = tokio_util::task::AbortOnDropHandle::new(operation);
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        while !reached.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("upload must reach post-COMMIT pause");
    let coordinator = domain.fragment_coordinator();
    let witness = coordinator
        .capture_current_readable_epoch(hash.as_ref())
        .await
        .unwrap()
        .expect("COMMIT has already published Remote");
    assert_eq!(
        coordinator
            .mark_missing(
                &witness,
                lore_postgres::domain::fragments::MissingDiagnostic::Absent
            )
            .await
            .unwrap(),
        lore_postgres::domain::fragments::CommitVerdict::Published
    );
    assert!(
        coordinator
            .capture_current_readable_epoch(hash.as_ref())
            .await
            .unwrap()
            .is_none()
    );
    drop(release);
    let result = tokio::time::timeout(std::time::Duration::from_secs(20), operation)
        .await
        .unwrap()
        .unwrap();
    let error = result.expect_err("concurrent lifecycle movement must refuse ordinary publication");
    assert!(error.is_slow_down(), "{error:?}");
    let pool = lore_postgres::pool::build_pool(&fixture.url, 1, &Default::default()).unwrap();
    let client = pool.get().await.unwrap();
    assert_eq!(
        client
            .query_one(
                "SELECT count(*) FROM lore_fragment_associations WHERE hash=$1",
                &[&hash.as_ref()]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        0
    );
    assert_eq!(
        client
            .query_one(
                "SELECT count(*) FROM lore_fragment_write_claims WHERE hash=$1 AND state=2",
                &[&hash.as_ref()]
            )
            .await
            .unwrap()
            .get::<_, i64>(0),
        1,
        "provider upload settled before the race"
    );
    assert!(!reached.exists());
}

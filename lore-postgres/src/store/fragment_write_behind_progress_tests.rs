// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use super::*;
use crate::domain::fragments::StageReservationInput;

#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture and Linux"]
async fn observer_sees_peer_stage_then_refuses_a_replaced_local_mount_without_restart() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    assert_eq!(fixture.handle.drain_pass(8).await.unwrap(), 1);
    assert_eq!(fixture.handle.observe().await.unwrap().pending_files, 0);
    let peer = PostgresDomainStore::connect(
        &std::env::var("LORE_TEST_PG_URL").unwrap(),
        1,
        &TlsConfig::default(),
    )
    .await
    .unwrap();
    let coordinator = peer.fragment_coordinator();
    let peer_stage = WriteBehindStage::open(WriteBehindSettings {
        root: fixture.root.join("stage"),
        watermarks: WriteBehindWatermarks {
            low_bytes: 10_000_000,
            high_bytes: 20_000_000,
            hard_bytes: 30_000_000,
            low_count: 1000,
            high_count: 2000,
            hard_count: 3000,
            min_free_bytes: 0,
        },
        drain_stale_after: Duration::from_secs(60),
        sample_interval: Duration::from_secs(3600),
    })
    .unwrap();
    let bytes = Bytes::from_static(b"peer stage after observer was empty");
    let hash = blake3::hash(&bytes);
    let BeginOutcome::Admitted(intent) = coordinator
        .begin_stage(
            hash.as_bytes(),
            StageReservationInput {
                size_payload: bytes.len() as u64,
                original_flags: 0,
            },
        )
        .await
        .unwrap()
    else {
        panic!("peer source admitted")
    };
    peer_stage
        .stage(hash.as_bytes(), intent.epoch, &intent.object_key, &bytes)
        .await
        .unwrap();
    let address = Address {
        context: Context::default(),
        hash: Hash::from(hash.as_bytes().as_slice()),
    };
    let manifest = PostgresImmutableStore::key_manifest(
        &intent.object_key,
        address,
        raw_fragment(&bytes),
        &bytes,
        EpochAuthority::Staged,
    )
    .unwrap();
    coordinator
        .commit_staged(&intent, IoObservation::Valid(manifest))
        .await
        .unwrap();
    assert_eq!(
        fixture.handle.observe().await.unwrap().pending_files,
        1,
        "live database observation notices the other replica's source"
    );
    let original = fixture.root.join("stage");
    let detached = fixture.root.join("detached-stage");
    std::fs::rename(&original, &detached).unwrap();
    std::fs::create_dir(&original).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match fixture.handle.observe().await {
                Err(_) => break,
                Ok(observation) if !observation.roots_usable && !observation.capacity_available => {
                    break;
                }
                Ok(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
    })
    .await
    .expect("the retained asynchronous inventory must detect mount replacement without restart");
    assert_eq!(
        fixture.port.puts.load(Ordering::SeqCst),
        1,
        "observation never sends the newly staged source"
    );
    std::fs::remove_dir(&original).unwrap();
    std::fs::rename(&detached, &original).unwrap();
}

#[cfg(feature = "failure_generator")]
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, Linux and failure_generator"]
async fn killed_active_promotion_is_barriered_then_a_peer_sends_with_a_new_fence() {
    if std::env::var_os("LORE_TEST_ACTIVE_PROMOTION_CHILD").is_some() {
        let domain = PostgresDomainStore::connect(
            &std::env::var("LORE_TEST_PG_URL").unwrap(),
            1,
            &TlsConfig::default(),
        )
        .await
        .unwrap();
        let coordinator = domain.fragment_coordinator();
        let source = coordinator
            .staged_drain_candidates(FragmentDrainCandidateBatch::new(1).unwrap())
            .await
            .unwrap()
            .pop()
            .unwrap();
        let bytes = payload();
        let claim = FragmentWriteClaimInput::new(
            *Uuid::now_v7().as_bytes(),
            *Uuid::now_v7().as_bytes(),
            *blake3::hash(&bytes).as_bytes(),
            bytes.len() as u64,
            Duration::from_secs(10),
            Duration::from_secs(10),
        )
        .unwrap();
        coordinator.begin_promotion(&source, claim).await.unwrap();
        panic!("parent must kill this child at the settled begin barrier");
    }
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    let markers = fixture.root.join("process-markers");
    std::fs::create_dir(&markers).unwrap();
    std::fs::write(markers.join("promotion.begin.settled.hold"), b"hold").unwrap();
    let child_log = fixture.root.join("active-promotion-child.log");
    let child_stderr = std::fs::File::create(&child_log).unwrap();
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "store::immutable_store::fragment_write_behind::adapter_tests::progress_tests::killed_active_promotion_is_barriered_then_a_peer_sends_with_a_new_fence", "--nocapture"])
        .env("LORE_TEST_ACTIVE_PROMOTION_CHILD", "1")
        .env("LORE_FRAGMENT_FAILPOINTS", "promotion.begin.settled=pause")
        .env("LORE_FRAGMENT_FAILPOINT_DIR", &markers)
        .stdout(std::process::Stdio::null()).stderr(child_stderr)
        .spawn().unwrap();
    let arrived = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if markers.join("promotion.begin.settled.reached").exists() {
                break;
            }
            if child.try_wait().unwrap().is_some() {
                panic!(
                    "child exited before its durable begin marker: {}",
                    std::fs::read_to_string(&child_log).unwrap()
                );
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    child.kill().unwrap();
    let status = child.wait().unwrap();
    arrived.expect("child reaches the postcommit pause");
    assert!(!status.success());
    let old_fence: i64 = fixture
        .admin
        .query_one(
            "SELECT fence FROM lore_fragment_write_claims WHERE hash=$1",
            &[&fixture.address.hash.data().as_slice()],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(fixture.handle.drain_pass(1).await.unwrap(), 0);
    assert_eq!(
        fixture.port.puts.load(Ordering::SeqCst),
        0,
        "peer cannot send while killed Prepared claim remains live"
    );
    tokio::time::sleep(Duration::from_secs(11)).await;
    assert_eq!(fixture.handle.drain_pass(1).await.unwrap(), 1);
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 1);
    let rows = fixture
        .admin
        .query(
            "SELECT fence,state FROM lore_fragment_write_claims WHERE hash=$1 ORDER BY fence",
            &[&fixture.address.hash.data().as_slice()],
        )
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].get::<_, i64>(0), old_fence);
    assert!(rows[1].get::<_, i64>(0) > old_fence);
    assert_eq!(
        fixture.current().await.state,
        FragmentLifecycleState::Remote
    );
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture and Linux"]
async fn small_worker_batches_advance_past_blocked_and_repeatedly_failing_lower_hashes() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    let coordinator = &fixture.handle.coordinator;
    let mut lower = Vec::new();
    for ordinal in 0..100_000 {
        let bytes = Bytes::from(format!("lower-hash source {ordinal}"));
        let hash = blake3::hash(&bytes);
        if hash.as_bytes().as_slice() < fixture.address.hash.data().as_slice() {
            lower.push((hash, bytes));
            if lower.len() == 2 {
                break;
            }
        }
    }
    assert_eq!(lower.len(), 2);
    lower.sort_by_key(|(hash, _)| *hash.as_bytes());
    for (hash, bytes) in &lower {
        let BeginOutcome::Admitted(intent) = coordinator
            .begin_stage(
                hash.as_bytes(),
                StageReservationInput {
                    size_payload: bytes.len() as u64,
                    original_flags: 0,
                },
            )
            .await
            .unwrap()
        else {
            panic!("new lower stage")
        };
        fixture
            .handle
            .stage
            .stage(hash.as_bytes(), intent.epoch, &intent.object_key, bytes)
            .await
            .unwrap();
        let address = Address {
            context: Context::default(),
            hash: Hash::from(hash.as_bytes().as_slice()),
        };
        let manifest = PostgresImmutableStore::key_manifest(
            &intent.object_key,
            address,
            raw_fragment(bytes),
            bytes,
            EpochAuthority::Staged,
        )
        .unwrap();
        coordinator
            .commit_staged(&intent, IoObservation::Valid(manifest))
            .await
            .unwrap();
    }
    let candidates = coordinator
        .staged_drain_candidates(FragmentDrainCandidateBatch::new(8).unwrap())
        .await
        .unwrap();
    let blocked = candidates
        .into_iter()
        .find(|candidate| candidate.hash() == lower[0].0.as_bytes())
        .unwrap();
    let claim = FragmentWriteClaimInput::new(
        *Uuid::now_v7().as_bytes(),
        *Uuid::now_v7().as_bytes(),
        *lower[0].0.as_bytes(),
        lower[0].1.len() as u64,
        Duration::from_secs(60),
        Duration::from_secs(60),
    )
    .unwrap();
    assert!(matches!(
        coordinator.begin_promotion(&blocked, claim).await.unwrap(),
        BeginOutcome::Admitted(_)
    ));
    let error_hash = hex::encode(lower[1].0.as_bytes());
    fixture.admin.batch_execute(&format!("CREATE FUNCTION fixture_refuse_lower_claim() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.hash=decode('{error_hash}','hex') THEN RAISE EXCEPTION 'injected lower-hash claim failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fixture_refuse_lower BEFORE INSERT ON lore_fragment_write_claims FOR EACH ROW EXECUTE FUNCTION fixture_refuse_lower_claim();")).await.unwrap();
    assert_eq!(
        fixture.handle.drain_pass(1).await.unwrap(),
        0,
        "the first eligible low hash fails before send"
    );
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture.handle.drain_pass(1).await.unwrap(),
        1,
        "the next page must reach later work despite the retained low hash"
    );
    assert_eq!(
        fixture.current().await.state,
        FragmentLifecycleState::Remote
    );
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 1);
    fixture.handle.state.lock().await.cooldown.clear();
    assert_eq!(
        fixture.handle.drain_pass(1).await.unwrap(),
        0,
        "wrapping the keyset encounters the persistent failure again"
    );
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 1);
}

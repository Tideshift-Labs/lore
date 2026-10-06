// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! `runtime.admission` at the store adapter: what a fragment PUT does when the
//! staging root is lost or the tier is under pressure.
//!
//! Each case drives `put_coordinated`, the route branch the trait `put` calls,
//! against the real coordinator, SQL, sampler and confined root. The modes are
//! reached through the same inputs production uses: the sampler's `stat` and
//! `statvfs`, the observer's `observe()`, and the worker's heartbeat calls.
//!
//! The pinned semantics are not "every condition refuses":
//!
//! - a lost root while acknowledged staged bytes may exist is `Unready`, and
//!   the PUT refuses with `SlowDown` rather than masking them with a direct
//!   write;
//! - a lost root after the observer positively saw zero pending staged rows is
//!   `DirectFallback`, and the PUT succeeds through the provider without
//!   staging (`immutable_store.rs`, `put_coordinated`);
//! - the byte, count and free-space ceilings are `Refuse`: `SlowDown`, with no
//!   direct write either.
use std::path::Path;

use super::*;

/// The repository every case binds its fragments to.
const REPOSITORY: [u8; 16] = [0x6b; 16];

/// A sampler interval short enough that a lost root is seen within a poll.
const LIVE_SAMPLE: Duration = Duration::from_millis(20);

/// How long a case waits for the sampler or observer to reach a mode.
const SETTLE: Duration = Duration::from_secs(10);

fn fragment_bytes(tag: &str) -> Bytes {
    Bytes::from(format!("admission {tag} payload repeated ").repeat(512))
}

/// Let the scripted provider accept `bytes` as a PUT body.
fn accept(fixture: &Fixture, bytes: &Bytes) {
    fixture
        .port
        .extra_bodies
        .lock()
        .unwrap()
        .push(bytes.clone());
}

fn address_of(bytes: &Bytes) -> Address {
    Address {
        context: Context::default(),
        hash: Hash::from(blake3::hash(bytes).as_bytes().as_slice()),
    }
}

/// Give the case a live repository, so a published association is `Published`
/// and a successful PUT returns `Ok` rather than a fenced `SlowDown`.
async fn bind_repository(fixture: &Fixture) {
    fixture
        .admin
        .execute(
            "INSERT INTO lore_domain_repositories(repository_id,state,generation,name,\
             metadata_hash,default_branch_id,creation_fingerprint_version,\
             creation_fingerprint,created_at) \
             VALUES($1,0,1,'admission',$2,$3,1,$2,clock_timestamp())",
            &[&&REPOSITORY[..], &&[0x78u8; 32][..], &&[0x79u8; 16][..]],
        )
        .await
        .unwrap();
}

/// One fragment PUT through `store`'s coordinated route, exactly as the trait
/// `put` calls it after its metadata validation.
async fn put(store: &PostgresImmutableStore, bytes: &Bytes) -> Result<(), StoreError> {
    let FragmentLifecycleRoute::Coordinated {
        coordinator,
        provider,
        budget_pin,
        late_effect_bound,
        ..
    } = &store.fragment_route
    else {
        panic!("the fixture store is coordinated");
    };
    store
        .put_coordinated(
            coordinator,
            CoordinatedProvider {
                entry: provider,
                budget_pin,
                late_effect_bound: *late_effect_bound,
            },
            Context::from(REPOSITORY),
            address_of(bytes),
            raw_fragment(bytes),
            Some(bytes.clone()),
        )
        .await
}

/// Rows a PUT leaves behind for `bytes`' hash, per lifecycle table. A refused
/// PUT must leave none: no preparation, no epoch, no claim, no custody.
async fn rows_for(fixture: &Fixture, bytes: &Bytes) -> Vec<(&'static str, i64)> {
    let hash = address_of(bytes).hash;
    let mut rows = Vec::new();
    for table in [
        "lore_fragment_lifecycle",
        "lore_fragment_epochs",
        "lore_fragment_write_claims",
        "lore_fragment_stage_custody",
    ] {
        let count: i64 = fixture
            .admin
            .query_one(
                &format!("SELECT count(*) FROM {table} WHERE hash=$1"),
                &[&hash.data().as_slice()],
            )
            .await
            .unwrap()
            .get(0);
        rows.push((table, count));
    }
    rows
}

/// A refused PUT: retryable `SlowDown`, no provider PUT, no lifecycle row.
async fn assert_refused_without_side_effects(fixture: &Fixture, bytes: &Bytes, why: &str) {
    let puts = fixture.port.puts.load(Ordering::SeqCst);
    let result = put(&fixture.store, bytes).await;
    assert!(
        matches!(&result, Err(error) if error.is_slow_down()),
        "{why}: the PUT must refuse with retryable SlowDown, got {result:?}"
    );
    assert_eq!(
        fixture.port.puts.load(Ordering::SeqCst),
        puts,
        "{why}: a refusal must not fall back to a direct provider PUT"
    );
    for (table, count) in rows_for(fixture, bytes).await {
        assert_eq!(count, 0, "{why}: a refused PUT writes no {table} row");
    }
}

/// The current readable authority for `bytes`, remote first.
async fn readable_state(fixture: &Fixture, bytes: &Bytes) -> Option<FragmentLifecycleState> {
    let hash = address_of(bytes).hash;
    let coordinator = &fixture.handle.coordinator;
    if let Some(remote) = coordinator
        .capture_current_readable_epoch(hash.data())
        .await
        .unwrap()
    {
        return Some(remote.state);
    }
    coordinator
        .capture_current_readable_epoch_for_authority(hash.data(), EpochAuthority::Staged)
        .await
        .unwrap()
        .map(|witness| witness.state)
}

/// Observe until the physical stage walk has completed and bound to a ledger
/// read. The walk runs beside `observe()`, so the first observation reports the
/// inventory missing; a mode read before this is not the steady mode.
async fn observe_settled(fixture: &Fixture) -> WriteBehindObservation {
    tokio::time::timeout(SETTLE, async {
        loop {
            let observation = fixture.handle.observe().await.unwrap();
            if !observation
                .capacity
                .failing
                .iter()
                .any(|name| name.ends_with("inventory_missing"))
            {
                return observation;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the stage inventory completes within the settle budget")
}

async fn wait_for(fixture: &Fixture, why: &str, done: impl Fn(&Fixture) -> bool) {
    tokio::time::timeout(SETTLE, async {
        while !done(fixture) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "{why}; mode {:?}, snapshot {:?}",
            fixture.handle.mode(),
            fixture.stage.snapshot()
        )
    });
}

/// Move the staging root away, as an unmounted volume looks to the sampler.
fn lose_root(fixture: &Fixture) -> PathBuf {
    let original = fixture.root.join("stage");
    let detached = fixture.root.join("detached-stage");
    std::fs::rename(&original, &detached).unwrap();
    detached
}

fn restore_root(fixture: &Fixture, detached: &Path) {
    std::fs::rename(detached, fixture.root.join("stage")).unwrap();
}

/// Lost mount, acknowledged staged bytes pending: `Unready`. The PUT refuses
/// and does not fall back to a direct write, because a direct write would hide
/// that this replica cannot read bytes it acknowledged. Restoring the root
/// restores admission, and the drain still promotes what was pending.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn admission_lost_root_with_pending_staged_bytes_is_unready_and_refuses_without_direct_fallback()
 {
    let fixture = Fixture::open_tuned(
        PutResult::Created,
        FragmentGetResponse::NotFound,
        payload(),
        false,
        |settings| settings.sample_interval = LIVE_SAMPLE,
    )
    .await;
    bind_repository(&fixture).await;
    let observation = observe_settled(&fixture).await;
    assert_eq!(
        observation.pending_files, 1,
        "the fixture's own source is pending"
    );
    fixture.handle.note_drain_heartbeat();
    assert_eq!(
        fixture.handle.mode(),
        StagingMode::Stage,
        "control: a healthy tier stages; capacity {:?}",
        observation.capacity
    );

    let detached = lose_root(&fixture);
    wait_for(
        &fixture,
        "a lost root with pending bytes must read Unready",
        |fixture| fixture.handle.mode() == StagingMode::Unready,
    )
    .await;
    assert!(!fixture.stage.snapshot().root_available);
    let refused = fragment_bytes("unready");
    accept(&fixture, &refused);
    assert_refused_without_side_effects(&fixture, &refused, "lost root, pending staged").await;

    restore_root(&fixture, &detached);
    wait_for(&fixture, "a restored root must leave Unready", |fixture| {
        fixture.stage.snapshot().root_available
    })
    .await;
    assert_eq!(fixture.handle.mode(), StagingMode::Stage);
    put(&fixture.store, &refused)
        .await
        .expect("the same PUT is admitted once the root is back");
    assert_eq!(
        readable_state(&fixture, &refused).await,
        Some(FragmentLifecycleState::Staged),
        "the retry staged rather than writing directly"
    );
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 0);
    assert_eq!(
        fixture.handle.drain_pass(8).await.unwrap(),
        2,
        "forward progress: the drain promotes the source pending across the loss and the retry"
    );
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 2);
}

/// Lost mount after the observer saw zero pending staged rows: `DirectFallback`.
/// No acknowledged staged bytes can be stranded, so the PUT writes through the
/// provider and stages nothing (D11). A stopped worker selects the same route.
/// Once the observation is unknown again, the same lost root is `Unready` and
/// refuses; restoring the root admits the PUT.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn admission_lost_root_with_no_pending_staged_bytes_falls_back_to_direct_writes() {
    let fixture = Fixture::open_tuned(
        PutResult::Created,
        FragmentGetResponse::NotFound,
        payload(),
        false,
        |settings| settings.sample_interval = LIVE_SAMPLE,
    )
    .await;
    bind_repository(&fixture).await;
    assert_eq!(fixture.handle.drain_pass(8).await.unwrap(), 1);
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 1);
    let observation = observe_settled(&fixture).await;
    assert_eq!(observation.pending_files, 0, "nothing staged is pending");
    fixture.handle.note_drain_heartbeat();
    assert_eq!(
        fixture.handle.mode(),
        StagingMode::Stage,
        "control: a healthy tier stages; capacity {:?}",
        observation.capacity
    );

    // Stale worker: direct writes, not refusal.
    fixture.handle.note_worker_stopped();
    assert_eq!(fixture.handle.mode(), StagingMode::DirectFallback);
    let stopped = fragment_bytes("worker-stopped");
    accept(&fixture, &stopped);
    put(&fixture.store, &stopped)
        .await
        .expect("a stopped worker falls back to a direct write");
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 2);
    assert_eq!(
        readable_state(&fixture, &stopped).await,
        Some(FragmentLifecycleState::Remote)
    );

    // Lost root with zero pending: direct writes, not refusal.
    fixture.handle.note_drain_heartbeat();
    assert_eq!(fixture.handle.mode(), StagingMode::Stage);
    let detached = lose_root(&fixture);
    wait_for(
        &fixture,
        "the sampler must observe the lost root",
        |fixture| !fixture.stage.snapshot().root_available,
    )
    .await;
    assert_eq!(fixture.handle.mode(), StagingMode::DirectFallback);
    let lost = fragment_bytes("lost-root");
    accept(&fixture, &lost);
    put(&fixture.store, &lost)
        .await
        .expect("a lost root with nothing pending falls back to a direct write");
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 3);
    assert_eq!(
        readable_state(&fixture, &lost).await,
        Some(FragmentLifecycleState::Remote)
    );
    for (table, count) in rows_for(&fixture, &lost).await {
        if table == "lore_fragment_stage_custody" {
            assert_eq!(count, 0, "a direct write takes no stage custody");
        }
    }

    // Stale observer: the zero-pending evidence is gone, so the same root loss
    // must now assume stranded bytes.
    fixture.handle.note_observation_unknown();
    assert_eq!(fixture.handle.mode(), StagingMode::Unready);
    let unknown = fragment_bytes("observation-unknown");
    accept(&fixture, &unknown);
    assert_refused_without_side_effects(&fixture, &unknown, "lost root, observation unknown").await;

    restore_root(&fixture, &detached);
    wait_for(
        &fixture,
        "the sampler must observe the restored root",
        |fixture| fixture.stage.snapshot().root_available,
    )
    .await;
    put(&fixture.store, &unknown)
        .await
        .expect("the same PUT is admitted once the root is back");
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 3);
    assert_eq!(
        readable_state(&fixture, &unknown).await,
        Some(FragmentLifecycleState::Staged)
    );
}

/// Pressure from occupancy the observer measured. Before any observation the
/// tier stages a control fragment; once `observe()` records the two staged
/// sources, the ceiling `tune` set refuses the next PUT with no direct write.
///
/// The hard limits are also the published stage policy, which the database
/// ledger enforces at `begin_stage`. Here admission refuses first, from the
/// observed occupancy, so the refused PUT never reaches that backstop. A PUT
/// that does reach it (occupancy stale between observations) gets the ledger's
/// `NotReady`, which `domain_store_err` maps to `Internal`, not `SlowDown`; no
/// case here pins that class.
async fn assert_occupancy_ceiling_refuses(
    tune: impl FnOnce(&mut WriteBehindWatermarks),
    ceiling: impl Fn(&AdmissionSnapshot) -> bool,
    why: &str,
) {
    let fixture = Fixture::open_tuned(
        PutResult::Created,
        FragmentGetResponse::NotFound,
        payload(),
        false,
        |settings| tune(&mut settings.watermarks),
    )
    .await;
    bind_repository(&fixture).await;
    fixture.handle.note_drain_heartbeat();
    assert_eq!(
        fixture.handle.mode(),
        StagingMode::Stage,
        "control: no occupancy is recorded yet"
    );
    let control = fragment_bytes("control");
    put(&fixture.store, &control)
        .await
        .expect("control: the tier stages below its ceiling");
    assert_eq!(
        readable_state(&fixture, &control).await,
        Some(FragmentLifecycleState::Staged)
    );

    let observation = observe_settled(&fixture).await;
    assert_eq!(observation.pending_files, 2);
    assert!(
        observation.capacity_available,
        "{why}: the refusal must come from the watermark, not the capacity verdict: {:?}",
        observation.capacity
    );
    let snapshot = fixture.stage.snapshot();
    assert!(
        ceiling(&snapshot),
        "{why}: the ceiling is reached: {snapshot:?}"
    );
    assert!(snapshot.root_available && snapshot.drain_healthy);
    assert_eq!(
        fixture.handle.mode(),
        StagingMode::Refuse,
        "{why}: {snapshot:?}"
    );
    let refused = fragment_bytes("over-ceiling");
    accept(&fixture, &refused);
    assert_refused_without_side_effects(&fixture, &refused, why).await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn admission_hard_byte_watermark_refuses_without_direct_fallback() {
    // Exactly the fixture's source plus the control: the stage ledger, pinned
    // to the same policy, admits both and nothing more.
    let hard_bytes = (payload().len() + fragment_bytes("control").len()) as u64;
    assert_occupancy_ceiling_refuses(
        |watermarks| {
            watermarks.low_bytes = 0;
            watermarks.high_bytes = hard_bytes;
            watermarks.hard_bytes = hard_bytes;
        },
        |snapshot| snapshot.staged_bytes >= hard_bytes && snapshot.staged_count < 3000,
        "hard byte watermark",
    )
    .await;
}

#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn admission_hard_count_watermark_refuses_without_direct_fallback() {
    const HARD_COUNT: u64 = 2;
    assert_occupancy_ceiling_refuses(
        |watermarks| {
            watermarks.low_count = 0;
            watermarks.high_count = HARD_COUNT;
            watermarks.hard_count = HARD_COUNT;
        },
        |snapshot| snapshot.staged_count >= HARD_COUNT && snapshot.staged_bytes < 30_000_000,
        "hard count watermark",
    )
    .await;
}

/// Free space below the minimum refuses on the sampler's own `statvfs`, with
/// nothing staged. The fixture cannot open with that floor (its setup stages a
/// source), so a second store over the fixture's coordinator and provider
/// carries a stage whose floor no real filesystem can meet.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn admission_min_free_space_refuses_without_direct_fallback() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    bind_repository(&fixture).await;
    let open_stage = |name: &str, min_free_bytes: u64| {
        let root = fixture.root.join(name);
        std::fs::create_dir(&root).unwrap();
        let stage = WriteBehindStage::open(WriteBehindSettings {
            root,
            watermarks: WriteBehindWatermarks {
                low_bytes: 10_000_000,
                high_bytes: 20_000_000,
                hard_bytes: 30_000_000,
                low_count: 1000,
                high_count: 2000,
                hard_count: 3000,
                min_free_bytes,
            },
            drain_stale_after: Duration::from_secs(60),
            sample_interval: Duration::from_secs(3600),
            stage_io_wait: crate::store::write_behind::DEFAULT_STAGE_IO_WAIT,
            stage_read_wait: crate::store::write_behind::DEFAULT_STAGE_READ_WAIT,
            drain_reserve: Default::default(),
        })
        .unwrap();
        stage.note_drain_heartbeat();
        stage
    };
    let control = open_stage("roomy-stage", 0);
    assert_eq!(
        control.mode(),
        StagingMode::Stage,
        "control: no floor, same filesystem"
    );
    let stage = open_stage("floor-stage", u64::MAX);
    let snapshot = stage.snapshot();
    assert!(snapshot.root_available);
    assert!(
        snapshot.free_bytes.is_some(),
        "the floor is checked against a real sample"
    );
    assert_eq!((snapshot.staged_bytes, snapshot.staged_count), (0, 0));
    assert_eq!(stage.mode(), StagingMode::Refuse);

    let FragmentLifecycleRoute::Coordinated {
        coordinator,
        provider,
        budget_pin,
        late_effect_bound,
        ..
    } = &fixture.store.fragment_route
    else {
        panic!("the fixture store is coordinated");
    };
    let url = std::env::var("LORE_TEST_PG_URL").unwrap();
    let s3_config = aws_sdk_s3::config::Builder::new()
        .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
        .region(aws_sdk_s3::config::Region::new("us-east-1"))
        .build();
    let floored = PostgresImmutableStore {
        pool: crate::pool::build_pool(&url, 2, &TlsConfig::default()).unwrap(),
        s3: S3Impl::new(
            aws_sdk_s3::Client::from_conf(s3_config),
            Duration::from_secs(30),
            None,
        ),
        bucket: "unused-test-transport".into(),
        instruments: crate::metrics::Instruments::new("admission-test"),
        fragment_route: FragmentLifecycleRoute::Legacy,
        staged_epoch_cleanup: None,
        write_behind: Some(stage),
        io_timeout: Duration::from_secs(3),
        cancel_withdrawals: CancelWithdrawals::new(CANCEL_WITHDRAW_PERMITS),
    }
    .with_fragment_lifecycle(
        coordinator.clone(),
        provider.clone(),
        budget_pin.clone(),
        *late_effect_bound,
        None,
    );
    let refused = fragment_bytes("below-floor");
    accept(&fixture, &refused);
    let puts = fixture.port.puts.load(Ordering::SeqCst);
    let result = put(&floored, &refused).await;
    assert!(
        matches!(&result, Err(error) if error.is_slow_down()),
        "free space below the floor refuses with SlowDown, got {result:?}"
    );
    assert_eq!(
        fixture.port.puts.load(Ordering::SeqCst),
        puts,
        "a refusal must not fall back to a direct provider PUT"
    );
    for (table, count) in rows_for(&fixture, &refused).await {
        assert_eq!(count, 0, "a refused PUT writes no {table} row");
    }
}

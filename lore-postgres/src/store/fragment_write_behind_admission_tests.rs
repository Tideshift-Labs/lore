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

/// WP-115 K11 guard at the store adapter. While the share gate holds (the
/// stage is not proven shared with the drain), a PUT that would stage writes
/// directly instead: `DirectFallback` is the real route, with no stage
/// custody. A PUT that chose `Stage` before the gate rose, and then waited for
/// a staging slot, refuses with `SlowDown` at its re-check and leaves no row;
/// its retry writes directly. A fragment staged while the gate was open stays
/// readable and the drain still promotes it. So a switch from `Stage` to
/// `DirectFallback` in the middle of a write loses nothing and stages nothing.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn admission_unproven_share_writes_directly_and_an_in_flight_staged_put_refuses() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    bind_repository(&fixture).await;
    assert_eq!(fixture.handle.drain_pass(8).await.unwrap(), 1);
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 1);
    observe_settled(&fixture).await;
    fixture.handle.note_drain_heartbeat();
    assert_eq!(fixture.handle.mode(), StagingMode::Stage, "control");

    let gate = Arc::new(std::sync::atomic::AtomicBool::new(true));
    assert!(fixture.stage.attach_share_gate(gate.clone()));
    assert_eq!(
        fixture.handle.mode(),
        StagingMode::DirectFallback,
        "an unproven stage writes directly"
    );
    let unproven = fragment_bytes("share-unproven");
    accept(&fixture, &unproven);
    put(&fixture.store, &unproven)
        .await
        .expect("an unproven stage falls back to a direct write");
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 2);
    assert_eq!(
        readable_state(&fixture, &unproven).await,
        Some(FragmentLifecycleState::Remote)
    );
    for (table, count) in rows_for(&fixture, &unproven).await {
        if table == "lore_fragment_stage_custody" {
            assert_eq!(count, 0, "a direct write takes no stage custody");
        }
    }

    // Proven: the next PUT stages.
    gate.store(false, Ordering::Release);
    assert_eq!(fixture.handle.mode(), StagingMode::Stage);
    let staged = fragment_bytes("share-proven");
    accept(&fixture, &staged);
    put(&fixture.store, &staged)
        .await
        .expect("a proven stage stages");
    assert_eq!(
        readable_state(&fixture, &staged).await,
        Some(FragmentLifecycleState::Staged)
    );
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 2);

    // In flight: the PUT chooses `Stage`, then waits for a staging slot. The
    // gate rises while it waits.
    let permits = std::iter::from_fn(|| {
        fixture
            .stage
            .root()
            .try_io_permit(crate::store::write_behind::StageIoPath::Put)
            .ok()
    })
    .take(64)
    .collect::<Vec<_>>();
    assert!(!permits.is_empty(), "the case holds every staging slot");
    let in_flight = fragment_bytes("share-in-flight");
    accept(&fixture, &in_flight);
    let raise = async {
        tokio::time::sleep(Duration::from_millis(300)).await;
        gate.store(true, Ordering::Release);
        drop(permits);
    };
    let (refused, ()) = tokio::join!(put(&fixture.store, &in_flight), raise);
    assert!(
        matches!(&refused, Err(error) if error.is_slow_down()),
        "a staged PUT whose stage lost its proof refuses at the re-check, got {refused:?}"
    );
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 2);
    for (table, count) in rows_for(&fixture, &in_flight).await {
        assert_eq!(count, 0, "the refused PUT writes no {table} row");
    }
    put(&fixture.store, &in_flight)
        .await
        .expect("the retry writes directly");
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 3);
    assert_eq!(
        readable_state(&fixture, &in_flight).await,
        Some(FragmentLifecycleState::Remote)
    );

    // The fragment staged while the gate was open is not lost.
    assert_eq!(
        readable_state(&fixture, &staged).await,
        Some(FragmentLifecycleState::Staged)
    );
    assert_eq!(fixture.handle.drain_pass(8).await.unwrap(), 1);
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 4);
    assert_eq!(
        readable_state(&fixture, &staged).await,
        Some(FragmentLifecycleState::Remote)
    );
}

/// The lifecycle head state of `hash`, as stored.
async fn head_state_of(fixture: &Fixture, hash: &[u8]) -> i16 {
    fixture
        .admin
        .query_one(
            "SELECT state FROM lore_fragment_lifecycle WHERE hash=$1",
            &[&hash],
        )
        .await
        .unwrap()
        .get(0)
}

/// The staged file of `(hash, epoch)` under the fixture's stage.
fn staged_path(fixture: &Fixture, hash: &Hash, epoch: i64) -> PathBuf {
    let key = format!("{hash}.s{epoch}");
    fixture
        .root
        .join("stage/staged")
        .join(&key[..2])
        .join(&key[2..4])
        .join(&key)
}

/// WP-115 drain guard at the drain, end to end through `put_coordinated`,
/// the real coordinator and a drain pass (review probe P1 as a test).
///
/// A web replica (`web-a`) stages a fragment; its stager row commits with the
/// custody. Its file is then lost, as a reader on ANOTHER directory sees it.
/// The reader process has not confirmed `web-a` (no echo of its challenge
/// from `web-a`; for example a drain restarted after `web-a` left). The
/// drain keeps the fragment `Staged` across passes: never `Missing`. A GET
/// answers `SlowDown` (the head is still that `Staged` epoch). The fixture's
/// own source fragment has no stager at all and stays `Staged` for the same
/// reason. Once the reader confirms `web-a` in its own stage, the drain reads
/// the loss as real and marks only that fragment `Missing`.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn drain_guard_keeps_a_departed_writers_file_staged_and_marks_it_missing_only_where_confirmed()
 {
    use crate::domain::fragments::StagerIdentity;
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    bind_repository(&fixture).await;
    observe_settled(&fixture).await;
    fixture.handle.note_drain_heartbeat();
    assert_eq!(fixture.handle.mode(), StagingMode::Stage, "control");

    // The web replica stages, recording itself as the stager.
    let web_a = StagerIdentity::new("web-a", "inc-a").unwrap();
    assert!(fixture.handle.attach_stager(web_a.clone()));
    assert!(
        !fixture
            .handle
            .attach_stager(StagerIdentity::new("web-b", "inc-b").unwrap()),
        "a second stager is refused"
    );
    let bytes = fragment_bytes("drain-guard");
    accept(&fixture, &bytes);
    put(&fixture.store, &bytes).await.expect("staged");
    let hash = address_of(&bytes).hash;
    assert_eq!(
        readable_state(&fixture, &bytes).await,
        Some(FragmentLifecycleState::Staged)
    );
    let epoch: i64 = fixture
        .admin
        .query_one(
            "SELECT current_epoch FROM lore_fragment_lifecycle WHERE hash=$1",
            &[&hash.data().as_slice()],
        )
        .await
        .unwrap()
        .get(0);
    let recorded = fixture
        .admin
        .query_one(
            "SELECT replica_id, incarnation FROM lore_domain_write_behind_stagers \
             WHERE hash=$1 AND epoch=$2",
            &[&hash.data().as_slice(), &epoch],
        )
        .await
        .unwrap();
    assert_eq!(
        (recorded.get::<_, String>(0), recorded.get::<_, String>(1)),
        ("web-a".to_owned(), "inc-a".to_owned()),
        "the stager commits with the custody"
    );

    // This reader process has not confirmed web-a. The minimum staged age
    // is the production one, so a confirmed miss stays kept until the test
    // ages the epoch row (review B S1 of rounds 4 and 5). The epoch row was
    // created moments ago; the steps below take well under that age.
    let confirmed = Arc::new(std::sync::Mutex::new(Vec::<StagerIdentity>::new()));
    let source = confirmed.clone();
    let counts = fixture
        .handle
        .attach_drain_absence_guard(
            Arc::new(move |stager| source.lock().unwrap().contains(stager)),
            MIN_STAGED_ABSENCE_AGE,
        )
        .expect("the drain guard attaches");
    assert!(
        fixture
            .handle
            .attach_drain_absence_guard(Arc::new(|_| true), Duration::ZERO)
            .is_none(),
        "a second drain guard is refused"
    );
    assert_eq!(
        fixture.handle.mode(),
        StagingMode::Stage,
        "the drain guard does not touch admission"
    );

    std::fs::remove_file(staged_path(&fixture, &hash, epoch)).expect("the staged file exists");
    std::fs::remove_file(staged_path(
        &fixture,
        &fixture.address.hash,
        fixture.source_epoch,
    ))
    .expect("the fixture's staged file exists");

    // A GET on this reader: the head is still (Staged, epoch), so the miss
    // answers SlowDown, and the fragment stays Staged.
    let FragmentLifecycleRoute::Coordinated {
        coordinator,
        provider,
        ..
    } = &fixture.store.fragment_route
    else {
        panic!("the fixture store is coordinated");
    };
    let got = fixture
        .store
        .load_coordinated_optimistic(
            coordinator,
            provider.as_ref(),
            Context::from(REPOSITORY),
            address_of(&bytes),
        )
        .await;
    assert!(
        matches!(&got, Err(error) if error.is_slow_down()),
        "a GET for an unconfirmed stager's lost file answers SlowDown, got {:?}",
        got.as_ref().map(|_| ())
    );
    assert_eq!(
        head_state_of(&fixture, hash.data().as_slice()).await,
        FragmentLifecycleState::Staged.bits(),
        "a GET never marks it Missing"
    );

    for _ in 0..3 {
        assert_eq!(fixture.handle.drain_pass(8).await.unwrap(), 0);
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    for (what, hash) in [
        ("the departed writer's file", hash.data().as_slice()),
        (
            "a file with no stager",
            fixture.address.hash.data().as_slice(),
        ),
    ] {
        assert_eq!(
            head_state_of(&fixture, hash).await,
            FragmentLifecycleState::Staged.bits(),
            "{what} stays Staged on another directory, never Missing"
        );
    }
    let seen = counts.snapshot();
    assert!(seen.unconfirmed >= 1, "{seen:?}");
    assert!(seen.no_stager >= 1, "{seen:?}");
    assert_eq!(seen.proven, 0, "{seen:?}");
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 0);

    // This reader confirms web-a in its own stage, but the representation is
    // younger than the minimum staged age: a two-way sync may not have
    // carried the file yet, so it stays Staged.
    confirmed.lock().unwrap().push(web_a.clone());
    tokio::time::timeout(Duration::from_secs(30), async {
        while counts.snapshot().too_recent == 0 {
            fixture.handle.drain_pass(8).await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("a confirmed miss younger than the minimum staged age is read");
    assert_eq!(
        head_state_of(&fixture, hash.data().as_slice()).await,
        FragmentLifecycleState::Staged.bits(),
        "a confirmed miss younger than the minimum staged age stays Staged"
    );
    assert_eq!(counts.snapshot().proven, 0, "{:?}", counts.snapshot());

    // Once the representation is older than the minimum staged age (by the
    // database clock, from its epoch row), the loss is real. A deferred
    // fragment waits out its cool-down, so pass until one reads.
    fixture
        .admin
        .execute(
            "UPDATE lore_fragment_epochs SET created_at = created_at - interval '2 hours' \
             WHERE hash = $1 AND epoch = $2",
            &[&hash.data().as_slice(), &epoch],
        )
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(30), async {
        while head_state_of(&fixture, hash.data().as_slice()).await
            != FragmentLifecycleState::Missing.bits()
        {
            fixture.handle.drain_pass(8).await.unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("a drain that confirmed the stager marks a truly lost file Missing");
    assert!(counts.snapshot().proven >= 1);
    assert_eq!(
        head_state_of(&fixture, fixture.address.hash.data().as_slice()).await,
        FragmentLifecycleState::Staged.bits(),
        "a file with no stager is never read as absent by a guarded drain"
    );
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 0);
}

/// Observe until `done` holds for one observation, and return it.
async fn observe_until(
    fixture: &Fixture,
    why: &str,
    done: impl Fn(&WriteBehindObservation) -> bool,
) -> WriteBehindObservation {
    tokio::time::timeout(SETTLE, async {
        loop {
            let observation = fixture.handle.observe().await.unwrap();
            if done(&observation) {
                return observation;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{why}; mode {:?}", fixture.handle.mode()))
}

/// Lost drain spool root. The spool writer pins its root by device and inode,
/// so a moved root, and an empty directory put in its place, both read as
/// unusable: `free_space_unknown` is a capacity predicate that refuses at once.
/// Staging refuses with `SlowDown` and no direct write, the drain sends nothing,
/// and the staged source stays readable. Restoring the original root restores
/// admission, and the drain then promotes what was pending.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn admission_lost_drain_spool_root_refuses_staging_and_sends_nothing() {
    let fixture = Fixture::open(PutResult::Created, FragmentGetResponse::NotFound, payload()).await;
    bind_repository(&fixture).await;
    fixture.handle.note_drain_heartbeat();
    let observation = observe_until(&fixture, "control: a healthy tier settles", |o| {
        o.capacity_available
    })
    .await;
    assert!(observation.roots_usable);
    assert_eq!(observation.pending_files, 1, "the fixture's own source");
    assert_eq!(fixture.handle.mode(), StagingMode::Stage, "control");

    let spool = fixture.root.join("spool");
    let detached = fixture.root.join("detached-spool");
    std::fs::rename(&spool, &detached).unwrap();
    for (why, replace) in [("moved spool root", false), ("replaced spool root", true)] {
        if replace {
            std::fs::create_dir(&spool).unwrap();
        }
        let lost = observe_until(&fixture, why, |o| !o.roots_usable).await;
        assert!(!lost.capacity_available, "{why}: {:?}", lost.capacity);
        assert!(
            lost.capacity.failing.contains(&"free_space_unknown"),
            "{why}: {:?}",
            lost.capacity
        );
        assert!(
            fixture.stage.snapshot().root_available,
            "{why}: the staging root itself is intact"
        );
        assert_eq!(fixture.handle.mode(), StagingMode::Refuse, "{why}");
        let refused = fragment_bytes("spool-lost");
        accept(&fixture, &refused);
        assert_refused_without_side_effects(&fixture, &refused, why).await;
        let drained = fixture.handle.drain_pass(8).await;
        assert!(
            !matches!(drained, Ok(promoted) if promoted > 0),
            "{why}: no promotion completes without a spool, got {drained:?}"
        );
        assert_eq!(
            fixture.port.puts.load(Ordering::SeqCst),
            0,
            "{why}: the drain cannot spool a body, so it sends nothing"
        );
        assert_eq!(
            readable_state(&fixture, &payload()).await,
            Some(FragmentLifecycleState::Staged),
            "{why}: the pending source stays readable from the stage"
        );
    }
    std::fs::remove_dir(&spool).unwrap();
    std::fs::rename(&detached, &spool).unwrap();

    observe_until(&fixture, "a restored spool root clears capacity", |o| {
        o.roots_usable && o.capacity_available
    })
    .await;
    fixture.handle.note_drain_heartbeat();
    assert_eq!(fixture.handle.mode(), StagingMode::Stage);
    let retried = fragment_bytes("spool-lost");
    put(&fixture.store, &retried)
        .await
        .expect("the same PUT is admitted once the spool root is back");
    assert_eq!(
        readable_state(&fixture, &retried).await,
        Some(FragmentLifecycleState::Staged)
    );
    let mut promoted = 0;
    tokio::time::timeout(SETTLE, async {
        while fixture.port.puts.load(Ordering::SeqCst) < 2 {
            promoted += fixture.handle.drain_pass(8).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("forward progress: the drain promotes both staged fragments");
    assert_eq!(promoted, 2);
}

/// The ledger backstop. Admission's occupancy is stale (no observation since
/// the control staged), so it still reads `Stage`, and the PUT reaches
/// `begin_stage`, whose ledger has no room under the published count. That
/// refusal is retryable backpressure: `SlowDown`, no direct write, and the
/// rolled-back begin leaves no preparation to fence the retry.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn admission_stale_occupancy_ledger_refusal_is_slow_down() {
    let fixture = ledger_full_fixture().await;
    let refused = fragment_bytes("ledger-full");
    accept(&fixture, &refused);
    assert_refused_without_side_effects(&fixture, &refused, "ledger backstop").await;
}

/// A missing stage usage row also charges zero rows at `begin_stage`. That is
/// corruption, not pressure, so it must not read as the retryable capacity
/// refusal: the PUT fails `Internal`, with no direct write.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn admission_missing_stage_usage_row_is_internal_not_slow_down() {
    let fixture = ledger_full_fixture().await;
    fixture
        .admin
        .execute("DELETE FROM lore_fragment_stage_usage", &[])
        .await
        .unwrap();
    let corrupt = fragment_bytes("usage-missing");
    accept(&fixture, &corrupt);
    let result = put(&fixture.store, &corrupt).await;
    assert!(
        matches!(&result, Err(StoreError::Internal(_))),
        "a missing usage row is permanent, got {result:?}"
    );
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 0);
    for (table, count) in rows_for(&fixture, &corrupt).await {
        assert_eq!(count, 0, "the failed begin writes no {table} row");
    }
}

/// A reservation larger than the published byte limit never fits, even in an
/// empty ledger, so it stays `Internal` rather than an endless `SlowDown`. The
/// control, a fragment exactly at the limit refused only because the ledger is
/// full, is the retryable `SlowDown`.
#[tokio::test]
#[ignore = "requires owned PostgreSQL BLAKE3 fixture, setup example, and Linux roots"]
async fn admission_reservation_over_the_stage_policy_is_internal_not_slow_down() {
    // The fixture's own source fills the ledger's bytes exactly.
    let hard_bytes = payload().len() as u64;
    let fixture = Fixture::open_tuned(
        PutResult::Created,
        FragmentGetResponse::NotFound,
        payload(),
        false,
        |settings| {
            settings.watermarks.low_bytes = 0;
            settings.watermarks.high_bytes = hard_bytes;
            settings.watermarks.hard_bytes = hard_bytes;
        },
    )
    .await;
    bind_repository(&fixture).await;
    fixture.handle.note_drain_heartbeat();
    assert_eq!(
        fixture.handle.mode(),
        StagingMode::Stage,
        "occupancy is stale"
    );

    // Boundary control: exactly the byte limit fits an empty ledger, so a full
    // ledger refusing it is retryable.
    let fits = Bytes::from(vec![b'f'; payload().len()]);
    assert_eq!(fits.len() as u64, hard_bytes);
    accept(&fixture, &fits);
    assert_refused_without_side_effects(&fixture, &fits, "control: full ledger at the limit").await;

    let oversized = Bytes::from("oversized reservation ".repeat(2048));
    assert!((oversized.len() as u64) > hard_bytes);
    accept(&fixture, &oversized);
    let result = put(&fixture.store, &oversized).await;
    assert!(
        matches!(&result, Err(StoreError::Internal(_))),
        "a reservation over the policy is permanent, got {result:?}"
    );
    assert_eq!(fixture.port.puts.load(Ordering::SeqCst), 0);
    for (table, count) in rows_for(&fixture, &oversized).await {
        assert_eq!(count, 0, "the failed begin writes no {table} row");
    }
}

/// A fixture whose stage ledger holds exactly its published file count (the
/// source plus a control), while admission has observed no occupancy.
async fn ledger_full_fixture() -> Fixture {
    const HARD_COUNT: u64 = 2;
    let fixture = Fixture::open_tuned(
        PutResult::Created,
        FragmentGetResponse::NotFound,
        payload(),
        false,
        |settings| {
            settings.watermarks.low_count = 0;
            settings.watermarks.high_count = HARD_COUNT;
            settings.watermarks.hard_count = HARD_COUNT;
        },
    )
    .await;
    bind_repository(&fixture).await;
    fixture.handle.note_drain_heartbeat();
    let control = fragment_bytes("control");
    put(&fixture.store, &control)
        .await
        .expect("control: the ledger admits up to its count");
    assert_eq!(
        readable_state(&fixture, &control).await,
        Some(FragmentLifecycleState::Staged)
    );
    let snapshot = fixture.stage.snapshot();
    assert_eq!(
        fixture.handle.mode(),
        StagingMode::Stage,
        "admission's occupancy is stale: {snapshot:?}"
    );
    assert!(snapshot.staged_count < HARD_COUNT, "{snapshot:?}");
    fixture
}

/// Pressure from occupancy the observer measured. Before any observation the
/// tier stages a control fragment; once `observe()` records the two staged
/// sources, the ceiling `tune` set refuses the next PUT with no direct write.
///
/// The hard limits are also the published stage policy, which the database
/// ledger enforces at `begin_stage`. Here admission refuses first, from the
/// observed occupancy, so the refused PUT never reaches that backstop. A PUT
/// that does reach it (occupancy stale between observations) is pinned by
/// `admission_stale_occupancy_ledger_refusal_is_slow_down`.
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

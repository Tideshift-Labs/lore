// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Observe actual directory fsync completion. These tests do not simulate power loss.

use std::cell::RefCell;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::mpsc;
use std::time::Duration;

use super::ConfinedRoot;
use super::StageIoPath;
use super::WriteBehindError;
use super::derived_staged_key;

type Observer = Box<dyn FnMut(&Path, bool) -> Result<(), WriteBehindError>>;
thread_local! {
    static OBSERVER: RefCell<Option<Observer>> = const { RefCell::new(None) };
}

pub(super) fn observe_sync(path: &Path, completed: bool) -> Result<(), WriteBehindError> {
    OBSERVER.with_borrow_mut(|observer| {
        if let Some(observer) = observer {
            observer(path, completed)
        } else {
            Ok(())
        }
    })
}

struct Hook;

type ReadGate = Arc<(mpsc::SyncSender<()>, Mutex<mpsc::Receiver<()>>)>;
static READ_GATES: std::sync::LazyLock<Mutex<std::collections::BTreeMap<PathBuf, ReadGate>>> =
    std::sync::LazyLock::new(|| Mutex::new(std::collections::BTreeMap::new()));

pub(super) fn before_read(path: &Path) {
    let gate = READ_GATES.lock().unwrap().get(path).cloned();
    if let Some(gate) = gate {
        gate.0.send(()).unwrap();
        gate.1
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(20))
            .unwrap();
    }
}

#[tokio::test]
async fn cancelled_file_reader_retains_its_io_slot_until_the_blocking_job_finishes() {
    let scratch = Scratch::new();
    let root = ConfinedRoot::open(&scratch.0).unwrap();
    let hash = [0x44; 32];
    let resolved = root
        .resolve(&hash, 1, &derived_staged_key(&hash, 1).unwrap())
        .unwrap();
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    READ_GATES.lock().unwrap().insert(
        resolved.path().to_path_buf(),
        Arc::new((entered_tx, Mutex::new(release_rx))),
    );
    let reader_root = root.clone();
    let reader_path = resolved.clone();
    let reader =
        lore_base::lore_spawn!(async move { reader_root.read_regular(&reader_path).await });
    lore_base::lore_spawn_blocking!(move || entered_rx.recv_timeout(Duration::from_secs(5)))
        .await
        .unwrap()
        .expect("real blocking read entered");
    let permits = (0..15)
        .map(|_| root.try_io_permit(StageIoPath::Read).unwrap())
        .collect::<Vec<_>>();
    reader.abort();
    assert!(reader.await.unwrap_err().is_cancelled());
    assert!(
        root.try_io_permit(StageIoPath::Read).is_err(),
        "cancelling the waiter cannot free a live blocking job's slot"
    );
    release_tx.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(permit) = root.try_io_permit(StageIoPath::Read) {
                drop(permit);
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("completed blocking read releases its slot");
    READ_GATES.lock().unwrap().remove(resolved.path());
    drop(permits);
    assert!(root.read_regular(&resolved).await.unwrap().is_none());
}
impl Hook {
    fn install(
        observer: impl FnMut(&Path, bool) -> Result<(), WriteBehindError> + 'static,
    ) -> Self {
        OBSERVER.with_borrow_mut(|slot| {
            assert!(slot.is_none());
            *slot = Some(Box::new(observer));
        });
        Self
    }
}
impl Drop for Hook {
    fn drop(&mut self) {
        OBSERVER.with_borrow_mut(|slot| *slot = None);
    }
}

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("lore-fsync-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn record_completed() -> (Hook, Arc<Mutex<Vec<PathBuf>>>) {
    let paths = Arc::new(Mutex::new(Vec::new()));
    let recorded = paths.clone();
    let hook = Hook::install(move |path, completed| {
        if completed {
            recorded.lock().unwrap().push(path.to_path_buf());
        }
        Ok(())
    });
    (hook, paths)
}

#[tokio::test]
async fn root_clones_share_each_bounded_io_pool_and_puts_cannot_starve_reads() {
    let scratch = Scratch::new();
    let root = ConfinedRoot::open(&scratch.0).unwrap();
    let clone = root.clone();
    let hash = [0x42; 32];
    let key = derived_staged_key(&hash, 1).unwrap();
    let resolved = root.resolve(&hash, 1, &key).unwrap();
    let mut permits = (0..16)
        .map(|_| root.try_io_permit(StageIoPath::Put).unwrap())
        .collect::<Vec<_>>();
    assert!(
        clone.read_regular(&resolved).await.unwrap().is_none(),
        "a full put pool leaves reads their own slots"
    );
    let reads = (0..16)
        .map(|_| root.try_io_permit(StageIoPath::Read).unwrap())
        .collect::<Vec<_>>();
    assert!(matches!(
        clone.read_regular(&resolved).await,
        Err(WriteBehindError::Io {
            operation: "staging I/O capacity",
            kind: std::io::ErrorKind::WouldBlock
        })
    ));
    drop(reads);
    assert!(matches!(
        super::super::finalize::finalize(&clone, &resolved, &bytes::Bytes::from_static(b"blocked"))
            .await,
        Err(WriteBehindError::Io {
            operation: "staging I/O capacity",
            kind: std::io::ErrorKind::WouldBlock
        })
    ));
    assert_eq!(
        std::fs::read_dir(scratch.0.join("incoming"))
            .unwrap()
            .count(),
        0
    );
    permits.pop();
    super::super::finalize::finalize(&clone, &resolved, &bytes::Bytes::from_static(b"freed"))
        .await
        .expect("a freed put slot admits the finalizer");
    assert_eq!(
        clone.read_regular(&resolved).await.unwrap().as_deref(),
        Some(b"freed".as_slice())
    );
}

#[tokio::test]
async fn a_put_waits_for_a_freed_slot_within_its_budget_and_is_refused_after_it() {
    // Row 76: a burst of puts larger than the pool was refused at once, and the
    // client's backoff turned each refusal into a 10 s wave.
    let scratch = Scratch::new();
    let root = ConfinedRoot::open(&scratch.0).unwrap();
    let mut held = (0..16)
        .map(|_| root.try_io_permit(StageIoPath::Put).unwrap())
        .collect::<Vec<_>>();
    let waiter_root = root.clone();
    let waiter = lore_base::lore_spawn!(async move {
        waiter_root
            .io_permit_within(StageIoPath::Put, Duration::from_secs(5))
            .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    held.pop();
    let _granted = tokio::time::timeout(Duration::from_secs(5), waiter)
        .await
        .expect("the waiter is woken by the freed slot, not by its budget")
        .unwrap()
        .expect("a slot freed inside the budget is granted");

    let started = std::time::Instant::now();
    let refused = root
        .io_permit_within(StageIoPath::Put, Duration::from_millis(100))
        .await;
    assert!(matches!(
        refused,
        Err(WriteBehindError::Io {
            operation: "staging I/O capacity",
            kind: std::io::ErrorKind::WouldBlock
        })
    ));
    assert!(started.elapsed() >= Duration::from_millis(100));
    assert!(
        root.io_permit_within(StageIoPath::Put, Duration::ZERO)
            .await
            .is_err(),
        "a zero budget refuses at once"
    );
}

fn put_stage(
    root: &Path,
    slots: usize,
    wait: Duration,
) -> Arc<crate::store::write_behind::WriteBehindStage> {
    crate::store::write_behind::WriteBehindStage::open(
        crate::store::write_behind::WriteBehindSettings {
            root: root.to_path_buf(),
            watermarks: crate::store::write_behind::WriteBehindWatermarks {
                low_bytes: 1 << 30,
                high_bytes: 2 << 30,
                hard_bytes: 3 << 30,
                low_count: 1_000_000,
                high_count: 2_000_000,
                hard_count: 3_000_000,
                min_free_bytes: 1,
            },
            drain_stale_after: Duration::from_secs(60),
            sample_interval: Duration::from_secs(3_600),
            stage_io_wait: wait,
            put_database_slots: slots,
        },
    )
    .unwrap()
}

fn refused_for(
    result: Result<crate::store::write_behind::PutReservation, WriteBehindError>,
) -> &'static str {
    match result {
        Err(WriteBehindError::Io { operation, .. }) => operation,
        Err(other) => panic!("unexpected refusal {other:?}"),
        Ok(_) => panic!("the reservation must be refused"),
    }
}

#[tokio::test]
async fn at_most_put_database_slots_puts_hold_a_reservation_at_once() {
    // Row 76: with only the I/O wait, 16 staged PUTs queued on a 3-connection
    // domain pool and the observer timed out behind them.
    let scratch = Scratch::new();
    let stage = put_stage(&scratch.0, 2, Duration::from_millis(100));
    let first = stage.reserve_put().await.unwrap();
    let _second = stage.reserve_put().await.unwrap();
    assert_eq!(
        refused_for(stage.reserve_put().await),
        crate::store::write_behind::PUT_DATABASE_CAPACITY,
        "a third PUT waits its budget for a database slot and is refused"
    );
    drop(first);
    let _third = stage
        .reserve_put()
        .await
        .expect("a freed database slot admits the next PUT");
}

#[tokio::test]
async fn a_put_refused_its_io_slot_returns_its_database_slot() {
    // The two waits share one deadline and are taken database first. A PUT
    // that then misses its I/O slot must not keep the database slot, or I/O
    // pressure would shrink the database bound.
    let scratch = Scratch::new();
    let stage = put_stage(&scratch.0, 1, Duration::from_millis(100));
    let held = (0..16)
        .map(|_| stage.root().try_io_permit(StageIoPath::Put).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        refused_for(stage.reserve_put().await),
        "staging I/O capacity"
    );
    drop(held);
    let _reservation = stage
        .reserve_put()
        .await
        .expect("the only database slot was given back");
}

/// The budget every put in the burst test below gets. A test constant so a
/// revert check can set it to zero, the behaviour before row 76's fix.
const BURST_WAIT: Duration = Duration::from_secs(1);

#[tokio::test]
async fn a_burst_larger_than_the_put_pool_completes_without_a_refusal() {
    let scratch = Scratch::new();
    let root = ConfinedRoot::open(&scratch.0).unwrap();
    let mut burst = tokio::task::JoinSet::new();
    for _ in 0..48 {
        let root = root.clone();
        lore_base::lore_spawn!(burst, async move {
            let permit = root.io_permit_within(StageIoPath::Put, BURST_WAIT).await?;
            // One staged put's slot hold: begin_stage plus the fsyncs.
            tokio::time::sleep(Duration::from_millis(20)).await;
            drop(permit);
            Ok::<(), WriteBehindError>(())
        });
    }
    let mut refused = 0;
    while let Some(result) = burst.join_next().await {
        if result.unwrap().is_err() {
            refused += 1;
        }
    }
    assert_eq!(
        refused, 0,
        "48 puts over 16 slots, each held 20 ms, fit inside one budget"
    );
}

#[test]
fn absent_cleanup_requires_the_nearest_parent_fsync_to_complete() {
    let scratch = Scratch::new();
    let root = ConfinedRoot::open(&scratch.0).unwrap();
    let hash = [0x43; 32];
    let key = derived_staged_key(&hash, 1).unwrap();
    let resolved = root.resolve(&hash, 1, &key).unwrap();
    let expected = scratch.0.canonicalize().unwrap().join("staged");
    let hook = Hook::install(move |path, done| {
        if path == expected && !done {
            return Err(WriteBehindError::RootProbeFailed);
        }
        Ok(())
    });
    assert!(
        matches!(
            root.remove_placement_blocking(&resolved, false),
            Err(WriteBehindError::RootProbeFailed)
        ),
        "ENOENT alone cannot certify durable cleanup"
    );
    drop(hook);
    root.remove_placement_blocking(&resolved, false).unwrap();
}

#[test]
fn open_syncs_root_after_provisioning_both_top_level_directories() {
    let scratch = Scratch::new();
    let root_path = scratch.0.canonicalize().unwrap();
    let observed = Arc::new(Mutex::new(false));
    let completed = observed.clone();
    let expected = root_path.clone();
    let _hook = Hook::install(move |path, done| {
        if path == expected && done {
            assert!(path.join("staged").is_dir());
            assert!(path.join("incoming").is_dir());
            *completed.lock().unwrap() = true;
        }
        Ok(())
    });
    ConfinedRoot::open(&root_path).expect("open fresh root");
    assert!(
        *observed.lock().unwrap(),
        "root provisioning must complete its parent fsync"
    );
}

#[test]
fn root_fsync_failure_refuses_open() {
    let scratch = Scratch::new();
    let root_path = scratch.0.canonicalize().unwrap();
    let expected = root_path.clone();
    let _hook = Hook::install(move |path, done| {
        if path == expected && !done {
            return Err(WriteBehindError::RootProbeFailed);
        }
        Ok(())
    });
    assert!(matches!(
        ConfinedRoot::open(&root_path),
        Err(WriteBehindError::RootProbeFailed)
    ));
}

#[test]
fn each_writer_syncs_both_ancestors_even_when_creator_has_not_synced_them() {
    for pause_at_first_parent in [true, false] {
        let scratch = Scratch::new();
        let root = ConfinedRoot::open(&scratch.0).unwrap();
        let staged = scratch.0.canonicalize().unwrap().join("staged");
        let first_parent = staged.join("ab");
        let pause_path = if pause_at_first_parent {
            staged.clone()
        } else {
            first_parent.clone()
        };
        let hash = [0xab; 32];
        let first = root
            .resolve(&hash, 1, &derived_staged_key(&hash, 1).unwrap())
            .unwrap();
        let second = root
            .resolve(&hash, 2, &derived_staged_key(&hash, 2).unwrap())
            .unwrap();
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let creator_root = root.clone();
        let creator = std::thread::spawn(move || {
            let _hook = Hook::install(move |path, done| {
                if path == pause_path && !done {
                    entered_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                }
                Ok(())
            });
            creator_root.ensure_parent(&first)
        });
        let entered = entered_rx.recv_timeout(Duration::from_secs(5));
        let (_hook, paths) = record_completed();
        let result = if entered.is_ok() {
            root.ensure_parent(&second)
        } else {
            Err(WriteBehindError::RootProbeFailed)
        };
        let _ = release_tx.send(());
        let creator_result = creator.join().expect("creator finishes");
        entered.expect("creator reached fsync before release");
        creator_result.expect("creator succeeds");
        result.expect("second writer succeeds independently");
        assert_eq!(
            *paths.lock().unwrap(),
            vec![staged, first_parent],
            "second writer must complete both parent fsyncs before returning"
        );
    }
}

#[test]
fn existing_fanout_parent_fsync_failure_refuses_the_second_writer() {
    let scratch = Scratch::new();
    let root = ConfinedRoot::open(&scratch.0).unwrap();
    let hash = [0xab; 32];
    let resolved = root
        .resolve(&hash, 1, &derived_staged_key(&hash, 1).unwrap())
        .unwrap();
    root.ensure_parent(&resolved).unwrap();
    for failed_parent in [scratch.0.join("staged"), scratch.0.join("staged/ab")] {
        let _hook = Hook::install(move |path, done| {
            if path == failed_parent && !done {
                return Err(WriteBehindError::RootProbeFailed);
            }
            Ok(())
        });
        assert_eq!(
            root.ensure_parent(&resolved).map(|_| ()),
            Err(WriteBehindError::RootProbeFailed)
        );
    }
}

// --- INV-FT F2 (WP-115 row 67): purge removes empty fan-out directories ---

fn staged_file(root: &ConfinedRoot, hash: &[u8; 32], epoch: i64) -> super::ResolvedStagedPath {
    root.resolve(hash, epoch, &derived_staged_key(hash, epoch).unwrap())
        .unwrap()
}

#[tokio::test]
async fn purge_removes_the_empty_fanout_directories_but_keeps_staged() {
    let scratch = Scratch::new();
    let root = ConfinedRoot::open(&scratch.0).unwrap();
    let resolved = staged_file(&root, &[0xab; 32], 1);
    crate::store::write_behind::finalize::finalize(
        &root,
        &resolved,
        &bytes::Bytes::from_static(b"x"),
    )
    .await
    .unwrap();
    root.remove_placement_blocking(&resolved, false).unwrap();
    assert!(
        !scratch.0.join("staged/ab/ab").exists(),
        "leaf fan-out removed"
    );
    assert!(
        !scratch.0.join("staged/ab").exists(),
        "upper fan-out removed"
    );
    assert!(scratch.0.join("staged").is_dir(), "staged itself stays");
    assert!(scratch.0.join("incoming").is_dir(), "incoming stays");
}

#[tokio::test]
async fn purge_keeps_a_fanout_directory_that_still_holds_another_file() {
    let scratch = Scratch::new();
    let root = ConfinedRoot::open(&scratch.0).unwrap();
    let (first, second) = (
        staged_file(&root, &[0xab; 32], 1),
        staged_file(&root, &[0xab; 32], 2),
    );
    for resolved in [&first, &second] {
        crate::store::write_behind::finalize::finalize(
            &root,
            resolved,
            &bytes::Bytes::from_static(b"x"),
        )
        .await
        .unwrap();
    }
    root.remove_placement_blocking(&first, false).unwrap();
    assert!(
        second.path().is_file(),
        "the other file keeps its directory"
    );
    root.remove_placement_blocking(&first, false).unwrap();
    root.remove_placement_blocking(&second, false).unwrap();
    assert!(!scratch.0.join("staged/ab").exists());
}

/// A purge may remove a fan-out directory a concurrent finalizer has just
/// made and not yet renamed into. The finalizer must redo step 1, not fail.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_purges_in_the_same_fanout_never_fail_a_finalize() {
    let scratch = Scratch::new();
    let root = ConfinedRoot::open(&scratch.0).unwrap();
    let hash = [0xab; 32];
    let purger_root = root.clone();
    let purger = std::thread::spawn(move || {
        for epoch in 0..400 {
            // Absent files still remove the empty fan-out: the race under test.
            let resolved = staged_file(&purger_root, &hash, 1_000_000 + epoch);
            purger_root
                .remove_placement_blocking(&resolved, false)
                .unwrap();
        }
    });
    for epoch in 0..400 {
        let resolved = staged_file(&root, &hash, epoch);
        crate::store::write_behind::finalize::finalize(
            &root,
            &resolved,
            &bytes::Bytes::from_static(b"x"),
        )
        .await
        .unwrap_or_else(|error| panic!("finalize {epoch} failed: {error}"));
        root.remove_placement_blocking(&resolved, false).unwrap();
    }
    purger.join().unwrap();
}

/// The reviewer's case: a purge removes the leaf step 1 synced and another
/// finalizer recreates one at the same path before syncing it. The rename must
/// refuse the held, removed leaf rather than land in the recreated directory.
#[test]
fn a_rename_into_a_removed_and_recreated_leaf_is_not_found() {
    let scratch = Scratch::new();
    let root = ConfinedRoot::open(&scratch.0).unwrap();
    let resolved = staged_file(&root, &[0xab; 32], 1);
    let leaf = root.ensure_parent(&resolved).unwrap();
    std::fs::remove_dir(resolved.parent()).unwrap();
    std::fs::create_dir(resolved.parent()).unwrap();
    let temporary = scratch.0.join("incoming").join("case.tmp");
    std::fs::write(&temporary, b"x").unwrap();
    assert!(matches!(
        ConfinedRoot::rename_into(&temporary, &resolved, &leaf),
        Err(WriteBehindError::Io {
            kind: std::io::ErrorKind::NotFound,
            ..
        })
    ));
    assert!(
        !resolved.path().exists(),
        "nothing lands in the recreated leaf"
    );
    assert!(
        temporary.exists(),
        "the synced temporary file is kept for the retry"
    );
}

/// Runs `finalize_blocking` on a blocking worker with a sync hook installed
/// there: the hook is thread-local, and the `failure_generator` failpoints need
/// a runtime handle that a plain `#[test]` does not have.
async fn finalize_with_hook(
    root: ConfinedRoot,
    resolved: super::ResolvedStagedPath,
    hook: impl FnMut(&Path, bool) -> Result<(), WriteBehindError> + Send + 'static,
) -> Result<(), WriteBehindError> {
    lore_base::lore_spawn_blocking!(move || {
        let _hook = Hook::install(hook);
        super::super::finalize::finalize_blocking(
            &root,
            &super::super::StageAttempt::default(),
            &resolved,
            &bytes::Bytes::from_static(b"x"),
        )
    })
    .await
    .unwrap()
}

/// A purge removes the upper fan-out directory after `ensure_parent` opened it
/// and before it creates the leaf inside it. The held upper is then removed, so
/// creating the leaf is `NotFound` and finalize redoes step 1.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finalize_redoes_step_one_when_the_upper_fanout_is_removed_before_the_leaf() {
    let scratch = Scratch::new();
    let root = ConfinedRoot::open(&scratch.0).unwrap();
    let resolved = staged_file(&root, &[0xab; 32], 1);
    let staged = scratch.0.canonicalize().unwrap().join("staged");
    let upper = staged.join("ab");
    let mut fired = false;
    finalize_with_hook(root, resolved.clone(), move |path, done| {
        // Syncing `staged` happens after `upper` is opened, before the leaf mkdirat.
        if path == staged && !done && !fired {
            fired = true;
            std::fs::remove_dir(&upper).unwrap();
        }
        Ok(())
    })
    .await
    .expect("finalize recreates the removed fan-out directory");
    assert_eq!(std::fs::read(resolved.path()).unwrap(), b"x");
}

/// End to end: a purge removes the leaf after step 1 synced it and another
/// finalizer recreates it at the same path. The rename into the held leaf is
/// `NotFound`, finalize redoes step 1, and the file lands in a leaf it synced.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn finalize_redoes_step_one_when_the_leaf_is_removed_and_recreated() {
    let scratch = Scratch::new();
    let root = ConfinedRoot::open(&scratch.0).unwrap();
    let resolved = staged_file(&root, &[0xab; 32], 1);
    let upper = scratch.0.canonicalize().unwrap().join("staged/ab");
    let leaf = upper.join("ab");
    let upper_syncs = Arc::new(Mutex::new(0));
    let counted = upper_syncs.clone();
    finalize_with_hook(root, resolved.clone(), move |path, done| {
        // The upper sync completes after the leaf is opened, before the rename.
        if path == upper && done {
            let mut count = counted.lock().unwrap();
            *count += 1;
            if *count == 1 {
                std::fs::remove_dir(&leaf).unwrap();
                std::fs::create_dir(&leaf).unwrap();
            }
        }
        Ok(())
    })
    .await
    .expect("finalize retries into a leaf it synced");
    assert_eq!(*upper_syncs.lock().unwrap(), 2, "step 1 ran again");
    assert_eq!(std::fs::read(resolved.path()).unwrap(), b"x");
}

// --- The withdraw/rename boundary (StageAttempt) ---

async fn finalize_attempt(
    root: ConfinedRoot,
    resolved: super::ResolvedStagedPath,
    attempt: super::super::StageAttempt,
) -> Result<(), WriteBehindError> {
    lore_base::lore_spawn_blocking!(move || {
        super::super::finalize::finalize_blocking(
            &root,
            &attempt,
            &resolved,
            &bytes::Bytes::from_static(b"x"),
        )
    })
    .await
    .unwrap()
}

fn temporary_for(scratch: &Scratch, resolved: &super::ResolvedStagedPath) -> PathBuf {
    let key = resolved.path().file_name().unwrap().to_str().unwrap();
    scratch.0.join("incoming").join(format!("{key}.tmp"))
}

#[tokio::test]
async fn a_withdrawn_attempt_refuses_its_rename_and_places_nothing() {
    let scratch = Scratch::new();
    let root = ConfinedRoot::open(&scratch.0).unwrap();
    let resolved = staged_file(&root, &[0x5a; 32], 1);
    let attempt = super::super::StageAttempt::default();
    assert!(attempt.withdraw());
    assert_eq!(
        finalize_attempt(root, resolved.clone(), attempt).await,
        Err(WriteBehindError::Withdrawn)
    );
    assert!(
        !resolved.path().exists(),
        "a withdrawn attempt never renames"
    );
    assert!(
        !temporary_for(&scratch, &resolved).exists(),
        "its temporary file is removed"
    );
}

/// The release path: the rename is claimed, the rename fails, and the claim
/// is released, so the caller can withdraw the preparation.
#[tokio::test]
async fn a_failed_rename_releases_its_claim_so_the_attempt_can_withdraw() {
    let scratch = Scratch::new();
    let root = ConfinedRoot::open(&scratch.0).unwrap();
    let hash = [0x5b; 32];
    let resolved = staged_file(&root, &hash, 1);
    super::super::finalize::test_faults::install(
        &hash,
        super::super::finalize::test_faults::Fault::RenameError,
    );
    let attempt = super::super::StageAttempt::default();
    let failed = finalize_attempt(root, resolved.clone(), attempt.clone()).await;
    assert!(
        matches!(failed, Err(WriteBehindError::Io { .. })),
        "the rename error reaches the caller: {failed:?}"
    );
    assert!(
        attempt.withdraw(),
        "a failed rename releases its claim, so withdrawal wins"
    );
    assert!(!resolved.path().exists());
    assert!(!temporary_for(&scratch, &resolved).exists());
}

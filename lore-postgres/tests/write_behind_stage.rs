// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT

//! Offline (no Postgres, no S3, no live provider) coverage for
//! `lore_postgres::store::write_behind::WriteBehindStage` -- WP-114 CD-6/CD-7's
//! store-adapter seam.
//!
//! `root.rs` and `admission.rs` already carry solid `#[cfg(test)] mod tests`
//! for their own pure logic (key derivation, watermark hysteresis). This file
//! does not repeat that; it drives the public `WriteBehindStage` surface --
//! `open`, `stage`, `read_staged`, `mode` -- end to end against a real temp
//! directory, because that is the boundary the store adapter actually calls
//! and the boundary a lagging test would miss a wiring mistake at.
//!
//! # The mandatory case
//!
//! `mod.rs`'s own header names the hazard this module exists to prevent: a
//! second process without a working staging root must never answer
//! `StagedRead::Absent` for a fragment that is merely unreachable, because the
//! caller in `immutable_store.rs` maps `Absent` onto
//! `MissingDiagnostic::Absent` and demotes a healthy fragment to `Missing`.
//! [`the_case_that_matters_most_an_unavailable_root_never_answers_absent`]
//! proves it directly against `read_staged`, for both a fragment this process
//! staged itself and one it never touched.
//!
//! Staging is Unix-only by owner ruling (2026-09-16): `WriteBehindStage::open`
//! returns `Err(WriteBehindError::UnsupportedPlatform)` off Unix (see
//! `root.rs`'s `#[cfg(not(unix))]` arm), so every case below is `#[cfg(unix)]`.
//! On the Windows dev rig this file compiles but contributes zero tests; that
//! is `cfg`, not `#[ignore]`, because this is a platform gate, not an
//! infrastructure gate.

#![cfg(unix)]

use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use bytes::Bytes;
use lore_base::types::FRAGMENT_SIZE_THRESHOLD;
use lore_postgres::store::write_behind::StagedRead;
use lore_postgres::store::write_behind::StagingMode;
use lore_postgres::store::write_behind::WriteBehindError;
use lore_postgres::store::write_behind::WriteBehindSettings;
use lore_postgres::store::write_behind::WriteBehindStage;
use lore_postgres::store::write_behind::WriteBehindWatermarks;

/// A freshly created, uniquely named temp directory, removed best-effort on
/// drop so a failed assertion does not leak fixtures across runs.
struct ScratchRoot(PathBuf);

impl ScratchRoot {
    fn new(case: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "lore-write-behind-{case}-{:016x}",
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&path).expect("create scratch staging root");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ScratchRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn generous_watermarks() -> WriteBehindWatermarks {
    // Large enough that no test here crosses a threshold by accident; the
    // watermark table itself is admission.rs's own test responsibility.
    WriteBehindWatermarks {
        low_bytes: 10_000_000,
        high_bytes: 20_000_000,
        hard_bytes: 30_000_000,
        low_count: 1_000,
        high_count: 2_000,
        hard_count: 3_000,
        min_free_bytes: 0,
    }
}

fn settings(root: PathBuf) -> WriteBehindSettings {
    WriteBehindSettings {
        root,
        watermarks: generous_watermarks(),
        drain_stale_after: Duration::from_secs(60),
        // Long enough that the admission sampler's periodic re-fire never
        // lands mid-test. Its first tick is consumed by `open` (which has
        // already sampled the root synchronously), so with this interval no
        // background sample runs during a case that does not ask for one.
        sample_interval: Duration::from_secs(3_600),
    }
}

fn open(root: &ScratchRoot) -> std::sync::Arc<WriteBehindStage> {
    WriteBehindStage::open(settings(root.path().to_path_buf())).expect("open a healthy root")
}

/// Twin of `root::derived_staged_key`, which is `pub(crate)` and unreachable
/// from an integration test. Duplicated here from the documented,
/// stability-committed format in `root.rs`'s module header rather than
/// guessed: `"<64 lowercase hex>.s<epoch>"`. Keep the two in sync the same way
/// `root.rs` keeps its own copy in sync with the coordinator's private
/// `staged_epoch_key`.
fn staged_key(hash: &[u8; 32], epoch: i64) -> String {
    format!("{}.s{epoch}", hex::encode(hash))
}

/// Twin of `root::ConfinedRoot::resolve`'s path arithmetic, for tests that
/// need to plant a file directly on disk (bypassing `WriteBehindStage::stage`)
/// to prove the read path refuses it.
fn staged_path(root: &Path, hash: &[u8; 32], epoch: i64) -> PathBuf {
    let key = staged_key(hash, epoch);
    root.join("staged")
        .join(&key[0..2])
        .join(&key[2..4])
        .join(&key)
}

fn random_hash() -> [u8; 32] {
    rand::random()
}

fn found_bytes(read: StagedRead) -> Bytes {
    match read {
        StagedRead::Found(bytes) => bytes,
        other => panic!("expected StagedRead::Found, got {other:?}"),
    }
}

#[tokio::test]
async fn bounded_inventory_finds_typed_temps_and_final_files_but_retains_unknown_names() {
    use lore_postgres::store::write_behind::cleanup::StageFileScanner;
    let root = ScratchRoot::new("typed-inventory");
    let stage = open(&root);
    let hash = [0x12; 32];
    let key = staged_key(&hash, 7);
    stage
        .stage(&hash, 7, &key, &Bytes::from_static(b"final"))
        .await
        .unwrap();
    let temporary = root
        .path()
        .join("incoming")
        .join(format!("{}.tmp", staged_key(&hash, 8)));
    std::fs::write(&temporary, b"identified temp").unwrap();
    let unknown = root.path().join("incoming").join("legacy-unowned.tmp");
    std::fs::write(&unknown, b"retain unknown custody").unwrap();
    let mut scanner = StageFileScanner::default();
    assert!(scanner.scan(&stage, 0).is_err());
    assert!(scanner.scan(&stage, 257).is_err());
    let mut found = std::collections::BTreeSet::new();
    for _ in 0..32 {
        let batch = scanner.scan(&stage, 1).unwrap();
        assert!(batch.len() <= 1);
        for candidate in batch {
            found.insert((candidate.hash, candidate.epoch));
        }
    }
    assert_eq!(
        found,
        std::collections::BTreeSet::from([(hash, 7), (hash, 8)])
    );
    assert!(temporary.exists());
    assert!(unknown.exists());
    let (_, bytes, files, unknown_count) = scanner
        .physical_observation()
        .expect("a full cycle completed");
    assert_eq!(bytes, 5 + 15 + 22);
    assert_eq!(files, 3);
    assert_eq!(unknown_count, 1);
    let mut scanner = StageFileScanner::default();
    for _ in 0..64 {
        scanner.scan(&stage, 1).unwrap();
        if scanner.physical_observation().is_some() {
            break;
        }
    }
    let completed = scanner.physical_observation();
    assert!(completed.is_some());
    scanner.scan(&stage, 1).unwrap();
    assert_eq!(
        scanner.physical_observation(),
        completed,
        "partial traversal retains the last complete occupancy"
    );
}

#[tokio::test]
async fn deterministic_temp_collision_preserves_the_existing_file() {
    let root = ScratchRoot::new("temp-collision");
    let stage = open(&root);
    let hash = [0x32; 32];
    let key = staged_key(&hash, 4);
    let temporary = root.path().join("incoming").join(format!("{key}.tmp"));
    std::fs::write(&temporary, b"existing writer custody").unwrap();
    assert!(
        stage
            .stage(&hash, 4, &key, &Bytes::from_static(b"second writer"))
            .await
            .is_err()
    );
    assert_eq!(
        std::fs::read(&temporary).unwrap(),
        b"existing writer custody"
    );
    assert!(!staged_path(root.path(), &hash, 4).exists());
}

#[tokio::test]
async fn replacement_of_root_on_the_same_device_refuses_read_and_stage() {
    let root = ScratchRoot::new("replaced-root");
    let stage = open(&root);
    let hash = [0x33; 32];
    let key = staged_key(&hash, 4);
    stage
        .stage(&hash, 4, &key, &Bytes::from_static(b"original"))
        .await
        .unwrap();
    let moved = ScratchRoot::new("moved-original");
    std::fs::remove_dir(moved.path()).unwrap();
    std::fs::rename(root.path(), moved.path()).unwrap();
    std::fs::create_dir(root.path()).unwrap();
    assert!(matches!(
        stage.read_staged(&hash, 4, &key).await,
        StagedRead::Unavailable(_)
    ));
    assert!(
        stage
            .stage(&hash, 4, &key, &Bytes::from_static(b"replacement"))
            .await
            .is_err()
    );
    assert_eq!(
        std::fs::read(staged_path(moved.path(), &hash, 4)).unwrap(),
        b"original"
    );
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn inventory_retains_directory_handles_when_a_shard_is_replaced_by_a_symlink() {
    use lore_postgres::store::write_behind::cleanup::StageFileScanner;
    let root = ScratchRoot::new("inventory-substitution");
    let stage = open(&root);
    let hash = [0x45; 32];
    for epoch in 0..32 {
        stage
            .stage(
                &hash,
                epoch,
                &staged_key(&hash, epoch),
                &Bytes::from_static(b"owned"),
            )
            .await
            .unwrap();
    }
    let mut scanner = StageFileScanner::default();
    let mut entered = false;
    for _ in 0..64 {
        if !scanner.scan(&stage, 1).unwrap().is_empty() {
            entered = true;
            break;
        }
    }
    assert!(
        entered,
        "scan has entered the real leaf and retains its cursor"
    );
    let leaf = staged_path(root.path(), &hash, 0)
        .parent()
        .unwrap()
        .to_path_buf();
    let moved = ScratchRoot::new("retained-leaf");
    std::fs::remove_dir(moved.path()).unwrap();
    std::fs::rename(&leaf, moved.path()).unwrap();
    let external = ScratchRoot::new("external-inventory");
    let sentinel = external.path().join(staged_key(&hash, 999));
    std::fs::write(&sentinel, vec![0x6a; 100_000]).unwrap();
    std::os::unix::fs::symlink(external.path(), &leaf).unwrap();
    for _ in 0..128 {
        for candidate in scanner.scan(&stage, 1).unwrap() {
            assert_ne!(
                candidate.epoch, 999,
                "replacement path must never redirect the retained descriptor"
            );
        }
        if let Some((_, bytes, _, _)) = scanner.physical_observation() {
            assert!(
                bytes <= 32 * 5,
                "external sentinel cannot enter occupancy evidence"
            );
        }
    }
    assert_eq!(std::fs::metadata(sentinel).unwrap().len(), 100_000);
    std::fs::remove_file(leaf).unwrap();
}

#[tokio::test]
async fn stage_then_read_staged_round_trips_byte_identical_payload() {
    let root = ScratchRoot::new("roundtrip");
    let stage = open(&root);
    let hash = random_hash();
    let key = staged_key(&hash, 0);
    let payload = Bytes::from_static(b"lore-write-behind-roundtrip-payload");

    stage
        .stage(&hash, 0, &key, &payload)
        .await
        .expect("stage a within-bound payload");

    let read = stage.read_staged(&hash, 0, &key).await;
    assert_eq!(found_bytes(read), payload);
}

#[tokio::test]
async fn a_fragment_that_was_never_staged_reads_as_decisive_absent() {
    let root = ScratchRoot::new("never-staged");
    let stage = open(&root);
    let hash = random_hash();
    let key = staged_key(&hash, 0);

    let read = stage.read_staged(&hash, 0, &key).await;
    assert!(
        matches!(read, StagedRead::Absent),
        "a real ENOENT under a proven-owned root must be decisive absence, got {read:?}"
    );
}

/// THE CASE THAT MATTERS MOST.
///
/// A staging root that goes away at runtime (unmounted, or the process loses
/// access to it) must never be read as "the fragment is gone" -- for a
/// fragment this process staged, AND for one it never touched. Either
/// direction reaching `StagedRead::Absent` reproduces the fail-open the
/// reviewer caught: `immutable_store.rs`'s staged read arm would map it to
/// `MissingDiagnostic::Absent` and demote a healthy fragment to `Missing`
/// with a null manifest.
#[tokio::test]
async fn the_case_that_matters_most_an_unavailable_root_never_answers_absent() {
    let root = ScratchRoot::new("root-vanishes");
    let stage = open(&root);

    let staged_hash = random_hash();
    let staged_fragment_key = staged_key(&staged_hash, 0);
    let payload = Bytes::from_static(b"healthy fragment this process staged itself");
    stage
        .stage(&staged_hash, 0, &staged_fragment_key, &payload)
        .await
        .expect("stage a healthy fragment before the root disappears");

    // Sanity: readable before the root vanishes.
    let read_before = stage
        .read_staged(&staged_hash, 0, &staged_fragment_key)
        .await;
    assert!(matches!(read_before, StagedRead::Found(_)));

    // Simulate the root going away out from under this process (an unmount or
    // a lost bind mount both surface the same way: the recorded canonical
    // path no longer stats cleanly).
    std::fs::remove_dir_all(root.path()).expect("simulate the staging root vanishing");

    let read_after = stage
        .read_staged(&staged_hash, 0, &staged_fragment_key)
        .await;
    assert!(
        !matches!(read_after, StagedRead::Absent),
        "a fragment this process staged and proved readable must never flip to \
         Absent just because the root vanished; got {read_after:?}"
    );
    assert!(
        matches!(read_after, StagedRead::Unavailable(_)),
        "the only other honest answer is Unavailable; got {read_after:?}"
    );

    // And a hash this process never staged must ALSO stay Unavailable, not
    // Absent -- otherwise the demotion hazard only looks closed for the
    // fragment the test happened to stage first.
    let untouched_hash = random_hash();
    let untouched_key = staged_key(&untouched_hash, 0);
    let read_untouched = stage.read_staged(&untouched_hash, 0, &untouched_key).await;
    assert!(
        matches!(read_untouched, StagedRead::Unavailable(_)),
        "an unavailable root must not answer Absent even for a fragment this \
         process never touched; got {read_untouched:?}"
    );
}

#[tokio::test]
async fn a_stored_key_that_does_not_match_the_derived_key_is_refused_on_stage_and_on_read() {
    let root = ScratchRoot::new("key-mismatch");
    let stage = open(&root);
    let hash = random_hash();
    let correct_key = staged_key(&hash, 0);
    let wrong_key = staged_key(&random_hash(), 0); // a different hash's key

    let payload = Bytes::from_static(b"must not reach the filesystem");
    let stage_result = stage.stage(&hash, 0, &wrong_key, &payload).await;
    assert_eq!(stage_result, Err(WriteBehindError::KeyMismatch));

    // Stage the fragment properly, then prove a read with a tampered key is
    // refused too -- byte-equality, not path containment.
    stage
        .stage(&hash, 0, &correct_key, &payload)
        .await
        .expect("stage under the correct derived key");
    let read_result = stage.read_staged(&hash, 0, &wrong_key).await;
    assert!(
        matches!(
            read_result,
            StagedRead::Unavailable(WriteBehindError::KeyMismatch)
        ),
        "a mismatched key must never resolve to a path, let alone read one; got {read_result:?}"
    );
}

#[tokio::test]
async fn a_hash_that_is_not_thirty_two_bytes_is_refused_before_any_filesystem_access() {
    let root = ScratchRoot::new("hash-width");
    let stage = open(&root);
    let short_hash = vec![0xAB_u8; 31];
    let payload = Bytes::from_static(b"irrelevant");

    let result = stage
        .stage(&short_hash, 0, "does-not-matter", &payload)
        .await;
    assert_eq!(result, Err(WriteBehindError::HashWidth));
}

#[tokio::test]
async fn a_negative_epoch_is_refused_before_any_filesystem_access() {
    let root = ScratchRoot::new("epoch-negative");
    let stage = open(&root);
    let hash = random_hash();
    let payload = Bytes::from_static(b"irrelevant");

    let result = stage.stage(&hash, -1, "does-not-matter", &payload).await;
    assert_eq!(result, Err(WriteBehindError::EpochNegative));
}

#[tokio::test]
async fn a_payload_over_the_fragment_size_threshold_is_refused_by_stage() {
    let root = ScratchRoot::new("oversized-stage");
    let stage = open(&root);
    let hash = random_hash();
    let key = staged_key(&hash, 0);
    let payload = Bytes::from(vec![0xAB_u8; FRAGMENT_SIZE_THRESHOLD + 1]);

    let result = stage.stage(&hash, 0, &key, &payload).await;
    assert_eq!(result, Err(WriteBehindError::PayloadOversized));

    // And it must never have touched the filesystem.
    let read = stage.read_staged(&hash, 0, &key).await;
    assert!(matches!(read, StagedRead::Absent));
}

/// `stage()` refuses an oversized payload before writing it, so proving the
/// *read* side also refuses a too-large file needs one planted directly on
/// disk, bypassing `stage()`. This is what U6 in the L2 plan calls "refused
/// before allocating" -- this test proves the functional outcome (refusal,
/// not a giant successful read); the allocation-order claim itself is
/// `root.rs`'s own `read_regular_blocking`, which checks `metadata.len()`
/// before `Vec::with_capacity`.
#[tokio::test]
async fn a_staged_file_larger_than_the_size_threshold_is_refused_on_read() {
    let root = ScratchRoot::new("oversized-on-disk");
    let stage = open(&root);
    let hash = random_hash();
    let path = staged_path(root.path(), &hash, 0);
    std::fs::create_dir_all(path.parent().expect("staged path has a parent"))
        .expect("create fan-out dirs directly for this fixture");
    std::fs::write(&path, vec![0xCD_u8; FRAGMENT_SIZE_THRESHOLD + 1])
        .expect("plant an oversized file the module never wrote itself");

    let key = staged_key(&hash, 0);
    let read = stage.read_staged(&hash, 0, &key).await;
    assert!(
        matches!(
            read,
            StagedRead::Unavailable(WriteBehindError::PayloadOversized)
        ),
        "an oversized staged file must be refused, not read; got {read:?}"
    );
}

#[tokio::test]
async fn a_symlink_planted_at_the_staged_leaf_is_refused_not_followed() {
    let root = ScratchRoot::new("symlink-leaf");
    let stage = open(&root);
    let hash = random_hash();
    let path = staged_path(root.path(), &hash, 0);
    std::fs::create_dir_all(path.parent().expect("staged path has a parent"))
        .expect("create fan-out dirs directly for this fixture");

    // Plant a symlink at the exact leaf a real stage() would have finalized
    // to, pointing at a file outside the confined root entirely.
    let outside = ScratchRoot::new("symlink-target");
    let target = outside.path().join("not-a-staged-fragment");
    std::fs::write(&target, b"must never be read through the staged path")
        .expect("create the symlink target");
    std::os::unix::fs::symlink(&target, &path).expect("plant the symlink");

    let key = staged_key(&hash, 0);
    let read = stage.read_staged(&hash, 0, &key).await;
    assert!(
        !matches!(read, StagedRead::Found(_)),
        "a symlink at the staged leaf must never be followed; got {read:?}"
    );
    assert!(
        matches!(
            read,
            StagedRead::Unavailable(WriteBehindError::Io {
                operation: "staged open",
                ..
            })
        ),
        "O_NOFOLLOW should refuse the open itself (ELOOP), not classify the \
         target's contents; got {read:?}"
    );
}

/// `open` must return with the root already sampled.
///
/// Before that sample existed, a freshly opened stage read its own root as
/// *unknown*, unknown read as unavailable, and `pending_staged` starts `true`
/// -- so the boot mode was `Unready`, which takes `SlowDown` on every PUT
/// until the first sampler tick. `DirectFallback` here is the whole point: the
/// root is available and only the absent drain heartbeat keeps the tier off
/// `Stage` (see `admission.rs`'s `a_missing_drain_heartbeat_falls_back`).
///
/// No `.await` before the assertion, deliberately: this pins the mode at
/// `open`'s return, not a mode the sampler reached afterwards.
#[tokio::test]
async fn open_returns_with_the_root_already_sampled_so_no_put_sees_unready() {
    let root = ScratchRoot::new("boot-mode");
    let stage = open(&root);

    assert_eq!(
        stage.mode(),
        StagingMode::DirectFallback,
        "a proven root must not read as unknown at open's return"
    );
    let snapshot = stage.snapshot();
    assert!(
        snapshot.root_available,
        "open's synchronous first sample must have reached admission"
    );
    assert!(
        snapshot.free_bytes.is_some(),
        "the first sample carries free space, not just reachability"
    );
}

/// `WriteBehindStage::mode()` upgrades an unavailable root to `Unready`
/// specifically while `pending_staged` has not been cleared -- the escape
/// hatch `admission.rs`'s own tests cannot see, because they exercise
/// `Admission` directly and never go through the wrapping stage.
///
/// Reaching the unavailable state now takes a real event (the root vanishing)
/// plus a real sampler tick, because `open` no longer leaves the root unknown.
/// That makes this case also the one that proves the sampler still observes a
/// root through its blocking-pool detour.
#[tokio::test]
async fn a_vanished_root_upgrades_to_unready_while_pending_staged_stands() {
    let root = ScratchRoot::new("mode-unready");
    let mut settings = settings(root.path().to_path_buf());
    settings.sample_interval = Duration::from_millis(10);
    let stage = WriteBehindStage::open(settings).expect("open a healthy root");

    assert_eq!(stage.mode(), StagingMode::DirectFallback);

    std::fs::remove_dir_all(root.path()).expect("simulate the staging root vanishing");

    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while stage.mode() != StagingMode::Unready && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(
        stage.mode(),
        StagingMode::Unready,
        "a sampler tick must observe the vanished root, and pending_staged must \
         upgrade that to Unready rather than mask it with direct writes"
    );

    stage.note_pending_staged(false);
    assert_eq!(
        stage.mode(),
        StagingMode::DirectFallback,
        "clearing pending_staged must remove the Unready upgrade even though \
         the root is still unavailable"
    );
}

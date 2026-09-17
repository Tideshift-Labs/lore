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
//! On the Windows dev rig this file compiles (once `cleanup.rs` lands -- see
//! below) but contributes zero tests; that is `cfg`, not `#[ignore]`, because
//! this is a platform gate, not an infrastructure gate.
//!
//! # Blocked at the time this file was written
//!
//! `lore-postgres/src/store/write_behind/mod.rs` declares `pub mod cleanup;`
//! but `cleanup.rs` does not exist yet (`cargo check -p lore-postgres --lib`
//! fails with E0583 for `cleanup` as of this writing). This file cannot run
//! until that lands; it is not a mistake on this file's part.

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
        // lands mid-test; its *first* tick still fires as soon as the runtime
        // polls the spawned task (`tokio::time::interval`'s documented
        // behavior), which is why `mode()`-focused cases below read it
        // synchronously, before this test's first `.await`.
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

/// `WriteBehindStage::mode()` upgrades an unavailable root to `Unready`
/// specifically while `pending_staged` has not been cleared -- the escape
/// hatch `admission.rs`'s own tests cannot see, because they exercise
/// `Admission` directly and never go through the wrapping stage.
///
/// Relies on the current-thread test runtime never polling the spawned
/// admission sampler before this test's first synchronous `mode()` call --
/// the same assumption every other case here makes implicitly, stated once
/// here because this is the one case that would silently pass for the wrong
/// reason if it were violated (a sampled-available root also reads
/// `DirectFallback`, not `Stage`, absent a drain heartbeat -- see
/// `admission.rs`'s `a_missing_drain_heartbeat_falls_back`).
#[tokio::test]
async fn pending_staged_upgrades_an_unavailable_root_to_unready_by_default() {
    let root = ScratchRoot::new("mode-unready");
    let stage = open(&root);

    // No `.await` yet: the admission sampler has not been polled, so the root
    // reads as not-yet-available, and `pending_staged` defaults to `true`.
    assert_eq!(stage.mode(), StagingMode::Unready);

    stage.note_pending_staged(false);
    assert_ne!(
        stage.mode(),
        StagingMode::Unready,
        "clearing pending_staged must remove the Unready upgrade even though \
         the root is still (as far as this process knows) unavailable"
    );
}

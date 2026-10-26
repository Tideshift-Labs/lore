// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Offline, tempdir-based proof for WP-122 L5's `LinuxSpoolWriter`.
//!
//! # The platform pair below cannot be caught by a case-count differential
//!
//! Each platform drops cases and gains others: off Linux, `linux_live`'s whole
//! module is compiled out and only `open_returns_unsupported_platform_off_linux`
//! (below, top level) exists; on Linux the reverse holds and that case never
//! compiles. (WP-115 f2 added `reclaim_step_is_closed_off_linux_like_the_other_stubs` beside it,
//! and five Linux-only reclaim cases.) **Here the counts differ (2 off Linux, many more on it), so a
//! count IS discriminating for this file today** — but only by accident of the
//! ratio. The general trap, and the reason the rule is "diff names, not counts",
//! is a `cfg(unix)`/`cfg(not(unix))` PAIR: one case each way leaves the total
//! unmoved and a differential proves nothing.
//! `lore-server`'s `the_same_write_behind_block_is_accepted_on_unix` is exactly
//! that shape, with a catalog of 1,842 on both platforms; the account is in
//! `lore-postgres/tests/run-write-behind-linux.ps1`'s header. Treat the name, not
//! the number, as the evidence here too: adding one Linux case and deleting one
//! would restore the accident.

#[cfg(not(target_os = "linux"))]
use std::path::PathBuf;

#[cfg(not(target_os = "linux"))]
use lore_object_dispatch::spool::SpoolLayout;
#[cfg(not(target_os = "linux"))]
use lore_object_dispatch::spool_writer::LinuxSpoolWriter;
#[cfg(not(target_os = "linux"))]
use lore_object_dispatch::spool_writer::MAX_SPOOL_BODY_BYTES;
#[cfg(not(target_os = "linux"))]
use lore_object_dispatch::spool_writer::SpoolWriteError;

#[cfg(not(target_os = "linux"))]
#[test]
fn open_returns_unsupported_platform_off_linux() {
    let nonexistent = if cfg!(windows) {
        PathBuf::from(r"Z:\must-not-be-opened\spool-writer-secret")
    } else {
        PathBuf::from("/must-not-be-opened/spool-writer-secret")
    };
    let layout = SpoolLayout::new(nonexistent.clone()).expect("absolute test root");
    assert_eq!(
        LinuxSpoolWriter::open(&layout, MAX_SPOOL_BODY_BYTES)
            .expect_err("non-Linux must be closed"),
        SpoolWriteError::UnsupportedPlatform
    );
    assert!(!nonexistent.exists());

    let writer_open_result = LinuxSpoolWriter::open(&layout, MAX_SPOOL_BODY_BYTES);
    assert!(writer_open_result.is_err());
}

#[cfg(not(target_os = "linux"))]
#[test]
fn reclaim_step_is_closed_off_linux_like_the_other_stubs() {
    // The stub is a unit struct, so it can be named without `open` (which is also closed).
    let layout = SpoolLayout::new(if cfg!(windows) {
        PathBuf::from(r"Z:\must-not-be-opened\spool-writer-secret")
    } else {
        PathBuf::from("/must-not-be-opened/spool-writer-secret")
    })
    .expect("absolute test root");
    assert_eq!(
        LinuxSpoolWriter
            .reclaim_step(&layout, "boundary", 1_700_000_000_000, 64)
            .expect_err("non-Linux must be closed"),
        SpoolWriteError::UnsupportedPlatform
    );
}
#[cfg(target_os = "linux")]
mod linux_live {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::Path;
    use std::path::PathBuf;
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;

    use lore_object_dispatch::bind_durable_put_body;
    use lore_object_dispatch::spool::LedgerSpoolView;
    use lore_object_dispatch::spool::SPOOL_LAYOUT_REVISION_V1;
    use lore_object_dispatch::spool::SpoolLayout;
    use lore_object_dispatch::spool::SpoolObjectKey;
    use lore_object_dispatch::spool::SpoolObjectKind;
    use lore_object_dispatch::spool_writer::LinuxSpoolWriter;
    use lore_object_dispatch::spool_writer::MAX_SPOOL_BODY_BYTES;
    use lore_object_dispatch::spool_writer::SpoolWriteError;

    const BOUNDARY: &str = "boundary";
    const LOGICAL_ID: &str = "018f3e12-a456-7abc-8def-0123456789ab";

    struct TestRoot(PathBuf);

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn test_root(label: &str) -> TestRoot {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos();
        let path = PathBuf::from(format!(
            "/tmp/lore-spool-writer-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create isolated absolute spool root");
        TestRoot(path)
    }

    fn put_key(attempt_id: &str) -> SpoolObjectKey {
        SpoolObjectKey {
            provider_boundary_id: BOUNDARY.into(),
            logical_request_id: LOGICAL_ID.into(),
            attempt_id: attempt_id.into(),
            kind: SpoolObjectKind::Put,
        }
    }

    #[test]
    fn bounded_physical_scan_eventually_covers_more_than_4096_historical_directories() {
        let root = test_root("large-resumable-inventory");
        for index in 0..5000 {
            fs::create_dir(root.0.join(format!("historical-{index:05}"))).unwrap();
        }
        fs::write(root.0.join("historical-04999").join("late-body"), b"abc").unwrap();
        let layout = SpoolLayout::new(root.0.clone()).unwrap();
        let writer = LinuxSpoolWriter::open(&layout, MAX_SPOOL_BODY_BYTES).unwrap();
        assert_eq!(
            writer.physical_usage(4096).unwrap(),
            None,
            "a partial first traversal cannot certify an empty spool"
        );
        let mut complete = None;
        for _ in 0..16 {
            complete = writer.physical_usage(4096).unwrap();
            if complete.is_some() {
                break;
            }
        }
        assert_eq!(
            complete,
            Some((3, 1)),
            "retained cursors must eventually reach every historical directory"
        );
        fs::write(
            root.0.join("historical-00001").join("new-body"),
            b"new residue",
        )
        .unwrap();
        let mut updated = None;
        for _ in 0..16 {
            updated = writer.physical_usage(4096).unwrap();
            if updated == Some((14, 2)) {
                break;
            }
        }
        assert_eq!(
            updated,
            Some((14, 2)),
            "completed scans must wrap and observe later residue"
        );
    }

    #[test]
    fn a_completed_physical_walk_reports_when_it_completed() {
        let root = test_root("completed-inventory");
        fs::write(root.0.join("body"), b"abcd").unwrap();
        let layout = SpoolLayout::new(root.0.clone()).unwrap();
        let writer = LinuxSpoolWriter::open(&layout, MAX_SPOOL_BODY_BYTES).unwrap();
        let before = std::time::Instant::now();
        let inventory = writer
            .physical_usage_completed(4096)
            .unwrap()
            .expect("a small root completes in one pass");
        assert_eq!((inventory.bytes, inventory.files), (4, 1));
        assert!(inventory.completed_at >= before);
        assert!(inventory.completed_at <= std::time::Instant::now());
        assert_eq!(writer.physical_usage(4096).unwrap(), Some((4, 1)));
    }

    /// INV-FT row 67: readiness binds a walk to the ledger read before it
    /// started and after it completed, so each step must say which edge it hit.
    #[test]
    fn each_inventory_step_reports_the_traversal_it_started_and_completed() {
        let root = test_root("inventory-steps");
        for index in 0..5000 {
            fs::create_dir(root.0.join(format!("historical-{index:05}"))).unwrap();
        }
        let layout = SpoolLayout::new(root.0.clone()).unwrap();
        let writer = LinuxSpoolWriter::open(&layout, MAX_SPOOL_BODY_BYTES).unwrap();
        let first = writer.physical_usage_step(4096).unwrap();
        assert!(first.started, "the first step starts a traversal");
        assert_eq!(
            first.completed, None,
            "5,000 directories need a second step"
        );
        let mut steps = 1;
        let completed = loop {
            let step = writer.physical_usage_step(4096).unwrap();
            steps += 1;
            assert!(!step.started, "a traversal in progress is not restarted");
            if let Some(completed) = step.completed {
                break completed;
            }
            assert!(steps < 16, "the traversal must complete");
        };
        assert_eq!((completed.bytes, completed.files), (0, 0));
        let next = writer.physical_usage_step(4096).unwrap();
        assert!(
            next.started,
            "the step after a completion starts the next traversal"
        );
        assert_eq!(
            writer.physical_usage_completed(0).unwrap(),
            Some(completed),
            "a step that completes nothing still leaves the last completed traversal readable"
        );
    }

    /// Purge removes empty directories, and reading a directory removed after
    /// the walk opened it is ENOENT. That must end the directory, not reset the
    /// walk into a missing inventory.
    #[test]
    fn a_directory_removed_while_the_walk_holds_it_ends_that_directory() {
        let root = test_root("removed-mid-walk");
        let doomed = root.0.join("doomed");
        fs::create_dir_all(doomed.join("inner")).unwrap();
        fs::write(doomed.join("inner").join("body"), b"gone").unwrap();
        fs::write(root.0.join("survivor"), b"kept").unwrap();
        let layout = SpoolLayout::new(root.0.clone()).unwrap();
        let writer = LinuxSpoolWriter::open(&layout, MAX_SPOOL_BODY_BYTES).unwrap();
        // One entry per step, until the walk has descended into `doomed`.
        let mut descended = false;
        for _ in 0..8 {
            let step = writer.physical_usage_step(1).unwrap();
            assert_eq!(step.completed, None, "one entry per step cannot finish yet");
            if Path::new("/proc/self/fd").read_dir().unwrap().any(|fd| {
                fs::read_link(fd.unwrap().path()).is_ok_and(|target| target.starts_with(&doomed))
            }) {
                descended = true;
                break;
            }
        }
        assert!(
            descended,
            "the walk must hold a descriptor inside the doomed tree"
        );
        fs::remove_dir_all(&doomed).unwrap();
        let mut completed = None;
        for _ in 0..16 {
            let step = writer
                .physical_usage_step(1)
                .expect("a removed directory is not a lost root");
            if step.completed.is_some() {
                completed = step.completed;
                break;
            }
        }
        let completed = completed.expect("the walk completes past the removed directory");
        assert_eq!((completed.bytes, completed.files), (4, 1));
    }

    fn result_key(attempt_id: &str) -> SpoolObjectKey {
        SpoolObjectKey {
            provider_boundary_id: BOUNDARY.into(),
            logical_request_id: LOGICAL_ID.into(),
            attempt_id: attempt_id.into(),
            kind: SpoolObjectKind::Result,
        }
    }

    fn assert_dir_is_empty(root: &Path) {
        let mut entries = fs::read_dir(root).expect("read root directory");
        assert!(
            entries.next().is_none(),
            "expected {} to be empty after a refused write",
            root.display()
        );
    }

    /// Case 1: a successful write leaves the blob at the derived final path,
    /// leaves no `.part`, and the receipt matches the derived handle and the
    /// body's own size/digest.
    #[test]
    fn a_successful_write_leaves_the_blob_with_no_part_and_a_matching_receipt() {
        let root = test_root("basic");
        let layout = SpoolLayout::new(root.0.clone()).expect("layout");
        let writer = LinuxSpoolWriter::open(&layout, MAX_SPOOL_BODY_BYTES).expect("open writer");
        let key = put_key("018f3e12-a457-7abc-8def-0123456789ab");
        let paths = layout.derive_paths(&key).expect("derive paths");
        let body = b"a-successful-spool-write-body";

        let receipt = writer
            .write_put_body(&layout, &key, body)
            .expect("first write must succeed");

        assert!(
            paths.final_path().is_file(),
            "blob must exist at final_path"
        );
        assert!(
            !paths.part_path().exists(),
            "no .part must survive a successful write"
        );
        assert_eq!(receipt.opaque_handle(), paths.opaque_handle());
        assert_eq!(receipt.size(), body.len() as u64);
        assert_eq!(receipt.blake3(), blake3::hash(body).as_bytes());
    }

    /// Case 2, the decisive case: binding the receipt's three fields into a
    /// `LedgerSpoolView::Ready` and calling the real binder the drain actually
    /// goes through must succeed and report the same size and digest -- proof
    /// against the consumer, not a string compared against itself.
    #[test]
    fn the_receipt_binds_through_the_real_provider_binder_with_matching_size_and_digest() {
        let root = test_root("bind");
        let layout = SpoolLayout::new(root.0.clone()).expect("layout");
        let writer = LinuxSpoolWriter::open(&layout, MAX_SPOOL_BODY_BYTES).expect("open writer");
        let key = put_key("018f3e12-a458-7abc-8def-0123456789ab");
        let body = b"bound-through-the-real-provider-binder";

        let receipt = writer
            .write_put_body(&layout, &key, body)
            .expect("write must succeed");

        let ledger = LedgerSpoolView::Ready {
            opaque_handle: receipt.opaque_handle().to_string(),
            size: receipt.size(),
            blake3: *receipt.blake3(),
        };
        let bound = bind_durable_put_body(&layout, &key, &ledger)
            .expect("a durably-written body must bind through the real provider binder");
        assert_eq!(bound.size(), body.len() as u64);
        assert_eq!(bound.blake3(), receipt.blake3());
    }

    /// Case 3: a second `write_put_body` with the same key returns
    /// `BodyAlreadyPresent`, and the bytes on disk are unchanged.
    #[test]
    fn a_second_write_with_the_same_key_is_refused_and_leaves_bytes_unchanged() {
        let root = test_root("already-present");
        let layout = SpoolLayout::new(root.0.clone()).expect("layout");
        let writer = LinuxSpoolWriter::open(&layout, MAX_SPOOL_BODY_BYTES).expect("open writer");
        let key = put_key("018f3e12-a459-7abc-8def-0123456789ab");
        let paths = layout.derive_paths(&key).expect("derive paths");
        let first_body = b"the-first-and-only-body-that-should-land";

        writer
            .write_put_body(&layout, &key, first_body)
            .expect("first write must succeed");
        let before = fs::read(paths.final_path()).expect("read the durable blob");

        let error = writer
            .write_put_body(&layout, &key, b"a-different-body-must-never-replace-it")
            .expect_err("a second write under the same key must be refused");
        assert_eq!(error, SpoolWriteError::BodyAlreadyPresent);

        let after = fs::read(paths.final_path()).expect("re-read the durable blob");
        assert_eq!(
            before, after,
            "bytes on disk must be unchanged by the refused write"
        );
        assert_eq!(before, first_body);
    }

    /// Case 4: a `Result` key returns `InvalidSpoolKind`, with no filesystem
    /// effect at all.
    #[test]
    fn a_result_kind_key_is_refused_before_any_filesystem_effect() {
        let root = test_root("wrong-kind");
        let layout = SpoolLayout::new(root.0.clone()).expect("layout");
        let writer = LinuxSpoolWriter::open(&layout, MAX_SPOOL_BODY_BYTES).expect("open writer");
        let key = result_key("018f3e12-a45a-7abc-8def-0123456789ab");

        let error = writer
            .write_put_body(&layout, &key, b"result-kind-must-never-be-written")
            .expect_err("a Result key must be refused");
        assert_eq!(error, SpoolWriteError::InvalidSpoolKind);
        assert_dir_is_empty(&root.0);
    }

    /// Case 5: an empty body and a `MAX_SPOOL_BODY_BYTES + 1` body both return
    /// `InvalidBodySize`, with no filesystem effect.
    #[test]
    fn empty_and_oversized_bodies_are_refused_before_any_filesystem_effect() {
        let root = test_root("bad-size");
        let layout = SpoolLayout::new(root.0.clone()).expect("layout");
        let writer = LinuxSpoolWriter::open(&layout, MAX_SPOOL_BODY_BYTES).expect("open writer");

        let empty_key = put_key("018f3e12-a45b-7abc-8def-0123456789ab");
        let empty_error = writer
            .write_put_body(&layout, &empty_key, &[])
            .expect_err("an empty body must be refused");
        assert_eq!(empty_error, SpoolWriteError::InvalidBodySize);

        let oversized_key = put_key("018f3e12-a45c-7abc-8def-0123456789ab");
        let oversized_body = vec![0u8; usize::try_from(MAX_SPOOL_BODY_BYTES + 1).unwrap()];
        let oversized_error = writer
            .write_put_body(&layout, &oversized_key, &oversized_body)
            .expect_err("an oversized body must be refused");
        assert_eq!(oversized_error, SpoolWriteError::InvalidBodySize);

        assert_dir_is_empty(&root.0);
    }

    /// Case 6a: `open` refuses `maximum_body_bytes` of `0` and of
    /// `MAX_SPOOL_BODY_BYTES + 1`. This is the constructor's own literal
    /// bound check, reached before any filesystem access, so no live syscall
    /// measurement is needed here.
    #[test]
    fn open_refuses_a_zero_or_oversized_maximum_body_bytes() {
        let root = test_root("open-bound");
        let layout = SpoolLayout::new(root.0.clone()).expect("layout");
        assert_eq!(
            LinuxSpoolWriter::open(&layout, 0).expect_err("zero maximum must be refused"),
            SpoolWriteError::InvalidBodySize
        );
        assert_eq!(
            LinuxSpoolWriter::open(&layout, MAX_SPOOL_BODY_BYTES + 1)
                .expect_err("over-cap maximum must be refused"),
            SpoolWriteError::InvalidBodySize
        );
    }

    /// Case 6b: `open` on an absent root, and on a path that is a regular
    /// file rather than a directory. **Measured, not guessed**: both go
    /// through the same `openat2(..., DIRECTORY_FLAGS, ...)` call in
    /// `LinuxSpoolWriter::open`, and `O_DIRECTORY` against a nonexistent path
    /// fails the syscall itself with `ENOENT`, and against an existing
    /// regular file fails it with `ENOTDIR` -- both are folded by `open`'s
    /// `.map_err(|_err| SpoolWriteError::RootUnavailable)` on that same call,
    /// before the code ever reaches its own `is_dir()` check (which would
    /// have produced `InvalidRoot`). Measured on `rust:slim-trixie`,
    /// 2026-09-19: both cases returned `RootUnavailable`.
    #[test]
    fn open_on_an_absent_root_and_a_regular_file_root_both_return_root_unavailable() {
        let parent = test_root("open-root-shapes");

        let absent = parent.0.join("does-not-exist");
        let absent_layout = SpoolLayout::new(absent.clone()).expect("layout shape");
        assert_eq!(
            LinuxSpoolWriter::open(&absent_layout, MAX_SPOOL_BODY_BYTES)
                .expect_err("an absent root must be refused"),
            SpoolWriteError::RootUnavailable,
            "measured: openat2(..., O_DIRECTORY, ...) on an absent path fails the syscall itself \
             (ENOENT), which open() maps to RootUnavailable before ever reaching its own is_dir() check"
        );
        assert!(!absent.exists());

        let regular_file = parent.0.join("a-regular-file");
        fs::write(&regular_file, b"not a directory").expect("create regular-file root fixture");
        let file_layout = SpoolLayout::new(regular_file.clone()).expect("layout shape");
        assert_eq!(
            LinuxSpoolWriter::open(&file_layout, MAX_SPOOL_BODY_BYTES)
                .expect_err("a regular-file root must be refused"),
            SpoolWriteError::RootUnavailable,
            "measured: openat2(..., O_DIRECTORY, ...) on a regular file fails the syscall itself \
             (ENOTDIR), which open() maps to RootUnavailable the same way as an absent root"
        );
    }

    /// Case 7: a pre-existing `.part` at the derived part path returns
    /// `PartAlreadyPresent` and no blob is created.
    #[test]
    fn a_preexisting_part_file_is_refused_and_no_blob_is_created() {
        let root = test_root("part-present");
        let layout = SpoolLayout::new(root.0.clone()).expect("layout");
        let writer = LinuxSpoolWriter::open(&layout, MAX_SPOOL_BODY_BYTES).expect("open writer");
        let key = put_key("018f3e12-a45d-7abc-8def-0123456789ab");
        let paths = layout.derive_paths(&key).expect("derive paths");
        fs::create_dir_all(paths.part_path().parent().expect("derived parent"))
            .expect("create derived tree");
        fs::write(paths.part_path(), b"a stale, abandoned part file").expect("plant stale part");

        let error = writer
            .write_put_body(&layout, &key, b"must never be written")
            .expect_err("a pre-existing part file must be refused");
        assert_eq!(error, SpoolWriteError::PartAlreadyPresent);
        assert!(
            !paths.final_path().exists(),
            "no blob may be created over a live part file"
        );
    }

    /// Case 8, the decisive confinement case: a symlink planted at an
    /// intermediate directory component of the derived path, pointing
    /// outside the root, must refuse the write and leave nothing written at
    /// the symlink's target. This is what distinguishes this writer from a
    /// plain `fs::rename`.
    ///
    /// Measured, not guessed: `ensure_directory_chain`'s `mkdirat` on an
    /// existing symlink returns `EEXIST` (swallowed, not durability
    /// evidence per the module's own doc comment), and the following
    /// `openat2(..., NO_SYMLINKS | BENEATH, ...)` on that same symlinked
    /// component fails with `ELOOP`, mapped to `UnsafeOrNonRegular`.
    #[test]
    fn a_symlinked_intermediate_directory_is_refused_and_nothing_lands_at_its_target() {
        let root = test_root("confinement-root");
        let outside_target = test_root("confinement-target");
        let layout = SpoolLayout::new(root.0.clone()).expect("layout");
        let key = put_key("018f3e12-a45e-7abc-8def-0123456789ab");

        // Plant the symlink BEFORE opening the writer, replacing the
        // top-level directory component the derived path descends through
        // first, pointing at a directory entirely outside the configured
        // root.
        symlink(&outside_target.0, root.0.join(SPOOL_LAYOUT_REVISION_V1))
            .expect("plant a hostile symlink at the first path component");

        let writer = LinuxSpoolWriter::open(&layout, MAX_SPOOL_BODY_BYTES).expect("open writer");
        let error = writer
            .write_put_body(&layout, &key, b"must never reach the symlinked target")
            .expect_err("a symlinked intermediate directory component must be refused");
        assert_eq!(error, SpoolWriteError::UnsafeOrNonRegular);

        assert!(
            fs::read_dir(&outside_target.0)
                .expect("read the symlink's target directory")
                .next()
                .is_none(),
            "nothing may be written at the symlink's target"
        );
    }

    /// Case 9: after a successful write, every directory level below the
    /// root exists and is a real directory, not a symlink.
    #[test]
    fn every_directory_level_below_the_root_is_a_real_directory_after_a_successful_write() {
        let root = test_root("directory-chain");
        let layout = SpoolLayout::new(root.0.clone()).expect("layout");
        let writer = LinuxSpoolWriter::open(&layout, MAX_SPOOL_BODY_BYTES).expect("open writer");
        let key = put_key("018f3e12-a45f-7abc-8def-0123456789ab");
        let paths = layout.derive_paths(&key).expect("derive paths");

        writer
            .write_put_body(&layout, &key, b"proves-the-real-directory-chain")
            .expect("write must succeed");

        let mut level = paths
            .final_path()
            .parent()
            .expect("final_path has a parent")
            .to_path_buf();
        while level != root.0 {
            let metadata = fs::symlink_metadata(&level).unwrap_or_else(|error| {
                panic!("stat directory level {}: {error}", level.display())
            });
            assert!(
                metadata.is_dir(),
                "{} must be a real directory, not a symlink or other entry",
                level.display()
            );
            level = level
                .parent()
                .unwrap_or_else(|| panic!("{} must have a parent under the root", level.display()))
                .to_path_buf();
        }
    }

    // ---------------------------------------------------------------------------------------
    // WP-115 f2: `reclaim_step` quarantines spool files below the retired floor.
    //
    // A body written for an attempt whose custody row no longer exists (a database restored to
    // before it, or a late writer after the row was deleted) has no row left to unlink it. The
    // retired floor says no custody row can have an attempt UUIDv7 older than the floor, so any
    // file below it is residue. It is MOVED to `<root>/quarantine`, never unlinked.
    // ---------------------------------------------------------------------------------------

    const FLOOR_MS: u64 = 1_700_000_000_000 + 1_000;

    /// A `UUIDv7` (version 7, variant 10) whose embedded unix-ms timestamp is `ms`.
    fn v7_with_ms(ms: u64, salt: u8) -> String {
        let mut bytes = [0_u8; 16];
        bytes[..6].copy_from_slice(&ms.to_be_bytes()[2..]);
        bytes[6] = 0x70;
        bytes[7] = salt;
        bytes[8] = 0x80;
        bytes[9] = salt;
        uuid::Uuid::from_bytes(bytes).to_string()
    }

    fn key_for(boundary: &str, attempt_id: &str) -> SpoolObjectKey {
        SpoolObjectKey {
            provider_boundary_id: boundary.into(),
            logical_request_id: LOGICAL_ID.into(),
            attempt_id: attempt_id.into(),
            kind: SpoolObjectKind::Put,
        }
    }

    /// Every regular file under `root`, by path.
    fn all_files(root: &Path) -> std::collections::BTreeMap<PathBuf, Vec<u8>> {
        fn walk(directory: &Path, out: &mut std::collections::BTreeMap<PathBuf, Vec<u8>>) {
            for entry in fs::read_dir(directory).expect("read directory") {
                let path = entry.expect("directory entry").path();
                if path.is_dir() {
                    walk(&path, out);
                } else {
                    let bytes = fs::read(&path).expect("read file");
                    out.insert(path, bytes);
                }
            }
        }
        let mut files = std::collections::BTreeMap::new();
        walk(root, &mut files);
        files
    }

    fn sorted_contents(files: &std::collections::BTreeMap<PathBuf, Vec<u8>>) -> Vec<Vec<u8>> {
        let mut contents: Vec<Vec<u8>> = files.values().cloned().collect();
        contents.sort();
        contents
    }

    /// Run bounded steps until the traversal completes. Returns
    /// `(calls, quarantined_files, quarantined_bytes, retained_unknown)`.
    fn reclaim_all(
        writer: &LinuxSpoolWriter,
        layout: &SpoolLayout,
        floor_ms: i64,
        entries: u32,
    ) -> (u32, u64, u64, u64) {
        let (mut calls, mut files, mut bytes, mut unknown) = (0, 0, 0, 0);
        loop {
            let step = writer
                .reclaim_step(layout, BOUNDARY, floor_ms, entries)
                .expect("a bounded reclaim step");
            calls += 1;
            files += step.quarantined_files;
            bytes += step.quarantined_bytes;
            unknown += step.retained_unknown;
            if step.completed {
                return (calls, files, bytes, unknown);
            }
            assert!(calls < 500, "the reclaim traversal must complete");
        }
    }

    /// A completed physical walk of the root, `(bytes, files)`.
    fn physical_walk(writer: &LinuxSpoolWriter) -> (u64, u64) {
        for _ in 0..64 {
            if let Some(inventory) = writer.physical_usage(4096).expect("physical walk") {
                return inventory;
            }
        }
        panic!("the physical walk must complete");
    }

    fn floor() -> i64 {
        i64::try_from(FLOOR_MS).expect("floor fits i64")
    }

    #[test]
    fn reclaim_moves_exactly_the_below_floor_parseable_files_into_quarantine_and_unlinks_nothing() {
        let root = test_root("reclaim-below-floor");
        let layout = SpoolLayout::new(root.0.clone()).expect("layout");
        let writer = LinuxSpoolWriter::open(&layout, MAX_SPOOL_BODY_BYTES).expect("open writer");

        // A: a below-floor blob. B: a below-floor `.part`. C: exactly at the floor. D: above it.
        let a = v7_with_ms(FLOOR_MS - 10_000, 0xa1);
        let b = v7_with_ms(FLOOR_MS - 5_000, 0xb2);
        let c = v7_with_ms(FLOOR_MS, 0xc3);
        let d = v7_with_ms(FLOOR_MS + 10_000, 0xd4);
        let body_a = b"a-blob-for-an-attempt-whose-row-was-deleted";
        let body_b = b"a-part-file-left-by-a-writer-that-died";
        writer
            .write_put_body(&layout, &key_for(BOUNDARY, &a), body_a)
            .expect("place A");
        let paths_b = layout
            .derive_paths(&key_for(BOUNDARY, &b))
            .expect("derive B");
        fs::create_dir_all(paths_b.part_path().parent().expect("B parent")).expect("B dirs");
        fs::write(paths_b.part_path(), body_b).expect("plant B");
        writer
            .write_put_body(&layout, &key_for(BOUNDARY, &c), b"at-the-floor")
            .expect("place C");
        let paths_d = layout
            .derive_paths(&key_for(BOUNDARY, &d))
            .expect("derive D");
        writer
            .write_put_body(&layout, &key_for(BOUNDARY, &d), b"above-the-floor")
            .expect("place D");
        // E: a name that is not an attempt UUID, inside a real request directory.
        let unparseable = paths_d
            .final_path()
            .parent()
            .expect("D parent")
            .join("not-an-attempt.blob");
        fs::write(&unparseable, b"unknown-name").expect("plant E");
        // F: another boundary's file, below the floor. It is not this boundary's to move.
        let other = v7_with_ms(FLOOR_MS - 20_000, 0xf5);
        let other_key = key_for("some-other-boundary", &other);
        let other_paths = layout.derive_paths(&other_key).expect("derive F");
        writer
            .write_put_body(&layout, &other_key, b"another-boundarys-body")
            .expect("place F");

        let before = all_files(&root.0);
        let (walk_bytes_before, walk_files_before) = physical_walk(&writer);

        // Control: a floor of zero selects nothing, so the floor is what drives the move.
        let (_, files, bytes, _) = reclaim_all(&writer, &layout, 0, 3);
        assert_eq!((files, bytes), (0, 0), "a zero floor moves nothing");
        assert_eq!(all_files(&root.0), before);

        let (calls, files, bytes, unknown) = reclaim_all(&writer, &layout, floor(), 3);
        assert!(
            calls > 1,
            "a three entry budget needs several calls, so the cursor is kept across them ({calls})"
        );
        assert_eq!(files, 2, "exactly A and B are below the floor");
        assert_eq!(bytes, (body_a.len() + body_b.len()) as u64);
        assert_eq!(
            unknown, 1,
            "only the unparseable name is retained as unknown"
        );

        let paths_a = layout
            .derive_paths(&key_for(BOUNDARY, &a))
            .expect("derive A");
        assert!(!paths_a.final_path().exists(), "A left its spool path");
        assert!(!paths_b.part_path().exists(), "B left its spool path");
        let quarantine = root.0.join("quarantine");
        assert_eq!(
            fs::read(quarantine.join(format!("{LOGICAL_ID}.{a}.blob"))).expect("A quarantined"),
            body_a,
            "A is byte equal in quarantine"
        );
        assert_eq!(
            fs::read(quarantine.join(format!("{LOGICAL_ID}.{b}.part"))).expect("B quarantined"),
            body_b,
            "B keeps its .part suffix and is byte equal in quarantine"
        );
        assert_eq!(fs::read_dir(&quarantine).expect("quarantine").count(), 2);
        let paths_c = layout
            .derive_paths(&key_for(BOUNDARY, &c))
            .expect("derive C");
        for kept in [
            paths_c.final_path(),
            paths_d.final_path(),
            unparseable.as_path(),
            other_paths.final_path(),
        ] {
            assert!(kept.is_file(), "{} must stay in place", kept.display());
        }

        // Nothing was unlinked: the same bytes exist, only their paths moved.
        let after = all_files(&root.0);
        assert_eq!(
            sorted_contents(&after),
            sorted_contents(&before),
            "a reclaim moves files, it never deletes or rewrites them"
        );

        // The next physical walk does not count the quarantine directory.
        let (walk_bytes_after, walk_files_after) = physical_walk(&writer);
        assert_eq!(walk_files_after, walk_files_before - 2);
        assert_eq!(
            walk_bytes_after,
            walk_bytes_before - (body_a.len() + body_b.len()) as u64
        );

        // A second traversal finds nothing new, and still retains the unknown name.
        let (_, files, _, unknown) = reclaim_all(&writer, &layout, floor(), 64);
        assert_eq!((files, unknown), (0, 1));

        // A late writer after the traversal: its below-floor body is found by the next one.
        let late = v7_with_ms(FLOOR_MS - 1, 0xe6);
        writer
            .write_put_body(&layout, &key_for(BOUNDARY, &late), b"a-late-writers-body")
            .expect("place the late body");
        let (_, files, bytes, _) = reclaim_all(&writer, &layout, floor(), 64);
        assert_eq!((files, bytes), (1, b"a-late-writers-body".len() as u64));
        assert!(
            quarantine
                .join(format!("{LOGICAL_ID}.{late}.blob"))
                .is_file()
        );
    }

    #[test]
    fn a_path_that_does_not_rederive_exactly_is_kept_even_below_the_floor() {
        let root = test_root("reclaim-rederive");
        let layout = SpoolLayout::new(root.0.clone()).expect("layout");
        let writer = LinuxSpoolWriter::open(&layout, MAX_SPOOL_BODY_BYTES).expect("open writer");

        // Control: a correctly placed below-floor file does move, so the walk really runs.
        let placed = v7_with_ms(FLOOR_MS - 7_000, 0x11);
        writer
            .write_put_body(&layout, &key_for(BOUNDARY, &placed), b"placed")
            .expect("place the control");

        // The same shape one fan-out directory over: it parses, but the path is not the derived one.
        let misplaced = v7_with_ms(FLOOR_MS - 8_000, 0x22);
        let derived = layout
            .derive_paths(&key_for(BOUNDARY, &misplaced))
            .expect("derive");
        let request_dir = derived.final_path().parent().expect("request directory");
        let fanout_dir = request_dir.parent().expect("fan-out directory");
        let put_dir = fanout_dir.parent().expect("put directory");
        let fanout_name = fanout_dir.file_name().expect("fan-out name");
        let other_fanout = if fanout_name == "00" { "01" } else { "00" };
        let wrong_dir = put_dir
            .join(other_fanout)
            .join(request_dir.file_name().expect("request name"));
        fs::create_dir_all(&wrong_dir).expect("wrong dirs");
        let wrong = wrong_dir.join(format!("{misplaced}.blob"));
        fs::write(&wrong, b"misplaced").expect("plant");

        let (_, files, _, _) = reclaim_all(&writer, &layout, floor(), 64);
        assert_eq!(files, 1, "only the correctly derived path is moved");
        assert!(wrong.is_file(), "a path that does not re-derive is kept");
        assert!(
            root.0
                .join("quarantine")
                .join(format!("{LOGICAL_ID}.{placed}.blob"))
                .is_file()
        );
    }

    #[test]
    fn reclaim_on_a_root_with_no_spool_layout_yet_completes_with_nothing_to_do() {
        let root = test_root("reclaim-empty");
        let layout = SpoolLayout::new(root.0.clone()).expect("layout");
        let writer = LinuxSpoolWriter::open(&layout, MAX_SPOOL_BODY_BYTES).expect("open writer");
        let (_, files, bytes, unknown) = reclaim_all(&writer, &layout, floor(), 8);
        assert_eq!((files, bytes, unknown), (0, 0, 0));
        assert!(
            !root.0.join("quarantine").exists(),
            "an empty reclaim creates no quarantine directory"
        );
    }

    #[test]
    fn the_physical_walk_skips_only_the_root_level_quarantine_directory() {
        let root = test_root("walk-quarantine");
        fs::create_dir(root.0.join("quarantine")).unwrap();
        fs::write(root.0.join("quarantine").join("moved"), b"12345").unwrap();
        fs::create_dir_all(root.0.join("elsewhere").join("quarantine")).unwrap();
        fs::write(
            root.0.join("elsewhere").join("quarantine").join("nested"),
            b"ab",
        )
        .unwrap();
        let layout = SpoolLayout::new(root.0.clone()).unwrap();
        let writer = LinuxSpoolWriter::open(&layout, MAX_SPOOL_BODY_BYTES).unwrap();
        assert_eq!(
            physical_walk(&writer),
            (2, 1),
            "the root-level quarantine is skipped; a nested directory of that name is not"
        );
    }

    #[test]
    fn two_writers_reclaiming_the_same_files_both_succeed_and_each_file_is_quarantined_once() {
        const FILES: u8 = 24;
        for round in 0..4 {
            let root = test_root(&format!("reclaim-race-{round}"));
            let layout = SpoolLayout::new(root.0.clone()).expect("layout");
            let seed = LinuxSpoolWriter::open(&layout, MAX_SPOOL_BODY_BYTES).expect("seed writer");
            let mut expected = Vec::new();
            for index in 0..FILES {
                let attempt = v7_with_ms(FLOOR_MS - 1_000 - u64::from(index), index);
                let body = format!("race-body-{index}").into_bytes();
                seed.write_put_body(&layout, &key_for(BOUNDARY, &attempt), &body)
                    .expect("place");
                expected.push((attempt, body));
            }
            let barrier = std::sync::Barrier::new(2);
            let outcomes: Vec<(u32, u64, u64, u64)> = std::thread::scope(|scope| {
                let handles: Vec<_> = (0..2)
                    .map(|_| {
                        scope.spawn(|| {
                            let writer = LinuxSpoolWriter::open(&layout, MAX_SPOOL_BODY_BYTES)
                                .expect("open a competing writer");
                            barrier.wait();
                            reclaim_all(&writer, &layout, floor(), 5)
                        })
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|handle| handle.join().expect("a reclaim thread must not panic"))
                    .collect()
            });
            let moved: u64 = outcomes.iter().map(|outcome| outcome.1).sum();
            assert!(
                moved >= u64::from(FILES),
                "round {round}: every file is moved by one writer or the other ({moved})"
            );
            let quarantine = root.0.join("quarantine");
            assert_eq!(
                fs::read_dir(&quarantine).expect("quarantine").count(),
                usize::from(FILES),
                "round {round}: each file ends up quarantined exactly once"
            );
            for (attempt, body) in &expected {
                assert_eq!(
                    &fs::read(quarantine.join(format!("{LOGICAL_ID}.{attempt}.blob")))
                        .expect("quarantined body"),
                    body,
                    "round {round}: bytes survive a raced move"
                );
                assert!(
                    !layout
                        .derive_paths(&key_for(BOUNDARY, attempt))
                        .expect("derive")
                        .final_path()
                        .exists()
                );
            }
        }
    }

    /// WP-115 f2 round 3: a per-entry failure no longer aborts the walk. A fan-out directory the
    /// walk cannot open is skipped and counted, and the files elsewhere are still quarantined.
    ///
    /// `chmod 000` does not stop root, and the Linux tier's container runs as root. Then this case
    /// reports NOT RUN on stderr and returns, because Rust has no skip; read the log for it.
    #[test]
    fn an_unreadable_fanout_directory_is_skipped_and_counted_and_the_rest_is_still_quarantined() {
        use std::os::unix::fs::PermissionsExt;

        let root = test_root("reclaim-unreadable");
        let layout = SpoolLayout::new(root.0.clone()).expect("layout");
        let writer = LinuxSpoolWriter::open(&layout, MAX_SPOOL_BODY_BYTES).expect("open writer");
        let first_key = key_for(BOUNDARY, &v7_with_ms(FLOOR_MS - 10_000, 0x31));
        writer
            .write_put_body(&layout, &first_key, b"readable-below-the-floor")
            .expect("place the readable file");
        let first_paths = layout.derive_paths(&first_key).expect("derive");
        let first_fanout = first_paths
            .final_path()
            .parent()
            .and_then(Path::parent)
            .expect("fan-out directory")
            .to_path_buf();

        // A second request whose fan-out directory differs from the first's.
        let (victim_key, victim_paths) = (0_u8..=255)
            .find_map(|salt| {
                let logical = v7_with_ms(FLOOR_MS - 20_000, salt);
                let key = SpoolObjectKey {
                    provider_boundary_id: BOUNDARY.into(),
                    logical_request_id: logical,
                    attempt_id: v7_with_ms(FLOOR_MS - 9_000, salt),
                    kind: SpoolObjectKind::Put,
                };
                let paths = layout.derive_paths(&key).expect("derive");
                let fanout = paths
                    .final_path()
                    .parent()
                    .and_then(Path::parent)?
                    .to_path_buf();
                (fanout != first_fanout).then_some((key, paths))
            })
            .expect("a request in another fan-out directory");
        writer
            .write_put_body(&layout, &victim_key, b"behind-an-unreadable-directory")
            .expect("place the victim file");
        let victim_fanout = victim_paths
            .final_path()
            .parent()
            .and_then(Path::parent)
            .expect("victim fan-out")
            .to_path_buf();

        fs::set_permissions(&victim_fanout, fs::Permissions::from_mode(0o000)).expect("chmod");
        if fs::read_dir(&victim_fanout).is_ok() {
            fs::set_permissions(&victim_fanout, fs::Permissions::from_mode(0o700)).expect("chmod");
            eprintln!(
                "NOT RUN: an_unreadable_fanout_directory_is_skipped_and_counted: chmod 000 does \
                 not stop this user (root)"
            );
            return;
        }
        let (mut skipped, mut moved) = (0_u64, 0_u64);
        let mut finished = false;
        for _ in 0..50 {
            let step = writer
                .reclaim_step(&layout, BOUNDARY, floor(), 16)
                .expect("an unreadable entry does not fail the step");
            skipped += step.skipped_entries;
            moved += step.quarantined_files;
            if step.completed {
                finished = true;
                break;
            }
        }
        fs::set_permissions(&victim_fanout, fs::Permissions::from_mode(0o700)).expect("chmod");
        assert!(finished, "the walk completes past the unreadable directory");
        assert_eq!(
            skipped, 1,
            "the unreadable directory is skipped and counted once"
        );
        assert_eq!(
            moved, 1,
            "the readable below-floor file is still quarantined"
        );
        assert!(!first_paths.final_path().exists());
        assert!(
            victim_paths.final_path().is_file(),
            "the file behind the unreadable directory is untouched"
        );
    }
}

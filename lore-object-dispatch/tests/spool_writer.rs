// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Offline, tempdir-based proof for WP-122 L5's `LinuxSpoolWriter`.
//!
//! # The platform pair below cannot be caught by a case-count differential
//!
//! Each platform drops cases and gains others: off Linux, `linux_live`'s whole
//! module is compiled out and only `open_returns_unsupported_platform_off_linux`
//! (below, top level) exists; on Linux the reverse holds and that case never
//! compiles. **Here the counts happen to differ (1 off Linux, 10 on it), so a
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
    /// `.map_err(|_| SpoolWriteError::RootUnavailable)` on that same call,
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
}

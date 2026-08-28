// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Source-dark, descriptor-relative spool observation contract.

use std::path::Path;
use std::path::PathBuf;

fn module() -> &'static str {
    include_str!("../src/spool_verifier.rs")
}

fn rust_sources(directory: &Path, output: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(directory).expect("read source directory") {
        let path = entry.expect("source entry").path();
        if path.is_dir() {
            rust_sources(&path, output);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            output.push(path);
        }
    }
}

#[test]
fn linux_contract_is_descriptor_relative_and_fail_closed() {
    let source = module();
    for required in [
        "rustix::fs::openat2",
        "ResolveFlags::BENEATH",
        "ResolveFlags::NO_SYMLINKS",
        "ResolveFlags::NO_MAGICLINKS",
        "ResolveFlags::NO_XDEV",
        ".is_file()",
        "blake3::Hasher",
    ] {
        assert!(source.contains(required), "missing Linux guard: {required}");
    }
    assert!(source.contains("UnsupportedPlatform"));
    assert!(source.contains("#[cfg(target_os = \"linux\")]"));
    assert!(source.contains("#[cfg(not(target_os = \"linux\"))]"));
}

#[test]
fn verifier_derives_paths_and_never_opens_a_caller_handle() {
    let source = module();
    assert!(source.contains("relative_artifact_path"));
    assert!(source.contains("part_path"));
    assert!(source.contains("final_path"));
    assert!(!source.contains("opaque_handle()"));
    assert!(!source.contains("PathBuf::from(opaque"));
    assert!(!source.contains("Path::new(opaque"));
}

#[test]
fn observation_only_module_has_no_mutation_or_external_authority() {
    let source = module();
    for forbidden in [
        "tokio_postgres",
        "object_store_dispatch_put_spool_ready_v1",
        "object_store_dispatch_put_upload_progress_v1",
        "std::fs::rename",
        "remove_file",
        "remove_dir",
        "set_len",
        "write_all",
        "reqwest",
        "tonic::",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden authority: {forbidden}"
        );
    }
}

#[test]
fn verifier_remains_source_dark_and_unwired() {
    assert!(include_str!("../src/lib.rs").contains("pub mod spool_verifier;"));
    let mut sources = Vec::new();
    rust_sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut sources,
    );
    for path in sources {
        if path.file_name().and_then(|name| name.to_str()) == Some("spool_verifier.rs") {
            continue;
        }
        let source = std::fs::read_to_string(&path).expect("read production source");
        assert!(
            !source.contains("LinuxSpoolVerifier::open")
                && !source.contains("LinuxSpoolVerifier::new"),
            "verifier wired from {}",
            path.display()
        );
    }
}

#[test]
fn diagnostics_are_explicitly_redacted() {
    let source = module();
    assert!(source.contains("impl std::fmt::Debug for LinuxSpoolVerifier"));
    assert!(source.contains("[REDACTED]"));
}

#[cfg(not(target_os = "linux"))]
#[test]
fn non_linux_is_closed_before_filesystem_access() {
    use lore_object_dispatch::spool::SpoolLayout;
    use lore_object_dispatch::spool_verifier::LinuxSpoolVerifier;
    use lore_object_dispatch::spool_verifier::SpoolVerificationError;

    let nonexistent = PathBuf::from(r"Z:\must-not-be-opened\spool-verifier-secret");
    let layout = SpoolLayout::new(nonexistent.clone()).expect("absolute test root");
    assert_eq!(
        LinuxSpoolVerifier::open(&layout, 1).expect_err("non-Linux must be closed"),
        SpoolVerificationError::UnsupportedPlatform
    );
    assert!(!nonexistent.exists());
    assert_eq!(
        format!("{:?}", SpoolVerificationError::UnsupportedPlatform),
        "UnsupportedPlatform"
    );
}

#[cfg(target_os = "linux")]
mod linux_live {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::Arc;
    use std::sync::Barrier;
    use std::thread;
    use std::time::Duration;
    use std::time::SystemTime;
    use std::time::UNIX_EPOCH;

    use lore_object_dispatch::spool::LedgerSpoolView;
    use lore_object_dispatch::spool::SpoolLayout;
    use lore_object_dispatch::spool::SpoolObjectKey;
    use lore_object_dispatch::spool::SpoolObjectKind;
    use lore_object_dispatch::spool::SpoolRecoveryDecision;
    use lore_object_dispatch::spool::SpoolRecoveryInconsistency;
    use lore_object_dispatch::spool_verifier::LinuxSpoolVerifier;
    use lore_object_dispatch::spool_verifier::SpoolVerificationError;

    const LOGICAL_ID: &str = "018f3e12-a456-7abc-8def-0123456789ab";
    const ATTEMPT_ID: &str = "018f3e12-a457-7abc-8def-0123456789ab";

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
            "/tmp/lore-spool-verifier-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create isolated absolute spool root");
        TestRoot(path)
    }

    fn key(attempt_id: &str) -> SpoolObjectKey {
        SpoolObjectKey {
            provider_boundary_id: "boundary".into(),
            logical_request_id: LOGICAL_ID.into(),
            attempt_id: attempt_id.into(),
            kind: SpoolObjectKind::Put,
        }
    }

    fn reserved(size: u64, digest: [u8; 32], prefix: u64) -> LedgerSpoolView {
        LedgerSpoolView::Reserved {
            expected_size: size,
            expected_blake3: digest,
            accounted_prefix_bytes: prefix,
        }
    }

    fn classify(
        verifier: &LinuxSpoolVerifier,
        ledger: &LedgerSpoolView,
        observation: &lore_object_dispatch::VerifiedFileObservation,
        paths: &lore_object_dispatch::spool::SpoolPaths,
    ) -> SpoolRecoveryDecision {
        verifier
            .classify_recovery(ledger, observation, paths)
            .expect("classification remains available")
    }

    fn reset_artifacts(paths: &lore_object_dispatch::spool::SpoolPaths) {
        if let Some(parent) = paths.part_path().parent() {
            let _ = fs::remove_dir_all(parent);
            fs::create_dir_all(parent).expect("recreate derived spool directory");
        }
    }

    #[test]
    #[ignore = "requires a disposable Linux filesystem with openat2 and mkfifo"]
    fn linux_observation_is_descriptor_bound_exact_and_fail_closed() {
        let root = test_root("live");
        let layout = SpoolLayout::new(root.0.clone()).expect("layout");
        let paths = layout
            .derive_paths(&key(ATTEMPT_ID))
            .expect("derived paths");
        fs::create_dir_all(paths.part_path().parent().expect("derived parent"))
            .expect("create derived tree");
        let verifier = LinuxSpoolVerifier::open(&layout, 64 * 1024 * 1024).expect("open root fd");
        assert!(!format!("{verifier:?}").contains(root.0.to_str().expect("UTF-8 root")));
        assert_eq!(format!("{verifier}"), "LinuxSpoolVerifier([REDACTED])");

        let abc_digest = *blake3::hash(b"abc").as_bytes();
        let absent = verifier.observe(&paths, 3).expect("observe absence");
        assert_eq!(
            classify(&verifier, &reserved(3, abc_digest, 0), &absent, &paths),
            SpoolRecoveryDecision::AwaitUpload
        );

        fs::write(paths.part_path(), b"ab").expect("write incomplete part");
        let incomplete = verifier
            .observe(&paths, 3)
            .expect("observe incomplete part");
        assert_eq!(
            classify(&verifier, &reserved(3, abc_digest, 2), &incomplete, &paths),
            SpoolRecoveryDecision::RevalidateAccountedPrefix
        );
        fs::write(paths.part_path(), b"abc").expect("complete part");
        let complete = verifier.observe(&paths, 3).expect("hash complete part");
        assert_eq!(
            classify(&verifier, &reserved(3, abc_digest, 3), &complete, &paths),
            SpoolRecoveryDecision::CandidateForFinalPublication
        );

        fs::remove_file(paths.part_path()).expect("remove part");
        fs::write(paths.final_path(), b"abc").expect("write blob");
        let blob = verifier.observe(&paths, 3).expect("hash blob");
        assert_eq!(
            classify(&verifier, &reserved(3, abc_digest, 3), &blob, &paths),
            SpoolRecoveryDecision::CandidateForReadyCommit
        );
        assert_eq!(
            classify(&verifier, &reserved(3, [0x11; 32], 3), &blob, &paths),
            SpoolRecoveryDecision::FailClosed(SpoolRecoveryInconsistency::BlobMismatch)
        );
        fs::write(paths.part_path(), b"abc").expect("write simultaneous part");
        let both = verifier.observe(&paths, 3).expect("observe both artifacts");
        assert_eq!(
            classify(&verifier, &reserved(3, abc_digest, 3), &both, &paths),
            SpoolRecoveryDecision::FailClosed(SpoolRecoveryInconsistency::MultipleArtifacts)
        );

        reset_artifacts(&paths);
        fs::create_dir(paths.part_path()).expect("directory artifact");
        let directory = verifier.observe(&paths, 3).expect("observe directory");
        assert_eq!(
            classify(&verifier, &reserved(3, abc_digest, 0), &directory, &paths),
            SpoolRecoveryDecision::FailClosed(SpoolRecoveryInconsistency::UnsafeFileType)
        );
        reset_artifacts(&paths);
        assert!(
            Command::new("mkfifo")
                .arg(paths.part_path())
                .status()
                .expect("run mkfifo")
                .success()
        );
        let fifo = verifier
            .observe(&paths, 3)
            .expect("observe FIFO without blocking");
        assert_eq!(
            classify(&verifier, &reserved(3, abc_digest, 0), &fifo, &paths),
            SpoolRecoveryDecision::FailClosed(SpoolRecoveryInconsistency::UnsafeFileType)
        );
        reset_artifacts(&paths);
        symlink("/etc/passwd", paths.part_path()).expect("symlink artifact");
        let linked = verifier
            .observe(&paths, 3)
            .expect("reject artifact symlink");
        assert_eq!(
            classify(&verifier, &reserved(3, abc_digest, 0), &linked, &paths),
            SpoolRecoveryDecision::FailClosed(SpoolRecoveryInconsistency::UnsafeFileType)
        );

        let linked_ancestor = root.0.join("object-store-spool-layout-v1");
        fs::remove_file(paths.part_path()).expect("remove artifact symlink");
        fs::remove_dir_all(&linked_ancestor).expect("remove derived ancestor");
        let ancestor_target = test_root("ancestor-target");
        symlink(&ancestor_target.0, &linked_ancestor).expect("symlink derived ancestor");
        let ancestor = verifier
            .observe(&paths, 3)
            .expect("reject symlinked ancestor");
        assert_eq!(
            classify(&verifier, &reserved(3, abc_digest, 0), &ancestor, &paths),
            SpoolRecoveryDecision::FailClosed(SpoolRecoveryInconsistency::UnsafeFileType)
        );
        fs::remove_file(&linked_ancestor).expect("remove symlinked ancestor");

        reset_artifacts(&paths);
        fs::write(paths.part_path(), []).expect("zero-byte part");
        let empty_digest = *blake3::hash(&[]).as_bytes();
        let zero_part = verifier.observe(&paths, 0).expect("hash empty part");
        assert_eq!(
            classify(&verifier, &reserved(0, empty_digest, 0), &zero_part, &paths),
            SpoolRecoveryDecision::CandidateForFinalPublication
        );
        fs::rename(paths.part_path(), paths.final_path()).expect("publish empty fixture");
        let zero_blob = verifier.observe(&paths, 0).expect("hash empty blob");
        assert_eq!(
            classify(&verifier, &reserved(0, empty_digest, 0), &zero_blob, &paths),
            SpoolRecoveryDecision::CandidateForReadyCommit
        );

        let other_root = test_root("other");
        let other_layout = SpoolLayout::new(other_root.0.clone()).expect("other layout");
        let other_paths = other_layout
            .derive_paths(&key(ATTEMPT_ID))
            .expect("other paths");
        fs::create_dir_all(
            other_paths
                .part_path()
                .parent()
                .expect("other derived parent"),
        )
        .expect("create other derived tree");
        let other_verifier =
            LinuxSpoolVerifier::open(&other_layout, 64 * 1024 * 1024).expect("open other root fd");
        assert_eq!(
            verifier
                .observe(&other_paths, 0)
                .expect_err("cross-layout path"),
            SpoolVerificationError::PathBindingMismatch
        );
        assert_eq!(
            verifier
                .classify_recovery(&reserved(0, empty_digest, 0), &zero_blob, &other_paths)
                .expect_err("classification path belongs to another verifier root"),
            SpoolVerificationError::PathBindingMismatch
        );
        assert_eq!(
            other_verifier
                .classify_recovery(&reserved(0, empty_digest, 0), &zero_blob, &other_paths)
                .expect("same-key cross-root observation is classified"),
            SpoolRecoveryDecision::FailClosed(SpoolRecoveryInconsistency::ObservationRootMismatch)
        );
        let other_identity = layout
            .derive_paths(&key("018f3e12-a458-7abc-8def-0123456789ab"))
            .expect("other identity");
        assert_eq!(
            classify(
                &verifier,
                &reserved(0, empty_digest, 0),
                &zero_blob,
                &other_identity,
            ),
            SpoolRecoveryDecision::FailClosed(SpoolRecoveryInconsistency::ObservationPathMismatch)
        );

        assert_eq!(
            verifier
                .observe(&paths, 64 * 1024 * 1024 + 1)
                .expect_err("size cap"),
            SpoolVerificationError::InvalidExpectedSize
        );
        assert_eq!(
            LinuxSpoolVerifier::open(&layout, u64::MAX).expect_err("host size overflow"),
            SpoolVerificationError::InvalidExpectedSize
        );
        reset_artifacts(&paths);
        fs::write(paths.part_path(), b"abcd").expect("oversized part");
        assert_eq!(
            verifier
                .observe(&paths, 3)
                .expect_err("part exceeds expected size"),
            SpoolVerificationError::InvalidFileSize
        );

        reset_artifacts(&paths);
        let changing_size = 64 * 1024 * 1024;
        fs::write(paths.part_path(), vec![0x5a; changing_size])
            .expect("write large changing fixture");
        let changing_path = paths.part_path().to_path_buf();
        let start = Arc::new(Barrier::new(2));
        let writer_start = Arc::clone(&start);
        let writer = thread::spawn(move || {
            writer_start.wait();
            let deadline = SystemTime::now() + Duration::from_secs(5);
            loop {
                let target_is_open = fs::read_dir("/proc/self/fd")
                    .expect("read process descriptors")
                    .filter_map(Result::ok)
                    .filter_map(|entry| fs::read_link(entry.path()).ok())
                    .any(|target| target == changing_path);
                if target_is_open {
                    break;
                }
                assert!(
                    SystemTime::now() < deadline,
                    "verifier never opened target inode"
                );
                thread::yield_now();
            }
            let file = fs::OpenOptions::new()
                .append(true)
                .open(&changing_path)
                .expect("open changing fixture");
            file.set_len(changing_size as u64 + 1)
                .expect("change size during hash");
        });
        start.wait();
        let changed = verifier
            .observe(&paths, changing_size as u64)
            .expect_err("changed file must not produce an observation");
        writer.join().expect("changing writer");
        assert!(matches!(
            changed,
            SpoolVerificationError::FileChanged | SpoolVerificationError::InvalidFileSize
        ));

        let moved_root = root.0.with_extension("retained-root");
        fs::rename(&root.0, &moved_root).expect("move configured root inode");
        fs::create_dir(&root.0).expect("replace configured root path");
        assert_eq!(
            verifier
                .observe(&paths, 0)
                .expect_err("configured root replaced"),
            SpoolVerificationError::RootChanged
        );
        assert_eq!(
            verifier
                .classify_recovery(&reserved(0, empty_digest, 0), &zero_blob, &paths)
                .expect_err("classification rejects replaced root"),
            SpoolVerificationError::RootChanged
        );
        fs::remove_dir(&root.0).expect("remove replacement root");
        fs::rename(&moved_root, &root.0).expect("restore configured root inode");

        let symlink_target = test_root("root-target");
        let symlink_root = root.0.with_extension("linked-root");
        symlink(&symlink_target.0, &symlink_root).expect("symlink configured root");
        let linked_layout = SpoolLayout::new(symlink_root.clone()).expect("linked layout shape");
        assert_eq!(
            LinuxSpoolVerifier::open(&linked_layout, 1).expect_err("symlinked root"),
            SpoolVerificationError::RootUnavailable
        );
        fs::remove_file(symlink_root).expect("remove linked root");
    }
}

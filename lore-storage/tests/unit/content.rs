// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift): `ContentSource::open` reports a directory as `InvalidArguments` at
//! once. Moved here from `src/content.rs` when the crate's lib test harness was turned off.
use std::io::Error;
use std::io::ErrorKind;
use std::time::Duration;
use std::time::Instant;

use lore_base::test_util::TempDir;
use lore_storage::content::*;

// `open` has no failure-injection seam: it calls the process-global IO driver directly. So the
// retryable branch is pinned by testing the classifier `open` consults, with the failure kinds
// the branch keys on, and the directory branch is pinned end to end through `open`.

#[tokio::test]
async fn permission_denied_on_a_regular_file_is_not_a_not_a_file_verdict() {
    let dir = TempDir::new("lore-storage-content-test-");
    let path = dir.path().join("regular");
    std::fs::write(&path, b"content").expect("write test file");

    for kind in [ErrorKind::PermissionDenied, ErrorKind::IsADirectory] {
        assert!(
            !names_something_not_a_file(&path, &Error::from(kind)).await,
            "{kind:?} on a regular file must stay on the retryable path"
        );
    }
}

#[tokio::test]
async fn permission_denied_on_a_missing_path_is_not_a_not_a_file_verdict() {
    let dir = TempDir::new("lore-storage-content-test-");
    let path = dir.path().join("missing");

    assert!(
        !names_something_not_a_file(&path, &Error::from(ErrorKind::PermissionDenied)).await,
        "a failed stat proves nothing, so the error must stay retryable"
    );
}

#[tokio::test]
async fn other_error_kinds_skip_the_path_stat_even_on_a_directory() {
    let dir = TempDir::new("lore-storage-content-test-");

    for kind in [
        ErrorKind::Other,
        ErrorKind::TimedOut,
        ErrorKind::Interrupted,
    ] {
        assert!(
            !names_something_not_a_file(dir.path(), &Error::from(kind)).await,
            "{kind:?} is not a not-a-file failure and must keep the back-off"
        );
    }
}

#[tokio::test]
async fn permission_denied_on_a_directory_is_a_not_a_file_verdict() {
    let dir = TempDir::new("lore-storage-content-test-");

    for kind in [ErrorKind::PermissionDenied, ErrorKind::IsADirectory] {
        assert!(
            names_something_not_a_file(dir.path(), &Error::from(kind)).await,
            "{kind:?} on a directory must be classified as not a regular file"
        );
    }
}

#[tokio::test]
async fn open_on_a_directory_is_invalid_arguments_without_back_off() {
    let dir = TempDir::new("lore-storage-content-test-");
    let source = ContentSource::file(dir.path());

    let started = Instant::now();
    let result = source.open().await;
    let elapsed = started.elapsed();

    let err = result.err().expect("opening a directory must fail");
    assert!(
        err.is_invalid_arguments(),
        "a directory must be InvalidArguments, got: {err:?}"
    );
    // The retry schedule spends about ten seconds; a first-attempt verdict is far inside this.
    assert!(
        elapsed < Duration::from_secs(5),
        "a directory must not spend the back-off, took {elapsed:?}"
    );
}

#[tokio::test]
async fn open_on_a_regular_file_succeeds_with_its_size() {
    let dir = TempDir::new("lore-storage-content-test-");
    let path = dir.path().join("regular");
    std::fs::write(&path, b"content").expect("write test file");

    let (_, size) = ContentSource::file(&path)
        .open()
        .await
        .expect("a regular file opens");
    assert_eq!(size, 7);
}

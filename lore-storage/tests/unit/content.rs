// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift): `ContentSource::open` reports a directory as `InvalidArguments` at
//! once. Moved here from `src/content.rs` when the crate's lib test harness was turned off.
use std::io::Error;
use std::io::ErrorKind;
use std::time::Duration;
use std::time::Instant;

use lore_base::test_util::TempDir;
use lore_base::types::Address;
use lore_base::types::Hash;
use lore_storage::content::*;
use lore_storage::error::StorageError;

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

fn test_address(seed: u64) -> Address {
    Address {
        hash: Hash::from_u64(seed),
        ..Default::default()
    }
}

/// Virtual content names no host path.
#[test]
fn virtual_immutable_has_no_file_path() {
    let source = ContentSource::virtual_immutable(test_address(1), 42);
    assert!(source.file_path().is_none());
}

/// This crate does not open virtual content.
#[tokio::test]
async fn virtual_immutable_open_once_is_unsupported() {
    let source = ContentSource::virtual_immutable(test_address(1), 42);
    match source.open_once().await {
        Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::Unsupported),
        Ok(_) => panic!("virtual content cannot be opened directly"),
    }
}

/// Virtual immutable content displays as the address it names.
#[test]
fn virtual_immutable_display_names_address() {
    let address = test_address(7);
    let source = ContentSource::virtual_immutable(address, 42);
    assert_eq!(format!("{source}"), format!("immutable:{address}"));
}

/// Virtual immutable content answers its declared size, which settles a comparison by size
/// without reading it.
#[tokio::test]
async fn virtual_immutable_size_is_its_declared_size() {
    let source = ContentSource::virtual_immutable(test_address(1), 42);
    assert_eq!(source.size().await.expect("a declared size"), 42);
}

/// Opening or reading virtual content fails at once as an argument error, with no back-off.
#[tokio::test]
async fn virtual_immutable_open_and_read_all_are_invalid_arguments() {
    let source = ContentSource::virtual_immutable(test_address(1), 42);
    let started = std::time::Instant::now();
    match source.open().await {
        Err(err) => assert!(matches!(err, StorageError::InvalidArguments(_)), "{err:?}"),
        Ok(_) => panic!("virtual content cannot be opened by this crate"),
    }
    assert!(
        started.elapsed() < std::time::Duration::from_secs(1),
        "the open waited on a back-off"
    );
    let err = source
        .read_all()
        .await
        .expect_err("virtual content cannot be read by this crate");
    assert!(matches!(err, StorageError::InvalidArguments(_)), "{err:?}");
}

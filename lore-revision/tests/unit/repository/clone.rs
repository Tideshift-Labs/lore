// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
// Fixture setup builds and permissions files directly rather than through the driver: what these
// tests exercise is how clone reacts to a filesystem in a given state, not how that state is
// reached.
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;

use lore_base::lore_spawn;
use lore_base::test_util::TempDir;
use lore_revision::fs::filesystem_provider::FilesystemProvider;
use lore_revision::fs::filesystem_provider::InstanceOperationImpl;
use lore_revision::fs::os::OsFilesystem;
use lore_revision::repository::clone::*;
use lore_revision::util::path::RelativePath;

async fn create_operation() -> (TempDir, Arc<InstanceOperationImpl>) {
    let temp = TempDir::new("lore-clone-temp-path-");
    let os_filesystem = OsFilesystem::new(temp.path());
    let operation = <OsFilesystem as FilesystemProvider>::begin_operation(&os_filesystem)
        .await
        .expect("Starting test operation");
    (temp, operation)
}

fn relative_path(path: &str) -> RelativePath {
    RelativePath::new_from_initial_path(path).expect("Relative path")
}

/// Where `path` is under the root the test operation was opened on, for the fixtures that
/// build filesystem state directly rather than through it.
fn on_disk(temp: &TempDir, path: &RelativePath) -> std::path::PathBuf {
    temp.path().join(path.as_str())
}

#[tokio::test]
async fn ensure_parent_dir_creates_missing_ancestors() {
    let (temp, operation) = create_operation().await;
    let file = relative_path("nested/deeper/file.txt");
    let stats = CloneStats::default();

    ensure_parent_dir(&file, &operation, &stats)
        .await
        .expect("missing parent should be created");

    assert!(on_disk(&temp, &file.parent_path()).is_dir());
}

/// The clone root already exists and is not ours to create: files at the top of the tree
/// take it as their parent, so this must not fail the clone.
#[tokio::test]
async fn ensure_parent_dir_accepts_existing_parent() {
    let (_temp, operation) = create_operation().await;
    let file = relative_path("file.txt");
    let stats = CloneStats::default();

    ensure_parent_dir(&file, &operation, &stats)
        .await
        .expect("existing parent should not fail");
}

#[tokio::test]
async fn ensure_parent_dir_caches_parent_once_per_path() {
    let (_temp, operation) = create_operation().await;
    let stats = CloneStats::default();
    let first = relative_path("dir/a.txt");
    let second = relative_path("dir/b.txt");

    ensure_parent_dir(&first, &operation, &stats)
        .await
        .expect("first file should create the parent");
    ensure_parent_dir(&second, &operation, &stats)
        .await
        .expect("sibling should hit the cache");

    assert_eq!(stats.created_parents.len(), 1);
}

/// Tolerating an existing parent must not extend to tolerating a real failure: a file
/// sitting where the parent directory belongs still has to abort the clone.
#[tokio::test]
async fn ensure_parent_dir_rejects_parent_that_is_a_file() {
    let (temp, operation) = create_operation().await;
    let blocker = relative_path("blocker");
    tokio::fs::File::create(on_disk(&temp, &blocker))
        .await
        .expect("create blocker file");
    let stats = CloneStats::default();

    let err = ensure_parent_dir(&blocker.join("file.txt"), &operation, &stats)
        .await
        .expect_err("a file where the parent belongs must fail");

    assert!(err.to_string().contains("Failed to create directory"));
    assert!(stats.created_parents.is_empty());
}

/// A parent that genuinely cannot be created still has to abort the clone.
#[cfg(unix)]
#[tokio::test]
async fn ensure_parent_dir_rejects_uncreatable_parent() {
    use std::os::unix::fs::PermissionsExt;

    let (temp, operation) = create_operation().await;
    let locked = relative_path("locked");
    tokio::fs::create_dir(on_disk(&temp, &locked))
        .await
        .expect("create locked dir");
    tokio::fs::set_permissions(
        on_disk(&temp, &locked),
        std::fs::Permissions::from_mode(0o500),
    )
    .await
    .expect("drop write permission");
    let stats = CloneStats::default();

    let result = ensure_parent_dir(&locked.join("child/file.txt"), &operation, &stats).await;

    // Restore write permission first so the temp dir can be cleaned up.
    tokio::fs::set_permissions(
        on_disk(&temp, &locked),
        std::fs::Permissions::from_mode(0o700),
    )
    .await
    .expect("restore write permission");
    let err = result.expect_err("uncreatable parent must fail");
    assert!(err.to_string().contains("Failed to create directory"));
    assert!(stats.created_parents.is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn adversarial_dangling_symlink_parent() {
    let (temp, operation) = create_operation().await;
    let link = relative_path("link");
    std::os::unix::fs::symlink(temp.path().join("nowhere"), on_disk(&temp, &link))
        .expect("create dangling symlink");
    let stats = CloneStats::default();

    let result = ensure_parent_dir(&link.join("file.txt"), &operation, &stats).await;

    assert!(result.is_err(), "a dangling symlink is not a usable parent");
}

#[cfg(unix)]
#[tokio::test]
async fn adversarial_symlink_to_file_parent() {
    let (temp, operation) = create_operation().await;
    let target = relative_path("target");
    tokio::fs::File::create(on_disk(&temp, &target))
        .await
        .expect("create target file");
    let link = relative_path("link");
    std::os::unix::fs::symlink(on_disk(&temp, &target), on_disk(&temp, &link))
        .expect("create symlink");
    let stats = CloneStats::default();

    let result = ensure_parent_dir(&link.join("file.txt"), &operation, &stats).await;

    assert!(
        result.is_err(),
        "a symlink to a file is not a usable parent"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn adversarial_symlink_to_directory_parent() {
    let (temp, operation) = create_operation().await;
    let target = relative_path("target");
    tokio::fs::create_dir(on_disk(&temp, &target))
        .await
        .expect("create target dir");
    let link = relative_path("link");
    std::os::unix::fs::symlink(on_disk(&temp, &target), on_disk(&temp, &link))
        .expect("create symlink");
    let stats = CloneStats::default();

    ensure_parent_dir(&link.join("file.txt"), &operation, &stats)
        .await
        .expect("a symlink to a directory is a usable parent");
}

#[tokio::test]
async fn adversarial_parent_nested_under_a_file() {
    let (temp, operation) = create_operation().await;
    let blocker = relative_path("blocker");
    tokio::fs::File::create(on_disk(&temp, &blocker))
        .await
        .expect("create blocker file");
    let stats = CloneStats::default();

    let result = ensure_parent_dir(&blocker.join("deep/file.txt"), &operation, &stats).await;

    assert!(result.is_err(), "a file cannot contain a directory");
}

#[tokio::test]
async fn adversarial_paths_without_a_usable_parent() {
    let (_temp, operation) = create_operation().await;
    let stats = CloneStats::default();

    // Filesystem root: no parent to create.
    ensure_parent_dir(&relative_path("/"), &operation, &stats)
        .await
        .expect("root must be a no-op");
    // Bare relative name: parent is the empty path.
    ensure_parent_dir(&relative_path("file.txt"), &operation, &stats)
        .await
        .expect("a bare relative name must be a no-op");
    // Empty path.
    ensure_parent_dir(&RelativePath::new(), &operation, &stats)
        .await
        .expect("empty path must be a no-op");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adversarial_concurrent_calls_same_parent() {
    let (temp, operation) = create_operation().await;
    let stats = Arc::new(CloneStats::default());
    let parent = relative_path("shared/nested");

    let mut tasks = Vec::new();
    for index in 0..16 {
        let operation = operation.clone();
        let stats = stats.clone();
        let file = parent.join(format!("file-{index}.txt"));
        tasks.push(lore_spawn!(async move {
            ensure_parent_dir(&file, &operation, &stats).await
        }));
    }
    for task in tasks {
        task.await
            .expect("task must not panic")
            .expect("concurrent creation of the same parent must not fail");
    }

    assert!(on_disk(&temp, &parent).is_dir());
    assert_eq!(stats.created_parents.len(), 1);
}

#[tokio::test]
async fn holds_entries_besides_dot_dir_missing_path_holds_nothing() {
    let temp = TempDir::new("lore-clone-holds-missing-");
    let path = temp.path().join("absent");
    let dot_dir = path.join(".lore");

    let holds = holds_entries_besides_dot_dir(&path, &dot_dir)
        .await
        .expect("a missing path is not an error");

    assert!(!holds);
}

#[tokio::test]
async fn holds_entries_besides_dot_dir_empty_dir_holds_nothing() {
    let temp = TempDir::new("lore-clone-holds-empty-");
    let dot_dir = temp.path().join(".lore");

    let holds = holds_entries_besides_dot_dir(temp.path(), &dot_dir)
        .await
        .expect("listing an empty folder");

    assert!(!holds);
}

#[tokio::test]
async fn holds_entries_besides_dot_dir_only_dot_dir_holds_nothing() {
    let temp = TempDir::new("lore-clone-holds-dot-");
    let dot_dir = temp.path().join(".lore");
    std::fs::create_dir(&dot_dir).expect("creating the control dir");
    std::fs::write(dot_dir.join("marker"), b"x").expect("writing inside the control dir");

    let holds = holds_entries_besides_dot_dir(temp.path(), &dot_dir)
        .await
        .expect("listing a folder with only the control dir");

    assert!(!holds, "the control dir and its contents must not count");
}

#[tokio::test]
async fn holds_entries_besides_dot_dir_file_holds_entries() {
    let temp = TempDir::new("lore-clone-holds-file-");
    let dot_dir = temp.path().join(".lore");
    std::fs::write(temp.path().join("user.txt"), b"mine").expect("writing a user file");

    let holds = holds_entries_besides_dot_dir(temp.path(), &dot_dir)
        .await
        .expect("listing a folder with a file");

    assert!(holds);
}

#[tokio::test]
async fn holds_entries_besides_dot_dir_file_beside_dot_dir_holds_entries() {
    let temp = TempDir::new("lore-clone-holds-both-");
    let dot_dir = temp.path().join(".lore");
    std::fs::create_dir(&dot_dir).expect("creating the control dir");
    std::fs::write(temp.path().join("user.txt"), b"mine").expect("writing a user file");

    let holds = holds_entries_besides_dot_dir(temp.path(), &dot_dir)
        .await
        .expect("listing a populated working copy");

    assert!(holds);
}

#[tokio::test]
async fn holds_entries_besides_dot_dir_subdir_holds_entries() {
    let temp = TempDir::new("lore-clone-holds-subdir-");
    let dot_dir = temp.path().join(".lore");
    std::fs::create_dir(temp.path().join("Content")).expect("creating a user folder");

    let holds = holds_entries_besides_dot_dir(temp.path(), &dot_dir)
        .await
        .expect("listing a folder with a subfolder");

    assert!(holds);
}

#[tokio::test]
async fn holds_entries_besides_dot_dir_legacy_urc_dir_holds_nothing() {
    let temp = TempDir::new("lore-clone-holds-urc-");
    let dot_dir = temp.path().join(".lore");
    std::fs::create_dir(temp.path().join(".urc")).expect("creating the legacy control dir");

    let holds = holds_entries_besides_dot_dir(temp.path(), &dot_dir)
        .await
        .expect("listing a folder with a legacy control dir");

    assert!(!holds, "the legacy .urc dir must not count");
}

#[tokio::test]
async fn holds_entries_besides_dot_dir_mixed_case_control_dirs_hold_nothing() {
    let temp = TempDir::new("lore-clone-holds-case-");
    let dot_dir = temp.path().join(".lore");
    std::fs::create_dir(temp.path().join(".Lore")).expect("creating .Lore");
    std::fs::create_dir(temp.path().join(".URC")).expect("creating .URC");

    let holds = holds_entries_besides_dot_dir(temp.path(), &dot_dir)
        .await
        .expect("listing a folder with mixed-case control dirs");

    assert!(!holds, "control dirs count in any letter case");
}

// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
// Fixtures build working-tree state directly; what these test is how the commit reads it.
#![allow(clippy::disallowed_methods)]

use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use async_trait::async_trait;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::runtime::runtime;
use lore_base::types::Hash;
use lore_revision::branch;
use lore_revision::commit::*;
use lore_revision::fs::filesystem_provider::FilesystemProvider;
use lore_revision::fs::filesystem_provider::FsError;
use lore_revision::fs::filesystem_provider::InstanceOperationImpl;
use lore_revision::fs::os::OsFilesystem;
use lore_revision::interface::LoreArray;
use lore_revision::interface::LoreString;
use lore_revision::lore::BranchId;
use lore_revision::lore::RepositoryId;
use lore_revision::repository::RepositoryContext;
use lore_revision::repository::RepositoryWriteToken;

use crate::fs::filesystem_provider::test_store_create;
use crate::repository::test_helpers::RepositoryContextCreationArgsExt;
use crate::repository::test_helpers::default_repository_creation_args;

/// One commit reads the working tree through the one operation it opens, whatever it
/// commits: a provider that freezes hands out one snapshot, and a second opened partway
/// would fragment some of the files against a tree the rest were never measured against.
///
/// The count is taken from the commit alone, the staging that precedes it opening its own.
#[tokio::test]
async fn one_call_reads_the_working_tree_through_one_operation() {
    let dir = lore_base::test_util::TempDir::new("lore-commit-test-");
    std::fs::write(dir.path().join("one.txt"), b"one").expect("write file");
    std::fs::write(dir.path().join("two.txt"), b"two").expect("write file");
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Making test stores");
    let root = dir.to_path_buf();

    let begins = runtime()
        .spawn(LORE_CONTEXT.scope(execution, async move {
            let fixture = counting_repository(&root, immutable_store, mutable_store).await;
            stage_working_tree(&fixture, &root).await;
            fixture.begins.store(0, Ordering::Release);

            commit_staged(&fixture).await.expect("Committing");

            fixture.begins.load(Ordering::Acquire)
        }))
        .await
        .expect("Test task failed");

    assert_eq!(
        1, begins,
        "The commit opened an operation beyond the one it reads the working tree through"
    );
}

/// A staged file the working tree no longer holds is reported rather than fragmented: what
/// a commit stores for a file it reads from the working tree, and a path holding nothing
/// has nothing to store.
#[tokio::test]
async fn a_staged_file_the_working_tree_no_longer_holds_is_reported() {
    let dir = lore_base::test_util::TempDir::new("lore-commit-test-");
    std::fs::write(dir.path().join("gone.txt"), b"content").expect("write file");
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Making test stores");
    let root = dir.to_path_buf();

    let error = runtime()
        .spawn(LORE_CONTEXT.scope(execution, async move {
            let fixture = counting_repository(&root, immutable_store, mutable_store).await;
            stage_working_tree(&fixture, &root).await;
            std::fs::remove_file(root.join("gone.txt")).expect("remove file");

            commit_staged(&fixture)
                .await
                .expect_err("A commit of a file that is gone reported a revision")
        }))
        .await
        .expect("Test task failed");

    assert!(
        matches!(error, CommitError::FileNotFound { .. }),
        "The missing file was reported as {error} rather than as the file it is"
    );
}

/// An [`OsFilesystem`] that counts the operations opened on it.
struct CountingFilesystem {
    inner: OsFilesystem,
    begins: Arc<AtomicUsize>,
}

#[async_trait]
impl FilesystemProvider for CountingFilesystem {
    async fn begin_operation(&self) -> Result<Arc<InstanceOperationImpl>, FsError> {
        self.begins.fetch_add(1, Ordering::AcqRel);
        FilesystemProvider::begin_operation(&self.inner).await
    }
}

/// A repository over the working tree at `root`, its filesystem counting the operations
/// opened on it.
struct CountingRepository {
    repository: Arc<RepositoryContext>,
    token: RepositoryWriteToken,
    begins: Arc<AtomicUsize>,
}

/// A repository created at `root`, anchored on a fresh default branch, over a filesystem
/// that counts.
///
/// Call from inside a `LORE_CONTEXT` scope: creating a repository reads the execution
/// context.
async fn counting_repository(
    root: &std::path::Path,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
) -> CountingRepository {
    let begins = Arc::new(AtomicUsize::new(0));
    let repository_id = RepositoryId::from(uuid::Uuid::now_v7());
    let branch_id = BranchId::from(uuid::Uuid::now_v7());
    let token = RepositoryWriteToken::acquire(root).await;
    let created = lore_revision::repository::create_local(
        root,
        &token,
        repository_id,
        branch_id,
        branch::DEFAULT_DEFAULT_NAME.to_string(),
        lore_revision::repository::RepositoryConfig::default(),
        false,
    )
    .await
    .expect("Initializing the repository");

    let repository = Arc::new(
        RepositoryContext::new(
            default_repository_creation_args(immutable_store, mutable_store)
                .with_path(root)
                .with_id(repository_id)
                .with_instance_id(created.instance_id)
                .with_filesystem_provider(Arc::new(CountingFilesystem {
                    inner: OsFilesystem::new(root),
                    begins: begins.clone(),
                })),
        )
        .with_write_token(token.share()),
    );
    lore_revision::instance::store_current_anchor_branch(&repository, branch_id)
        .await
        .expect("Storing the anchor branch");

    CountingRepository {
        repository,
        token,
        begins,
    }
}

/// Stages everything the working tree at `root` holds, scanning rather than reading dirty
/// flags so a fixture that wrote its files directly is staged whole.
async fn stage_working_tree(fixture: &CountingRepository, root: &std::path::Path) {
    lore_revision::file::stage::stage(
        fixture.repository.clone(),
        &fixture.token,
        LoreArray::from_vec(vec![LoreString::from(&root.to_path_buf())]),
        lore_revision::stage::StageOptions {
            scan: true,
            ..Default::default()
        },
    )
    .await
    .expect("Staging the working tree");
}

/// Commits what the fixture holds staged, with no metadata beyond what a commit stamps.
async fn commit_staged(fixture: &CountingRepository) -> Result<Hash, CommitError> {
    Box::pin(commit_with_metadata(
        fixture.repository.clone(),
        &fixture.token,
        CommitOptions::new(String::from("test")),
        LoreArray::from_vec(Vec::default()),
        LoreArray::from_vec(Vec::default()),
        LoreArray::from_vec(Vec::default()),
    ))
    .await
}

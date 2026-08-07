// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)] // Test fixture writes; not subject to repository write-token discipline.

    use std::fs;
    use std::io::Write;
    use std::path::Path;
    use std::sync::Arc;

    use lore_base::runtime::LORE_CONTEXT;
    use lore_base::runtime::runtime;
    use lore_base::types::BranchId;
    use lore_base::types::Context;
    use lore_base::types::Hash;
    use lore_revision::branch;
    use lore_revision::branch::BranchLatestStatus;
    use lore_revision::commit;
    use lore_revision::commit::CommitOptions;
    use lore_revision::file;
    use lore_revision::instance;
    use lore_revision::interface::LoreArray;
    use lore_revision::interface::LoreString;
    use lore_revision::lore::RepositoryId;
    use lore_revision::node::NodeFlags;
    use lore_revision::repository;
    use lore_revision::repository::RepositoryContext;
    use lore_revision::repository::RepositoryWriteToken;
    use lore_revision::revision::sync;
    use lore_revision::revision::sync::SyncOptions;
    use lore_revision::stage;
    use lore_revision::stage::StageOptions;

    include!("helper.rs");

    struct SyncFixture {
        repository: Arc<RepositoryContext>,
        write_token: RepositoryWriteToken,
        branch_id: BranchId,
        first_revision: Hash,
        second_revision: Hash,
    }

    async fn commit_file(
        repository: Arc<RepositoryContext>,
        write_token: &RepositoryWriteToken,
        repository_path: &Path,
        file_name: &str,
    ) -> Hash {
        let file_path = repository_path.join(file_name);
        let mut file = std::fs::File::options()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(file_path)
            .expect("Failed to create test file");
        file.write_all(&[0, 1, 2, 3, 4])
            .expect("Failed to write test file");
        drop(file);

        file::stage::stage(
            repository.clone(),
            write_token,
            LoreArray::from_vec(vec![LoreString::from(&repository_path.to_path_buf())]),
            StageOptions {
                case_change: stage::StageCaseChange::Error,
                node_flags: NodeFlags::NoFlags,
                file_id: None,
                no_children: false,
                scan: true,
            },
        )
        .await
        .expect("Failed to stage file");

        Box::pin(commit::commit(
            repository,
            write_token,
            CommitOptions {
                message: String::new(),
                link_messages: std::collections::HashMap::new(),
                link: None,
                layer_messages: std::collections::HashMap::new(),
                layer: None,
                stats: false,
            },
        ))
        .await
        .expect("Failed to commit revision")
    }

    async fn create_sync_fixture(path: &Path) -> SyncFixture {
        std::fs::create_dir_all(path).expect("Create directory failed");
        let write_token = RepositoryWriteToken::acquire(path).await;
        let branch_id = Context::from(uuid::Uuid::now_v7());
        let repository = repository::create_local(
            path,
            &write_token,
            RepositoryId::from(uuid::Uuid::now_v7()),
            branch_id,
            branch::DEFAULT_DEFAULT_NAME.to_string(),
            repository::RepositoryConfig::default(),
            false,
        )
        .await
        .expect("Failed to create repository");

        let first_revision =
            commit_file(repository.clone(), &write_token, path, "first.test.file").await;
        let second_revision =
            commit_file(repository.clone(), &write_token, path, "second.test.file").await;

        SyncFixture {
            repository,
            write_token,
            branch_id,
            first_revision,
            second_revision,
        }
    }

    async fn sync_explicit(fixture: &SyncFixture, revision: Hash, revision_is_remote: bool) {
        Box::pin(sync::sync(
            fixture.repository.clone(),
            &fixture.write_token,
            SyncOptions {
                revision: Some(revision.to_string()),
                revision_is_remote,
                filter_mode: lore_revision::filter::FilterMode::Full,
                ..Default::default()
            },
        ))
        .await
        .expect("Failed to sync to explicit revision");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn local_explicit_backward_sync_preserves_branch_latest() {
        let (_immutable_store, _mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        runtime()
            .spawn(LORE_CONTEXT.scope(execution, async move {
                let tempdir = generate_tempdir();
                let fixture = create_sync_fixture(tempdir.path()).await;

                sync_explicit(&fixture, fixture.first_revision, false).await;

                let latest = branch::load_latest(fixture.repository.clone(), fixture.branch_id)
                    .await
                    .expect("Failed to load branch latest");
                assert_eq!(latest, fixture.second_revision);
                assert!(fs::metadata(tempdir.path().join("first.test.file")).is_ok());
                assert!(fs::metadata(tempdir.path().join("second.test.file")).is_err());
            }))
            .await
            .expect("Test task failed");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn remote_explicit_no_op_sync_repairs_stale_branch_bookkeeping() {
        let (_immutable_store, _mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        runtime()
            .spawn(LORE_CONTEXT.scope(execution, async move {
                let tempdir = generate_tempdir();
                let fixture = create_sync_fixture(tempdir.path()).await;

                branch::store_latest(
                    fixture.repository.clone(),
                    fixture.branch_id,
                    fixture.first_revision,
                    BranchLatestStatus::Convergent,
                )
                .await
                .expect("Failed to make branch latest stale");
                branch::store_last_sync(
                    fixture.repository.clone(),
                    fixture.branch_id,
                    fixture.first_revision,
                )
                .await;

                sync_explicit(&fixture, fixture.second_revision, true).await;

                let latest = branch::load_latest(fixture.repository.clone(), fixture.branch_id)
                    .await
                    .expect("Failed to load repaired branch latest");
                let last_sync =
                    branch::load_last_sync(fixture.repository.clone(), fixture.branch_id)
                        .await
                        .expect("Failed to load repaired last sync");
                assert_eq!(latest, fixture.second_revision);
                assert_eq!(last_sync, fixture.second_revision);
            }))
            .await
            .expect("Test task failed");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn older_remote_explicit_sync_preserves_newer_local_branch_latest() {
        let (_immutable_store, _mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        runtime()
            .spawn(LORE_CONTEXT.scope(execution, async move {
                let tempdir = generate_tempdir();
                let fixture = create_sync_fixture(tempdir.path()).await;

                sync_explicit(&fixture, fixture.first_revision, true).await;

                let latest = branch::load_latest(fixture.repository.clone(), fixture.branch_id)
                    .await
                    .expect("Failed to load preserved branch latest");
                let (current_revision, current_branch) =
                    instance::load_current_anchor(&fixture.repository)
                        .await
                        .expect("Failed to load current anchor");
                assert_eq!(latest, fixture.second_revision);
                assert_eq!(current_revision, fixture.first_revision);
                assert_eq!(current_branch, fixture.branch_id);
                assert!(fs::metadata(tempdir.path().join("second.test.file")).is_err());
            }))
            .await
            .expect("Test task failed");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cross_branch_remote_explicit_sync_does_not_rewrite_current_branch_bookkeeping() {
        let (_immutable_store, _mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        runtime()
            .spawn(LORE_CONTEXT.scope(execution, async move {
                let tempdir = generate_tempdir();
                let fixture = create_sync_fixture(tempdir.path()).await;
                branch::store_last_sync(
                    fixture.repository.clone(),
                    fixture.branch_id,
                    fixture.first_revision,
                )
                .await;

                branch::create::create(
                    fixture.repository.clone(),
                    &fixture.write_token,
                    "other".to_string(),
                    None,
                    String::new(),
                    false,
                )
                .await
                .expect("Failed to create other branch");
                let (_, other_branch) = instance::load_current_anchor(&fixture.repository)
                    .await
                    .expect("Failed to load other branch anchor");
                let other_revision = commit_file(
                    fixture.repository.clone(),
                    &fixture.write_token,
                    tempdir.path(),
                    "other.test.file",
                )
                .await;

                instance::store_current_anchor_branch(&fixture.repository, fixture.branch_id)
                    .await
                    .expect("Failed to restore original anchor branch");
                instance::store_current_anchor(&fixture.repository, fixture.second_revision)
                    .await
                    .expect("Failed to restore original anchor revision");

                sync_explicit(&fixture, other_revision, true).await;

                let latest = branch::load_latest(fixture.repository.clone(), fixture.branch_id)
                    .await
                    .expect("Failed to load original branch latest");
                let last_sync =
                    branch::load_last_sync(fixture.repository.clone(), fixture.branch_id)
                        .await
                        .expect("Failed to load original branch last sync");
                let (current_revision, current_branch) =
                    instance::load_current_anchor(&fixture.repository)
                        .await
                        .expect("Failed to load synced anchor");
                assert_eq!(latest, fixture.second_revision);
                assert_eq!(last_sync, fixture.first_revision);
                assert_eq!(current_revision, other_revision);
                assert_eq!(current_branch, other_branch);
            }))
            .await
            .expect("Test task failed");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn remote_explicit_forward_sync_advances_branch_bookkeeping() {
        let (_immutable_store, _mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        runtime()
            .spawn(LORE_CONTEXT.scope(execution, async move {
                let tempdir = generate_tempdir();
                let fixture = create_sync_fixture(tempdir.path()).await;

                sync_explicit(&fixture, fixture.first_revision, false).await;
                branch::store_latest(
                    fixture.repository.clone(),
                    fixture.branch_id,
                    fixture.first_revision,
                    BranchLatestStatus::Convergent,
                )
                .await
                .expect("Failed to make branch latest stale");
                branch::store_last_sync(
                    fixture.repository.clone(),
                    fixture.branch_id,
                    fixture.first_revision,
                )
                .await;

                sync_explicit(&fixture, fixture.second_revision, true).await;

                let latest = branch::load_latest(fixture.repository.clone(), fixture.branch_id)
                    .await
                    .expect("Failed to load advanced branch latest");
                let last_sync =
                    branch::load_last_sync(fixture.repository.clone(), fixture.branch_id)
                        .await
                        .expect("Failed to load advanced last sync");
                assert_eq!(latest, fixture.second_revision);
                assert_eq!(last_sync, fixture.second_revision);
                assert!(fs::metadata(tempdir.path().join("second.test.file")).is_ok());
            }))
            .await
            .expect("Test task failed");
    }
}

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

    /// The file the executable bit test carries across two revisions.
    #[cfg(target_family = "unix")]
    const SCRIPT: &str = "script.sh";
    #[cfg(target_family = "unix")]
    const FIRST: &[u8] = b"#!/bin/sh\necho first";
    #[cfg(target_family = "unix")]
    const SECOND: &[u8] = b"#!/bin/sh\necho second";

    /// Syncs `instance` to `revision`, discarding local modifications where `reset` asks it to.
    #[cfg(target_family = "unix")]
    async fn sync_to(instance: &TestRepository, revision: lore_base::types::Hash, reset: bool) {
        sync::sync_boxed(
            instance.repository.clone(),
            &instance.write_token,
            SyncOptions {
                revision: Some(revision.to_string()),
                reset,
                ..Default::default()
            },
        )
        .await
        .expect("Failed to sync to the revision");
    }

    /// A repository whose second revision rewrites [`SCRIPT`], answered beside the working tree
    /// standing on the first revision with the file marked executable by hand.
    #[cfg(target_family = "unix")]
    async fn a_chmodded_working_tree(
        immutable_store: std::sync::Arc<dyn lore_storage::ImmutableStore>,
        mutable_store: std::sync::Arc<dyn lore_storage::MutableStore>,
    ) -> (TestRepository, lore_base::types::Hash) {
        use std::os::unix::fs::PermissionsExt;

        let instance = test_repository_create(
            immutable_store,
            mutable_store,
            RepositoryId::from(uuid::Uuid::now_v7()),
        )
        .await;
        let script = instance.path.join(SCRIPT);

        test_file_write(script.as_path(), FIRST);
        let first = test_commit_tree(&instance, "First").await.revision();
        test_file_write(script.as_path(), SECOND);
        let second = test_commit_tree(&instance, "Second").await.revision();

        sync_to(&instance, first, false).await;
        std::fs::set_permissions(script.as_path(), std::fs::Permissions::from_mode(0o755))
            .expect("Failed to set the executable bit");

        (instance, second)
    }

    /// Whether the working file at `path` carries the executable bit.
    #[cfg(target_family = "unix")]
    fn working_executable(path: &std::path::Path) -> bool {
        use std::os::unix::fs::PermissionsExt;

        fs::metadata(path)
            .expect("The working file must be readable")
            .permissions()
            .mode()
            & 0o111
            != 0
    }

    /// A chmod is a modification of the executable bit and nothing else, which the content an
    /// incoming revision carries answers nothing about. A sync to that revision writes the content
    /// and leaves the bit, so the change the user made stands as a local modification against the
    /// revision the tree lands on rather than being reverted by the write.
    #[cfg(target_family = "unix")]
    #[tokio::test(flavor = "multi_thread")]
    async fn a_sync_writes_new_content_and_keeps_a_local_executable_bit() {
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        #[allow(clippy::disallowed_methods)]
        runtime()
            .spawn(LORE_CONTEXT.scope(execution, async move {
                let (instance, second) =
                    a_chmodded_working_tree(immutable_store, mutable_store).await;
                let script = instance.path.join(SCRIPT);

                sync_to(&instance, second, false).await;

                assert_eq!(
                    fs::read(script.as_path()).expect("The synced file must be readable"),
                    SECOND,
                    "the sync has to carry the content the revision it lands on holds"
                );
                assert!(
                    working_executable(script.as_path()),
                    "the bit the user set has to survive the write"
                );

                let (current, staged) = test_anchor_states(&instance.repository).await;
                let scanned =
                    test_reported(&test_scan(instance.repository.clone(), staged, current).await);
                assert!(
                    scanned.contains(&("M".to_string(), SCRIPT.to_string())),
                    "the bit has to stand as a local modification against the revision synced \
                     to, reported {scanned:?}"
                );
            }))
            .await
            .expect("Test task failed");
    }

    /// A reset discards local modifications, which the executable bit is one of: the file is left
    /// holding the mode its revision names.
    #[cfg(target_family = "unix")]
    #[tokio::test(flavor = "multi_thread")]
    async fn a_reset_sync_discards_a_local_executable_bit() {
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        #[allow(clippy::disallowed_methods)]
        runtime()
            .spawn(LORE_CONTEXT.scope(execution, async move {
                let (instance, second) =
                    a_chmodded_working_tree(immutable_store, mutable_store).await;
                let script = instance.path.join(SCRIPT);

                sync_to(&instance, second, true).await;

                assert_eq!(
                    fs::read(script.as_path()).expect("The synced file must be readable"),
                    SECOND,
                    "a reset carries the content the revision it lands on holds"
                );
                assert!(
                    !working_executable(script.as_path()),
                    "a reset leaves the mode the revision names, the local bit with it"
                );
            }))
            .await
            .expect("Test task failed");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sync_explicit_revision() {
        let (_immutable_store, _mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");
        let repository_id = RepositoryId::from(uuid::Uuid::now_v7());
        let tempdir = generate_tempdir();
        let temp_path = tempdir.to_path_buf();
        let path = temp_path.clone();

        #[allow(clippy::disallowed_methods)]
        runtime()
            .spawn(LORE_CONTEXT.scope(execution.clone(), async move {
                std::fs::create_dir_all(path.as_path()).expect("Create directory failed");
                let write_token = repository::RepositoryWriteToken::acquire(path.as_path()).await;
                let repository = repository::create_local(
                    path.as_path(),
                    &write_token,
                    repository_id,
                    Context::from(uuid::Uuid::now_v7()),
                    branch::DEFAULT_DEFAULT_NAME.to_string(),
                    repository::RepositoryConfig::default(),
                    false,
                )
                .await
                .expect("Failed to create repository");

                let file_path = path.as_path().join("test.file");
                {
                    let mut file = std::fs::File::options()
                        .create(true)
                        .truncate(true)
                        .read(true)
                        .write(true)
                        .open(file_path.as_path())
                        .expect("Failed to create test file");
                    file.write_all(&[0, 1, 2, 3, 4])
                        .expect("Failed to write test file");
                }

                let _signature = file::stage::stage(
                    repository.clone(),
                    &write_token,
                    LoreArray::from_vec(vec![LoreString::from(&path)]),
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

                let options = CommitOptions {
                    message: String::new(),
                    link_messages: std::collections::HashMap::new(),
                    link: None,
                    layer_messages: std::collections::HashMap::new(),
                    layer: None,
                };
                let first_signature =
                    commit::commit_boxed(repository.clone(), &write_token, options)
                        .await
                        .expect("Failed to commit revision");

                let other_file_path = path.as_path().join("second.test.file");
                {
                    let mut file = std::fs::File::options()
                        .create(true)
                        .truncate(true)
                        .read(true)
                        .write(true)
                        .open(other_file_path.as_path())
                        .expect("Failed to create test file");
                    file.write_all(&[0, 1, 2, 3, 4])
                        .expect("Failed to write test file");
                }

                let _signature = file::stage::stage(
                    repository.clone(),
                    &write_token,
                    LoreArray::from_vec(vec![LoreString::from(&path)]),
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

                let options = CommitOptions {
                    message: String::new(),
                    link_messages: std::collections::HashMap::new(),
                    link: None,
                    layer_messages: std::collections::HashMap::new(),
                    layer: None,
                };
                let second_signature =
                    commit::commit_boxed(repository.clone(), &write_token, options)
                        .await
                        .expect("Failed to commit revision");

                // Sync back to first revision
                sync::sync_boxed(
                    repository.clone(),
                    &write_token,
                    SyncOptions {
                        revision: Some(first_signature.to_string()),
                        filter_mode: lore_revision::filter::FilterMode::Full,
                        ..Default::default()
                    },
                )
                .await
                .expect("Failed to sync back to first revision");

                // Verify file added in first revision is still there
                assert!(
                    fs::metadata(file_path.as_path())
                        .expect("Failed to find first file as expected")
                        .is_file()
                );

                // Verify file added in second revision is gone
                fs::metadata(other_file_path.as_path()).expect_err(
                    "File added in second revision was not removed as expected after sync back",
                );

                // Sync forward to second revision
                sync::sync_boxed(
                    repository.clone(),
                    &write_token,
                    SyncOptions {
                        revision: Some(second_signature.to_string()),
                        filter_mode: lore_revision::filter::FilterMode::Full,
                        ..Default::default()
                    },
                )
                .await
                .expect("Failed to sync forward to second revision");

                // Verify file added in first revision is still there
                assert!(
                    fs::metadata(file_path.as_path())
                        .expect("Failed to find first file as expected")
                        .is_file()
                );

                // Verify file added in second revision is restored
                assert!(
                    fs::metadata(other_file_path.as_path())
                        .expect("Failed to find first file as expected")
                        .is_file()
                );
            }))
            .await
            .expect("Test task failed");
    }

    // FORK-LOCAL (Tideshift, cb596789): remote-proven explicit sync branch bookkeeping.
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

        commit::commit_boxed(
            repository,
            write_token,
            CommitOptions {
                message: String::new(),
                link_messages: std::collections::HashMap::new(),
                link: None,
                layer_messages: std::collections::HashMap::new(),
                layer: None,
            },
        )
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
        sync::sync_boxed(
            fixture.repository.clone(),
            &fixture.write_token,
            SyncOptions {
                revision: Some(revision.to_string()),
                revision_is_remote,
                filter_mode: lore_revision::filter::FilterMode::Full,
                ..Default::default()
            },
        )
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
                    fixture.second_revision,
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
                    instance::load_current_anchor_boxed(&fixture.repository)
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
                let (_, other_branch) = instance::load_current_anchor_boxed(&fixture.repository)
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
                    instance::load_current_anchor_boxed(&fixture.repository)
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
                    fixture.second_revision,
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

// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Khurram Virani
// SPDX-License-Identifier: MIT

#![allow(clippy::disallowed_methods)] // Test fixtures write outside repository token discipline.

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::collections::VecDeque;
    use std::io::Write;
    use std::path::PathBuf;
    use std::sync::Arc;

    use lore_base::runtime::LORE_CONTEXT;
    use lore_base::types::Hash;
    use lore_revision::branch;
    use lore_revision::commit;
    use lore_revision::commit::CommitOptions;
    use lore_revision::file;
    use lore_revision::interface::ExecutionContext;
    use lore_revision::interface::LoreArray;
    use lore_revision::interface::LoreString;
    use lore_revision::lore::BranchId;
    use lore_revision::lore::RepositoryId;
    use lore_revision::node::NodeFlags;
    use lore_revision::node::ROOT_NODE;
    use lore_revision::relay::EventDispatcher;
    use lore_revision::repository;
    use lore_revision::repository::RepositoryContext;
    use lore_revision::repository::RepositoryWriteToken;
    use lore_revision::stage;
    use lore_revision::stage::StageOptions;
    use lore_revision::state::State;
    use lore_revision::state::StateNodeChildrenWithNameIterator;

    include!("helper.rs");

    const NESTED_FILE_COUNT: usize = 64;

    struct StageFixture {
        repository: Arc<RepositoryContext>,
        write_token: RepositoryWriteToken,
        repo_path: PathBuf,
        main_branch: BranchId,
        _tempdir: TempDir,
    }

    impl StageFixture {
        async fn new() -> Self {
            let tempdir = generate_tempdir();
            let repo_path = tempdir.to_path_buf();
            let main_branch = BranchId::from(uuid::Uuid::now_v7());
            let write_token = RepositoryWriteToken::acquire(repo_path.as_path()).await;
            let repository = repository::create_local(
                repo_path.as_path(),
                &write_token,
                RepositoryId::from(uuid::Uuid::now_v7()),
                main_branch,
                branch::DEFAULT_DEFAULT_NAME.to_string(),
                repository::RepositoryConfig::default(),
                false,
            )
            .await
            .expect("initialize repository");

            Self {
                repository,
                write_token,
                repo_path,
                main_branch,
                _tempdir: tempdir,
            }
        }

        fn absolute(&self, relative: &str) -> PathBuf {
            self.repo_path.join(relative)
        }

        fn write_file(&self, relative: &str, content: &[u8]) {
            let absolute = self.absolute(relative);
            if let Some(parent) = absolute.parent() {
                std::fs::create_dir_all(parent).expect("create file parent");
            }
            let mut file = std::fs::File::options()
                .create(true)
                .truncate(true)
                .write(true)
                .open(absolute)
                .expect("open fixture file");
            file.write_all(content).expect("write fixture file");
        }

        fn nested_files(&self, directory: &str) -> Vec<String> {
            (0..NESTED_FILE_COUNT)
                .map(|index| format!("{directory}/actor-{index:03}.uasset"))
                .collect()
        }

        fn write_nested_files(&self, paths: &[String], prefix: &str) {
            for path in paths {
                self.write_file(path, format!("{prefix}:{path}\n").as_bytes());
            }
        }

        async fn stage(&self, paths: &[String], case_change: stage::StageCaseChange) -> Hash {
            let paths = paths
                .iter()
                .map(|path| LoreString::from(self.absolute(path)))
                .collect();
            file::stage::stage(
                self.repository.clone(),
                &self.write_token,
                LoreArray::from_vec(paths),
                StageOptions {
                    case_change,
                    node_flags: NodeFlags::NoFlags,
                    file_id: None,
                    no_children: false,
                    scan: true,
                },
            )
            .await
            .expect("stage selected paths")
        }

        async fn stage_all(&self) -> Hash {
            file::stage::stage(
                self.repository.clone(),
                &self.write_token,
                LoreArray::from_vec(vec![LoreString::from(&self.repo_path)]),
                StageOptions {
                    case_change: stage::StageCaseChange::Error,
                    node_flags: NodeFlags::NoFlags,
                    file_id: None,
                    no_children: false,
                    scan: true,
                },
            )
            .await
            .expect("stage repository")
        }

        async fn commit(&self, message: &str) -> Hash {
            Box::pin(commit::commit(
                self.repository.clone(),
                &self.write_token,
                CommitOptions::new(message.to_string()),
            ))
            .await
            .expect("commit staged state")
        }

        async fn stage_and_commit_all(&self, message: &str) -> Hash {
            self.stage_all().await;
            self.commit(message).await
        }

        async fn create_branch(&self, name: &str) -> BranchId {
            branch::create::create(
                self.repository.clone(),
                &self.write_token,
                name.to_string(),
                None,
                String::new(),
                false,
            )
            .await
            .expect("create branch");
            let (_, branch) = lore_revision::instance::load_current_anchor(&self.repository)
                .await
                .expect("load branch anchor");
            branch
        }

        async fn switch_to(&self, branch: BranchId, revision: Hash) {
            lore_revision::instance::store_current_anchor_branch(&self.repository, branch)
                .await
                .expect("store branch anchor");
            lore_revision::instance::store_current_anchor(&self.repository, revision)
                .await
                .expect("store revision anchor");
        }
    }

    fn execution(force: bool) -> Arc<ExecutionContext> {
        let mut globals = LoreGlobalArgs::default().set_offline();
        globals.force = u8::from(force);
        Arc::new(ExecutionContext::new_client_with_user_id(
            globals,
            EventDispatcher::no_dispatch(),
            "stage-topology-test".to_string(),
        ))
    }

    async fn state_at(fixture: &StageFixture, revision: Hash) -> Arc<State> {
        State::deserialize(fixture.repository.clone(), revision)
            .await
            .expect("deserialize exact revision")
    }

    async fn collect_files(fixture: &StageFixture, state: Arc<State>) -> BTreeSet<String> {
        let mut files = BTreeSet::new();
        let mut directories = VecDeque::from([(String::new(), ROOT_NODE)]);

        while let Some((parent_path, parent_id)) = directories.pop_front() {
            let mut children = StateNodeChildrenWithNameIterator::new(
                state.clone(),
                fixture.repository.clone(),
                parent_id,
            )
            .await
            .expect("iterate state directory");
            while let Some((child_id, child, name)) =
                children.next().await.expect("load state child")
            {
                if child.is_staged_delete() || child.is_discarded() {
                    continue;
                }
                let name = name.freeze();
                let path = if parent_path.is_empty() {
                    name.to_string()
                } else {
                    format!("{parent_path}/{name}")
                };
                if child.is_file() {
                    files.insert(path);
                } else if child.is_directory() {
                    directories.push_back((path, child_id));
                }
            }
        }

        files
    }

    async fn assert_staged_selection(
        fixture: &StageFixture,
        staged_revision: Hash,
        expected_files: &BTreeSet<String>,
        admitted_files: &BTreeSet<String>,
    ) -> Arc<State> {
        let anchor_revision = lore_revision::instance::load_staged_revision(&fixture.repository)
            .await
            .expect("reload staged anchor")
            .expect("staged anchor must exist");
        assert_eq!(
            anchor_revision, staged_revision,
            "public stage result must be the serialized staged anchor"
        );
        let staged = state_at(fixture, anchor_revision).await;
        assert_eq!(
            collect_files(fixture, staged.clone()).await,
            *expected_files,
            "serialized staged tree must contain exactly the admitted files"
        );
        for path in admitted_files {
            let node = staged
                .find_node(fixture.repository.clone(), path)
                .await
                .unwrap_or_else(|error| panic!("staged path {path} is unreachable: {error}"));
            assert!(node.is_staged(), "staged path {path} lacks a staged flag");
        }
        staged
    }

    async fn assert_exact_commit(
        fixture: &StageFixture,
        message: &str,
        expected_files: &BTreeSet<String>,
    ) -> Arc<State> {
        let revision = fixture.commit(message).await;
        let committed = state_at(fixture, revision).await;
        assert_eq!(
            collect_files(fixture, committed.clone()).await,
            *expected_files,
            "serialized commit must contain exactly the admitted files"
        );
        for path in expected_files {
            let node = committed
                .find_node(fixture.repository.clone(), path)
                .await
                .unwrap_or_else(|error| panic!("committed path {path} is unreachable: {error}"));
            assert_eq!(
                node.flags,
                NodeFlags::File.bits(),
                "committed file {path} must contain only the File flag"
            );
        }
        committed
    }

    async fn assert_directory_topology(
        fixture: &StageFixture,
        state: Arc<State>,
        path: &str,
        expected_children: &BTreeSet<String>,
        children_must_be_staged: bool,
    ) {
        let directory_link = state
            .find_node_link(fixture.repository.clone(), path)
            .await
            .expect("find transitioned directory");
        let directory = state
            .node(fixture.repository.clone(), directory_link.node)
            .await
            .expect("load transitioned directory");
        assert!(directory.is_directory(), "{path} must be a directory");
        assert!(
            directory.child().is_some(),
            "{path} must retain its child head"
        );

        let mut children = StateNodeChildrenWithNameIterator::new(
            state,
            fixture.repository.clone(),
            directory_link.node,
        )
        .await
        .expect("iterate transitioned directory");
        let mut actual_children = BTreeSet::new();
        while let Some((_child_id, child, name)) =
            children.next().await.expect("load transitioned child")
        {
            let name = name.freeze().to_string();
            assert!(child.is_file(), "{path}/{name} must be a file");
            if children_must_be_staged {
                assert!(child.is_staged(), "{path}/{name} must be staged");
            }
            actual_children.insert(name);
        }
        assert_eq!(
            actual_children, *expected_children,
            "{path} must retain the exact direct-child topology"
        );
    }

    async fn assert_file_structure(
        fixture: &StageFixture,
        state: Arc<State>,
        path: &str,
        expected_mode: u16,
        expected_size: u64,
    ) {
        let file = state
            .find_node(fixture.repository.clone(), path)
            .await
            .expect("load transitioned file");
        assert!(file.is_file(), "{path} must be a file");
        assert_eq!(file.child, 0, "{path} must not retain directory children");
        assert_eq!(
            file.mode, expected_mode,
            "{path} mode must match filesystem"
        );
        assert_eq!(
            file.size, expected_size,
            "{path} size must match filesystem"
        );
    }

    async fn committed_ancestor(force: bool) {
        let fixture = StageFixture::new().await;
        fixture.write_file("Content/Bulk/seed.uasset", b"seed\n");
        fixture.stage_and_commit_all("seed ancestor").await;

        let selected = fixture.nested_files("Content/Bulk");
        fixture.write_nested_files(&selected, "selected");
        let staged_revision = fixture
            .stage(&selected, stage::StageCaseChange::Error)
            .await;
        let expected = selected
            .iter()
            .cloned()
            .chain(["Content/Bulk/seed.uasset".to_string()])
            .collect();
        let admitted = selected.iter().cloned().collect();
        assert_staged_selection(&fixture, staged_revision, &expected, &admitted).await;
        let message = format!("committed ancestor force={force}");
        assert_exact_commit(&fixture, &message, &expected).await;
    }

    async fn staged_add_ancestor() {
        let fixture = StageFixture::new().await;
        fixture.write_file("Content/Bulk/seed.uasset", b"seed\n");
        fixture
            .stage(
                &["Content/Bulk/seed.uasset".to_string()],
                stage::StageCaseChange::Error,
            )
            .await;

        let selected = fixture.nested_files("Content/Bulk");
        fixture.write_nested_files(&selected, "selected");
        let staged_revision = fixture
            .stage(&selected, stage::StageCaseChange::Error)
            .await;
        let expected = selected
            .iter()
            .cloned()
            .chain(["Content/Bulk/seed.uasset".to_string()])
            .collect();
        let admitted = selected.iter().cloned().collect();
        assert_staged_selection(&fixture, staged_revision, &expected, &admitted).await;
        assert_exact_commit(&fixture, "staged add ancestor", &expected).await;
    }

    async fn file_to_directory() {
        let fixture = StageFixture::new().await;
        fixture.write_file("Content/Bulk", b"was a file\n");
        fixture.stage_and_commit_all("file ancestor").await;
        std::fs::remove_file(fixture.absolute("Content/Bulk")).expect("remove ancestor file");

        let selected = fixture.nested_files("Content/Bulk");
        fixture.write_nested_files(&selected, "selected");
        let staged_revision = fixture
            .stage(&selected, stage::StageCaseChange::Error)
            .await;
        let expected: BTreeSet<String> = selected.into_iter().collect();
        let expected_children = expected
            .iter()
            .map(|path: &String| path.rsplit('/').next().expect("file name").to_string())
            .collect();
        let staged = assert_staged_selection(&fixture, staged_revision, &expected, &expected).await;
        assert_directory_topology(&fixture, staged, "Content/Bulk", &expected_children, true).await;
        let committed = assert_exact_commit(&fixture, "file to directory", &expected).await;
        assert_directory_topology(
            &fixture,
            committed,
            "Content/Bulk",
            &expected_children,
            false,
        )
        .await;
    }

    async fn directory_to_file() {
        let fixture = StageFixture::new().await;
        fixture.write_file("Content/Bulk/old.uasset", b"old\n");
        fixture.stage_and_commit_all("directory ancestor").await;
        std::fs::remove_dir_all(fixture.absolute("Content/Bulk")).expect("remove ancestor dir");
        fixture.write_file("Content/Bulk", b"now a file\n");
        let metadata = std::fs::metadata(fixture.absolute("Content/Bulk"))
            .expect("read transitioned file metadata");
        let expected_mode = lore_revision::util::fs::metadata_to_mode(&metadata, 0);
        let expected_size = metadata.len();

        let selected = ["Content/Bulk".to_string()];
        let staged_revision = fixture
            .stage(&selected, stage::StageCaseChange::Error)
            .await;
        let expected = selected.into_iter().collect();
        let staged = assert_staged_selection(&fixture, staged_revision, &expected, &expected).await;
        assert_file_structure(
            &fixture,
            staged,
            "Content/Bulk",
            expected_mode,
            expected_size,
        )
        .await;
        let committed = assert_exact_commit(&fixture, "directory to file", &expected).await;
        assert_file_structure(
            &fixture,
            committed,
            "Content/Bulk",
            expected_mode,
            expected_size,
        )
        .await;
    }

    async fn undelete() {
        let fixture = StageFixture::new().await;
        let selected = fixture.nested_files("Content/Bulk");
        fixture.write_nested_files(&selected, "original");
        fixture.stage_and_commit_all("original files").await;
        std::fs::remove_dir_all(fixture.absolute("Content/Bulk")).expect("remove files");
        fixture.stage_all().await;

        fixture.write_nested_files(&selected, "restored");
        let staged_revision = fixture
            .stage(&selected, stage::StageCaseChange::Error)
            .await;
        let expected = selected.into_iter().collect();
        assert_staged_selection(&fixture, staged_revision, &expected, &expected).await;
        assert_exact_commit(&fixture, "undelete", &expected).await;
    }

    async fn case_only_directory_rename() {
        let fixture = StageFixture::new().await;
        fixture.write_file("Content/Bulk/seed.uasset", b"seed\n");
        let committed_revision = fixture.stage_and_commit_all("uppercase directory").await;
        let committed = state_at(&fixture, committed_revision).await;
        let original_link = committed
            .find_node_link(fixture.repository.clone(), "Content/Bulk")
            .await
            .expect("find original directory");

        let temporary = fixture.absolute("Content/rename-hop");
        std::fs::rename(fixture.absolute("Content/Bulk"), &temporary).expect("rename to hop");
        std::fs::rename(&temporary, fixture.absolute("Content/bulk")).expect("rename case");
        let selected = fixture.nested_files("Content/bulk");
        fixture.write_nested_files(&selected, "selected");
        let staged_revision = fixture
            .stage(&selected, stage::StageCaseChange::Rename)
            .await;
        let expected: BTreeSet<String> = selected
            .iter()
            .cloned()
            .chain(["Content/bulk/seed.uasset".to_string()])
            .collect();
        let admitted = selected.iter().cloned().collect();
        let staged = assert_staged_selection(&fixture, staged_revision, &expected, &admitted).await;
        let renamed_link = staged
            .find_node_link(fixture.repository.clone(), "Content/bulk")
            .await
            .expect("find renamed directory");
        let renamed = staged
            .node(fixture.repository.clone(), renamed_link.node)
            .await
            .expect("load renamed directory");
        assert_eq!(
            renamed_link.node, original_link.node,
            "case-only rename must preserve directory identity"
        );
        assert_eq!(
            renamed.flags, 56,
            "the shared ancestor is Dirty + StagedModify after an in-walk case rename"
        );
        let committed = assert_exact_commit(&fixture, "case-only rename", &expected).await;
        let committed_renamed = committed
            .find_node(fixture.repository.clone(), "Content/bulk")
            .await
            .expect("load committed renamed directory");
        assert_eq!(committed_renamed.flags, NodeFlags::NoFlags.bits());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 16)]
    async fn public_multi_path_stage_preserves_exact_topology_through_commit() {
        LORE_CONTEXT
            .scope(execution(false), async {
                committed_ancestor(false).await;
                undelete().await;
            })
            .await;
        LORE_CONTEXT
            .scope(execution(true), async {
                committed_ancestor(true).await;
                staged_add_ancestor().await;
                file_to_directory().await;
                directory_to_file().await;
                undelete().await;
                case_only_directory_rename().await;
            })
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 16)]
    async fn merge_resolve_theirs_preserves_flags_and_defers_content_address_until_commit() {
        LORE_CONTEXT
            .scope(execution(false), async {
                let fixture = StageFixture::new().await;
                fixture.write_file("nested/conflict.txt", b"base\n");
                let base_revision = fixture.stage_and_commit_all("base").await;

                let source_branch = fixture.create_branch("source").await;
                fixture.write_file("nested/conflict.txt", b"theirs\n");
                let source_revision = fixture.stage_and_commit_all("theirs").await;
                let source = state_at(&fixture, source_revision).await;
                let source_node = source
                    .find_node(fixture.repository.clone(), "nested/conflict.txt")
                    .await
                    .expect("load theirs node");

                fixture.switch_to(fixture.main_branch, base_revision).await;
                fixture.write_file("nested/conflict.txt", b"mine\n");
                fixture.stage_and_commit_all("mine").await;

                let unresolved_revision = branch::merge::merge_start(
                    fixture.repository.clone(),
                    &fixture.write_token,
                    source_branch,
                    branch::merge::MergeStartOptions {
                        message: "merge source".to_string(),
                        no_commit: true,
                        scope: branch::merge::MergeScope::MainOnly,
                    },
                )
                .await
                .expect("start conflicting merge");
                let unresolved = state_at(&fixture, unresolved_revision).await;
                let unresolved_node = unresolved
                    .find_node(fixture.repository.clone(), "nested/conflict.txt")
                    .await
                    .expect("load unresolved conflict");
                assert_eq!(unresolved_node.flags, 3089, "exact unresolved raw flags");

                branch::merge::merge_resolve_theirs(
                    fixture.repository.clone(),
                    &fixture.write_token,
                    LoreArray::from_vec(vec![LoreString::from(fixture.absolute("nested"))]),
                )
                .await
                .expect("resolve conflict with theirs");
                let resolved_revision =
                    lore_revision::instance::load_staged_revision(&fixture.repository)
                        .await
                        .expect("load resolved staged anchor")
                        .expect("resolved staged anchor must exist");
                let resolved = state_at(&fixture, resolved_revision).await;
                let resolved_node = resolved
                    .find_node(fixture.repository.clone(), "nested/conflict.txt")
                    .await
                    .expect("load resolved conflict");
                assert_eq!(
                    collect_files(&fixture, resolved.clone()).await,
                    BTreeSet::from(["nested/conflict.txt".to_string()]),
                    "resolved staged tree must contain exactly the conflict file"
                );
                assert_eq!(resolved_node.flags, 23601, "exact resolved raw flags");
                assert_eq!(resolved_node.size, source_node.size, "resolved theirs size");
                assert_eq!(
                    resolved_node.address, unresolved_node.address,
                    "same-type staged resolution deliberately retains the unresolved address"
                );
                assert_ne!(
                    resolved_node.address, source_node.address,
                    "theirs content address is deferred until commit re-fragments the file"
                );

                let committed_revision = fixture.commit("resolve theirs").await;
                let committed = state_at(&fixture, committed_revision).await;
                let committed_node = committed
                    .find_node(fixture.repository.clone(), "nested/conflict.txt")
                    .await
                    .expect("load committed theirs node");
                assert_eq!(committed_node.flags, 1, "exact committed raw flags");
                assert_eq!(committed_node.size, source_node.size);
                assert_eq!(committed_node.address, source_node.address);
                assert_eq!(
                    std::fs::read(fixture.absolute("nested/conflict.txt"))
                        .expect("read resolved working file"),
                    b"theirs\n"
                );
                assert_eq!(
                    collect_files(&fixture, committed).await,
                    BTreeSet::from(["nested/conflict.txt".to_string()])
                );
            })
            .await;
    }
}

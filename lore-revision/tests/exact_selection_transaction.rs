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
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use std::time::Instant;

    use lore_base::runtime::LORE_CONTEXT;
    use lore_base::runtime::runtime;
    use lore_base::types::Hash;
    use lore_revision::branch;
    use lore_revision::commit::CommitOptions;
    use lore_revision::commit::{self};
    use lore_revision::exact_selection::ExactActionRow;
    use lore_revision::exact_selection::ExactMetadataType;
    use lore_revision::exact_selection::ExactSelectionError;
    use lore_revision::exact_selection::ExactSelectionErrorKind;
    use lore_revision::exact_selection::ExactSelectionOptions;
    use lore_revision::exact_selection::ExpectedFileAction;
    use lore_revision::exact_selection::FileMetadataEntry;
    use lore_revision::exact_selection::FileMetadataSelection;
    use lore_revision::exact_selection::SelectedFile;
    use lore_revision::exact_selection::commit_exact_selection;
    use lore_revision::file;
    use lore_revision::interface::ExecutionContext;
    use lore_revision::interface::LoreArray;
    use lore_revision::interface::LoreError;
    use lore_revision::interface::LoreEvent;
    use lore_revision::interface::LoreGlobalArgs;
    use lore_revision::interface::LoreString;
    use lore_revision::lore::BranchId;
    use lore_revision::lore::RepositoryId;
    use lore_revision::metadata::Metadata;
    use lore_revision::metadata::MetadataType;
    use lore_revision::metadata::{self};
    use lore_revision::node::NodeFileMetadata;
    use lore_revision::node::NodeFileMetadataBlock;
    use lore_revision::node::NodeFlags;
    use lore_revision::node::ROOT_NODE;
    use lore_revision::node::node_to_file_metadata;
    use lore_revision::relay::EventDispatcher;
    use lore_revision::repository::RepositoryContext;
    use lore_revision::repository::RepositoryWriteToken;
    use lore_revision::repository::{self};
    use lore_revision::stage::StageCaseChange;
    use lore_revision::stage::StageOptions;
    use lore_revision::state::State;
    use lore_revision::state::StateNodeChildrenWithNameIterator;
    use lore_revision::util::path::RelativePath;
    use md5::Digest;
    use md5::Md5;

    include!("helper.rs");

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Anchors {
        current: Hash,
        staged: Option<Hash>,
        branch_latest: Hash,
    }

    struct Fixture {
        repository: Arc<RepositoryContext>,
        write_token: RepositoryWriteToken,
        root: PathBuf,
        branch: BranchId,
        _tempdir: TempDir,
    }

    impl Fixture {
        async fn new() -> Self {
            let tempdir = generate_tempdir();
            let root = tempdir.to_path_buf();
            let branch = BranchId::from(uuid::Uuid::now_v7());
            let write_token = RepositoryWriteToken::acquire(&root).await;
            let repository = repository::create_local(
                &root,
                &write_token,
                RepositoryId::from(uuid::Uuid::now_v7()),
                branch,
                branch::DEFAULT_DEFAULT_NAME.to_string(),
                repository::RepositoryConfig::default(),
                false,
            )
            .await
            .expect("initialize exact-selection repository");
            Self {
                repository,
                write_token,
                root,
                branch,
                _tempdir: tempdir,
            }
        }

        fn absolute(&self, path: &str) -> PathBuf {
            self.root.join(path)
        }

        fn write(&self, path: &str, bytes: &[u8]) {
            let absolute = self.absolute(path);
            if let Some(parent) = absolute.parent() {
                std::fs::create_dir_all(parent).expect("create fixture parent");
            }
            let mut file = std::fs::File::options()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&absolute)
                .unwrap_or_else(|error| panic!("open {}: {error}", absolute.display()));
            file.write_all(bytes)
                .unwrap_or_else(|error| panic!("write {}: {error}", absolute.display()));
        }

        async fn stage_all(&self) {
            file::stage::stage(
                self.repository.clone(),
                &self.write_token,
                LoreArray::from_vec(vec![LoreString::from(&self.root)]),
                StageOptions {
                    case_change: StageCaseChange::Error,
                    node_flags: NodeFlags::NoFlags,
                    file_id: None,
                    no_children: false,
                    scan: true,
                },
            )
            .await
            .expect("stage fixture repository");
        }

        async fn seed_commit(&self, message: &str) -> Hash {
            self.stage_all().await;
            Box::pin(commit::commit(
                self.repository.clone(),
                &self.write_token,
                CommitOptions::new(message.to_string()),
            ))
            .await
            .expect("commit fixture baseline")
        }

        async fn exact(
            &self,
            message: &str,
            files: Vec<SelectedFile>,
        ) -> Result<lore_revision::exact_selection::ExactSelectionResult, ExactSelectionError>
        {
            commit_exact_selection(
                self.repository.clone(),
                &self.write_token,
                ExactSelectionOptions {
                    message: message.to_string(),
                    files,
                    revision_metadata: Vec::new(),
                    stats: false,
                },
            )
            .await
        }

        async fn anchors(&self) -> Anchors {
            Anchors {
                current: lore_revision::instance::load_current_anchor(&self.repository)
                    .await
                    .expect("load current anchor")
                    .0,
                staged: lore_revision::instance::load_staged_revision(&self.repository)
                    .await
                    .expect("load staged anchor"),
                branch_latest: branch::load_latest_history(
                    self.repository.clone(),
                    self.branch,
                    None,
                )
                .await
                .expect("load branch latest")
                .revision,
            }
        }
    }

    fn execution() -> Arc<ExecutionContext> {
        Arc::new(ExecutionContext::new_client_with_user_id(
            LoreGlobalArgs::default().set_offline(),
            EventDispatcher::no_dispatch(),
            "exact-selection-test".to_string(),
        ))
    }

    fn execution_with_callback(
        callback: impl Fn(&LoreEvent) + Send + Sync + 'static,
    ) -> Arc<ExecutionContext> {
        Arc::new(ExecutionContext::new_client_with_user_id(
            LoreGlobalArgs::default().set_offline(),
            EventDispatcher::new(Some(Box::new(callback))),
            "exact-selection-callback-test".to_string(),
        ))
    }

    fn digest(bytes: &[u8]) -> String {
        hex::encode(Md5::digest(bytes))
    }

    fn selected(path: &str, action: ExpectedFileAction, bytes: Option<&[u8]>) -> SelectedFile {
        SelectedFile {
            path: path.to_string(),
            expected_effective_action: action,
            source_hash: bytes.map(digest),
            file_metadata: FileMetadataSelection::Unchanged,
        }
    }

    fn row(path: &str, action: ExpectedFileAction) -> ExactActionRow {
        ExactActionRow {
            path: path.to_string(),
            action,
        }
    }

    async fn collect_files(fixture: &Fixture, state: Arc<State>) -> BTreeSet<String> {
        let mut files = BTreeSet::new();
        let mut directories = VecDeque::from([(String::new(), ROOT_NODE)]);
        while let Some((parent_path, parent_id)) = directories.pop_front() {
            let mut children = StateNodeChildrenWithNameIterator::new(
                state.clone(),
                fixture.repository.clone(),
                parent_id,
            )
            .await
            .expect("iterate committed directory");
            while let Some((child_id, child, name)) =
                children.next().await.expect("load committed child")
            {
                if child.is_staged_delete() || child.is_discarded() {
                    continue;
                }
                let path = if parent_path.is_empty() {
                    name.freeze().to_string()
                } else {
                    format!("{parent_path}/{}", name.freeze())
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

    async fn committed_bytes(fixture: &Fixture, revision: Hash, path: &str) -> Vec<u8> {
        let state = State::deserialize(fixture.repository.clone(), revision)
            .await
            .expect("deserialize exact committed state");
        let node = state
            .find_node(fixture.repository.clone(), path)
            .await
            .unwrap_or_else(|error| panic!("find committed {path}: {error}"));
        lore_revision::immutable::read(
            fixture.repository.clone(),
            node.address,
            None,
            lore_revision::immutable::read_options_from_repository(&fixture.repository).no_remote(),
        )
        .await
        .unwrap_or_else(|error| panic!("materialize committed {path}: {error}"))
        .to_vec()
    }

    async fn file_metadata_at(
        fixture: &Fixture,
        revision: Hash,
        path: &str,
    ) -> Option<(Hash, Metadata)> {
        let state = State::deserialize(fixture.repository.clone(), revision)
            .await
            .expect("deserialize exact metadata state");
        let relative = RelativePath::new_from_user_path(
            &fixture.root,
            fixture.absolute(path).to_string_lossy().as_ref(),
        )
        .expect("normalize metadata path");
        let link = state
            .find_node_link(fixture.repository.clone(), relative.as_str())
            .await
            .expect("find exact metadata node");
        if !link.is_valid() {
            return None;
        }
        let metadata_node = node_to_file_metadata(link.node);
        let block = state
            .block_file_metadata(
                fixture.repository.clone(),
                NodeFileMetadataBlock::index(metadata_node),
            )
            .await
            .expect("read exact metadata block");
        let hash = block
            .read()
            .node(NodeFileMetadata::index(metadata_node))
            .metadata;
        if hash.is_zero() {
            None
        } else {
            let metadata = Metadata::deserialize(fixture.repository.clone(), hash)
                .await
                .expect("deserialize exact file metadata");
            Some((hash, metadata))
        }
    }

    async fn assert_rejection_preserves_anchors(
        fixture: &Fixture,
        files: Vec<SelectedFile>,
        expected: impl FnOnce(&ExactSelectionErrorKind) -> bool,
    ) {
        let before = fixture.anchors().await;
        let error = fixture
            .exact("must reject", files)
            .await
            .expect_err("exact-selection case must reject");
        assert!(expected(error.kind()), "unexpected exact error: {error:?}");
        assert_eq!(fixture.anchors().await, before);
    }

    #[test]
    fn validation_mismatch_errors_use_invalid_arguments_code() {
        let errors = [
            ExactSelectionError::new(ExactSelectionErrorKind::GeneratedSelectionMismatch {
                expected: Vec::new(),
                actual: Vec::new(),
                missing: Vec::new(),
                extras: Vec::new(),
                action_mismatches: Vec::new(),
            }),
            ExactSelectionError::new(ExactSelectionErrorKind::SemanticSelectionMismatch {
                expected: Vec::new(),
                actual: Vec::new(),
                missing: Vec::new(),
                extras: Vec::new(),
                action_mismatches: Vec::new(),
            }),
            ExactSelectionError::new(ExactSelectionErrorKind::UnselectedFileMetadata {
                paths: vec!["unselected.bin".to_string()],
            }),
            ExactSelectionError::new(ExactSelectionErrorKind::StagedMetadataHashMismatch {
                mismatches: Vec::new(),
            }),
            ExactSelectionError::new(ExactSelectionErrorKind::SourceHashMismatch {
                mismatches: Vec::new(),
            }),
        ];

        for error in errors {
            assert_eq!(error.code(), LoreError::InvalidArguments as i32);
        }
    }

    #[test]
    fn publication_failure_carries_restoration_state_and_uses_internal_code() {
        for anchors_restored in [true, false] {
            let error = ExactSelectionError::new(ExactSelectionErrorKind::PublicationFailure {
                anchors_restored,
                reason: "injected publication failure".to_string(),
            });

            assert!(
                matches!(
                    error.kind(),
                    ExactSelectionErrorKind::PublicationFailure {
                        anchors_restored: actual,
                        reason,
                    } if *actual == anchors_restored && reason == "injected publication failure"
                ),
                "publication failure lost anchors_restored={anchors_restored}: {error:?}"
            );
            assert_eq!(error.code(), LoreError::Internal as i32);
        }
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn drive_relative_path_rejects_as_path_normalization() {
        LORE_CONTEXT
            .scope(execution(), async {
                let fixture = Fixture::new().await;
                let error = fixture
                    .exact(
                        "drive-relative path",
                        vec![selected("C:x", ExpectedFileAction::Add, Some(b"x"))],
                    )
                    .await
                    .expect_err("drive-relative Windows path must reject");

                assert!(
                    matches!(
                        error.kind(),
                        ExactSelectionErrorKind::PathNormalization { path, .. } if path == "C:x"
                    ),
                    "unexpected drive-relative path error: {error:?}"
                );
                assert_eq!(error.code(), LoreError::InvalidArguments as i32);
            })
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 16)]
    async fn admits_exact_mixed_actions_and_rename_then_deserializes_published_state() {
        LORE_CONTEXT
            .scope(execution(), async {
                let fixture = Fixture::new().await;
                fixture.write("stable.txt", b"stable-before\n");
                fixture.write("same-size.bin", b"AAAA");
                fixture.write("delete.txt", b"delete me\n");
                fixture.write("old-name.txt", b"rename payload\n");
                fixture.seed_commit("baseline").await;

                let stable = b"stable-after-with-a-different-size\n";
                let same_size = b"BBBB";
                let added = b"new payload\n";
                fixture.write("stable.txt", stable);
                fixture.write("same-size.bin", same_size);
                fixture.write("add.txt", added);
                std::fs::remove_file(fixture.absolute("delete.txt")).expect("delete tracked file");
                std::fs::rename(
                    fixture.absolute("old-name.txt"),
                    fixture.absolute("new-name.txt"),
                )
                .expect("rename tracked file");

                let result = fixture
                    .exact(
                        "mixed exact transaction",
                        vec![
                            selected("stable.txt", ExpectedFileAction::Modify, Some(stable)),
                            selected("same-size.bin", ExpectedFileAction::Modify, Some(same_size)),
                            selected("add.txt", ExpectedFileAction::Add, Some(added)),
                            selected("delete.txt", ExpectedFileAction::Delete, None),
                            selected("old-name.txt", ExpectedFileAction::Delete, None),
                            selected(
                                "new-name.txt",
                                ExpectedFileAction::Add,
                                Some(b"rename payload\n"),
                            ),
                        ],
                    )
                    .await
                    .expect("admit exact mixed transaction");

                let expected_actions = vec![
                    row("add.txt", ExpectedFileAction::Add),
                    row("delete.txt", ExpectedFileAction::Delete),
                    row("new-name.txt", ExpectedFileAction::Add),
                    row("old-name.txt", ExpectedFileAction::Delete),
                    row("same-size.bin", ExpectedFileAction::Modify),
                    row("stable.txt", ExpectedFileAction::Modify),
                ];
                assert_eq!(result.generated_actions, expected_actions);
                assert_eq!(result.effective_actions, expected_actions);

                let anchors = fixture.anchors().await;
                assert_eq!(anchors.current, result.revision);
                assert_eq!(anchors.branch_latest, result.revision);
                assert_eq!(anchors.staged, None);
                let committed = State::deserialize(fixture.repository.clone(), result.revision)
                    .await
                    .expect("deserialize exact published revision");
                assert_eq!(
                    collect_files(&fixture, committed).await,
                    BTreeSet::from([
                        "add.txt".to_string(),
                        "new-name.txt".to_string(),
                        "same-size.bin".to_string(),
                        "stable.txt".to_string(),
                    ])
                );
                assert_eq!(
                    committed_bytes(&fixture, result.revision, "stable.txt").await,
                    stable
                );
                assert_eq!(
                    committed_bytes(&fixture, result.revision, "same-size.bin").await,
                    same_size
                );
                assert_eq!(
                    committed_bytes(&fixture, result.revision, "new-name.txt").await,
                    b"rename payload\n"
                );
            })
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 16)]
    async fn rejects_public_input_and_semantic_mismatches_without_publishing_anchors() {
        LORE_CONTEXT
            .scope(execution(), async {
                let fixture = Fixture::new().await;
                let original = b"original bytes\n";
                fixture.write("tracked.txt", original);
                fixture.write("delete.txt", b"delete bytes\n");
                fixture.seed_commit("baseline").await;
                let original_mtime = std::fs::metadata(fixture.absolute("tracked.txt"))
                    .expect("read baseline metadata")
                    .modified()
                    .expect("read baseline mtime");

                fixture.write("tracked.txt", b"changed bytes!\n");
                assert_rejection_preserves_anchors(
                    &fixture,
                    vec![selected(
                        "tracked.txt",
                        ExpectedFileAction::Delete,
                        None,
                    )],
                    |kind| matches!(kind, ExactSelectionErrorKind::GeneratedSelectionMismatch { action_mismatches, .. } if action_mismatches.len() == 1),
                )
                .await;

                fixture.write("tracked.txt", original);
                assert_rejection_preserves_anchors(
                    &fixture,
                    vec![selected(
                        "tracked.txt",
                        ExpectedFileAction::Modify,
                        Some(original),
                    )],
                    |kind| matches!(kind, ExactSelectionErrorKind::GeneratedSelectionMismatch { missing, .. } if missing == &vec![row("tracked.txt", ExpectedFileAction::Modify)]),
                )
                .await;

                fixture.write("tracked.txt", b"same-size-drift");
                let file = std::fs::File::options()
                    .write(true)
                    .open(fixture.absolute("tracked.txt"))
                    .expect("open drifted fixture");
                file.set_times(std::fs::FileTimes::new().set_modified(original_mtime))
                    .expect("restore drifted fixture mtime");
                assert_rejection_preserves_anchors(
                    &fixture,
                    vec![selected(
                        "tracked.txt",
                        ExpectedFileAction::Modify,
                        Some(original),
                    )],
                    |kind| matches!(kind, ExactSelectionErrorKind::SourceHashMismatch { mismatches } if mismatches.len() == 1 && mismatches[0].path == "tracked.txt"),
                )
                .await;

                assert_rejection_preserves_anchors(
                    &fixture,
                    vec![SelectedFile {
                        path: "delete.txt".to_string(),
                        expected_effective_action: ExpectedFileAction::Delete,
                        source_hash: Some(digest(b"delete bytes\n")),
                        file_metadata: FileMetadataSelection::Unchanged,
                    }],
                    |kind| matches!(kind, ExactSelectionErrorKind::UnexpectedContentDigest { path } if path == "delete.txt"),
                )
                .await;

                assert_rejection_preserves_anchors(
                    &fixture,
                    vec![SelectedFile {
                        path: "tracked.txt".to_string(),
                        expected_effective_action: ExpectedFileAction::Modify,
                        source_hash: Some("ABC-not-lowercase-md5".to_string()),
                        file_metadata: FileMetadataSelection::Unchanged,
                    }],
                    |kind| matches!(kind, ExactSelectionErrorKind::MalformedSourceHash { path, .. } if path == "tracked.txt"),
                )
                .await;

                assert_rejection_preserves_anchors(
                    &fixture,
                    vec![SelectedFile {
                        path: "tracked.txt".to_string(),
                        expected_effective_action: ExpectedFileAction::Modify,
                        source_hash: None,
                        file_metadata: FileMetadataSelection::Unchanged,
                    }],
                    |kind| matches!(kind, ExactSelectionErrorKind::MalformedSourceHash { path, value } if path == "tracked.txt" && value.is_empty()),
                )
                .await;

                let duplicate = selected(
                    "tracked.txt",
                    ExpectedFileAction::Modify,
                    Some(b"same-size-drift"),
                );
                let mut conflicting = duplicate.clone();
                conflicting.source_hash = Some(digest(b"different"));
                assert_rejection_preserves_anchors(
                    &fixture,
                    vec![duplicate, conflicting],
                    |kind| matches!(kind, ExactSelectionErrorKind::InvalidInput { paths, .. } if paths == &vec!["tracked.txt".to_string()]),
                )
                .await;
            })
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 16)]
    async fn repairs_unselected_staged_content_and_metadata_before_exact_commit() {
        LORE_CONTEXT
            .scope(execution(), async {
                let fixture = Fixture::new().await;
                let selected_baseline = b"selected baseline\n";
                let unrelated_baseline = b"unrelated baseline\n";
                fixture.write("selected.bin", selected_baseline);
                fixture.write("unrelated.bin", unrelated_baseline);
                fixture.seed_commit("baseline").await;
                let selected_modified = b"selected modified\n";
                let unrelated_modified = b"unrelated modified\n";
                fixture.write("selected.bin", selected_modified);
                fixture.write("unrelated.bin", unrelated_modified);
                fixture.stage_all().await;
                let unrelated_path = fixture.absolute("unrelated.bin");
                metadata::set::set_file(
                    fixture.repository.clone(),
                    &fixture.write_token,
                    &[unrelated_path.to_string_lossy().as_ref()],
                    &[b"unselected"],
                    &[b"must not ride"],
                    &[MetadataType::String],
                    &[1],
                )
                .await
                .expect("stage unrelated metadata before repair");
                let staged_revision = fixture
                    .anchors()
                    .await
                    .staged
                    .expect("pre-transaction staged anchor");
                let staged = State::deserialize(fixture.repository.clone(), staged_revision)
                    .await
                    .expect("deserialize pre-transaction staged state");
                assert!(
                    staged
                        .find_node(fixture.repository.clone(), "unrelated.bin")
                        .await
                        .expect("find unrelated staged row")
                        .is_staged(),
                    "fixture must prove unrelated content was staged before repair"
                );

                let result = fixture
                    .exact(
                        "repair unrelated staged state",
                        vec![selected(
                            "selected.bin",
                            ExpectedFileAction::Modify,
                            Some(selected_modified),
                        )],
                    )
                    .await
                    .expect("commit exact selection after staged repair");

                assert_eq!(
                    result.generated_actions,
                    vec![row("selected.bin", ExpectedFileAction::Modify)]
                );
                assert_eq!(
                    committed_bytes(&fixture, result.revision, "selected.bin").await,
                    selected_modified
                );
                assert_eq!(
                    committed_bytes(&fixture, result.revision, "unrelated.bin").await,
                    unrelated_baseline
                );
                assert!(
                    file_metadata_at(&fixture, result.revision, "unrelated.bin")
                        .await
                        .is_none(),
                    "unselected staged metadata must not ride into exact commit"
                );
                assert_eq!(fixture.anchors().await.staged, None);
            })
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 16)]
    async fn unchanged_modify_metadata_inherits_committed_not_abandoned_staged_state() {
        LORE_CONTEXT
            .scope(execution(), async {
                let fixture = Fixture::new().await;
                fixture.write("tracked.bin", b"baseline\n");
                fixture.stage_all().await;
                let tracked_path = fixture.absolute("tracked.bin");
                metadata::set::set_file(
                    fixture.repository.clone(),
                    &fixture.write_token,
                    &[tracked_path.to_string_lossy().as_ref()],
                    &[b"owner"],
                    &[b"committed"],
                    &[MetadataType::String],
                    &[1],
                )
                .await
                .expect("seed committed file metadata");
                let baseline = Box::pin(commit::commit(
                    fixture.repository.clone(),
                    &fixture.write_token,
                    CommitOptions::new("metadata baseline".to_string()),
                ))
                .await
                .expect("commit metadata baseline");
                let (committed_hash, committed_metadata) =
                    file_metadata_at(&fixture, baseline, "tracked.bin")
                        .await
                        .expect("load committed metadata");
                assert_eq!(
                    committed_metadata
                        .get_string("owner")
                        .expect("committed owner metadata"),
                    "committed"
                );

                metadata::set::set_file(
                    fixture.repository.clone(),
                    &fixture.write_token,
                    &[tracked_path.to_string_lossy().as_ref()],
                    &[b"owner"],
                    &[b"abandoned-staged"],
                    &[MetadataType::String],
                    &[1],
                )
                .await
                .expect("stage abandoned file metadata");
                let abandoned_revision = fixture
                    .anchors()
                    .await
                    .staged
                    .expect("abandoned metadata must publish a staged anchor");
                let (abandoned_hash, abandoned_metadata) =
                    file_metadata_at(&fixture, abandoned_revision, "tracked.bin")
                        .await
                        .expect("load abandoned staged metadata");
                assert_ne!(abandoned_hash, committed_hash);
                assert_eq!(
                    abandoned_metadata
                        .get_string("owner")
                        .expect("abandoned owner metadata"),
                    "abandoned-staged"
                );

                let modified = b"modified\n";
                fixture.write("tracked.bin", modified);
                let result = fixture
                    .exact(
                        "inherit committed metadata",
                        vec![selected(
                            "tracked.bin",
                            ExpectedFileAction::Modify,
                            Some(modified),
                        )],
                    )
                    .await
                    .expect("commit Modify with unchanged metadata");

                let (published_hash, published_metadata) =
                    file_metadata_at(&fixture, result.revision, "tracked.bin")
                        .await
                        .expect("load published inherited metadata");
                assert_eq!(published_hash, committed_hash);
                assert_eq!(
                    published_metadata
                        .get_string("owner")
                        .expect("published owner metadata"),
                    "committed"
                );
                assert_eq!(fixture.anchors().await.staged, None);
            })
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 16)]
    async fn admits_exact_add_modify_clear_mixed_metadata_and_preserves_delete_inheritance() {
        LORE_CONTEXT
            .scope(execution(), async {
                let fixture = Fixture::new().await;
                for path in ["modify.bin", "clear.bin", "delete.bin", "unchanged.bin"] {
                    fixture.write(path, format!("baseline:{path}\n").as_bytes());
                }
                fixture.stage_all().await;
                let metadata_paths: Vec<_> = ["modify.bin", "clear.bin", "delete.bin"]
                    .iter()
                    .map(|path| fixture.absolute(path).to_string_lossy().into_owned())
                    .collect();
                metadata::set::set_file(
                    fixture.repository.clone(),
                    &fixture.write_token,
                    &metadata_paths
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                    &[b"prior", b"prior", b"prior"],
                    &[b"modify", b"clear", b"delete"],
                    &[
                        MetadataType::String,
                        MetadataType::String,
                        MetadataType::String,
                    ],
                    &[1, 1, 1],
                )
                .await
                .expect("seed baseline file metadata");
                let baseline = Box::pin(commit::commit(
                    fixture.repository.clone(),
                    &fixture.write_token,
                    CommitOptions::new("metadata baseline".to_string()),
                ))
                .await
                .expect("commit metadata baseline");
                let (delete_metadata_hash, _) = file_metadata_at(&fixture, baseline, "delete.bin")
                    .await
                    .expect("delete baseline metadata");

                let modify = b"modified owner bytes\n";
                let clear = b"clear owner bytes\n";
                let unchanged = b"unchanged metadata owner bytes\n";
                let added = b"added owner bytes\n";
                fixture.write("modify.bin", modify);
                fixture.write("clear.bin", clear);
                fixture.write("unchanged.bin", unchanged);
                fixture.write("add.bin", added);
                std::fs::remove_file(fixture.absolute("delete.bin"))
                    .expect("remove metadata-bearing file");
                let binary_payload = b"\x00exact audit payload\xff";
                fixture.write("audit-source.bin", binary_payload);

                let result = fixture
                    .exact(
                        "exact metadata transaction",
                        vec![
                            SelectedFile {
                                path: "modify.bin".to_string(),
                                expected_effective_action: ExpectedFileAction::Modify,
                                source_hash: Some(digest(modify)),
                                file_metadata: FileMetadataSelection::Exact(vec![
                                    FileMetadataEntry {
                                        key: "kind".to_string(),
                                        value: "Actor".to_string(),
                                        value_type: ExactMetadataType::String,
                                    },
                                    FileMetadataEntry {
                                        key: "audit".to_string(),
                                        value: "audit-source.bin".to_string(),
                                        value_type: ExactMetadataType::Binary,
                                    },
                                ]),
                            },
                            SelectedFile {
                                path: "add.bin".to_string(),
                                expected_effective_action: ExpectedFileAction::Add,
                                source_hash: Some(digest(added)),
                                file_metadata: FileMetadataSelection::Exact(vec![
                                    FileMetadataEntry {
                                        key: "count".to_string(),
                                        value: "7".to_string(),
                                        value_type: ExactMetadataType::Numeric,
                                    },
                                ]),
                            },
                            SelectedFile {
                                path: "clear.bin".to_string(),
                                expected_effective_action: ExpectedFileAction::Modify,
                                source_hash: Some(digest(clear)),
                                file_metadata: FileMetadataSelection::Clear,
                            },
                            selected("unchanged.bin", ExpectedFileAction::Modify, Some(unchanged)),
                            selected("delete.bin", ExpectedFileAction::Delete, None),
                        ],
                    )
                    .await
                    .expect("admit exact metadata transaction");

                let (_, modify_metadata) =
                    file_metadata_at(&fixture, result.revision, "modify.bin")
                        .await
                        .expect("committed modify metadata");
                assert_eq!(
                    modify_metadata.get_string("kind").expect("kind metadata"),
                    "Actor"
                );
                let audit_address = modify_metadata
                    .get_address("audit")
                    .expect("audit metadata address");
                let audit_bytes = lore_revision::immutable::read(
                    fixture.repository.clone(),
                    audit_address,
                    None,
                    lore_revision::immutable::read_options_from_repository(&fixture.repository)
                        .no_remote(),
                )
                .await
                .expect("materialize exact audit metadata");
                assert_eq!(audit_bytes.as_ref(), binary_payload);

                let (_, add_metadata) = file_metadata_at(&fixture, result.revision, "add.bin")
                    .await
                    .expect("committed add metadata");
                assert_eq!(add_metadata.get_u64("count").expect("numeric metadata"), 7);
                assert!(
                    file_metadata_at(&fixture, result.revision, "clear.bin")
                        .await
                        .is_none(),
                    "Clear must commit a zero file-metadata hash"
                );
                assert!(
                    result
                        .committed_file_metadata_hashes
                        .iter()
                        .any(|item| item.path == "delete.bin"
                            && item.hash == delete_metadata_hash.to_string()),
                    "Delete must report the inherited prior metadata hash"
                );
            })
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 16)]
    async fn rejects_duplicate_metadata_keys_and_missing_binary_source_without_publishing() {
        LORE_CONTEXT
            .scope(execution(), async {
                let fixture = Fixture::new().await;
                let modified = b"modified\n";
                fixture.write("tracked.bin", b"baseline\n");
                fixture.seed_commit("baseline").await;
                fixture.write("tracked.bin", modified);

                let duplicate_entries = vec![
                    FileMetadataEntry {
                        key: "audit".to_string(),
                        value: "first".to_string(),
                        value_type: ExactMetadataType::String,
                    },
                    FileMetadataEntry {
                        key: "audit".to_string(),
                        value: "second".to_string(),
                        value_type: ExactMetadataType::String,
                    },
                ];
                assert_rejection_preserves_anchors(
                    &fixture,
                    vec![SelectedFile {
                        path: "tracked.bin".to_string(),
                        expected_effective_action: ExpectedFileAction::Modify,
                        source_hash: Some(digest(modified)),
                        file_metadata: FileMetadataSelection::Exact(duplicate_entries),
                    }],
                    |kind| matches!(kind, ExactSelectionErrorKind::DuplicateMetadataKey { path, key } if path == "tracked.bin" && key == "audit"),
                )
                .await;

                assert_rejection_preserves_anchors(
                    &fixture,
                    vec![SelectedFile {
                        path: "tracked.bin".to_string(),
                        expected_effective_action: ExpectedFileAction::Modify,
                        source_hash: Some(digest(modified)),
                        file_metadata: FileMetadataSelection::Exact(vec![FileMetadataEntry {
                            key: "audit".to_string(),
                            value: "missing-audit.bin".to_string(),
                            value_type: ExactMetadataType::Binary,
                        }]),
                    }],
                    |kind| matches!(kind, ExactSelectionErrorKind::MetadataInputRead { path, key, .. } if path == "tracked.bin" && key == "audit"),
                )
                .await;
            })
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn equivalent_duplicate_normalized_path_rejects_before_binary_metadata_source_io() {
        LORE_CONTEXT
            .scope(execution(), async {
                let fixture = Fixture::new().await;
                let modified = b"modified\n";
                fixture.write("tracked.bin", b"baseline\n");
                fixture.seed_commit("baseline").await;
                fixture.write("tracked.bin", modified);
                let with_missing_binary = |path: &str| SelectedFile {
                    path: path.to_string(),
                    expected_effective_action: ExpectedFileAction::Modify,
                    source_hash: Some(digest(modified)),
                    file_metadata: FileMetadataSelection::Exact(vec![FileMetadataEntry {
                        key: "audit".to_string(),
                        value: "missing-duplicate-audit.bin".to_string(),
                        value_type: ExactMetadataType::Binary,
                    }]),
                };
                let before = fixture.anchors().await;

                let error = fixture
                    .exact(
                        "duplicate normalized path",
                        vec![
                            with_missing_binary("tracked.bin"),
                            with_missing_binary("./tracked.bin"),
                        ],
                    )
                    .await
                    .expect_err("equivalent duplicate normalized path must reject");

                assert!(
                    matches!(
                        error.kind(),
                        ExactSelectionErrorKind::InvalidInput { reason, paths }
                            if reason == "duplicate selected path"
                                && paths == &vec!["tracked.bin".to_string()]
                    ),
                    "duplicate detection must precede binary metadata source I/O: {error:?}"
                );
                assert_eq!(error.code(), LoreError::InvalidArguments as i32);
                assert_eq!(fixture.anchors().await, before);
            })
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rejects_input_bounds_before_reading_binary_metadata_sources() {
        LORE_CONTEXT
            .scope(execution(), async {
                let fixture = Fixture::new().await;
                let payload = b"bounded input\n";
                fixture.write("baseline.bin", b"baseline\n");
                fixture.seed_commit("baseline").await;
                fixture.write("bounded.bin", payload);
                let mut file = selected("bounded.bin", ExpectedFileAction::Add, Some(payload));
                file.file_metadata = FileMetadataSelection::Exact(vec![
                    FileMetadataEntry {
                        key: "missing-binary".to_string(),
                        value: "does-not-exist.bin".to_string(),
                        value_type: ExactMetadataType::Binary,
                    },
                    FileMetadataEntry {
                        key: "oversized".to_string(),
                        value: "x".repeat(4 * 1_024 * 1_024 + 1),
                        value_type: ExactMetadataType::String,
                    },
                ]);

                assert_rejection_preserves_anchors(&fixture, vec![file], |kind| {
                    matches!(
                        kind,
                        ExactSelectionErrorKind::InvalidInput { reason, .. }
                            if reason.contains("metadata value exceeds limit")
                    )
                })
                .await;
            })
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 16)]
    async fn mixed_source_hash_rejection_reports_only_bad_path_and_preserves_anchors() {
        LORE_CONTEXT
            .scope(execution(), async {
                let fixture = Fixture::new().await;
                fixture.write("good.bin", b"good baseline\n");
                fixture.write("bad.bin", b"bad baseline\n");
                fixture.seed_commit("baseline").await;
                let good = b"good modified\n";
                let bad = b"bad modified\n";
                fixture.write("good.bin", good);
                fixture.write("bad.bin", bad);

                assert_rejection_preserves_anchors(
                    &fixture,
                    vec![
                        selected("good.bin", ExpectedFileAction::Modify, Some(good)),
                        selected(
                            "bad.bin",
                            ExpectedFileAction::Modify,
                            Some(b"stale producer bytes\n"),
                        ),
                    ],
                    |kind| matches!(kind, ExactSelectionErrorKind::SourceHashMismatch { mismatches } if mismatches.len() == 1 && mismatches[0].path == "bad.bin"),
                )
                .await;
            })
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn vanished_add_after_stage_rejects_before_fragmentation_and_preserves_anchors() {
        LORE_CONTEXT
            .scope(execution(), async {
                let fixture = Fixture::new().await;
                fixture.write("seed.bin", b"seed\n");
                fixture.seed_commit("baseline").await;
                let added = b"vanishing add\n";
                fixture.write("vanish.bin", added);
                let before = fixture.anchors().await;
                let vanished = Arc::new(AtomicBool::new(false));
                let callback_vanished = vanished.clone();
                let vanish_path = fixture.absolute("vanish.bin");
                let callback_execution = execution_with_callback(move |event| {
                    if matches!(event, LoreEvent::FileStageEnd(_))
                        && !callback_vanished.swap(true, Ordering::SeqCst)
                    {
                        std::fs::remove_file(&vanish_path)
                            .expect("remove Add from FileStageEnd callback");
                    }
                });

                let error = LORE_CONTEXT
                    .scope(callback_execution, async {
                        fixture
                            .exact(
                                "vanished Add",
                                vec![selected(
                                    "vanish.bin",
                                    ExpectedFileAction::Add,
                                    Some(added),
                                )],
                            )
                            .await
                    })
                    .await
                    .expect_err("Add removed after staging must reject");

                assert!(vanished.load(Ordering::SeqCst), "FileStageEnd callback did not run");
                assert!(
                    matches!(error.kind(), ExactSelectionErrorKind::PreFragmentationFileRead { path, .. } if path == "vanish.bin"),
                    "unexpected vanished-Add error: {error:?}"
                );
                assert_eq!(fixture.anchors().await, before);
            })
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn filesystem_mutation_after_fragment_capture_cannot_change_committed_bytes() {
        LORE_CONTEXT
            .scope(execution(), async {
                let fixture = Fixture::new().await;
                fixture.write("tracked.bin", b"baseline\n");
                fixture.seed_commit("baseline").await;
                let captured = vec![b'A'; 3_200];
                let later = vec![b'B'; 3_200];
                fixture.write("tracked.bin", &captured);
                let mutated = Arc::new(AtomicBool::new(false));
                let callback_mutated = mutated.clone();
                let mutation_path = fixture.absolute("tracked.bin");
                let later_for_callback = later.clone();
                let callback_execution = execution_with_callback(move |event| {
                    if matches!(event, LoreEvent::FragmentWrite(_))
                        && !callback_mutated.swap(true, Ordering::SeqCst)
                    {
                        std::fs::write(&mutation_path, &later_for_callback)
                            .expect("mutate working file after FragmentWrite");
                    }
                });

                let result = LORE_CONTEXT
                    .scope(callback_execution, async {
                        commit_exact_selection(
                            fixture.repository.clone(),
                            &fixture.write_token,
                            ExactSelectionOptions {
                                message: "captured immutable bytes".to_string(),
                                files: vec![selected(
                                    "tracked.bin",
                                    ExpectedFileAction::Modify,
                                    Some(&captured),
                                )],
                                revision_metadata: Vec::new(),
                                stats: true,
                            },
                        )
                        .await
                    })
                    .await
                    .expect("post-capture filesystem mutation must not alter admission");

                assert!(
                    mutated.load(Ordering::SeqCst),
                    "FragmentWrite callback did not run"
                );
                assert_eq!(
                    std::fs::read(fixture.absolute("tracked.bin"))
                        .expect("read later working bytes"),
                    later
                );
                assert_eq!(
                    committed_bytes(&fixture, result.revision, "tracked.bin").await,
                    captured
                );
            })
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 16)]
    #[ignore = "descriptive performance measurement; run explicitly with --ignored --nocapture"]
    async fn measures_validation_only_reread_and_md5_at_actor_sized_100_and_1000_files() {
        LORE_CONTEXT
            .scope(execution(), async {
                for file_count in [100_usize, 1_000] {
                    let fixture = Fixture::new().await;
                    let mut files = Vec::with_capacity(file_count);
                    let mut expected_digests = Vec::with_capacity(file_count);
                    for index in 0..file_count {
                        let path = format!("Actors/actor-{index:04}.uasset");
                        let mut bytes = vec![b'A'; 3_200];
                        bytes[..8].copy_from_slice(&(index as u64).to_le_bytes());
                        fixture.write(&path, &bytes);
                        expected_digests.push((path.clone(), digest(&bytes)));
                        files.push(selected(&path, ExpectedFileAction::Add, Some(&bytes)));
                    }
                    let result = fixture
                        .exact("actor-sized performance fixture", files)
                        .await
                        .expect("commit actor-sized performance fixture");
                    let state = State::deserialize(fixture.repository.clone(), result.revision)
                        .await
                        .expect("deserialize post-rehash performance state");

                    let started = Instant::now();
                    for (path, expected_digest) in &expected_digests {
                        let node = state
                            .find_node(fixture.repository.clone(), path)
                            .await
                            .unwrap_or_else(|error| panic!("find performance row {path}: {error}"));
                        let payload = lore_revision::immutable::read(
                            fixture.repository.clone(),
                            node.address,
                            None,
                            lore_revision::immutable::read_options_from_repository(
                                &fixture.repository,
                            )
                            .with_cache(),
                        )
                        .await
                        .unwrap_or_else(|error| {
                            panic!("reread performance row {path}: {error}")
                        });
                        assert_eq!(digest(&payload), *expected_digest);
                    }
                    let elapsed = started.elapsed();
                    eprintln!(
                        "exact-selection validation-only reread+md5 files={file_count} elapsed_us={}",
                        elapsed.as_micros()
                    );
                }
            })
            .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn competing_client_writer_waits_for_transaction_token_release() {
        LORE_CONTEXT
            .scope(execution(), async {
                let fixture = Fixture::new().await;
                fixture.write("tracked.bin", b"baseline\n");
                fixture.seed_commit("baseline").await;
                let modified = b"modified\n";
                fixture.write("tracked.bin", modified);

                let competing_root = fixture.root.clone();
                let mut competing = runtime()
                    .spawn(async move { RepositoryWriteToken::acquire(&competing_root).await });
                assert!(
                    tokio::time::timeout(Duration::from_millis(50), &mut competing)
                        .await
                        .is_err(),
                    "competing CLIENT writer acquired while transaction token was held"
                );

                fixture
                    .exact(
                        "token-held transaction",
                        vec![selected(
                            "tracked.bin",
                            ExpectedFileAction::Modify,
                            Some(modified),
                        )],
                    )
                    .await
                    .expect("commit while holding caller token");
                let Fixture {
                    repository,
                    write_token,
                    _tempdir,
                    ..
                } = fixture;
                drop(write_token);
                drop(repository);

                let competing_token = tokio::time::timeout(Duration::from_secs(1), &mut competing)
                    .await
                    .expect("competing CLIENT writer remained blocked after token release")
                    .expect("competing token task failed");
                drop(competing_token);
            })
            .await;
    }
}

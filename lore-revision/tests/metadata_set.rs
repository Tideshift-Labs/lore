// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Khurram Virani
// SPDX-License-Identifier: MIT
#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)] // Test fixture writes; not subject to repository write-token discipline.

    use std::collections::HashMap;
    use std::io::Write;
    use std::path::Path;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use lore_base::error::NoRemote;
    use lore_base::runtime::LORE_CONTEXT;
    use lore_base::runtime::runtime;
    use lore_base::types::Hash;
    use lore_revision::branch;
    use lore_revision::commit;
    use lore_revision::commit::CommitOptions;
    use lore_revision::event::LoreErrorDetail;
    use lore_revision::file;
    use lore_revision::immutable;
    use lore_revision::interface::ExecutionContext;
    use lore_revision::interface::LoreArray;
    use lore_revision::interface::LoreEvent;
    use lore_revision::interface::LoreString;
    use lore_revision::lore::BranchId;
    use lore_revision::lore::RepositoryId;
    use lore_revision::metadata;
    use lore_revision::metadata::Metadata;
    use lore_revision::metadata::MetadataType;
    use lore_revision::node;
    use lore_revision::node::NodeFileMetadata;
    use lore_revision::node::NodeFileMetadataBlock;
    use lore_revision::node::NodeFlags;
    use lore_revision::relay::EventDispatcher;
    use lore_revision::repository;
    use lore_revision::repository::RepositoryContext;
    use lore_revision::repository::RepositoryFormat;
    use lore_revision::repository::RepositoryWriteToken;
    use lore_revision::stage;
    use lore_revision::stage::StageOptions;
    use lore_revision::state::State;
    use lore_revision::util::path::RelativePath;
    use lore_transport::ProtocolError;

    include!("helper.rs");

    struct Fixture {
        _tempdir: TempDir,
        root: PathBuf,
        repository: Arc<RepositoryContext>,
        write_token: RepositoryWriteToken,
        branch: BranchId,
    }

    #[derive(Debug, PartialEq)]
    struct Anchors {
        current: Hash,
        staged: Option<Hash>,
        branch_latest: Hash,
    }

    impl Fixture {
        async fn new(file_names: &[&str]) -> Self {
            let (immutable_store, mutable_store, _execution) =
                test_store_create().await.expect("Failed to create stores");
            let repository_id = RepositoryId::from(uuid::Uuid::now_v7());
            let branch = BranchId::from(uuid::Uuid::now_v7());
            let tempdir = generate_tempdir();
            let root = tempdir.to_path_buf();
            let write_token = RepositoryWriteToken::acquire(&root).await;
            let created_repo = repository::create_local(
                &root,
                &write_token,
                repository_id,
                branch,
                branch::DEFAULT_DEFAULT_NAME.to_string(),
                repository::RepositoryConfig::default(),
                false,
            )
            .await
            .expect("Failed to initialize repository");
            let repository = Arc::new(
                RepositoryContext::new(
                    Some(root.clone()),
                    immutable_store,
                    mutable_store,
                    repository_id,
                    created_repo.instance_id,
                    Err(ProtocolError::from(NoRemote)),
                    Arc::default(),
                    RepositoryFormat::Lore,
                )
                .with_write_token(write_token.share()),
            );
            lore_revision::instance::store_current_anchor_branch(&repository, branch)
                .await
                .expect("Failed to store current branch anchor");

            for (index, name) in file_names.iter().enumerate() {
                write_file(
                    &root.join(name),
                    format!("initial content {index}").as_bytes(),
                );
            }
            stage_paths(
                repository.clone(),
                &write_token,
                file_names.iter().map(|name| root.join(name)).collect(),
            )
            .await;
            commit(repository.clone(), &write_token, "initial commit").await;

            Self {
                _tempdir: tempdir,
                root,
                repository,
                write_token,
                branch,
            }
        }

        async fn anchors(&self) -> Anchors {
            Anchors {
                current: lore_revision::instance::load_current_anchor(&self.repository)
                    .await
                    .expect("Failed to load current anchor")
                    .0,
                staged: lore_revision::instance::load_staged_revision(&self.repository)
                    .await
                    .expect("Failed to load staged anchor"),
                branch_latest: branch::load_latest_history(
                    self.repository.clone(),
                    self.branch,
                    None,
                )
                .await
                .expect("Failed to load branch latest")
                .revision,
            }
        }
    }

    fn write_file(path: &Path, bytes: &[u8]) {
        let mut file = std::fs::File::create(path)
            .unwrap_or_else(|_| panic!("Failed to create fixture file {}", path.display()));
        file.write_all(bytes)
            .unwrap_or_else(|_| panic!("Failed to write fixture file {}", path.display()));
    }

    async fn stage_paths(
        repository: Arc<RepositoryContext>,
        write_token: &RepositoryWriteToken,
        paths: Vec<PathBuf>,
    ) {
        file::stage::stage(
            repository,
            write_token,
            LoreArray::from_vec(paths.iter().map(LoreString::from).collect()),
            StageOptions {
                case_change: stage::StageCaseChange::Error,
                node_flags: NodeFlags::NoFlags,
                file_id: None,
                no_children: false,
                scan: true,
            },
        )
        .await
        .expect("Failed to stage fixture paths");
    }

    async fn commit(
        repository: Arc<RepositoryContext>,
        write_token: &RepositoryWriteToken,
        message: &str,
    ) -> Hash {
        Box::pin(commit::commit(
            repository,
            write_token,
            CommitOptions {
                message: message.to_string(),
                link_messages: HashMap::new(),
                link: None,
                layer_messages: HashMap::new(),
                layer: None,
                stats: false,
            },
        ))
        .await
        .expect("Failed to commit fixture")
    }

    async fn file_metadata(
        repository: Arc<RepositoryContext>,
        revision: Hash,
        path: &Path,
    ) -> Option<Metadata> {
        let state = State::deserialize(repository.clone(), revision)
            .await
            .expect("Failed to deserialize metadata state");
        let relative = RelativePath::new_from_user_path(
            repository.require_path().expect("Repository path missing"),
            path.to_string_lossy().as_ref(),
        )
        .expect("Failed to resolve metadata path");
        let node_link = state
            .find_node_link(repository.clone(), relative.as_str())
            .await
            .expect("Failed to find metadata node");
        assert!(node_link.is_valid(), "Metadata node must be valid");
        let metadata_node = node::node_to_file_metadata(node_link.node);
        let block = state
            .block_file_metadata(
                repository.clone(),
                NodeFileMetadataBlock::index(metadata_node),
            )
            .await
            .expect("Failed to load file metadata block");
        let hash = block
            .read()
            .node(NodeFileMetadata::index(metadata_node))
            .metadata;
        if hash.is_zero() {
            None
        } else {
            Some(
                Metadata::deserialize(repository, hash)
                    .await
                    .expect("Failed to deserialize file metadata"),
            )
        }
    }

    async fn run_test(test: impl std::future::Future<Output = ()> + Send + 'static) {
        let execution = setup_test_execution();
        runtime()
            .spawn(LORE_CONTEXT.scope(execution, test))
            .await
            .expect("Test task failed");
    }

    #[tokio::test]
    async fn file_set_rejects_missing_binary_source_without_publishing() {
        run_test(async move {
            let fixture = Fixture::new(&["tracked.bin"]).await;
            let before = fixture.anchors().await;
            let metadata_events = Arc::new(AtomicUsize::new(0));
            let ended = Arc::new(AtomicBool::new(false));
            let captured_metadata = metadata_events.clone();
            let captured_end = ended.clone();
            let callback = Some(Box::new(move |event: &LoreEvent| match event {
                LoreEvent::Metadata(_) => {
                    captured_metadata.fetch_add(1, Ordering::SeqCst);
                }
                LoreEvent::End(_) => captured_end.store(true, Ordering::SeqCst),
                _ => {}
            }) as Box<_>);
            let execution = Arc::new(ExecutionContext::new_client_with_user_id(
                LoreGlobalArgs::default(),
                EventDispatcher::new(callback),
                "test-user".to_string(),
            ));
            let tracked_path = fixture.root.join("tracked.bin");
            let missing_source = fixture.root.join("missing-metadata.bin");

            LORE_CONTEXT
                .scope(execution.clone(), async {
                    metadata::set::set_file(
                        fixture.repository.clone(),
                        &fixture.write_token,
                        &[tracked_path.to_string_lossy().as_ref()],
                        &[b"audit"],
                        &[missing_source.to_string_lossy().as_bytes()],
                        &[MetadataType::Binary],
                        &[1],
                    )
                    .await
                })
                .await
                .expect_err("missing binary metadata source must reject the batch");
            execution
                .dispatcher
                .complete(LoreErrorDetail::default())
                .await;
            drop(execution);
            for _ in 0..100 {
                if ended.load(Ordering::SeqCst) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }

            assert!(
                ended.load(Ordering::SeqCst),
                "Event dispatcher did not drain"
            );
            assert_eq!(metadata_events.load(Ordering::SeqCst), 0);
            assert_eq!(fixture.anchors().await, before);
        })
        .await;
    }

    #[tokio::test]
    async fn file_set_rejects_failed_task_without_partial_anchor() {
        run_test(async move {
            let fixture = Fixture::new(&["good.bin", "bad.bin"]).await;
            let before = fixture.anchors().await;
            let good_path = fixture.root.join("good.bin");
            let bad_path = fixture.root.join("bad.bin");
            let missing_source = fixture.root.join("missing-metadata.bin");

            metadata::set::set_file(
                fixture.repository.clone(),
                &fixture.write_token,
                &[
                    good_path.to_string_lossy().as_ref(),
                    bad_path.to_string_lossy().as_ref(),
                ],
                &[b"status", b"audit"],
                &[b"ready", missing_source.to_string_lossy().as_bytes()],
                &[MetadataType::String, MetadataType::Binary],
                &[1, 1],
            )
            .await
            .expect_err("one failed task must reject successful siblings");

            assert_eq!(fixture.anchors().await, before);
        })
        .await;
    }

    #[tokio::test]
    async fn file_set_returns_lowest_input_index_error_deterministically() {
        run_test(async move {
            let fixture = Fixture::new(&["tracked.bin"]).await;
            let invalid_path = fixture.root.join("not-tracked.bin");
            let tracked_path = fixture.root.join("tracked.bin");
            let missing_source = fixture.root.join("missing-metadata.bin");

            for _ in 0..32 {
                let error = metadata::set::set_file(
                    fixture.repository.clone(),
                    &fixture.write_token,
                    &[
                        tracked_path.to_string_lossy().as_ref(),
                        invalid_path.to_string_lossy().as_ref(),
                    ],
                    &[b"first", b"second"],
                    &[missing_source.to_string_lossy().as_bytes(), b"value"],
                    &[MetadataType::Binary, MetadataType::String],
                    &[1, 1],
                )
                .await
                .expect_err("both failing tasks must reject");
                assert!(
                    error.to_string().contains("Invalid path"),
                    "lowest-index error must win, got {error}"
                );
            }
        })
        .await;
    }

    #[tokio::test]
    async fn file_set_multi_path_string_and_binary_commits_and_materializes_exact_bytes() {
        run_test(async move {
            let fixture = Fixture::new(&["text.bin", "binary.bin"]).await;
            let text_path = fixture.root.join("text.bin");
            let binary_path = fixture.root.join("binary.bin");
            write_file(&text_path, b"updated text owner");
            write_file(&binary_path, b"updated binary owner");
            stage_paths(
                fixture.repository.clone(),
                &fixture.write_token,
                vec![text_path.clone(), binary_path.clone()],
            )
            .await;
            let binary_source = fixture.root.join("audit.bin");
            let binary_bytes = b"\x00\x01exact metadata bytes\xff";
            write_file(&binary_source, binary_bytes);

            metadata::set::set_file(
                fixture.repository.clone(),
                &fixture.write_token,
                &[
                    text_path.to_string_lossy().as_ref(),
                    binary_path.to_string_lossy().as_ref(),
                ],
                &[b"kind", b"audit"],
                &[b"Actor", binary_source.to_string_lossy().as_bytes()],
                &[MetadataType::String, MetadataType::Binary],
                &[1, 1],
            )
            .await
            .expect("multi-path metadata set failed");

            let staged = fixture
                .anchors()
                .await
                .staged
                .expect("successful metadata set must publish staged anchor");
            let staged_text = file_metadata(fixture.repository.clone(), staged, &text_path)
                .await
                .expect("string metadata missing from staged state");
            assert_eq!(
                staged_text.get_string("kind").expect("string key missing"),
                "Actor"
            );
            let staged_binary = file_metadata(fixture.repository.clone(), staged, &binary_path)
                .await
                .expect("binary metadata missing from staged state");
            let address = staged_binary
                .get_address("audit")
                .expect("binary address missing");
            let materialized = immutable::read(
                fixture.repository.clone(),
                address,
                None,
                immutable::read_options_from_repository(&fixture.repository).no_remote(),
            )
            .await
            .expect("Failed to materialize binary metadata");
            assert_eq!(materialized.as_ref(), binary_bytes);

            let committed = commit(
                fixture.repository.clone(),
                &fixture.write_token,
                "metadata commit",
            )
            .await;
            let committed_text = file_metadata(fixture.repository.clone(), committed, &text_path)
                .await
                .expect("string metadata missing after commit");
            assert_eq!(
                committed_text
                    .get_string("kind")
                    .expect("committed string key missing"),
                "Actor"
            );
            let committed_binary =
                file_metadata(fixture.repository.clone(), committed, &binary_path)
                    .await
                    .expect("binary metadata missing after commit");
            assert_eq!(
                committed_binary
                    .get_address("audit")
                    .expect("committed binary address missing"),
                address
            );
        })
        .await;
    }

    #[tokio::test]
    async fn file_set_duplicate_key_remains_last_write_wins() {
        run_test(async move {
            let fixture = Fixture::new(&["tracked.bin"]).await;
            let tracked_path = fixture.root.join("tracked.bin");
            metadata::set::set_file(
                fixture.repository.clone(),
                &fixture.write_token,
                &[tracked_path.to_string_lossy().as_ref()],
                &[b"status", b"status"],
                &[b"first", b"second"],
                &[MetadataType::String, MetadataType::String],
                &[2],
            )
            .await
            .expect("duplicate-key legacy set failed");

            let staged = fixture
                .anchors()
                .await
                .staged
                .expect("metadata set must publish staged anchor");
            let metadata = file_metadata(fixture.repository, staged, &tracked_path)
                .await
                .expect("duplicate-key metadata missing");
            assert_eq!(
                metadata
                    .get_string("status")
                    .expect("duplicate key missing"),
                "second"
            );
        })
        .await;
    }

    #[tokio::test]
    async fn revision_set_rejects_missing_binary_source_synchronously() {
        run_test(async move {
            let fixture = Fixture::new(&["tracked.bin"]).await;
            let before = fixture.anchors().await;
            let missing_source = fixture.root.join("missing-revision-metadata.bin");
            metadata::set::set_revision(
                fixture.repository.clone(),
                &fixture.write_token,
                &[b"audit"],
                &[missing_source.to_string_lossy().as_bytes()],
                &[MetadataType::Binary],
            )
            .await
            .expect_err("revision metadata missing binary source must reject");
            assert_eq!(fixture.anchors().await, before);
        })
        .await;
    }

    #[tokio::test]
    async fn clear_file_removes_staged_metadata() {
        run_test(async move {
            let fixture = Fixture::new(&["tracked.bin"]).await;
            let tracked_path = fixture.root.join("tracked.bin");
            metadata::set::set_file(
                fixture.repository.clone(),
                &fixture.write_token,
                &[tracked_path.to_string_lossy().as_ref()],
                &[b"status"],
                &[b"attached"],
                &[MetadataType::String],
                &[1],
            )
            .await
            .expect("metadata set before clear failed");
            metadata::clear::clear_file(
                fixture.repository.clone(),
                &fixture.write_token,
                tracked_path.to_string_lossy().into_owned(),
            )
            .await
            .expect("clear_file failed");

            let staged = fixture
                .anchors()
                .await
                .staged
                .expect("clear_file must publish staged state");
            assert!(
                file_metadata(fixture.repository, staged, &tracked_path)
                    .await
                    .is_none(),
                "clear_file must remove the staged metadata hash"
            );
        })
        .await;
    }
}

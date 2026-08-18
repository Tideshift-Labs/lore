// SPDX-FileCopyrightText: 2026 Khurram Virani
// SPDX-License-Identifier: MIT

mod test_util;

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::future::poll_fn;
    use std::path::Path;
    use std::str::FromStr;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::task::Poll;

    use lore::branch::LoreBranchCreateArgs;
    use lore::branch::LoreBranchMergeResolveArgs;
    use lore::branch::LoreBranchMergeResolveMineArgs;
    use lore::branch::LoreBranchMergeResolveTheirsArgs;
    use lore::branch::LoreBranchMergeStartArgs;
    use lore::branch::LoreBranchSwitchArgs;
    use lore::file::LoreFileStageArgs;
    use lore::repository::LoreRepositoryCreateArgs;
    use lore::repository::LoreRepositoryStatusArgs;
    use lore::revision::LoreRevisionCherryPickArgs;
    use lore::revision::LoreRevisionCommitArgs;
    use lore::revision::LoreRevisionRevertArgs;
    use lore_base::error::Conflict;
    use lore_base::error::InvalidArguments;
    use lore_base::error::NothingStaged;
    use lore_base::lore_spawn;
    use lore_base::runtime::LORE_CONTEXT;
    use lore_base::types::Hash;
    use lore_base::types::RepositoryId;
    use lore_error_set::FfiError;
    use lore_revision::commit::LoreRevisionCommitRevisionEventData;
    use lore_revision::interface::ExecutionContext;
    use lore_revision::interface::LoreArray;
    use lore_revision::interface::LoreEvent;
    use lore_revision::interface::LoreGlobalArgs;
    use lore_revision::interface::LoreString;
    use lore_revision::layer::Layer;
    use lore_revision::relay::EventDispatcher;
    use lore_revision::repository;
    use lore_revision::repository::RepositoryAccess;
    use lore_revision::repository::RepositoryWriteToken;
    use lore_revision::repository::status::LoreRepositoryStatusFileEventData;
    use lore_revision::repository::status::LoreRepositoryStatusRevisionEventData;
    use lore_revision::state::State;

    use super::test_util::TempDir;

    struct Fixture {
        _tempdir: TempDir,
        root: std::path::PathBuf,
        globals: LoreGlobalArgs,
    }

    impl Fixture {
        async fn new(name: &str) -> Self {
            let tempdir = TempDir::new(name);
            let root = tempdir.path().to_path_buf();
            let globals = LoreGlobalArgs {
                repository_path: root.as_path().into(),
                offline: 1,
                identity: "merge-finalize-test".into(),
                ..Default::default()
            };
            let args = LoreRepositoryCreateArgs {
                repository_url: format!("lore://localhost/{}", uuid::Uuid::now_v7()).into(),
                id: LoreString::default(),
                description: LoreString::default(),
                use_shared_store: 0,
                shared_store_path: LoreString::default(),
            };
            assert_eq!(
                lore::repository::create(globals.clone(), args, None).await,
                0
            );
            Self {
                _tempdir: tempdir,
                root,
                globals,
            }
        }

        async fn stage(&self, path: &Path) {
            let args = LoreFileStageArgs {
                paths: LoreArray::from_vec(vec![path.into()]),
                case_change: 0,
                scan: 0,
            };
            assert_eq!(lore::file::stage(self.globals.clone(), args, None).await, 0);
        }

        async fn write_stage_commit(&self, relative: &str, bytes: &[u8], message: &str) -> Hash {
            let path = self.root.join(relative);
            std::fs::write(&path, bytes).expect("write fixture file");
            self.stage(&path).await;
            let committed = Arc::new(Mutex::new(None));
            let captured = committed.clone();
            let callback = Some(Box::new(move |event: &LoreEvent| {
                if let LoreEvent::RevisionCommitRevision(data) = event {
                    *captured.lock().expect("commit capture lock") = Some(data.clone());
                }
            }) as Box<_>);
            let args = LoreRevisionCommitArgs {
                message: message.into(),
                ..Default::default()
            };
            assert_eq!(
                lore::revision::commit(self.globals.clone(), args, callback).await,
                0
            );
            committed
                .lock()
                .expect("commit capture lock")
                .as_ref()
                .expect("commit revision event")
                .revision
        }

        async fn create_branch(&self, branch: &str) {
            let args = LoreBranchCreateArgs {
                branch: branch.into(),
                category: LoreString::default(),
                id: LoreString::default(),
            };
            assert_eq!(
                lore::branch::create(self.globals.clone(), args, None).await,
                0
            );
        }

        async fn switch(&self, branch: &str) {
            let args = LoreBranchSwitchArgs {
                branch: branch.into(),
                revision: LoreString::default(),
                reset: 1,
                bare: 0,
            };
            assert_eq!(
                lore::branch::switch(self.globals.clone(), args, None).await,
                0
            );
        }

        async fn status(&self) -> LoreRepositoryStatusRevisionEventData {
            let revision = Arc::new(Mutex::new(None));
            let captured = revision.clone();
            let callback = Some(Box::new(move |event: &LoreEvent| {
                if let LoreEvent::RepositoryStatusRevision(data) = event {
                    *captured.lock().expect("status capture lock") = Some(data.clone());
                }
            }) as Box<_>);
            let args = LoreRepositoryStatusArgs {
                staged: 1,
                scan: 0,
                check_dirty: 0,
                reset: 0,
                sync_point: 0,
                revision_only: 1,
                count: 0,
                paths: LoreArray::default(),
            };
            assert_eq!(
                lore::repository::status(self.globals.clone(), args, callback).await,
                0
            );
            revision
                .lock()
                .expect("status capture lock")
                .clone()
                .expect("repository status revision event")
        }

        async fn status_files(&self) -> Vec<LoreRepositoryStatusFileEventData> {
            let files = Arc::new(Mutex::new(Vec::new()));
            let captured = files.clone();
            let callback = Some(Box::new(move |event: &LoreEvent| {
                if let LoreEvent::RepositoryStatusFile(data) = event {
                    captured
                        .lock()
                        .expect("status files lock")
                        .push(data.clone());
                }
            }) as Box<_>);
            let args = LoreRepositoryStatusArgs {
                staged: 1,
                scan: 0,
                check_dirty: 0,
                reset: 0,
                sync_point: 0,
                revision_only: 0,
                count: 0,
                paths: LoreArray::default(),
            };
            assert_eq!(
                lore::repository::status(self.globals.clone(), args, callback).await,
                0
            );
            files.lock().expect("status files lock").clone()
        }

        async fn staged_is_merge(&self) -> bool {
            let execution = Arc::new(ExecutionContext::new_client_with_user_id(
                self.globals.clone(),
                EventDispatcher::new(None),
                "merge-finalize-test".to_string(),
            ));
            let root = self.root.clone();
            LORE_CONTEXT
                .scope(execution, async move {
                    let repository =
                        repository::load_and_connect(&root, RepositoryAccess::ReadOnly)
                            .await
                            .expect("load fixture repository");
                    let (_, staged, _) = State::deserialize_current_and_staged(repository.clone())
                        .await
                        .expect("deserialize fixture staged state");
                    let is_merge = staged
                        .as_ref()
                        .is_some_and(|state_staged| state_staged.is_merge());
                    drop(staged);
                    drop(repository);
                    repository::repository_release(&root);
                    is_merge
                })
                .await
        }

        async fn start_conflicted_merge(&self) {
            self.write_stage_commit("shared.txt", b"base\n", "base")
                .await;
            self.create_branch("feature").await;
            self.switch("feature").await;
            self.write_stage_commit("shared.txt", b"feature\n", "feature")
                .await;
            self.switch("main").await;
            self.write_stage_commit("shared.txt", b"main\n", "main")
                .await;
            let args = LoreBranchMergeStartArgs {
                branch: "feature".into(),
                message: "merge feature".into(),
                no_commit: 1,
                link: LoreString::default(),
                ignore_links: 0,
            };
            assert_eq!(
                lore::branch::merge_start(self.globals.clone(), args, None).await,
                0
            );
            let status = self.status().await;
            assert!(
                !status.revision_staged.is_zero(),
                "merge must stage a revision"
            );
            assert!(
                !status.revision_merged.is_zero(),
                "merge must carry its second parent"
            );
        }

        async fn resolve_merge(&self) {
            let args = LoreBranchMergeResolveTheirsArgs {
                paths: LoreArray::from_vec(vec![self.root.join("shared.txt").as_path().into()]),
            };
            assert_eq!(
                lore::branch::merge_resolve_theirs(self.globals.clone(), args, None).await,
                0
            );
        }

        async fn resolve_merge_mine(&self) {
            let args = LoreBranchMergeResolveMineArgs {
                paths: LoreArray::from_vec(vec![self.root.join("shared.txt").as_path().into()]),
            };
            assert_eq!(
                lore::branch::merge_resolve_mine(self.globals.clone(), args, None).await,
                0
            );
        }

        async fn resolve_merge_manually(&self) {
            std::fs::write(self.root.join("shared.txt"), b"manual resolution\n")
                .expect("write manual merge resolution");
            let args = LoreBranchMergeResolveArgs {
                paths: LoreArray::from_vec(vec![self.root.join("shared.txt").as_path().into()]),
            };
            assert_eq!(
                lore::branch::merge_resolve(self.globals.clone(), args, None).await,
                0
            );
        }

        fn add_staged_layer_residue(&self, target_path: &str) {
            #[derive(serde::Serialize)]
            struct LayerConfigFixture {
                layers: Vec<Layer>,
            }

            let current = Hash::from_str(&"11".repeat(32)).expect("current layer hash");
            let staged = Hash::from_str(&"22".repeat(32)).expect("staged layer hash");
            let config = LayerConfigFixture {
                layers: vec![Layer {
                    target_path: target_path.to_string(),
                    source_path: String::new(),
                    repository: RepositoryId::from(uuid::Uuid::now_v7()),
                    metadata: None,
                    current,
                    staged,
                }],
            };
            let encoded = toml::to_string_pretty(&config).expect("serialize layer fixture");
            std::fs::write(lore_revision::layer::layer_config_path(&self.root), encoded)
                .expect("write layer fixture");
        }

        fn remove_staged_layer_residue(&self) {
            std::fs::remove_file(lore_revision::layer::layer_config_path(&self.root))
                .expect("remove layer fixture");
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct OwnedComplete {
        status: i32,
        error_code: i32,
        message: String,
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    enum TerminalEvent {
        Complete(OwnedComplete),
        End,
    }

    #[derive(Clone, Default)]
    struct FinalizeCapture {
        revision: Option<LoreRevisionCommitRevisionEventData>,
        terminals: Vec<TerminalEvent>,
    }

    fn finalize_capture() -> (
        Arc<Mutex<FinalizeCapture>>,
        lore_revision::interface::LoreEventCallback,
    ) {
        let capture = Arc::new(Mutex::new(FinalizeCapture::default()));
        let captured = capture.clone();
        let callback = Some(Box::new(move |event: &LoreEvent| {
            let mut captured = captured.lock().expect("finalize capture lock");
            match event {
                LoreEvent::RevisionCommitRevision(data) => captured.revision = Some(data.clone()),
                LoreEvent::Complete(data) => {
                    captured
                        .terminals
                        .push(TerminalEvent::Complete(OwnedComplete {
                            status: data.status,
                            error_code: data.error.error_code,
                            message: data.error.message.as_str().to_string(),
                        }));
                }
                LoreEvent::End(_) => captured.terminals.push(TerminalEvent::End),
                _ => {}
            }
        }) as Box<_>);
        (capture, callback)
    }

    fn assert_terminal_contract(
        returned_status: i32,
        capture: &Arc<Mutex<FinalizeCapture>>,
        expected_code: i32,
        expected_message: &str,
    ) {
        let captured = capture.lock().expect("finalize capture lock");
        assert_eq!(returned_status, expected_code);
        assert_eq!(
            captured.terminals,
            vec![
                TerminalEvent::Complete(OwnedComplete {
                    status: expected_code,
                    error_code: expected_code,
                    message: expected_message.to_string(),
                }),
                TerminalEvent::End,
            ],
            "facade must emit exactly one Complete followed by End"
        );
    }

    async fn finalize_and_capture(
        fixture: &Fixture,
        message: &str,
    ) -> (i32, Arc<Mutex<FinalizeCapture>>) {
        let (capture, callback) = finalize_capture();
        let status = lore::revision::finalize_resolved_merge(
            fixture.globals.clone(),
            message.to_string(),
            callback,
        )
        .await;
        (status, capture)
    }

    #[tokio::test]
    async fn rejects_nothing_active_and_ordinary_staged_with_typed_details() {
        let empty = Fixture::new("lore-merge-finalize-empty-").await;
        let (status, capture) = finalize_and_capture(&empty, "must reject empty").await;
        let expected = NothingStaged;
        assert_eq!(expected.ffi_code(), 21);
        assert_terminal_contract(status, &capture, expected.ffi_code(), &expected.to_string());
        assert!(capture.lock().expect("capture lock").revision.is_none());

        let fixture = Fixture::new("lore-merge-finalize-ordinary-").await;
        let path = fixture.root.join("ordinary.txt");
        std::fs::write(&path, b"ordinary\n").expect("write ordinary file");
        fixture.stage(&path).await;
        let before = fixture.status().await;
        let (status, capture) = finalize_and_capture(&fixture, "must reject ordinary").await;
        let expected = InvalidArguments {
            reason: "merge finalize rejected: no fully-resolved branch merge is staged".into(),
        };
        assert_eq!(expected.ffi_code(), 1);
        assert_terminal_contract(status, &capture, expected.ffi_code(), &expected.to_string());
        assert!(capture.lock().expect("capture lock").revision.is_none());
        let after = fixture.status().await;
        assert_eq!(after.revision, before.revision);
        assert_eq!(after.revision_staged, before.revision_staged);
    }

    #[tokio::test]
    async fn rejects_unresolved_and_mixed_merge_states_without_publishing_an_anchor() {
        let fixture = Fixture::new("lore-merge-finalize-rejections-").await;
        fixture.start_conflicted_merge().await;
        assert!(fixture.staged_is_merge().await);
        let unresolved = fixture.status().await;
        let (status, capture) = finalize_and_capture(&fixture, "must reject unresolved").await;
        let expected = Conflict {
            path: "shared.txt".to_string(),
        };
        assert_eq!(expected.ffi_code(), 23);
        assert_terminal_contract(status, &capture, expected.ffi_code(), &expected.to_string());
        assert!(capture.lock().expect("capture lock").revision.is_none());
        let after_unresolved = fixture.status().await;
        assert_eq!(after_unresolved.revision, unresolved.revision);
        assert_eq!(after_unresolved.revision_staged, unresolved.revision_staged);

        fixture.resolve_merge().await;
        assert!(fixture.staged_is_merge().await);
        let ride_along = fixture.root.join("ride-along.txt");
        std::fs::write(&ride_along, b"unrelated\n").expect("write ride-along file");
        fixture.stage(&ride_along).await;
        let mixed = fixture.status().await;
        let (status, capture) = finalize_and_capture(&fixture, "must reject mixed").await;
        let expected = InvalidArguments {
            reason: "merge finalize rejected: staged state contains changes outside the merge: ride-along.txt".into(),
        };
        assert_terminal_contract(status, &capture, expected.ffi_code(), &expected.to_string());
        assert!(capture.lock().expect("capture lock").revision.is_none());
        let after_mixed = fixture.status().await;
        assert_eq!(after_mixed.revision, mixed.revision);
        assert_eq!(after_mixed.revision_staged, mixed.revision_staged);
    }

    #[tokio::test]
    async fn rejects_cherry_pick_and_revert_topologies() {
        let cherry = Fixture::new("lore-merge-finalize-cherry-").await;
        cherry
            .write_stage_commit("shared.txt", b"base\n", "base")
            .await;
        cherry.create_branch("feature").await;
        cherry.switch("feature").await;
        let picked = cherry
            .write_stage_commit("shared.txt", b"feature\n", "feature")
            .await;
        cherry.switch("main").await;
        let args = LoreRevisionCherryPickArgs {
            revision: picked.to_string().into(),
            message: "pick feature".into(),
            no_commit: 1,
        };
        assert_eq!(
            lore::revision::cherry_pick(cherry.globals.clone(), args, None).await,
            0
        );
        let cherry_before = cherry.status().await;
        let (status, capture) = finalize_and_capture(&cherry, "must reject cherry-pick").await;
        let expected = InvalidArguments {
            reason: "merge finalize rejected: no fully-resolved branch merge is staged".into(),
        };
        assert_terminal_contract(status, &capture, expected.ffi_code(), &expected.to_string());
        let cherry_after = cherry.status().await;
        assert_eq!(cherry_after.revision, cherry_before.revision);
        assert_eq!(cherry_after.revision_staged, cherry_before.revision_staged);

        let revert = Fixture::new("lore-merge-finalize-revert-").await;
        revert
            .write_stage_commit("shared.txt", b"base\n", "base")
            .await;
        let reverted = revert
            .write_stage_commit("shared.txt", b"second\n", "second")
            .await;
        let args = LoreRevisionRevertArgs {
            revision: reverted.to_string().into(),
            message: "revert second".into(),
            no_commit: 1,
        };
        assert_eq!(
            lore::revision::revert(revert.globals.clone(), args, None).await,
            0
        );
        let revert_before = revert.status().await;
        let (status, capture) = finalize_and_capture(&revert, "must reject revert").await;
        let expected = InvalidArguments {
            reason: "merge finalize rejected: no fully-resolved branch merge is staged".into(),
        };
        assert_terminal_contract(status, &capture, expected.ffi_code(), &expected.to_string());
        let revert_after = revert.status().await;
        assert_eq!(revert_after.revision, revert_before.revision);
        assert_eq!(revert_after.revision_staged, revert_before.revision_staged);
    }

    #[tokio::test]
    async fn rejects_staged_layer_residue_with_typed_invalid_arguments() {
        let fixture = Fixture::new("lore-merge-finalize-layer-").await;
        fixture.start_conflicted_merge().await;
        fixture.resolve_merge().await;
        let before = fixture.status().await;
        fixture.add_staged_layer_residue("layer-content");

        let (status, capture) = finalize_and_capture(&fixture, "must reject layer").await;
        let expected = InvalidArguments {
            reason: "merge finalize rejected: staged state contains changes outside the merge: layer-content".into(),
        };
        assert_terminal_contract(status, &capture, expected.ffi_code(), &expected.to_string());
        assert!(capture.lock().expect("capture lock").revision.is_none());
        fixture.remove_staged_layer_residue();
        let after = fixture.status().await;
        assert_eq!(after.revision, before.revision);
        assert_eq!(after.revision_staged, before.revision_staged);
    }

    #[tokio::test]
    async fn manual_and_mine_resolutions_remain_admissible() {
        let manual = Fixture::new("lore-merge-finalize-manual-").await;
        manual.start_conflicted_merge().await;
        manual.resolve_merge_manually().await;
        let manual_files = manual.status_files().await;
        assert_eq!(manual_files.len(), 1, "manual status: {manual_files:?}");
        assert_eq!(manual_files[0].flag_conflict_unresolved, 0);
        assert!(manual.staged_is_merge().await);
        let (status, capture) = finalize_and_capture(&manual, "manual resolution").await;
        assert_terminal_contract(status, &capture, 0, "");
        assert!(capture.lock().expect("capture lock").revision.is_some());

        let mine = Fixture::new("lore-merge-finalize-mine-").await;
        mine.start_conflicted_merge().await;
        mine.resolve_merge_mine().await;
        let mine_files = mine.status_files().await;
        assert_eq!(mine_files.len(), 1, "mine status: {mine_files:?}");
        assert_eq!(mine_files[0].flag_conflict_unresolved, 0);
        assert_eq!(mine_files[0].flag_conflict_mine, 1);
        assert!(mine.staged_is_merge().await);
        let (status, capture) = finalize_and_capture(&mine, "mine resolution").await;
        assert_terminal_contract(status, &capture, 0, "");
        assert!(capture.lock().expect("capture lock").revision.is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn resolved_merge_commits_two_parents_under_one_write_token_and_clears_state() {
        let fixture = Fixture::new("lore-merge-finalize-success-").await;
        fixture.start_conflicted_merge().await;
        fixture.resolve_merge().await;
        assert!(fixture.staged_is_merge().await);
        let before = fixture.status().await;
        let resolved_files = fixture.status_files().await;
        assert_eq!(
            resolved_files.len(),
            1,
            "resolved fixture files: {resolved_files:?}"
        );
        assert_eq!(resolved_files[0].path.as_str(), "shared.txt");
        assert_eq!(resolved_files[0].flag_merged, 1);
        assert_eq!(resolved_files[0].flag_conflict, 1);
        assert_eq!(resolved_files[0].flag_conflict_unresolved, 0);

        let gate = RepositoryWriteToken::acquire(&fixture.root).await;
        let (capture, callback) = finalize_capture();
        let globals = fixture.globals.clone();
        let mut facade_future = Box::pin(lore::revision::finalize_resolved_merge(
            globals,
            "resolved merge".to_string(),
            callback,
        ));

        // Poll through the synchronous preparation path until the token wait
        // itself returns Pending. The facade is now deterministically queued
        // behind `gate` before the competing writer is created.
        poll_fn(|cx| match facade_future.as_mut().poll(cx) {
            Poll::Pending => Poll::Ready(()),
            Poll::Ready(status) => {
                panic!("facade unexpectedly completed before gate release: {status}")
            }
        })
        .await;

        let facade = lore_spawn!(facade_future);
        let competing_path = fixture.root.clone();
        let competing_globals = fixture.globals.clone();
        let competing = lore_spawn!(async move {
            let token = RepositoryWriteToken::acquire(&competing_path).await;
            let execution = Arc::new(ExecutionContext::new_client_with_user_id(
                competing_globals,
                EventDispatcher::new(None),
                "merge-finalize-competitor".to_string(),
            ));
            let observed_current = LORE_CONTEXT
                .scope(execution, async {
                    let repository = repository::load_and_connect_with_token(
                        &competing_path,
                        RepositoryAccess::ReadWrite,
                        Some(token.share()),
                    )
                    .await
                    .expect("load competitor repository");
                    let (current, _) = lore_revision::instance::load_current_anchor(&repository)
                        .await
                        .expect("load competitor current anchor");
                    drop(repository);
                    repository::repository_release(&competing_path);
                    current
                })
                .await;
            (token, observed_current)
        });
        drop(gate);

        let facade_status = tokio::time::timeout(std::time::Duration::from_secs(30), facade)
            .await
            .expect("facade must finish")
            .expect("facade must not panic");
        assert_terminal_contract(facade_status, &capture, 0, "");
        let (competing_token, competitor_current) =
            tokio::time::timeout(std::time::Duration::from_secs(2), competing)
                .await
                .expect("competitor must acquire after facade cleanup")
                .expect("competitor must not panic");
        drop(competing_token);

        let commit = capture
            .lock()
            .expect("success capture lock")
            .revision
            .clone()
            .expect("merge commit event");
        assert_eq!(
            competitor_current, commit.revision,
            "competitor acquired before the admitted merge was published"
        );
        assert_eq!(commit.parent, before.revision);
        assert_eq!(commit.parent_other, before.revision_merged);
        assert!(!commit.parent_other.is_zero());

        let after = fixture.status().await;
        assert_eq!(after.revision, commit.revision);
        assert!(
            after.revision_staged.is_zero(),
            "commit must clear staged state"
        );
        assert!(
            fixture.status_files().await.is_empty(),
            "commit must leave no pending merge rows"
        );
        let (status, capture) = finalize_and_capture(&fixture, "cannot finalize twice").await;
        let expected = NothingStaged;
        assert_terminal_contract(status, &capture, expected.ffi_code(), &expected.to_string());
    }
}

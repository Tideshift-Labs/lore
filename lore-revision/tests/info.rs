// SPDX-FileCopyrightText: 2026 Khurram Virani
// SPDX-License-Identifier: MIT
#[cfg(test)]
mod tests {
    #![allow(clippy::disallowed_methods)] // Test fixture writes; not subject to repository write-token discipline.

    use std::sync::Arc;
    use std::sync::Mutex;

    use lore_base::error::NoRemote;
    use lore_base::runtime::LORE_CONTEXT;
    use lore_base::runtime::runtime;
    use lore_base::types::Context;
    use lore_base::types::Hash;
    use lore_revision::branch;
    use lore_revision::commit;
    use lore_revision::commit::CommitOptions;
    use lore_revision::event::LoreEvent;
    use lore_revision::file;
    use lore_revision::interface::ExecutionContext;
    use lore_revision::interface::LoreArray;
    use lore_revision::interface::LoreEventCallback;
    use lore_revision::interface::LoreGlobalArgs;
    use lore_revision::interface::LoreString;
    use lore_revision::lore::BranchId;
    use lore_revision::lore::RepositoryId;
    use lore_revision::node::NodeFlags;
    use lore_revision::relay::EventDispatcher;
    use lore_revision::repository;
    use lore_revision::repository::RepositoryContext;
    use lore_revision::repository::RepositoryContextCreationArgs;
    use lore_revision::repository::RepositoryFormat;
    use lore_revision::repository::RepositoryWriteToken;
    use lore_revision::revision::info::InfoOptions;
    use lore_revision::revision::info::info;
    use lore_revision::stage;
    use lore_revision::stage::StageOptions;
    use lore_revision::state::State;
    use lore_transport::ProtocolError;

    include!("helper.rs");

    /// Builds a capturing dispatcher-backed execution context plus a fresh
    /// in-memory repository, mirroring `tests/commit.rs`'s
    /// `commit_emits_revision_commit_event_on_success` fixture shape. Every
    /// `LoreEvent` `info()` sends is cloned into the returned sink.
    async fn setup_capturing_repository() -> (
        Arc<ExecutionContext>,
        Arc<RepositoryContext>,
        RepositoryWriteToken,
        Arc<Mutex<Vec<LoreEvent>>>,
    ) {
        let events: Arc<Mutex<Vec<LoreEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let captured = events.clone();
        let callback: LoreEventCallback = Some(Box::new(move |event: &LoreEvent| {
            captured.lock().expect("lock").push(event.clone());
        }));

        let (immutable_store, mutable_store, _unused_execution) =
            test_store_create().await.expect("Failed to create stores");
        let execution = Arc::new(ExecutionContext::new_client_with_user_id(
            LoreGlobalArgs::default(),
            EventDispatcher::new(callback),
            "test-user".to_string(),
        ));

        let repository_id = Context::from(uuid::Uuid::now_v7());
        let tempdir = generate_tempdir();
        let path = tempdir.to_path_buf();

        let write_token = RepositoryWriteToken::acquire(path.as_path()).await;
        let repository = Arc::new(
            RepositoryContext::new(RepositoryContextCreationArgs {
                path: Some(path.clone()),
                immutable_store,
                mutable_store,
                id: repository_id.into(),
                instance_id: lore_revision::instance::InstanceId::default(),
                remote: Err(ProtocolError::from(NoRemote)),
                filter: Arc::default(),
                format: RepositoryFormat::Lore,
                filesystem_provider: None,
            })
            .with_write_token(write_token.share()),
        );

        (execution, repository, write_token, events)
    }

    /// Drops the caller's only remaining strong `ExecutionContext` reference
    /// (closing the dispatcher's sender) and polls until the forwarder has
    /// delivered `LoreEvent::End` -- the terminal event `relay.rs`'s
    /// forwarder loop sends unconditionally once the channel closes and
    /// every buffered item has been forwarded (`relay.rs:76`). Waiting for
    /// `End` rather than "any event arrived" is required: `info()` always
    /// sends `LoreEvent::RevisionInfo` first, so breaking on the first event
    /// (as an earlier version of this helper did, mirroring
    /// `tests/commit.rs`'s drain loop) can return before a later `Error`
    /// event arrives -- a latent flake for a positive assertion, and close
    /// to vacuous for a negative "no Error event" assertion, since it would
    /// only prove the *first* event wasn't an error.
    async fn drain_events(execution: Arc<ExecutionContext>, events: &Arc<Mutex<Vec<LoreEvent>>>) {
        drop(execution);
        for _ in 0..200 {
            if events
                .lock()
                .expect("lock")
                .iter()
                .any(|event| matches!(event, LoreEvent::End(_)))
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let discriminants: Vec<u32> = events
            .lock()
            .expect("lock")
            .iter()
            .map(|event| event.discriminant())
            .collect();
        panic!(
            "forwarder never delivered LoreEvent::End within the poll budget; captured event \
             discriminants so far: {discriminants:?}"
        );
    }

    /// Regression guard for the delta-read-failure fix in
    /// `revision/info.rs`: before the fix, a failed `state.delta_block(...)`
    /// read fell through an `if let Ok(...) { ... }` with no `Err` arm, so
    /// `info()` silently emitted zero `RevisionInfoDelta` rows and returned
    /// `Ok(())` -- indistinguishable from a revision that genuinely changed
    /// nothing. Reverting the added `if let Err(error) = &delta_buffer { ...
    /// send_error(...) }` block turns this test red (verified manually; see
    /// the report accompanying this test).
    ///
    /// Uses `State::set_delta_block` to point the persisted revision's tree
    /// at a delta-block hash nothing has ever stored -- the cheapest lever
    /// to reproduce a genuine delta read failure offline, per the fix's own
    /// comment in `revision/info.rs`.
    #[tokio::test]
    async fn delta_read_failure_reports_error_event_and_still_completes() {
        let (execution, repository, write_token, events) = setup_capturing_repository().await;

        let revision = runtime()
            .spawn(LORE_CONTEXT.scope(execution.clone(), async move {
                let state = Arc::new(State::new());
                // Install the in-memory zeroed tree (hash_tree is zero on a
                // fresh state) so `set_delta_block`'s `tree_readonly()` call
                // has a tree to mutate.
                state
                    .tree(repository.clone())
                    .await
                    .expect("Failed to load tree");
                // `set_delta_block` alone only dirties the tree, not the
                // state -- `serialize` gates on the state's own dirty flag,
                // so this is required for the poisoned tree to actually be
                // persisted below.
                state.mark_dirty();
                state
                    .set_delta_block(Hash::from_u64(0xDEAD_BEEF_u64), 1)
                    .expect("Failed to set delta block");

                let revision = state
                    .serialize(repository.clone(), &write_token)
                    .await
                    .expect("Failed to serialize state");

                let options = InfoOptions {
                    signature: Some(revision.to_string()),
                    delta: true,
                    metadata: false,
                };
                info(repository.clone(), options).await.expect(
                    "info() must still return Ok(()) when the delta block can't be read \
                     (a mid-stream Error event is reported instead of a hard failure)",
                );

                revision
            }))
            .await
            .expect("Test task failed");

        drain_events(execution, &events).await;

        let captured = events.lock().expect("lock").clone();

        let revision_string = revision.to_string();
        let error_messages: Vec<String> = captured
            .iter()
            .filter_map(|event| match event {
                LoreEvent::Error(data) => Some(data.error_inner.as_str().to_string()),
                _ => None,
            })
            .collect();
        assert!(
            error_messages
                .iter()
                .any(|message| message.contains(&revision_string)),
            "expected a LoreEvent::Error naming revision {revision_string}, got {error_messages:?}"
        );

        let delta_row_count = captured
            .iter()
            .filter(|event| matches!(event, LoreEvent::RevisionInfoDelta(_)))
            .count();
        let discriminants: Vec<u32> = captured.iter().map(|event| event.discriminant()).collect();
        assert_eq!(
            delta_row_count, 0,
            "expected zero RevisionInfoDelta rows when the delta block can't be read, got \
             event discriminants: {discriminants:?}"
        );
    }

    /// Companion negative control: a revision with a genuinely zero
    /// `hash_delta` (nothing ever set via `set_delta_block`) is the "no
    /// changes" case the fix must not start misreporting as a failure --
    /// `lore_storage::read::load_fragment` short-circuits a zero hash to
    /// `Ok(empty)` before ever touching the store, so no read failure and no
    /// `LoreEvent::Error` should occur.
    #[tokio::test]
    async fn zero_hash_delta_reports_no_error_and_no_delta_rows() {
        let (execution, repository, write_token, events) = setup_capturing_repository().await;

        runtime()
            .spawn(LORE_CONTEXT.scope(execution.clone(), async move {
                let state = Arc::new(State::new());
                state
                    .tree(repository.clone())
                    .await
                    .expect("Failed to load tree");
                // Dirty the state without ever touching the delta block --
                // the tree's `hash_delta` stays at its zeroed default.
                state.mark_dirty();

                let revision = state
                    .serialize(repository.clone(), &write_token)
                    .await
                    .expect("Failed to serialize state");

                let options = InfoOptions {
                    signature: Some(revision.to_string()),
                    delta: true,
                    metadata: false,
                };
                info(repository.clone(), options)
                    .await
                    .expect("info() must return Ok(()) for a genuinely empty revision");
            }))
            .await
            .expect("Test task failed");

        drain_events(execution, &events).await;

        let captured = events.lock().expect("lock").clone();

        let discriminants: Vec<u32> = captured.iter().map(|event| event.discriminant()).collect();

        let error_count = captured
            .iter()
            .filter(|event| matches!(event, LoreEvent::Error(_)))
            .count();
        assert_eq!(
            error_count, 0,
            "expected no LoreEvent::Error for a revision with a zero hash_delta, got event \
             discriminants: {discriminants:?}"
        );

        let delta_row_count = captured
            .iter()
            .filter(|event| matches!(event, LoreEvent::RevisionInfoDelta(_)))
            .count();
        assert_eq!(
            delta_row_count, 0,
            "expected zero RevisionInfoDelta rows for a genuinely unchanged revision, got event \
             discriminants: {discriminants:?}"
        );
    }

    /// Positive control the other two tests can't provide: an implementation
    /// that emitted the mid-stream `Error` event on every call AND skipped
    /// the delta loop unconditionally would still satisfy both tests above
    /// (neither one exercises a delta block that actually deserializes to
    /// real rows). This drives a genuinely healthy revision -- built through
    /// the real `repository::create_local` + `file::stage::stage` +
    /// `commit::commit` pipeline, the same one `tests/commit.rs` uses,
    /// rather than a hand-poked `State` -- and asserts both halves: the
    /// expected `RevisionInfoDelta` row for the one staged file, and no
    /// `LoreEvent::Error`.
    ///
    /// Revert-checked: narrowing `revision/info.rs`'s `if let Ok(delta_buffer)
    /// = delta_buffer { ... }` gate to also run its body when `delta_buffer`
    /// is `Err` (or dropping the loop's body) turns this test red, as does
    /// reverting the fix so the mid-stream error fires unconditionally
    /// (verified manually; see the report accompanying this test).
    #[tokio::test]
    async fn healthy_revision_reports_delta_rows_and_no_error_event() {
        let events: Arc<Mutex<Vec<LoreEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let captured = events.clone();
        let callback: LoreEventCallback = Some(Box::new(move |event: &LoreEvent| {
            captured.lock().expect("lock").push(event.clone());
        }));

        let (immutable_store, mutable_store, _unused_execution) =
            test_store_create().await.expect("Failed to create stores");
        let execution = Arc::new(ExecutionContext::new_client_with_user_id(
            LoreGlobalArgs::default(),
            EventDispatcher::new(callback),
            "test-user".to_string(),
        ));
        let repository_id = RepositoryId::from(uuid::Uuid::now_v7());

        runtime()
            .spawn(LORE_CONTEXT.scope(execution.clone(), async move {
                let tempdir = generate_tempdir();
                let path = tempdir.to_path_buf();
                std::fs::create_dir_all(path.as_path()).expect("Create directory failed");

                let default_branch_id = BranchId::from(uuid::Uuid::now_v7());
                let write_token = RepositoryWriteToken::acquire(path.as_path()).await;
                let created_repo = repository::create_local(
                    path.as_path(),
                    &write_token,
                    repository_id,
                    default_branch_id,
                    branch::DEFAULT_DEFAULT_NAME.to_string(),
                    repository::RepositoryConfig::default(),
                    false,
                )
                .await
                .expect("Failed to initialize repository");

                let repository = Arc::new(
                    RepositoryContext::new(RepositoryContextCreationArgs {
                        path: Some(path.clone()),
                        immutable_store,
                        mutable_store,
                        id: repository_id,
                        instance_id: created_repo.instance_id,
                        remote: Err(ProtocolError::from(NoRemote)),
                        filter: Arc::default(),
                        format: RepositoryFormat::Lore,
                        filesystem_provider: None,
                    })
                    .with_write_token(write_token.share()),
                );
                lore_revision::instance::store_current_anchor_branch(
                    &repository,
                    default_branch_id,
                )
                .await
                .expect("Failed to store anchor branch");

                let file_path = path.as_path().join("test.file");
                std::fs::write(&file_path, [1u8, 2, 3, 4, 5]).expect("Failed to write test file");

                file::stage::stage(
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

                let commit_options = CommitOptions {
                    message: String::new(),
                    link_messages: std::collections::HashMap::new(),
                    link: None,
                    layer_messages: std::collections::HashMap::new(),
                    layer: None,
                    stats: false,
                };
                let revision = Box::pin(commit::commit(
                    repository.clone(),
                    &write_token,
                    commit_options,
                ))
                .await
                .expect("Failed to commit revision");

                let info_options = InfoOptions {
                    signature: Some(revision.to_string()),
                    delta: true,
                    metadata: false,
                };
                info(repository.clone(), info_options)
                    .await
                    .expect("info() must return Ok(()) for a healthy revision");
            }))
            .await
            .expect("Test task failed");

        drain_events(execution, &events).await;

        let captured = events.lock().expect("lock").clone();
        let discriminants: Vec<u32> = captured.iter().map(|event| event.discriminant()).collect();

        let error_count = captured
            .iter()
            .filter(|event| matches!(event, LoreEvent::Error(_)))
            .count();
        assert_eq!(
            error_count, 0,
            "expected no LoreEvent::Error for a healthy revision, got event discriminants: \
             {discriminants:?}"
        );

        let delta_row_count = captured
            .iter()
            .filter(|event| matches!(event, LoreEvent::RevisionInfoDelta(_)))
            .count();
        assert_eq!(
            delta_row_count, 1,
            "expected exactly one RevisionInfoDelta row for the single staged file, got event \
             discriminants: {discriminants:?}"
        );
    }
}

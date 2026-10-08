// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift, INV-CX): the exact-selection transaction's tests, moved from the inline
//! `src/exact_selection.rs` module when the crate's lib test harness was turned off.
// Fixtures write working-tree files and clean temp dirs directly.
#![allow(clippy::disallowed_methods)]

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use async_trait::async_trait;
use lore_base::error::NoRemote;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Hash;
use lore_base::types::Partition;
use lore_revision::branch;
use lore_revision::commit;
use lore_revision::commit::CommitOptions;
use lore_revision::exact_selection::*;
use lore_revision::interface::ExecutionContext;
use lore_revision::interface::LoreArray;
use lore_revision::interface::LoreError;
use lore_revision::interface::LoreGlobalArgs;
use lore_revision::interface::LoreString;
use lore_revision::lore::BranchId;
use lore_revision::lore::RepositoryId;
use lore_revision::relay::EventDispatcher;
use lore_revision::repository::DOT_LORE;
use lore_revision::repository::RepositoryContext;
use lore_revision::repository::RepositoryContextCreationArgs;
use lore_revision::repository::RepositoryPaths;
use lore_revision::repository::RepositoryWriteToken;
use lore_revision::stage::StageCaseChange;
use lore_revision::stage::StageOptions;
use lore_revision::state;
use lore_revision::state::State;
use lore_revision::util::path::RelativePath;
use lore_storage::LocalMutableStore;
use lore_storage::MutableStore;
use lore_storage::MutableStoreSettings;
use lore_storage::StoreError;
use lore_storage::store_types::KeyType;
use lore_storage::store_types::KeyValueStream;
use lore_transport::ProtocolError;
use md5::Digest;
use md5::Md5;
#[derive(Clone, Copy, Debug, PartialEq)]
struct StoreCall {
    partition: Partition,
    key: Hash,
    value: Hash,
    key_type: KeyType,
    injected_failure: bool,
}

#[derive(Default)]
struct FaultState {
    fail_calls: BTreeSet<usize>,
    calls: Vec<StoreCall>,
}

#[derive(Clone, Default)]
struct StoreFaultControl {
    state: Arc<Mutex<FaultState>>,
}

impl StoreFaultControl {
    fn arm(&self, fail_calls: impl IntoIterator<Item = usize>) {
        let mut state = self.state.lock().expect("lock mutable-store fault state");
        state.fail_calls = fail_calls.into_iter().collect();
        state.calls.clear();
    }

    fn observe_store(
        &self,
        partition: Partition,
        key: Hash,
        value: Hash,
        key_type: KeyType,
    ) -> bool {
        let mut state = self.state.lock().expect("lock mutable-store fault state");
        let call_number = state.calls.len() + 1;
        let injected_failure = state.fail_calls.contains(&call_number);
        state.calls.push(StoreCall {
            partition,
            key,
            value,
            key_type,
            injected_failure,
        });
        injected_failure
    }

    fn calls(&self) -> Vec<StoreCall> {
        self.state
            .lock()
            .expect("read mutable-store fault calls")
            .calls
            .clone()
    }
}

struct FaultInjectingMutableStore {
    inner: Arc<LocalMutableStore>,
    control: StoreFaultControl,
}

#[async_trait]
impl MutableStore for FaultInjectingMutableStore {
    async fn load(
        self: Arc<Self>,
        partition: Partition,
        key: Hash,
        key_type: KeyType,
    ) -> Result<Hash, StoreError> {
        self.inner.clone().load(partition, key, key_type).await
    }

    async fn store(
        self: Arc<Self>,
        partition: Partition,
        key: Hash,
        value: Hash,
        key_type: KeyType,
    ) -> Result<(), StoreError> {
        if self.control.observe_store(partition, key, value, key_type) {
            return Err(StoreError::internal(format!(
                "injected real mutable-store call {}",
                self.control.calls().len()
            )));
        }
        self.inner
            .clone()
            .store(partition, key, value, key_type)
            .await
    }

    async fn compare_and_swap(
        self: Arc<Self>,
        partition: Partition,
        key: Hash,
        expected: Hash,
        value: Hash,
        key_type: KeyType,
    ) -> Result<Hash, StoreError> {
        self.inner
            .clone()
            .compare_and_swap(partition, key, expected, value, key_type)
            .await
    }

    async fn list(
        self: Arc<Self>,
        partition: Partition,
        key_type: KeyType,
    ) -> Result<KeyValueStream, StoreError> {
        self.inner.clone().list(partition, key_type).await
    }

    async fn flush(self: Arc<Self>, sync_data: bool) -> Result<(), StoreError> {
        self.inner.clone().flush(sync_data).await
    }
}

#[derive(Debug)]
struct DurableAnchorEvidence {
    original: commit::ExactAnchorSnapshot,
    published: commit::ExactAnchorSnapshot,
    reopened: commit::ExactAnchorSnapshot,
    calls: Vec<StoreCall>,
    public_error: ExactSelectionError,
}

async fn exercise_real_store_publication_failure(
    fail_calls: impl IntoIterator<Item = usize>,
) -> DurableAnchorEvidence {
    let tempdir = tempfile::tempdir().expect("create real mutable-store fixture");
    let store_path = tempdir.path().join("store");
    let repository_path = tempdir.path().join("repository");
    std::fs::create_dir_all(&repository_path).expect("create repository fixture path");

    let immutable = lore_storage::LocalImmutableStore::new(
        Some(store_path.clone()),
        lore_storage::ImmutableStoreSettings::default(),
    )
    .await
    .expect("create disk-backed immutable store");
    let real_mutable = Arc::new(
        LocalMutableStore::new(
            Some(&store_path),
            MutableStoreSettings::default(),
            immutable.clone(),
        )
        .await
        .expect("create disk-backed mutable store"),
    );
    let control = StoreFaultControl::default();
    let faulting_mutable = Arc::new(FaultInjectingMutableStore {
        inner: real_mutable,
        control: control.clone(),
    });

    let repository_id = RepositoryId::from(uuid::Uuid::now_v7());
    let instance_id = lore_revision::instance::InstanceId::generate();
    let branch = BranchId::from(uuid::Uuid::now_v7());
    let token = RepositoryWriteToken::acquire(&repository_path).await;
    let repository = Arc::new(
        RepositoryContext::new(RepositoryContextCreationArgs {
            paths: Some(RepositoryPaths::new(
                repository_path.clone(),
                repository_path.join(DOT_LORE),
            )),
            immutable_store: immutable.clone(),
            mutable_store: faulting_mutable.clone(),
            id: repository_id,
            instance_id,
            remote: Err(ProtocolError::from(NoRemote)),
            filter: Arc::default(),
            filesystem_provider: None,
        })
        .with_write_token(token),
    );

    let original = commit::ExactAnchorSnapshot {
        branch_latest: Hash::from([1_u8; 32]),
        current: Hash::from([2_u8; 32]),
        staged: Hash::from([3_u8; 32]),
    };
    let published = commit::ExactAnchorSnapshot {
        branch_latest: Hash::from([4_u8; 32]),
        current: Hash::from([4_u8; 32]),
        staged: Hash::default(),
    };

    branch::store_latest_anchor(repository.clone(), branch, original.branch_latest)
        .await
        .expect("seed branch-latest anchor");
    lore_revision::instance::store_current_anchor(&repository, original.current)
        .await
        .expect("seed current anchor");
    lore_revision::instance::store_current_anchor_branch(&repository, branch)
        .await
        .expect("seed current branch anchor");
    lore_revision::instance::store_staged_anchor(&repository, original.staged)
        .await
        .expect("seed staged anchor");
    faulting_mutable
        .clone()
        .flush(true)
        .await
        .expect("persist original anchors");

    let staged_state = State::new();
    staged_state
        .tree(repository.clone())
        .await
        .expect("initialize empty staged tree");
    control.arm(fail_calls);

    let internal_error = commit::finalize_exact_commit(
        repository.clone(),
        &staged_state,
        published.current,
        branch,
        original,
    )
    .await
    .expect_err("injected authoritative publication must reject");
    let public_error = map_exact_finalize_error(internal_error);
    let calls = control.calls();

    faulting_mutable
        .clone()
        .flush(true)
        .await
        .expect("persist post-compensation anchors");
    drop(staged_state);
    drop(repository);
    drop(faulting_mutable);

    let reopened_mutable = Arc::new(
        LocalMutableStore::new(
            Some(&store_path),
            MutableStoreSettings::default(),
            immutable.clone(),
        )
        .await
        .expect("reopen disk-backed mutable store"),
    );
    let reopened_repository = Arc::new(RepositoryContext::new(RepositoryContextCreationArgs {
        paths: Some(RepositoryPaths::new(
            repository_path.clone(),
            repository_path.join(DOT_LORE),
        )),
        immutable_store: immutable,
        mutable_store: reopened_mutable,
        id: repository_id,
        instance_id,
        remote: Err(ProtocolError::from(NoRemote)),
        filter: Arc::default(),
        filesystem_provider: None,
    }));
    let reopened = commit::ExactAnchorSnapshot {
        branch_latest: branch::load_latest(reopened_repository.clone(), branch)
            .await
            .expect("reload durable branch-latest anchor"),
        current: lore_revision::instance::load_current_anchor_boxed(&reopened_repository)
            .await
            .expect("reload durable current anchor")
            .0,
        staged: lore_revision::instance::load_staged_revision(&reopened_repository)
            .await
            .expect("reload durable staged anchor")
            .unwrap_or_default(),
    };

    DurableAnchorEvidence {
        original,
        published,
        reopened,
        calls,
        public_error,
    }
}

fn selected_input(path: String) -> SelectedFile {
    SelectedFile {
        path,
        expected_effective_action: ExpectedFileAction::Delete,
        source_hash: None,
        file_metadata: FileMetadataSelection::Unchanged,
    }
}

fn metadata_input(key: String, value: String) -> FileMetadataEntry {
    FileMetadataEntry {
        key,
        value,
        value_type: ExactMetadataType::String,
    }
}

fn assert_invalid_input(error: ExactSelectionError, reason: &str) {
    assert!(
        matches!(
            error.kind(),
            ExactSelectionErrorKind::InvalidInput { reason: actual, .. }
                if actual.contains(reason)
        ),
        "unexpected bounds error: {error:?}"
    );
}

fn action(path: &str, action: ExpectedFileAction) -> ExactActionRow {
    ExactActionRow {
        path: path.to_string(),
        action,
    }
}

fn normalized(path: &str, expected_action: ExpectedFileAction) -> NormalizedSelectedFile {
    NormalizedSelectedFile {
        row: action(path, expected_action),
        source_hash: None,
        file_metadata: FileMetadataSelection::Unchanged,
        prepared_metadata: Vec::new(),
    }
}

#[test]
fn finalize_publication_failure_maps_public_kind_json_and_internal_code() {
    for anchors_restored in [true, false] {
        let reason = format!("injected anchors_restored={anchors_restored}");
        let error = map_exact_finalize_error(commit::ExactFinalizeError::Publication {
            anchors_restored,
            reason: reason.clone(),
        });

        assert_eq!(
            error.kind(),
            &ExactSelectionErrorKind::PublicationFailure {
                anchors_restored,
                reason: reason.clone(),
            }
        );
        assert_eq!(error.code(), LoreError::Internal as i32);
        assert_eq!(
            serde_json::to_value(error.kind()).expect("serialize public exact error kind"),
            serde_json::json!({
                "kind": "publicationFailure",
                "anchorsRestored": anchors_restored,
                "reason": reason,
            })
        );
    }
}

#[tokio::test]
async fn real_store_one_shot_publication_failure_restores_durable_anchors() {
    LORE_CONTEXT
        .scope(
            Arc::new(ExecutionContext::new_client_with_user_id(
                LoreGlobalArgs::default().set_offline(),
                EventDispatcher::no_dispatch(),
                "exact-real-store-restore-test".to_string(),
            )),
            async {
                let evidence = exercise_real_store_publication_failure([2]).await;

                assert!(
                    matches!(
                        evidence.public_error.kind(),
                        ExactSelectionErrorKind::PublicationFailure {
                            anchors_restored: true,
                            reason,
                        } if reason.contains("injected real mutable-store call 2")
                    ),
                    "one-shot real-store failure must report truthful recovery: {:?}",
                    evidence.public_error
                );
                assert_eq!(evidence.reopened, evidence.original);
                assert_eq!(
                    evidence
                        .calls
                        .iter()
                        .map(|call| (call.value, call.injected_failure))
                        .collect::<Vec<_>>(),
                    vec![
                        (evidence.published.branch_latest, false),
                        (evidence.published.current, true),
                        (evidence.original.branch_latest, false),
                        (evidence.original.current, false),
                        (evidence.original.staged, false),
                    ]
                );
                assert_eq!(evidence.calls[0].key, evidence.calls[2].key);
                assert_eq!(evidence.calls[1].key, evidence.calls[3].key);
                assert_ne!(evidence.calls[0].key, evidence.calls[1].key);
                assert_ne!(evidence.calls[0].key, evidence.calls[4].key);
                assert_ne!(evidence.calls[1].key, evidence.calls[4].key);
            },
        )
        .await;
}

#[tokio::test]
async fn real_store_persistent_restoration_failure_reports_durable_partial_state() {
    LORE_CONTEXT
        .scope(
            Arc::new(ExecutionContext::new_client_with_user_id(
                LoreGlobalArgs::default().set_offline(),
                EventDispatcher::no_dispatch(),
                "exact-real-store-failed-restore-test".to_string(),
            )),
            async {
                let evidence = exercise_real_store_publication_failure([2, 3, 4, 5]).await;

                assert!(
                    matches!(
                        evidence.public_error.kind(),
                        ExactSelectionErrorKind::PublicationFailure {
                            anchors_restored: false,
                            reason,
                        } if reason.contains("injected real mutable-store call 5")
                    ),
                    "persistent real-store failure must report failed recovery: {:?}",
                    evidence.public_error
                );
                assert_eq!(
                    evidence.reopened,
                    commit::ExactAnchorSnapshot {
                        branch_latest: evidence.published.branch_latest,
                        current: evidence.original.current,
                        staged: evidence.original.staged,
                    }
                );
                assert_eq!(
                    evidence
                        .calls
                        .iter()
                        .map(|call| (call.value, call.injected_failure))
                        .collect::<Vec<_>>(),
                    vec![
                        (evidence.published.branch_latest, false),
                        (evidence.published.current, true),
                        (evidence.original.branch_latest, true),
                        (evidence.original.branch_latest, true),
                        (evidence.original.branch_latest, true),
                        (evidence.original.current, false),
                        (evidence.original.staged, false),
                    ]
                );
                assert_eq!(evidence.calls[0].key, evidence.calls[2].key);
                assert_eq!(evidence.calls[2].key, evidence.calls[3].key);
                assert_eq!(evidence.calls[3].key, evidence.calls[4].key);
                assert_eq!(evidence.calls[1].key, evidence.calls[5].key);
                assert_ne!(evidence.calls[0].key, evidence.calls[1].key);
                assert_ne!(evidence.calls[0].key, evidence.calls[6].key);
                assert_ne!(evidence.calls[1].key, evidence.calls[6].key);
            },
        )
        .await;
}

#[test]
fn input_bounds_accept_and_reject_selected_count_and_path_bytes_at_boundary() {
    let selected = selected_input("a".to_string());
    let mut files = vec![selected; MAX_SELECTED_FILES];
    validate_input_bounds("", &files, &[]).expect("selected count at limit must pass bounds");
    files.push(selected_input("a".to_string()));
    assert_invalid_input(
        validate_input_bounds("", &files, &[]).expect_err("selected count over limit must reject"),
        "selected file count",
    );

    let exact_path = "é".repeat(MAX_REPOSITORY_RELATIVE_PATH_BYTES / 2);
    let exact = vec![selected_input(exact_path)];
    validate_input_bounds("", &exact, &[]).expect("path byte count at limit must pass bounds");
    let over_path = format!("{}a", exact[0].path);
    let error = validate_input_bounds("", &[selected_input(over_path.clone())], &[])
        .expect_err("path byte count over limit must reject");
    assert_eq!(
        error.kind(),
        &ExactSelectionErrorKind::PathNormalization {
            path: over_path,
            reason: format!("path exceeds limit {MAX_REPOSITORY_RELATIVE_PATH_BYTES} bytes"),
        }
    );
}

#[test]
fn input_bounds_accept_and_reject_file_and_revision_metadata_counts_at_boundary() {
    let entry = metadata_input("key".to_string(), "value".to_string());
    let mut file_entries = vec![entry.clone(); MAX_METADATA_ENTRIES_PER_SCOPE];
    let mut files = vec![selected_input("asset.bin".to_string())];
    files[0].file_metadata = FileMetadataSelection::Exact(file_entries.clone());
    validate_input_bounds("", &files, &[]).expect("file metadata count at limit must pass");
    file_entries.push(entry.clone());
    files[0].file_metadata = FileMetadataSelection::Exact(file_entries);
    assert_invalid_input(
        validate_input_bounds("", &files, &[])
            .expect_err("file metadata count over limit must reject"),
        "file metadata entry count",
    );

    let mut revision_entries = vec![entry; MAX_METADATA_ENTRIES_PER_SCOPE];
    validate_input_bounds("", &[], &revision_entries)
        .expect("revision metadata count at limit must pass");
    revision_entries.push(metadata_input("key".to_string(), "value".to_string()));
    assert_invalid_input(
        validate_input_bounds("", &[], &revision_entries)
            .expect_err("revision metadata count over limit must reject"),
        "revision metadata entry count",
    );
}

#[test]
fn input_bounds_measure_metadata_key_and_value_limits_in_utf8_bytes() {
    let exact_key = "é".repeat(MAX_METADATA_KEY_BYTES / 2);
    validate_input_bounds("", &[], &[metadata_input(exact_key.clone(), String::new())])
        .expect("metadata key byte count at limit must pass");
    assert_invalid_input(
        validate_input_bounds(
            "",
            &[],
            &[metadata_input(format!("{exact_key}a"), String::new())],
        )
        .expect_err("metadata key byte count over limit must reject"),
        "metadata key exceeds limit",
    );

    let exact_value = "é".repeat(MAX_METADATA_VALUE_BYTES / 2);
    validate_input_bounds(
        "",
        &[],
        &[metadata_input("key".to_string(), exact_value.clone())],
    )
    .expect("metadata value byte count at limit must pass");
    assert_invalid_input(
        validate_input_bounds(
            "",
            &[],
            &[metadata_input("key".to_string(), format!("{exact_value}a"))],
        )
        .expect_err("metadata value byte count over limit must reject"),
        "metadata value exceeds limit",
    );
}

#[test]
fn input_bounds_accept_and_reject_aggregate_bytes_at_boundary() {
    let mut file = selected_input("a".to_string());
    file.source_hash = Some("x".repeat(MAX_AGGREGATE_INPUT_BYTES - file.path.len()));
    validate_input_bounds("", &[file.clone()], &[])
        .expect("aggregate input byte count at limit must pass");
    file.source_hash
        .as_mut()
        .expect("source hash exists")
        .push('x');
    assert_invalid_input(
        validate_input_bounds("", &[file], &[])
            .expect_err("aggregate input byte count over limit must reject"),
        "aggregate input size exceeds limit",
    );
}

#[test]
fn input_bounds_include_commit_message_in_aggregate_bytes() {
    let mut message = "m".repeat(MAX_AGGREGATE_INPUT_BYTES);
    validate_input_bounds(&message, &[], &[])
        .expect("message at aggregate byte limit must pass bounds");
    message.push('m');
    assert_invalid_input(
        validate_input_bounds(&message, &[], &[])
            .expect_err("message over aggregate byte limit must reject"),
        "aggregate input size exceeds limit",
    );
}

#[tokio::test]
#[allow(clippy::disallowed_methods)] // Cleans an isolated temp fixture, not a repository path.
async fn binary_metadata_read_is_capped_one_byte_past_limit() {
    let root =
        std::env::temp_dir().join(format!("lore-exact-binary-bound-{}", uuid::Uuid::now_v7()));
    std::fs::create_dir_all(&root).expect("create binary bounds fixture");
    let source = root.join("oversized.bin");
    let file = std::fs::File::create(&source).expect("create sparse binary metadata source");
    file.set_len(MAX_BINARY_METADATA_PAYLOAD_BYTES + 1)
        .expect("size sparse binary metadata source");
    drop(file);

    let selected = SelectedFile {
        path: "asset.bin".to_string(),
        expected_effective_action: ExpectedFileAction::Add,
        source_hash: Some("00000000000000000000000000000000".to_string()),
        file_metadata: FileMetadataSelection::Exact(vec![FileMetadataEntry {
            key: "payload".to_string(),
            value: source.display().to_string(),
            value_type: ExactMetadataType::Binary,
        }]),
    };
    let error = match normalize_selected_files(&root, vec![selected]).await {
        Ok(_) => panic!("binary metadata source over cap must reject"),
        Err(error) => error,
    };
    let _ = std::fs::remove_dir_all(&root);

    assert!(
        matches!(
            error.kind(),
            ExactSelectionErrorKind::MetadataInputRead { path, key, reason, .. }
                if path == "asset.bin"
                    && key == "payload"
                    && reason.contains("binary metadata payload exceeds limit")
        ),
        "unexpected capped binary read error: {error:?}"
    );
}

#[test]
fn admission_result_is_extracted_before_anchor_publication() {
    let source = include_str!("../../src/exact_selection.rs");
    let extraction = source
        .rfind("let mut result = admission")
        .expect("exact transaction extracts admission result");
    let publication = source
        .rfind("commit::finalize_exact_commit(")
        .expect("exact transaction publishes authoritative anchors");

    assert!(
        extraction < publication,
        "fallible admission extraction must precede authoritative anchor publication"
    );
}

#[test]
fn action_comparison_reports_missing_extra_and_mismatch_rows_deterministically() {
    let expected = vec![
        action("action.bin", ExpectedFileAction::Delete),
        action("missing.bin", ExpectedFileAction::Modify),
    ];
    let actual = vec![
        action("action.bin", ExpectedFileAction::Modify),
        action("extra.bin", ExpectedFileAction::Add),
    ];

    let (missing, extras, mismatches) = compare_action_sets(&expected, &actual);

    assert_eq!(
        (missing, extras, mismatches,),
        (
            vec![action("missing.bin", ExpectedFileAction::Modify)],
            vec![action("extra.bin", ExpectedFileAction::Add)],
            vec![ExactActionMismatch {
                path: "action.bin".to_string(),
                expected: ExpectedFileAction::Delete,
                actual: ExpectedFileAction::Modify,
            }],
        )
    );
}

#[test]
fn semantic_action_membership_reports_the_semantic_authority() {
    let expected = vec![
        action("action.bin", ExpectedFileAction::Delete),
        action("missing.bin", ExpectedFileAction::Modify),
    ];
    let actual = vec![
        action("action.bin", ExpectedFileAction::Modify),
        action("extra.bin", ExpectedFileAction::Add),
    ];

    let error = validate_action_membership(&expected, &actual, ActionAuthority::Semantic)
        .expect_err("semantic membership mismatch must reject");

    assert_eq!(
        error.kind(),
        &ExactSelectionErrorKind::SemanticSelectionMismatch {
            expected,
            actual,
            missing: vec![action("missing.bin", ExpectedFileAction::Modify)],
            extras: vec![action("extra.bin", ExpectedFileAction::Add)],
            action_mismatches: vec![ExactActionMismatch {
                path: "action.bin".to_string(),
                expected: ExpectedFileAction::Delete,
                actual: ExpectedFileAction::Modify,
            }],
        }
    );
}

#[tokio::test]
async fn immutable_read_failure_reports_selected_path_and_cause() {
    let error = map_immutable_read("missing.bin", async {
        Err("injected immutable absence".to_string())
    })
    .await
    .expect_err("missing immutable content must reject");

    assert_eq!(
        error.kind(),
        &ExactSelectionErrorKind::MissingImmutableContent {
            path: "missing.bin".to_string(),
            reason: "injected immutable absence".to_string(),
        }
    );
}

#[test]
fn metadata_membership_rejects_changed_unselected_path() {
    let selected = vec![normalized("selected.bin", ExpectedFileAction::Modify)];
    let expected_metadata = BTreeMap::from([("selected.bin".to_string(), Hash::from([1_u8; 32]))]);
    let current_metadata = BTreeMap::from([
        ("selected.bin".to_string(), Hash::from([1_u8; 32])),
        ("unselected.bin".to_string(), Hash::from([2_u8; 32])),
    ]);
    let staged_metadata = BTreeMap::from([
        ("selected.bin".to_string(), Hash::from([1_u8; 32])),
        ("unselected.bin".to_string(), Hash::from([3_u8; 32])),
    ]);

    let error = validate_metadata_membership(
        &selected,
        &expected_metadata,
        &current_metadata,
        &staged_metadata,
    )
    .expect_err("changed unselected metadata must reject");

    assert_eq!(
        error.kind(),
        &ExactSelectionErrorKind::UnselectedFileMetadata {
            paths: vec!["unselected.bin".to_string()],
        }
    );
}

#[test]
fn metadata_membership_rejects_staged_hash_mismatch() {
    let selected = vec![normalized("selected.bin", ExpectedFileAction::Modify)];
    let expected_hash = Hash::from([1_u8; 32]);
    let staged_hash = Hash::from([2_u8; 32]);
    let expected_metadata = BTreeMap::from([("selected.bin".to_string(), expected_hash)]);
    let current_metadata = BTreeMap::new();
    let staged_metadata = BTreeMap::from([("selected.bin".to_string(), staged_hash)]);

    let error = validate_metadata_membership(
        &selected,
        &expected_metadata,
        &current_metadata,
        &staged_metadata,
    )
    .expect_err("staged metadata hash mismatch must reject");

    assert_eq!(
        error.kind(),
        &ExactSelectionErrorKind::StagedMetadataHashMismatch {
            mismatches: vec![ExactMetadataMismatch {
                path: "selected.bin".to_string(),
                expected_hash: expected_hash.to_string(),
                staged_hash: staged_hash.to_string(),
            }],
        }
    );
}

// -- Store-after-finalize ordering (`commit_exact_selection` composes
//    `commit_staged_revision` + `finalize_exact_commit` + `modified_times.store()`
//    directly, rather than going through `commit()`) --------------------------

/// A real disk-backed `MutableStore` that fails every `store()` call to one
/// pre-known key once `armed`, and passes everything else straight through to
/// a real `LocalMutableStore`. Unlike `FaultInjectingMutableStore` above (which
/// matches by ordinal call number, suited to a narrow, fully-enumerated call
/// sequence), this matches by key identity so it can be wired into a full,
/// realistic `commit_exact_selection` run without needing to know or hardcode
/// how many unrelated store calls precede the one under test.
struct FailKeyMutableStore {
    inner: Arc<LocalMutableStore>,
    poison_key: Hash,
    armed: Arc<AtomicBool>,
    triggered: Arc<AtomicBool>,
}

#[async_trait]
impl MutableStore for FailKeyMutableStore {
    async fn load(
        self: Arc<Self>,
        partition: Partition,
        key: Hash,
        key_type: KeyType,
    ) -> Result<Hash, StoreError> {
        self.inner.clone().load(partition, key, key_type).await
    }

    async fn store(
        self: Arc<Self>,
        partition: Partition,
        key: Hash,
        value: Hash,
        key_type: KeyType,
    ) -> Result<(), StoreError> {
        if self.armed.load(Ordering::SeqCst) && key == self.poison_key {
            self.triggered.store(true, Ordering::SeqCst);
            return Err(StoreError::internal(
                "injected finalize anchor-write failure",
            ));
        }
        self.inner
            .clone()
            .store(partition, key, value, key_type)
            .await
    }

    async fn compare_and_swap(
        self: Arc<Self>,
        partition: Partition,
        key: Hash,
        expected: Hash,
        value: Hash,
        key_type: KeyType,
    ) -> Result<Hash, StoreError> {
        self.inner
            .clone()
            .compare_and_swap(partition, key, expected, value, key_type)
            .await
    }

    async fn list(
        self: Arc<Self>,
        partition: Partition,
        key_type: KeyType,
    ) -> Result<KeyValueStream, StoreError> {
        self.inner.clone().list(partition, key_type).await
    }

    async fn flush(self: Arc<Self>, sync_data: bool) -> Result<(), StoreError> {
        self.inner.clone().flush(sync_data).await
    }
}

fn store_order_execution() -> Arc<ExecutionContext> {
    Arc::new(ExecutionContext::new_client_with_user_id(
        LoreGlobalArgs::default().set_offline(),
        EventDispatcher::no_dispatch(),
        "exact-selection-store-order-test".to_string(),
    ))
}

/// A real, disk-backed repository with a legitimate baseline commit already
/// published, wired so the caller can arm a deterministic write failure on the
/// branch-latest anchor -- `finalize_exact_commit`'s first authoritative write
/// -- at a moment of the caller's choosing (after the baseline commit, so the
/// baseline itself is unaffected).
// Test fixture writes the working-tree file directly, outside repository
// token discipline -- there is no staged content yet for a token-gated
// helper to write.
#[allow(clippy::disallowed_methods)]
async fn build_exact_selection_store_order_fixture() -> (
    tempfile::TempDir,
    Arc<RepositoryContext>,
    RepositoryWriteToken,
    PathBuf,
    BranchId,
    Arc<AtomicBool>,
    Arc<AtomicBool>,
) {
    let tempdir = tempfile::tempdir().expect("create real mutable-store fixture");
    let store_path = tempdir.path().join("store");
    let repository_path = tempdir.path().join("repository");
    std::fs::create_dir_all(&repository_path).expect("create repository fixture path");

    let immutable = lore_storage::LocalImmutableStore::new(
        Some(store_path.clone()),
        lore_storage::ImmutableStoreSettings::default(),
    )
    .await
    .expect("create disk-backed immutable store");
    let real_mutable = Arc::new(
        LocalMutableStore::new(
            Some(&store_path),
            MutableStoreSettings::default(),
            immutable.clone(),
        )
        .await
        .expect("create disk-backed mutable store"),
    );

    let repository_id = RepositoryId::from(uuid::Uuid::now_v7());
    let instance_id = lore_revision::instance::InstanceId::generate();
    let branch = BranchId::from(uuid::Uuid::now_v7());

    // The branch-latest anchor key is deterministic from (salt, repository id,
    // branch id) alone, so it can be computed before the repository -- let alone
    // any commit -- exists.
    let (poison_key, _) = lore_revision::branch::mutable_key(
        lore_revision::repository::SALT_LORE,
        branch::LATEST,
        repository_id,
        branch,
    );
    let armed = Arc::new(AtomicBool::new(false));
    let triggered = Arc::new(AtomicBool::new(false));
    let mutable: Arc<dyn MutableStore> = Arc::new(FailKeyMutableStore {
        inner: real_mutable,
        poison_key,
        armed: armed.clone(),
        triggered: triggered.clone(),
    });

    let token = RepositoryWriteToken::acquire(&repository_path).await;
    let repository = Arc::new(
        RepositoryContext::new(RepositoryContextCreationArgs {
            paths: Some(RepositoryPaths::new(
                repository_path.clone(),
                repository_path.join(DOT_LORE),
            )),
            immutable_store: immutable,
            mutable_store: mutable,
            id: repository_id,
            instance_id,
            remote: Err(ProtocolError::from(NoRemote)),
            filter: Arc::default(),
            filesystem_provider: None,
        })
        .with_write_token(token.share()),
    );

    lore_revision::instance::register_instance(
        &repository,
        instance_id,
        &repository_path.display().to_string(),
    )
    .await
    .expect("register instance");
    branch::create(
        repository.clone(),
        &token,
        branch,
        "main",
        branch::default_category(),
        "exact-selection-store-order-test",
        lore_revision::util::time::timestamp(),
        vec![],
        false,
        false,
    )
    .await
    .expect("create default branch");
    lore_revision::instance::store_current_anchor_branch(&repository, branch)
        .await
        .expect("seed current-branch anchor");

    // A real baseline commit, going through the ordinary `commit()` path (not
    // exact-selection), so the branch's LATEST/LATEST_STATUS/LATEST_HISTORY and
    // the current/staged anchors all carry legitimate values before the test
    // arms the poisoned key -- exact-selection's early reads (`load_current_anchor`,
    // `branch::load_latest`) require exactly this state to already exist.
    std::fs::write(repository_path.join("baseline.txt"), b"baseline\n")
        .expect("write baseline fixture file");
    lore_revision::file::stage::stage(
        repository.clone(),
        &token,
        LoreArray::from_vec(vec![LoreString::from(&repository_path)]),
        StageOptions {
            case_change: StageCaseChange::Error,
            scan: true,
            ..Default::default()
        },
    )
    .await
    .expect("stage baseline fixture file");
    commit::commit_boxed(
        repository.clone(),
        &token,
        CommitOptions::new("baseline".to_string()),
    )
    .await
    .expect("commit baseline revision");

    (
        tempdir,
        repository,
        token,
        repository_path,
        branch,
        armed,
        triggered,
    )
}

fn exact_add(path: &str, bytes: &[u8]) -> SelectedFile {
    SelectedFile {
        path: path.to_string(),
        expected_effective_action: ExpectedFileAction::Add,
        source_hash: Some(hex::encode(Md5::digest(bytes))),
        file_metadata: FileMetadataSelection::Unchanged,
    }
}

/// Positive control for the ordering property below: a successful
/// exact-selection commit (finalize succeeds) must store the modified times it
/// recorded while fragmenting the new file, exactly as `commit()` does for the
/// ordinary commit path.
// Test fixture writes the working-tree file directly, outside repository
// token discipline -- there is no staged content yet for a token-gated
// helper to write.
#[allow(clippy::disallowed_methods)]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn commit_exact_selection_stores_modified_times_after_a_successful_finalize() {
    LORE_CONTEXT
        .scope(store_order_execution(), async {
            let (_tempdir, repository, token, repository_path, _branch, armed, triggered) =
                build_exact_selection_store_order_fixture().await;
            // Not armed for this test, but confirm the fixture itself never
            // trips the poison during the exercised call, or a false positive
            // here would be indistinguishable from a passing test.
            assert!(!armed.load(Ordering::SeqCst));

            std::fs::write(repository_path.join("added.txt"), b"exact add\n")
                .expect("write exact-selection fixture file");

            let path =
                RelativePath::new_from_initial_path("added.txt").expect("clean relative path");
            assert_eq!(
                state::file_modified_time(repository.clone(), &path).await,
                0,
                "sanity: nothing recorded for a path before exact-selection has run"
            );

            commit_exact_selection(
                repository.clone(),
                &token,
                ExactSelectionOptions {
                    message: "exact selection stores modified times".to_string(),
                    files: vec![exact_add("added.txt", b"exact add\n")],
                    revision_metadata: Vec::new(),
                    stats: false,
                },
            )
            .await
            .expect("exact-selection commit succeeds");

            assert!(
                !triggered.load(Ordering::SeqCst),
                "positive control must not exercise the poisoned key"
            );
            let recorded = state::file_modified_time(repository.clone(), &path).await;
            assert_ne!(
                recorded, 0,
                "a successful exact-selection commit must store the modified times \
                 it recorded while fragmenting the added file"
            );
        })
        .await;
}

/// A `finalize_exact_commit` failure must store nothing: the modified time
/// `commit_staged_revision` already recorded in memory for the fragmented file
/// must never reach the mutable store for a revision that never became current.
/// Recording a time for a revision that did not land is exactly the correctness
/// defect upstream's `RecordedModifiedTimes` design fixes -- a following `stage`
/// would then trust a cached witness describing content the working copy was
/// never advanced to.
// Test fixture writes the working-tree file directly, outside repository
// token discipline -- there is no staged content yet for a token-gated
// helper to write.
#[allow(clippy::disallowed_methods)]
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn commit_exact_selection_stores_nothing_when_finalize_fails() {
    LORE_CONTEXT
        .scope(store_order_execution(), async {
            let (_tempdir, repository, token, repository_path, _branch, armed, triggered) =
                build_exact_selection_store_order_fixture().await;

            std::fs::write(repository_path.join("added.txt"), b"exact add\n")
                .expect("write exact-selection fixture file");

            let path =
                RelativePath::new_from_initial_path("added.txt").expect("clean relative path");
            assert_eq!(
                state::file_modified_time(repository.clone(), &path).await,
                0,
                "sanity: nothing recorded for a path before exact-selection has run"
            );

            // Arm only now: the baseline commit inside the fixture already
            // wrote this exact key once (legitimately) and must not be
            // disturbed, only the write `finalize_exact_commit` makes below.
            armed.store(true, Ordering::SeqCst);

            let error = commit_exact_selection(
                repository.clone(),
                &token,
                ExactSelectionOptions {
                    message: "exact selection finalize failure stores nothing".to_string(),
                    files: vec![exact_add("added.txt", b"exact add\n")],
                    revision_metadata: Vec::new(),
                    stats: false,
                },
            )
            .await
            .expect_err("poisoned branch-latest anchor write must reject the commit");

            assert!(
                triggered.load(Ordering::SeqCst),
                "the injected fault must actually have fired for this to be a \
                 meaningful negative control"
            );
            assert!(
                matches!(
                    error.kind(),
                    ExactSelectionErrorKind::PublicationFailure { .. }
                ),
                "unexpected exact-selection error shape: {error:?}"
            );
            assert_eq!(
                state::file_modified_time(repository.clone(), &path).await,
                0,
                "a finalize_exact_commit failure must store no modified time, even \
                 though commit_staged_revision already recorded one in memory for \
                 the fragmented file"
            );
        })
        .await;
}
#[allow(clippy::disallowed_methods)] // Remove only the isolated fixture's selected Add.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn vanished_add_after_stage_rejects_before_fragmentation_and_preserves_anchors() {
    LORE_CONTEXT.scope(store_order_execution(), async {
        let (_tempdir, repository, token, root, branch, armed, triggered) =
            build_exact_selection_store_order_fixture().await;
        assert!(!armed.load(Ordering::SeqCst));
        let added = b"vanishing add\n";
        let path = root.join("vanish.bin");
        std::fs::write(&path, added).expect("write selected Add");
        let before = vanished_add_anchors(&repository, branch).await;
        let removed = Arc::new(AtomicBool::new(false));
        let hook_removed = removed.clone();
        let hook: Box<dyn FnOnce() + Send> = Box::new(move || {
            std::fs::remove_file(path).expect("remove selected Add synchronously after stage");
            hook_removed.store(true, Ordering::SeqCst);
        });
        let error = AFTER_EXACT_STAGE.scope(std::cell::RefCell::new(Some(hook)),
            commit_exact_selection(repository.clone(), &token, ExactSelectionOptions {
                message: "vanished Add".to_string(),
                files: vec![exact_add("vanish.bin", added)],
                revision_metadata: Vec::new(),
                stats: false,
            })
        ).await.expect_err("Add removed after staging must reject");
        assert!(removed.load(Ordering::SeqCst), "post-stage hook must run");
        assert!(matches!(error.kind(), ExactSelectionErrorKind::PreFragmentationFileRead { path, .. } if path == "vanish.bin"), "unexpected vanished-Add error: {error:?}");
        assert_eq!(vanished_add_anchors(&repository, branch).await, before);
        assert!(!triggered.load(Ordering::SeqCst), "no unrelated store fault may fire");
    }).await;
}

async fn vanished_add_anchors(
    repository: &Arc<RepositoryContext>,
    branch: BranchId,
) -> (Hash, Option<Hash>, Hash) {
    (
        lore_revision::instance::load_current_anchor_boxed(repository)
            .await
            .expect("current anchor")
            .0,
        lore_revision::instance::load_staged_revision(repository)
            .await
            .expect("staged anchor"),
        branch::load_latest_history(repository.clone(), branch, None)
            .await
            .expect("branch latest anchor")
            .revision,
    )
}

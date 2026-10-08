// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
mod operation_tests;
mod statistics_level_tests;
mod walk_tests;

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use lore_base::error::NotALayer;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Hash;
use lore_revision::branch;
use lore_revision::commit::*;
use lore_revision::fs::filesystem_provider::with_operation;
use lore_revision::interface::LoreArray;
use lore_revision::interface::LoreString;
use lore_revision::lore::BranchId;
use lore_revision::lore::RepositoryId;
use lore_revision::node::NodeFlags;
use lore_revision::node::ROOT_NODE;
use lore_revision::repository::RepositoryWriteToken;
use lore_revision::runtime::execution_context;
use lore_revision::state;
use lore_revision::state::RecordedModifiedTimes;
use lore_revision::state::State;
use lore_revision::util::path::RelativePath;

#[test]
fn commit_options_new_has_empty_layer_defaults() {
    let opts = CommitOptions::new("msg".into());
    assert!(opts.layer_messages.is_empty());
    assert!(opts.layer.is_none());
    assert!(opts.link_messages.is_empty());
    assert!(opts.link.is_none());
}

#[test]
fn commit_error_carries_not_a_layer() {
    let err: CommitError = NotALayer {
        path: "external/lib".into(),
    }
    .into();
    assert!(matches!(err, CommitError::NotALayer { .. }));
    assert!(err.to_string().contains("external/lib"));
}

// ---------------------------------------------------------------------------
// FORK-LOCAL (Tideshift): exact-selection anchor publication (INV-CX) and the
// `commit_files_and_rehash` wrapper's `modified_times` forwarding. Moved from the
// inline `src/commit.rs` tests when the crate's lib test harness was turned off.
// ---------------------------------------------------------------------------

fn anchor_index(kind: ExactAnchorKind) -> usize {
    match kind {
        ExactAnchorKind::BranchLatest => 0,
        ExactAnchorKind::Current => 1,
        ExactAnchorKind::Staged => 2,
    }
}

#[tokio::test]
async fn exact_anchor_publication_failure_restores_every_original_anchor() {
    let original = ExactAnchorSnapshot {
        branch_latest: Hash::from([1_u8; 32]),
        current: Hash::from([2_u8; 32]),
        staged: Hash::from([3_u8; 32]),
    };
    let published = ExactAnchorSnapshot {
        branch_latest: Hash::from([4_u8; 32]),
        current: Hash::from([5_u8; 32]),
        staged: Hash::default(),
    };

    for fail_on in [
        ExactAnchorKind::BranchLatest,
        ExactAnchorKind::Current,
        ExactAnchorKind::Staged,
    ] {
        let anchors = Arc::new(Mutex::new([
            original.branch_latest,
            original.current,
            original.staged,
        ]));
        let injected = Arc::new(AtomicBool::new(false));
        let mut writer = |kind, value| {
            let anchors = anchors.clone();
            let injected = injected.clone();
            async move {
                if kind == fail_on && !injected.swap(true, Ordering::SeqCst) {
                    return Err(format!("injected {kind:?} publication failure"));
                }
                anchors.lock().expect("lock anchor fixture")[anchor_index(kind)] = value;
                Ok(())
            }
        };

        let error =
            publish_exact_anchor_snapshot_with_compensation(original, published, &mut writer)
                .await
                .expect_err("injected publication step must reject");
        assert_eq!(
            error,
            ExactFinalizeError::Publication {
                anchors_restored: true,
                reason: format!(
                    "publishing anchors failed: injected {fail_on:?} publication failure"
                ),
            }
        );
        assert_eq!(
            *anchors.lock().expect("read restored anchors"),
            [original.branch_latest, original.current, original.staged],
            "all original anchors must be exact after {fail_on:?} rejection"
        );
    }
}

#[tokio::test]
async fn exact_anchor_publication_reports_when_original_anchor_restoration_fails() {
    let original = ExactAnchorSnapshot {
        branch_latest: Hash::from([1_u8; 32]),
        current: Hash::from([2_u8; 32]),
        staged: Hash::from([3_u8; 32]),
    };
    let published = ExactAnchorSnapshot {
        branch_latest: Hash::from([4_u8; 32]),
        current: Hash::from([5_u8; 32]),
        staged: Hash::default(),
    };
    let anchors = Arc::new(Mutex::new([
        original.branch_latest,
        original.current,
        original.staged,
    ]));
    let mut writer = |kind, value| {
        let anchors = anchors.clone();
        async move {
            if kind == ExactAnchorKind::Current && value == published.current {
                return Err("injected current publication failure".to_string());
            }
            if kind == ExactAnchorKind::BranchLatest && value == original.branch_latest {
                return Err("injected branch restoration failure".to_string());
            }
            anchors.lock().expect("lock anchor fixture")[anchor_index(kind)] = value;
            Ok(())
        }
    };

    let error = publish_exact_anchor_snapshot_with_compensation(original, published, &mut writer)
        .await
        .expect_err("publication and restoration failures must reject");

    assert_eq!(
        error,
        ExactFinalizeError::Publication {
            anchors_restored: false,
            reason: "publishing anchors failed (injected current publication failure); restoring the original anchors failed (BranchLatest: injected branch restoration failure)".to_string(),
        }
    );
    assert_eq!(
        *anchors.lock().expect("read unrestored anchors"),
        [published.branch_latest, original.current, original.staged],
        "failed restoration must leave the partial publication observable"
    );
}

/// Standalone fixture for the public `commit_files_and_rehash` wrapper: a
/// real disk-backed repository with one staged file, built without going
/// through `commit_staged_revision` (the other, already-covered call
/// site), so this test can observe only what the wrapper itself does with
/// the `modified_times` collector its caller hands it.
fn wrapper_fixture_execution() -> Arc<lore_revision::interface::ExecutionContext> {
    Arc::new(
        lore_revision::interface::ExecutionContext::new_client_with_user_id(
            lore_revision::interface::LoreGlobalArgs::default().set_offline(),
            lore_revision::relay::EventDispatcher::no_dispatch(),
            "commit-files-and-rehash-wrapper-test".to_string(),
        ),
    )
}

/// Regression for the merge that produced a `commit_files_and_rehash`
/// wrapper which accepted the caller's `modified_times` parameter and then
/// never forwarded it to `commit_files_and_rehash_with_admission`,
/// recording every fragmented file's time into an internal collector the
/// caller could never observe or `store()`.
///
/// This calls the wrapper directly (not `commit_staged_revision`, which
/// delegates to `commit_files_and_rehash_with_admission` itself and so
/// cannot see a bug confined to the wrapper's delegation call), passes in a
/// `RecordedModifiedTimes` the test owns, and proves the wrapper's work
/// reaches that exact instance: `store()`-ing it must persist a non-zero
/// mtime for the file the wrapper fragmented.
///
/// Confirmed to catch the regression: reverting the wrapper's delegation
/// call to build a fresh `Arc::new(RecordedModifiedTimes::default())`
/// in place of forwarding `modified_times` turns this test red (the
/// caller's collector stays empty, so `store()` is a no-op and the
/// read-back stays 0); restoring the forwarding turns it green again.
// Test fixture writes the working-tree file directly, outside repository
// token discipline -- there is no staged content yet for a token-gated
// helper to write.
#[allow(clippy::disallowed_methods)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn commit_files_and_rehash_wrapper_forwards_callers_modified_times() {
    LORE_CONTEXT
        .scope(wrapper_fixture_execution(), async {
            let tempdir = tempfile::tempdir().expect("create temp repository dir");
            let root = tempdir.path().to_path_buf();
            let branch_id = BranchId::from(uuid::Uuid::now_v7());
            let write_token = RepositoryWriteToken::acquire(&root).await;
            let repository = lore_revision::repository::create_local(
                &root,
                &write_token,
                RepositoryId::from(uuid::Uuid::now_v7()),
                branch_id,
                branch::DEFAULT_DEFAULT_NAME.to_string(),
                lore_revision::repository::RepositoryConfig::default(),
                false,
            )
            .await
            .expect("create local repository fixture");

            std::fs::write(root.join("tracked.txt"), b"hello world").expect("write fixture file");

            lore_revision::file::stage::stage(
                repository.clone(),
                &write_token,
                LoreArray::from_vec(vec![LoreString::from(&root)]),
                lore_revision::stage::StageOptions {
                    case_change: lore_revision::stage::StageCaseChange::Error,
                    node_flags: NodeFlags::NoFlags,
                    file_id: None,
                    no_children: false,
                    scan: true,
                },
            )
            .await
            .expect("stage fixture file");

            let staged_revision = lore_revision::instance::load_staged_revision(&repository)
                .await
                .expect("load staged anchor")
                .expect("staged anchor present after staging a new file");
            let state_staged = State::deserialize(repository.clone(), staged_revision)
                .await
                .expect("deserialize staged state");

            let metadata = build_commit_metadata(
                repository.clone(),
                &state_staged,
                branch_id,
                "wrapper forwards modified times".to_string(),
                LoreArray::from_vec(Vec::new()),
                LoreArray::from_vec(Vec::new()),
                LoreArray::from_vec(Vec::new()),
            )
            .await
            .expect("build commit metadata fixture");

            prune_dirty_for_commit(state_staged.clone(), repository.clone())
                .await
                .expect("prune dirty state before rehash");

            let tracker = Arc::new(lore_storage::write_tracker::WriteTracker::new());
            let modified_times = Arc::new(RecordedModifiedTimes::default());

            // Exercise the WRAPPER, not `commit_staged_revision` -- this is the
            // delegation site the merge dropped the parameter at. Upstream v0.10.1
            // reads the working tree through a filesystem operation, so the fixture
            // opens one around the call the way `commit()` does.
            with_operation(repository.file_system(), async |operation| {
                commit_files_and_rehash(
                    operation,
                    repository.clone(),
                    write_token.share(),
                    state_staged.clone(),
                    RelativePath::new(),
                    ROOT_NODE,
                    metadata,
                    Arc::new(HashMap::new()),
                    branch_id,
                    tracker.clone(),
                    modified_times.clone(),
                    CommitStats::new(),
                    execution_context().globals().event_interval(),
                )
                .await
            })
            .await
            .expect("wrapper rehash succeeds");
            tracker
                .await_all()
                .await
                .expect("drain rehash tracker after wrapper call");

            let path =
                RelativePath::new_from_initial_path("tracked.txt").expect("clean relative path");
            assert_eq!(
                state::file_modified_time(repository.clone(), &path).await,
                0,
                "recording happens in-memory only; nothing is durable before store()"
            );

            // This is the caller's own collector -- if the wrapper silently
            // built and used a fresh one internally instead of forwarding it,
            // this `store()` call has nothing to write and the read-back below
            // stays 0.
            modified_times.store(repository.clone()).await;

            let recorded = state::file_modified_time(repository.clone(), &path).await;
            assert_ne!(
                recorded, 0,
                "commit_files_and_rehash must forward the caller's \
                 RecordedModifiedTimes into the inner commit so the fragmented \
                 file's mtime reaches it, rather than being recorded into an \
                 internal collector the caller can never store"
            );
        })
        .await;
}

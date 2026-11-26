// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! [CLIENT] `local_commit_evidence`: a journalled local commit reads `NotApplied` only while every
//! anchor it recorded is exactly as recorded. Anything else, a commit that DID apply included, is
//! unknown: there is no Applied rule. Real commits on an in-memory repository, so the anchors are
//! the ones a commit writes.
#![allow(clippy::disallowed_methods)] // Fixtures write in their own temporary directories.

use lore_base::types::Hash;
use lore_revision::commit::CommitOptions;
use lore_revision::instance::ANCHOR_COMMITTING;
use lore_revision::instance::anchor_key;
use lore_revision::interface::LoreArray;
use lore_revision::interface::LoreString;
use lore_revision::local_commit_evidence::LocalCommitEvidence;
use lore_revision::local_commit_evidence::capture;
use lore_revision::local_commit_evidence::decide;
use lore_revision::local_commit_evidence::decide_from;
use lore_revision::lore::BranchId;
use lore_transport::AttemptResolution;

use crate::dirty_move_fixture::with_instance;
use crate::dirty_move_fixture::written;
use crate::helper::TestRepository;
use crate::helper::create_branch_on_instance;

/// Stages everything the working tree holds, as `lore stage --scan` of the root does.
async fn stage_all(instance: &TestRepository) {
    lore_revision::file::stage::stage(
        instance.repository.clone(),
        &instance.write_token,
        LoreArray::from_vec(vec![LoreString::from(&instance.path)]),
        lore_revision::stage::StageOptions {
            scan: true,
            ..Default::default()
        },
    )
    .await
    .expect("staging the working tree");
}

/// Writes `file`, stages the tree and commits it.
async fn commit_file(instance: &TestRepository, file: &str, message: &str) {
    written(instance, &[file]);
    stage_all(instance).await;
    lore_revision::commit::commit_with_metadata_boxed(
        instance.repository.clone(),
        &instance.write_token,
        CommitOptions::new(message.to_string()),
        LoreArray::from_vec(Vec::new()),
        LoreArray::from_vec(Vec::new()),
        LoreArray::from_vec(Vec::new()),
    )
    .await
    .expect("committing");
}

async fn evidence(instance: &TestRepository) -> LocalCommitEvidence {
    capture(&instance.repository)
        .await
        .expect("capturing the anchors")
}

async fn decided(
    instance: &TestRepository,
    recorded: &LocalCommitEvidence,
) -> Option<AttemptResolution> {
    decide(&instance.repository, recorded)
        .await
        .expect("reading the anchors")
}

/// A repository with one commit already made, so the recorded current is a real revision.
async fn with_base<F: std::future::Future<Output = ()>>(body: impl FnOnce(TestRepository) -> F) {
    with_instance(|instance| async move {
        commit_file(&instance, "base.txt", "base").await;
        body(instance).await;
    })
    .await;
}

/// Rule: `NotApplied` when the anchors are exactly as recorded (the crash came before the commit
/// published anything).
#[tokio::test]
async fn nothing_moved_is_not_applied() {
    with_base(|instance| async move {
        let recorded = evidence(&instance).await;
        assert!(!recorded.current.is_zero());
        assert_eq!(
            decided(&instance, &recorded).await,
            Some(AttemptResolution::NotApplied)
        );
    })
    .await;
}

/// Rule: one moved anchor is enough to prove nothing. Each field is moved on its own, on the
/// recorded evidence, so exactly that field rejects it.
#[test]
fn each_single_moved_anchor_is_unknown() {
    let recorded = LocalCommitEvidence {
        branch: Hash::from([1; 32]),
        current: Hash::from([2; 32]),
        branch_latest: Hash::from([2; 32]),
        staged: Hash::from([3; 32]),
        committing: Hash::default(),
    };
    assert_eq!(
        decide_from(&recorded, &recorded),
        Some(AttemptResolution::NotApplied),
        "control"
    );
    let other = Hash::from([9; 32]);
    for (name, now) in [
        (
            "branch",
            LocalCommitEvidence {
                branch: other,
                ..recorded
            },
        ),
        (
            "current",
            LocalCommitEvidence {
                current: other,
                ..recorded
            },
        ),
        (
            "branch latest",
            LocalCommitEvidence {
                branch_latest: other,
                ..recorded
            },
        ),
        (
            "staged",
            LocalCommitEvidence {
                staged: other,
                ..recorded
            },
        ),
        (
            "staged cleared",
            LocalCommitEvidence {
                staged: Hash::default(),
                ..recorded
            },
        ),
        (
            "commit intent",
            LocalCommitEvidence {
                committing: other,
                ..recorded
            },
        ),
    ] {
        assert_eq!(decide_from(&recorded, &now), None, "{name}");
    }
}

/// The same, against real anchors: a real stage moves only the staged anchor, a real commit moves
/// current, branch latest and the staged anchor, and none of them reads `NotApplied`.
#[tokio::test]
async fn a_real_stage_or_commit_after_capture_is_unknown() {
    with_base(|instance| async move {
        let recorded = evidence(&instance).await;
        written(&instance, &["staged-only.txt"]);
        stage_all(&instance).await;
        let now = evidence(&instance).await;
        assert_ne!(now.staged, recorded.staged);
        assert_eq!(now.current, recorded.current);
        assert_eq!(decided(&instance, &recorded).await, None, "staged moved");

        // The applied case: the commit the journal recorded did run.
        let before_commit = evidence(&instance).await;
        commit_file(&instance, "next.txt", "next").await;
        let now = evidence(&instance).await;
        assert_ne!(now.current, before_commit.current);
        assert_eq!(now.current, now.branch_latest);
        assert_eq!(decided(&instance, &recorded).await, None, "applied commit");
        assert_eq!(decided(&instance, &before_commit).await, None);
    })
    .await;
}

/// A different branch proves nothing. Switching back with nothing else changed reads
/// `NotApplied` BY DESIGN: every recorded anchor is exactly as it was, so nothing of the attempt's
/// is on the working copy.
#[tokio::test]
async fn a_branch_switch_is_unknown_and_switching_back_reads_not_applied() {
    with_base(|instance| async move {
        crate::dirty_move_fixture::scanned(&instance).await;
        let (_, original) =
            lore_revision::instance::load_current_anchor_boxed(&instance.repository)
                .await
                .expect("the current anchor");
        let other = BranchId::from(uuid::Uuid::now_v7());
        create_branch_on_instance(&instance.repository, "other", Some(other), "", false)
            .await
            .expect("creating the other branch");
        // Creating a branch may or may not move the anchor; start from the original either way.
        lore_revision::instance::store_current_anchor_branch(&instance.repository, original)
            .await
            .expect("anchoring the original branch");
        let recorded = evidence(&instance).await;

        lore_revision::instance::store_current_anchor_branch(&instance.repository, other)
            .await
            .expect("switching the anchor branch");
        let away = evidence(&instance).await;
        assert_ne!(away.branch, recorded.branch);
        assert_eq!(decided(&instance, &recorded).await, None);

        lore_revision::instance::store_current_anchor_branch(&instance.repository, original)
            .await
            .expect("switching the anchor branch back");
        assert_eq!(evidence(&instance).await, recorded);
        assert_eq!(
            decided(&instance, &recorded).await,
            Some(AttemptResolution::NotApplied)
        );
    })
    .await;
}

/// A commit cut short (commit intent non-zero) is unknown, as is a recorded intent that cleared.
#[tokio::test]
async fn a_commit_cut_short_is_unknown() {
    with_base(|instance| async move {
        let recorded = evidence(&instance).await;
        let (key, key_type) = anchor_key(
            instance.repository.salt(),
            ANCHOR_COMMITTING,
            instance.repository.instance_id,
        );
        instance
            .repository
            .try_write_mutable_store()
            .expect("a write handle")
            .store(instance.repository.id, key, recorded.current, key_type)
            .await
            .expect("storing the commit intent");
        assert_eq!(evidence(&instance).await.committing, recorded.current);
        assert_eq!(decided(&instance, &recorded).await, None);
    })
    .await;
}

/// A store that fails a read fails the capture rather than reading as zero or as unchanged: a
/// missing anchor branch is an error, so recovery leaves the attempt unresolved.
#[tokio::test]
async fn an_unreadable_branch_fails_the_capture_instead_of_reading_as_zero() {
    with_base(|instance| async move {
        let recorded = evidence(&instance).await;
        lore_revision::instance::store_current_anchor_branch(
            &instance.repository,
            BranchId::default(),
        )
        .await
        .expect("clearing the anchor branch");
        assert!(capture(&instance.repository).await.is_err());
        assert!(decide(&instance.repository, &recorded).await.is_err());
    })
    .await;
}

/// The branch latest is read from the local store alone: an anchor naming a branch the store has
/// no latest for reads zero there, and the moved branch still settles nothing.
#[tokio::test]
async fn an_unknown_branch_reads_a_zero_latest_and_stays_unknown() {
    with_base(|instance| async move {
        let recorded = evidence(&instance).await;
        lore_revision::instance::store_current_anchor_branch(
            &instance.repository,
            BranchId::from(uuid::Uuid::now_v7()),
        )
        .await
        .expect("pointing the anchor at a branch the store lacks");
        let now = capture(&instance.repository)
            .await
            .expect("a missing latest reads zero");
        assert!(now.branch_latest.is_zero());
        assert_eq!(decide_from(&recorded, &now), None);
    })
    .await;
}
/// A commit of a linked repository publishes the inner anchors first, so the outer anchors alone
/// prove nothing: a link in the current or the staged state fails the capture.
#[tokio::test]
async fn capture_refuses_a_repository_holding_a_link() {
    for staged in [false, true] {
        with_base(|instance| async move {
            let (current, branch) =
                lore_revision::instance::load_current_anchor_boxed(&instance.repository)
                    .await
                    .expect("the current anchor");
            capture(&instance.repository)
                .await
                .expect("control: no link, no refusal");
            let (state, _, _, _) =
                crate::helper::in_memory::linking_twice(&instance.repository, current).await;
            let linked =
                crate::helper::in_memory::commit(&instance.repository, &state, current, branch)
                    .await;
            if staged {
                lore_revision::instance::store_staged_anchor(&instance.repository, linked)
                    .await
                    .expect("staging the link");
            } else {
                lore_revision::instance::store_current_anchor(&instance.repository, linked)
                    .await
                    .expect("making the link current");
            }
            let refused = capture(&instance.repository).await;
            assert!(refused.is_err(), "staged: {staged}: {refused:?}");
        })
        .await;
    }
}

// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift): `lore::sync_settled::sync_settled` against a repository whose remote
//! answers (the `live_fixture` stub) and one that has no remote at all.
//!
//! The load-bearing claims: a read that could not ask is an `Err`, never `Settled` (fail closed),
//! and a torn tracked file reads as `Dirty` rather than `Settled`. Its own test binary, like
//! `live_push_journal.rs`, because the fixture needs a process-wide runtime of its own.
//!
//! `Behind` is not driven here: it needs the stub to serve a remote history the local object store
//! can walk, which the fixture does not model. The verdict rule itself is pinned in
//! `lore-revision/tests/unit/revision/sync_settled.rs`.

use std::sync::Arc;
use std::sync::Mutex;

use lore::interface::LoreEventCallback;
use lore::interface::LoreString;
use lore::repository::LoreRepositoryCreateArgs;
use lore::repository::LoreVfsType;
use lore::sync_settled::SyncSettled;
use lore::sync_settled::SyncSettledError;
use lore::sync_settled::sync_settled;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::test_util::TempDir;
use lore_revision::event::LoreEvent;
use lore_revision::interface::LoreGlobalArgs;
use lore_revision::live_fixture::BranchAnswer;
use lore_revision::live_fixture::LiveRepository;
use lore_revision::live_fixture::LockServer;
use lore_revision::live_fixture::Refusal;
use lore_revision::live_fixture::RevisionPolicy;
use lore_revision::live_fixture::RevisionRpc;
use lore_revision::live_fixture::RpcOutcome;
use lore_revision::live_fixture::fixture_execution_context;
use lore_revision::repository::LoreSharedStoreMode;

fn no_callback() -> LoreEventCallback {
    None
}

/// A remote whose branch tip equals the fixture's local tip, so the dry-run push finds nothing
/// missing either way.
async fn synced_fixture() -> (LockServer, LiveRepository) {
    let server = LockServer::start().await;
    let fixture = LORE_CONTEXT
        .scope(fixture_execution_context(), async {
            LiveRepository::create(&server.remote_url()).await
        })
        .await;
    server.set_revision_policy(RevisionPolicy {
        branch_get: BranchAnswer::Present {
            latest: <[u8; 32]>::from(fixture.committed_revision).to_vec(),
            metadata: vec![0x11; 32],
            deleted: false,
        },
        branch_create: RpcOutcome::Grant,
        branch_push: RpcOutcome::Grant,
    });
    (server, fixture)
}

#[tokio::test(flavor = "multi_thread")]
async fn clean_synced_tree_is_settled() {
    let (_server, fixture) = synced_fixture().await;

    let verdict = sync_settled(fixture.globals(), no_callback(), None).await;

    assert_eq!(verdict, Ok(SyncSettled::Settled));
}

/// The read is a dry run: it must never dispatch a mutation to the remote.
#[tokio::test(flavor = "multi_thread")]
async fn the_read_dispatches_no_push_or_branch_create() {
    let (server, fixture) = synced_fixture().await;

    let verdict = sync_settled(fixture.globals(), no_callback(), None).await;

    assert_eq!(verdict, Ok(SyncSettled::Settled));
    assert!(
        !server.revision_calls_for(RevisionRpc::BranchGet).is_empty(),
        "the remote tip must actually have been read"
    );
    assert!(
        server
            .revision_calls_for(RevisionRpc::BranchPush)
            .is_empty()
    );
    assert!(
        server
            .revision_calls_for(RevisionRpc::BranchCreate)
            .is_empty()
    );
}

fn answer(server: &LockServer, branch_get: BranchAnswer) {
    server.set_revision_policy(RevisionPolicy {
        branch_get,
        branch_create: RpcOutcome::Grant,
        branch_push: RpcOutcome::Grant,
    });
}

/// The read is never allowed to mutate the remote, whatever it concludes.
fn assert_no_mutation_reached(server: &LockServer) {
    assert!(
        server
            .revision_calls_for(RevisionRpc::BranchPush)
            .is_empty(),
        "a BranchPush reached the remote"
    );
    assert!(
        server
            .revision_calls_for(RevisionRpc::BranchCreate)
            .is_empty(),
        "a BranchCreate reached the remote"
    );
}

/// A repository with a configured remote and no revisions, as a clone that failed before
/// realizing anything leaves behind. Created offline, so nothing reaches the stub until the read.
async fn empty_repository(server: &LockServer) -> (TempDir, LoreGlobalArgs) {
    let tempdir = TempDir::new("lore-sync-settled-empty-");
    let globals = LoreGlobalArgs {
        repository_path: tempdir.path().into(),
        offline: 1,
        ..Default::default()
    };
    let created = lore::repository::create(
        globals.clone(),
        LoreRepositoryCreateArgs {
            repository_url: LoreString::from(
                format!("{}/empty-repo", server.remote_url()).as_str(),
            ),
            id: LoreString::default(),
            description: LoreString::default(),
            vfs: LoreVfsType::default(),
            use_shared_store: LoreSharedStoreMode::Disabled,
            shared_store_path: LoreString::default(),
        },
        None,
    )
    .await;
    assert_eq!(created, 0, "creating the empty repository");
    (
        tempdir,
        LoreGlobalArgs {
            offline: 0,
            ..globals
        },
    )
}

/// Local revisions the remote does not have, against a remote that reports no branch: not a
/// state a sync leaves behind, so never a verdict.
#[tokio::test(flavor = "multi_thread")]
async fn an_empty_remote_with_local_history_is_an_error() {
    let server = LockServer::start().await;
    let fixture = LORE_CONTEXT
        .scope(fixture_execution_context(), async {
            LiveRepository::create(&server.remote_url()).await
        })
        .await;
    answer(&server, BranchAnswer::NotFound);

    let verdict = sync_settled(fixture.globals(), no_callback(), None).await;

    assert_eq!(verdict, Err(SyncSettledError::EmptyRemoteWithLocalHistory));
    assert_no_mutation_reached(&server);
}

/// The server confirms the branch does not exist and the working copy has nothing: settled.
#[tokio::test(flavor = "multi_thread")]
async fn an_empty_repository_against_a_confirmed_empty_remote_is_settled() {
    let server = LockServer::start().await;
    let (_dir, globals) = empty_repository(&server).await;
    answer(&server, BranchAnswer::NotFound);

    let verdict = sync_settled(globals, no_callback(), None).await;

    assert_eq!(verdict, Ok(SyncSettled::Settled));
    assert!(
        server.revision_calls_for(RevisionRpc::BranchGet).len() >= 2,
        "the push read and the direct confirming read must both have asked"
    );
    assert_no_mutation_reached(&server);
}

/// A confirmed-empty remote still falls through to the status scan: a staged file is Dirty.
#[tokio::test(flavor = "multi_thread")]
async fn a_confirmed_empty_remote_still_reads_a_dirty_tree_as_dirty() {
    let server = LockServer::start().await;
    let (dir, globals) = empty_repository(&server).await;
    answer(&server, BranchAnswer::NotFound);
    let file = dir.path().join("pending.txt");
    #[allow(clippy::disallowed_methods)] // Test fixture writing into a temporary repository.
    std::fs::write(&file, "pending").expect("writing the pending file");
    let staged = lore::file::stage(
        LoreGlobalArgs {
            offline: 1,
            ..globals.clone()
        },
        lore::file::LoreFileStageArgs {
            paths: lore_revision::interface::LoreArray::from_vec(vec![LoreString::from(&file)]),
            case_change: 0,
            scan: 1,
        },
        None,
    )
    .await;
    assert_eq!(staged, 0, "staging the pending file");

    let verdict = sync_settled(globals, no_callback(), None).await;

    assert_eq!(verdict, Ok(SyncSettled::Dirty));
    assert_no_mutation_reached(&server);
}

/// A branch record with a zero tip is the same confirmation as `NotFound`.
#[tokio::test(flavor = "multi_thread")]
async fn a_zero_tip_record_is_a_confirmed_empty_remote() {
    let server = LockServer::start().await;
    let (_dir, globals) = empty_repository(&server).await;
    answer(
        &server,
        BranchAnswer::Present {
            latest: vec![0; 32],
            metadata: vec![0x11; 32],
            deleted: false,
        },
    );

    let verdict = sync_settled(globals, no_callback(), None).await;

    assert_eq!(verdict, Ok(SyncSettled::Settled));
    assert_no_mutation_reached(&server);
}

/// A failed clone that realized nothing (no revisions, remote configured), with the remote lookup
/// failing for any reason other than `NotFound`. Push reads that failure as "no remote branch";
/// settled must not.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_clone_with_a_failing_branch_get_is_an_error_not_settled() {
    for refusal in [Refusal::Internal, Refusal::PermissionDenied] {
        let server = LockServer::start().await;
        let (_dir, globals) = empty_repository(&server).await;
        answer(&server, BranchAnswer::Fail(refusal));

        let verdict = sync_settled(globals, no_callback(), None).await;

        assert_eq!(
            verdict,
            Err(SyncSettledError::RemoteTipUnknown),
            "{refusal:?} must not read as an empty remote"
        );
        assert_no_mutation_reached(&server);
    }
}

/// With history behind a failing lookup the zero tip is still unconfirmed, and the local
/// revisions are reported first.
#[tokio::test(flavor = "multi_thread")]
async fn a_failing_branch_get_on_a_committed_tree_is_an_error() {
    let server = LockServer::start().await;
    let fixture = LORE_CONTEXT
        .scope(fixture_execution_context(), async {
            LiveRepository::create(&server.remote_url()).await
        })
        .await;
    answer(&server, BranchAnswer::Fail(Refusal::Internal));

    let verdict = sync_settled(fixture.globals(), no_callback(), None).await;

    // The ahead check runs before the direct read.
    assert_eq!(verdict, Err(SyncSettledError::EmptyRemoteWithLocalHistory));
    assert_no_mutation_reached(&server);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_modified_tracked_file_is_dirty() {
    let (_server, fixture) = synced_fixture().await;
    #[allow(clippy::disallowed_methods)] // Test fixture editing a file in a temporary repository.
    std::fs::write(
        &fixture.committed_files_absolute[0],
        "live fixture payload 0 plus an edit that changes the length",
    )
    .expect("editing the tracked file");

    let verdict = sync_settled(fixture.globals(), no_callback(), None).await;

    assert_eq!(verdict, Ok(SyncSettled::Dirty));
}

/// The important one: sync's realize path truncates a small file in place, so the revision pointer
/// can be right while the bytes on disk are not. Same path, fewer bytes.
#[tokio::test(flavor = "multi_thread")]
async fn a_truncated_tracked_file_is_dirty() {
    let (_server, fixture) = synced_fixture().await;
    let path = &fixture.committed_files_absolute[0];
    let original_len = std::fs::metadata(path).expect("stat").len();
    #[allow(clippy::disallowed_methods)] // Test fixture editing a file in a temporary repository.
    std::fs::write(path, "live").expect("truncating the tracked file");
    assert!(std::fs::metadata(path).expect("stat").len() < original_len);

    let verdict = sync_settled(fixture.globals(), no_callback(), None).await;

    assert_eq!(verdict, Ok(SyncSettled::Dirty));
}

/// The caller's callback still sees every event: the tee forwards rather than swallows.
#[tokio::test(flavor = "multi_thread")]
async fn the_callers_callback_receives_events() {
    let (_server, fixture) = synced_fixture().await;
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let sink = seen.clone();
    let callback: LoreEventCallback = Some(Box::new(move |event| {
        let name = match event {
            LoreEvent::BranchPush(_) => "BranchPush",
            LoreEvent::Complete(_) => "Complete",
            _ => "other",
        };
        sink.lock().expect("event sink").push(name.to_owned());
    }));

    let verdict = sync_settled(fixture.globals(), callback, None).await;

    assert_eq!(verdict, Ok(SyncSettled::Settled));
    let seen = seen.lock().expect("event sink");
    assert!(
        seen.iter().any(|name| name == "BranchPush"),
        "the dry-run push's event must reach the caller, saw {seen:?}"
    );
    assert!(
        seen.iter().filter(|name| *name == "Complete").count() >= 2,
        "both the push and the status scan must forward their events, saw {seen:?}"
    );
}

/// Fail closed: a repository with no remote cannot answer the push read, which is an error and
/// never a verdict.
#[tokio::test(flavor = "multi_thread")]
async fn a_repository_without_a_remote_is_an_error_not_settled() {
    let tempdir = TempDir::new("lore-sync-settled-no-remote-");
    let globals = LoreGlobalArgs {
        repository_path: tempdir.path().into(),
        offline: 1,
        ..Default::default()
    };
    let created = lore::repository::create(
        globals.clone(),
        LoreRepositoryCreateArgs {
            repository_url: LoreString::default(),
            id: LoreString::default(),
            description: LoreString::default(),
            vfs: LoreVfsType::default(),
            use_shared_store: LoreSharedStoreMode::Disabled,
            shared_store_path: LoreString::default(),
        },
        None,
    )
    .await;
    assert_eq!(created, 0, "creating the local repository");

    for globals in [
        globals,
        LoreGlobalArgs {
            repository_path: tempdir.path().into(),
            ..Default::default()
        },
    ] {
        let verdict = sync_settled(globals, no_callback(), None).await;
        assert!(
            matches!(verdict, Err(SyncSettledError::RemoteReadFailed { .. })),
            "no remote must fail closed, got {verdict:?}"
        );
    }
}

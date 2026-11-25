// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! [CLIENT] A commit or a push is refused when another user holds a lock on a file it changes.
//!
//! Locks stay advisory on the server; this is the client's own check, enabled by
//! `LoreRevisionCommitArgs::refuse_locked_by_others` and
//! `branch::push_managed_refusing_others_locks(.., true)`. The remote is the in-process stub of
//! `lore_revision::live_fixture`; its `Status` answer is steered with `set_status_locks`, and the
//! caller's identity is the repository config identity. Two identities are therefore "the lock's
//! owner" (named by the stub) and "the caller" (named by the repository config).
//!
//! The stub models no storage service, so a commit's best-effort upload and a push's fragment
//! upload cannot complete here. What is asserted for the not-refused cases is therefore that the
//! lock check did not refuse (status is not `LockNotOwned`) and, for a commit, that it was made.

use std::sync::Arc;
use std::sync::Mutex;

use lore::interface::LoreEventCallback;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Hash;
use lore_revision::interface::LoreArray;
use lore_revision::interface::LoreEvent;
use lore_revision::interface::LoreString;
use lore_revision::live_fixture::BranchAnswer;
use lore_revision::live_fixture::LiveRepository;
use lore_revision::live_fixture::LockRpc;
use lore_revision::live_fixture::LockServer;
use lore_revision::live_fixture::RevisionPolicy;
use lore_revision::live_fixture::RevisionRpc;
use lore_revision::live_fixture::RpcOutcome;
use lore_revision::live_fixture::fixture_execution_context;
use lore_revision::repository::RepositoryAccess;

const CALLER: &str = "user-b";
const HOLDER: &str = "user-a";
/// The FFI code of `LockNotOwned`.
const LOCK_NOT_OWNED: i32 = 45;
const F: &str = "f.file";
const G: &str = "g.file";

/// What the callback saw: log text (the refusal is logged with its full message) and any error
/// event text.
#[derive(Default)]
struct Seen {
    logs: Vec<String>,
    /// The status of the last Complete event, if one arrived.
    complete_status: Option<i32>,
}

fn capture() -> (LoreEventCallback, Arc<Mutex<Seen>>) {
    // Routes `lore_warn!`/`lore_error!` into the event stream; idempotent.
    lore::log::initialize();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let sink = seen.clone();
    let callback: LoreEventCallback = Some(Box::new(move |event: &LoreEvent| {
        let mut seen = sink.lock().expect("the capture mutex must not be poisoned");
        match event {
            LoreEvent::Log(data) => seen.logs.push(data.message.as_str().to_owned()),
            LoreEvent::Error(data) => seen.logs.push(data.error_inner.as_str().to_owned()),
            LoreEvent::Complete(data) => {
                seen.complete_status = Some(data.status);
                seen.logs.push(data.error.message.as_str().to_owned());
                for location in data.error.trace_locations.as_slice() {
                    seen.logs.push(location.context.as_str().to_owned());
                }
            }
            _ => {}
        }
    }));
    (callback, seen)
}

fn joined(seen: &Arc<Mutex<Seen>>) -> String {
    seen.lock()
        .expect("the capture mutex must not be poisoned")
        .logs
        .join(
            "
",
        )
}

struct Rig {
    runtime: tokio::runtime::Handle,
    server: LockServer,
    fixture: LiveRepository,
}

/// A server and a repository (`f.file`, `g.file` committed) whose caller identity is `identity`.
/// The server reports `f.file` as locked by [`HOLDER`].
fn rig(identity: &str) -> Rig {
    let runtime = lore::runtime();
    let server = runtime.block_on(LockServer::start());
    let fixture = runtime.block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
        LiveRepository::create_with_files_and_identity(&server.remote_url(), &[F, G], identity)
            .await
    }));
    server.set_status_locks(vec![(F.to_owned(), HOLDER.to_owned())]);
    Rig {
        runtime,
        server,
        fixture,
    }
}

/// The current revision and the staged revision, as stored.
fn anchors(rig: &Rig) -> (Hash, Option<Hash>) {
    rig.runtime
        .block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
            let repository = rig.fixture.connect(RepositoryAccess::ReadOnly).await;
            let (current, _) = lore_revision::instance::load_current_anchor_boxed(&repository)
                .await
                .expect("reading the current revision");
            let staged = lore_revision::instance::load_staged_revision(&repository)
                .await
                .expect("reading the staged revision");
            (current, staged)
        }))
}

/// Change `name` on disk and stage it.
fn modify_and_stage(rig: &Rig, name: &str, content: &str) {
    let path = rig.fixture.path.join(name);
    // Test fixture write; not subject to repository write-token discipline.
    #[allow(clippy::disallowed_methods)]
    std::fs::write(&path, content).expect("modifying the fixture file");
    let (callback, _) = capture();
    let status = rig.runtime.block_on(lore::file::stage(
        rig.fixture.globals(),
        lore::file::LoreFileStageArgs {
            paths: LoreArray::from_vec(vec![LoreString::from(&path)]),
            case_change: 0,
            scan: 0,
        },
        callback,
    ));
    assert_eq!(status, 0, "staging {name}");
}

fn commit_args(refuse: u8) -> lore::revision::LoreRevisionCommitArgs {
    lore::revision::LoreRevisionCommitArgs {
        message: LoreString::from("change"),
        refuse_locked_by_others: refuse,
        ..lore::revision::LoreRevisionCommitArgs::default()
    }
}

fn commit(rig: &Rig, refuse: u8, globals: lore::interface::LoreGlobalArgs) -> (i32, String) {
    let (callback, seen) = capture();
    let status = rig.runtime.block_on(lore::revision::commit(
        globals,
        commit_args(refuse),
        callback,
    ));
    (status, joined(&seen))
}

fn lock_status_calls(rig: &Rig) -> usize {
    rig.server.calls_for(LockRpc::Status).len()
}

/// B changes a file A has locked and commits with the flag: refused with `LockNotOwned`, the
/// message names the file and the holder, and the commit was not made (current revision
/// unchanged, change still staged).
#[test]
fn a_commit_over_another_users_lock_is_refused_and_not_made() {
    let rig = rig(CALLER);
    modify_and_stage(&rig, F, "changed by b");
    let (before, staged_before) = anchors(&rig);
    assert!(
        staged_before.is_some_and(|staged| staged != before),
        "the change must be staged"
    );

    let (status, log) = commit(&rig, 1, rig.fixture.globals());

    assert_eq!(status, LOCK_NOT_OWNED, "log: {log}");
    assert_eq!(status, 45);
    assert!(log.contains(F), "the message must name the file: {log}");
    assert!(
        log.contains(HOLDER),
        "the message must name the holder: {log}"
    );
    assert!(
        log.contains("--ignore-locks"),
        "the message names the override: {log}"
    );
    assert!(lock_status_calls(&rig) >= 1, "the lock status was asked");

    let (after, staged_after) = anchors(&rig);
    assert_eq!(after, before, "no revision may be made");
    assert_eq!(staged_after, staged_before, "the change must stay staged");
}

/// The same commit without the flag is not refused: the lock service is not even asked.
#[test]
fn a_commit_without_the_flag_does_not_check_locks() {
    let rig = rig(CALLER);
    modify_and_stage(&rig, F, "changed by b");
    let (before, _) = anchors(&rig);

    let (status, log) = commit(&rig, 0, rig.fixture.globals());

    assert_ne!(status, LOCK_NOT_OWNED, "log: {log}");
    assert_eq!(
        lock_status_calls(&rig),
        0,
        "no lock lookup without the flag"
    );
    let (after, _) = anchors(&rig);
    assert_ne!(
        after, before,
        "the commit must have been made (status {status}): {log}"
    );
}

/// A commits `f` under A's own lock with the flag: the holder is the caller, so no refusal.
#[test]
fn a_commit_under_the_callers_own_lock_is_not_refused() {
    let rig = rig(HOLDER);
    modify_and_stage(&rig, F, "changed by a");
    let (before, _) = anchors(&rig);

    let (status, log) = commit(&rig, 1, rig.fixture.globals());

    assert_ne!(status, LOCK_NOT_OWNED, "log: {log}");
    assert!(lock_status_calls(&rig) >= 1, "the lock status was asked");
    let (after, _) = anchors(&rig);
    assert_ne!(
        after, before,
        "the commit must have been made (status {status}): {log}"
    );
}

/// With the global offline flag the check is skipped with a warning and the commit goes ahead.
#[test]
fn an_offline_commit_with_the_flag_skips_the_check_with_a_warning() {
    let rig = rig(CALLER);
    modify_and_stage(&rig, F, "changed by b");
    let (before, _) = anchors(&rig);
    let mut globals = rig.fixture.globals();
    globals.offline = 1;

    let (status, log) = commit(&rig, 1, globals);

    assert_eq!(status, 0, "log: {log}");
    assert_eq!(
        lock_status_calls(&rig),
        0,
        "offline must not ask the server"
    );
    assert!(
        log.contains("Not checking file locks"),
        "a warning is expected: {log}"
    );
    let (after, _) = anchors(&rig);
    assert_ne!(after, before, "the commit must have been made");
}

/// A lock on an unrelated file does not block a commit of `f`.
#[test]
fn a_lock_on_an_unrelated_file_does_not_block_the_commit() {
    let rig = rig(CALLER);
    rig.server
        .set_status_locks(vec![(G.to_owned(), HOLDER.to_owned())]);
    modify_and_stage(&rig, F, "changed by b");
    let (before, _) = anchors(&rig);

    let (status, log) = commit(&rig, 1, rig.fixture.globals());

    assert_ne!(status, LOCK_NOT_OWNED, "log: {log}");
    let (after, _) = anchors(&rig);
    assert_ne!(
        after, before,
        "the commit must have been made (status {status}): {log}"
    );
}

/// A lock whose holder the server does not record (auth off) never refuses: the commit goes ahead.
#[test]
fn a_commit_over_only_unattributed_locks_is_not_refused() {
    let rig = rig(CALLER);
    rig.server
        .set_status_locks(vec![(F.to_owned(), "<unknown>".to_owned())]);
    modify_and_stage(&rig, F, "changed by b");
    let (before, _) = anchors(&rig);

    let (status, log) = commit(&rig, 1, rig.fixture.globals());

    assert_ne!(status, LOCK_NOT_OWNED, "log: {log}");
    assert!(lock_status_calls(&rig) >= 1, "the lock status was asked");
    let (after, _) = anchors(&rig);
    assert_ne!(
        after, before,
        "the commit must have been made (status {status}): {log}"
    );
}

/// An unattributed lock beside a real other holder still refuses, naming only the real one.
#[test]
fn an_unattributed_lock_beside_a_real_holder_refuses_naming_only_the_real_one() {
    let rig = rig(CALLER);
    rig.server.set_status_locks(vec![
        (F.to_owned(), "<unknown>".to_owned()),
        (G.to_owned(), HOLDER.to_owned()),
    ]);
    modify_and_stage(&rig, F, "changed by b");
    modify_and_stage(&rig, G, "changed by b");
    let (before, _) = anchors(&rig);

    let (status, log) = commit(&rig, 1, rig.fixture.globals());

    assert_eq!(status, LOCK_NOT_OWNED, "log: {log}");
    assert!(log.contains(G) && log.contains(HOLDER), "{log}");
    assert!(
        !log.contains("<unknown>"),
        "the placeholder must not be named: {log}"
    );
    let (after, _) = anchors(&rig);
    assert_eq!(after, before, "no revision may be made");
}

/// A lock lookup that fails is a warning, not a refusal.
#[test]
fn a_failing_lock_lookup_lets_the_commit_go_ahead() {
    let rig = rig(CALLER);
    // A caller with no identity cannot be told apart from the holder, so the answer is unknown.
    let rig_no_identity = {
        let runtime = lore::runtime();
        let server = runtime.block_on(LockServer::start());
        let fixture = runtime.block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
            LiveRepository::create_with_files(&server.remote_url(), &[F, G]).await
        }));
        server.set_status_locks(vec![(F.to_owned(), HOLDER.to_owned())]);
        Rig {
            runtime,
            server,
            fixture,
        }
    };
    drop(rig);
    modify_and_stage(&rig_no_identity, F, "changed by nobody");
    let (before, _) = anchors(&rig_no_identity);

    let (status, log) = commit(&rig_no_identity, 1, rig_no_identity.fixture.globals());

    assert_ne!(status, LOCK_NOT_OWNED, "log: {log}");
    assert!(
        log.contains("Could not check file locks"),
        "a warning is expected: {log}"
    );
    let (after, _) = anchors(&rig_no_identity);
    assert_ne!(
        after, before,
        "the commit must have been made (status {status}): {log}"
    );
}

fn push_args() -> lore::branch::LoreBranchPushArgs {
    lore::branch::LoreBranchPushArgs {
        branch: LoreString::default(),
        fast_forward_merge: 0,
    }
}

/// Commit locally as B without the check, then point the remote at the pre-change tip.
fn local_commit_ahead_of_remote(rig: &Rig) -> Hash {
    let base = rig.fixture.committed_revision;
    modify_and_stage(rig, F, "changed by b");
    let (status, log) = commit(rig, 0, rig.fixture.globals());
    assert_ne!(status, LOCK_NOT_OWNED, "log: {log}");
    let (tip, _) = anchors(rig);
    assert_ne!(
        tip, base,
        "the local commit must exist (status {status}): {log}"
    );
    rig.server.set_revision_policy(RevisionPolicy {
        branch_get: BranchAnswer::Present {
            latest: <[u8; 32]>::from(base).to_vec(),
            metadata: vec![0x11; 32],
            deleted: false,
        },
        branch_create: RpcOutcome::Grant,
        branch_push: RpcOutcome::Grant,
    });
    base
}

fn push(rig: &Rig, refuse: bool) -> (i32, String) {
    let (callback, seen) = capture();
    let status = rig
        .runtime
        .block_on(lore::branch::push_managed_refusing_others_locks(
            rig.fixture.globals(),
            push_args(),
            callback,
            None,
            refuse,
        ));
    (status, joined(&seen))
}

/// B pushes a local commit changing a file A has locked, with the check on: refused, naming the
/// file and the holder, and nothing is sent to the revision service.
#[test]
fn a_push_over_another_users_lock_is_refused_and_sends_nothing() {
    let rig = rig(CALLER);
    local_commit_ahead_of_remote(&rig);
    let calls_before = rig.server.revision_calls_for(RevisionRpc::BranchPush).len();

    let (status, log) = push(&rig, true);

    assert_eq!(status, LOCK_NOT_OWNED, "log: {log}");
    assert!(log.contains(F), "the message must name the file: {log}");
    assert!(
        log.contains(HOLDER),
        "the message must name the holder: {log}"
    );
    assert_eq!(
        rig.server.revision_calls_for(RevisionRpc::BranchPush).len(),
        calls_before,
        "a refused push must not reach the server"
    );
    assert!(
        rig.server
            .revision_calls_for(RevisionRpc::BranchCreate)
            .is_empty(),
        "a refused push must not create anything"
    );
}

/// The CLI's push entry (`lore branch push` calls `push_managed_refusing_others_locks`, pinned in
/// `lore-client/tests/unit/commands/branch.rs`) runs under a `ManagedPushRunner`: a push that gets
/// past the lock check opens a durable managed stage in the repository's attempt journal, and
/// leaves no unresolved attempt behind when the stub refuses it.
#[test]
fn the_cli_push_entry_runs_under_the_managed_runner() {
    // The caller owns the only lock, so the check passes and the push proceeds. The stub models no
    // storage service, so a push that has fragments to send fails at the server query before any
    // stage opens. The remote therefore reports the branch tombstoned at exactly this repository's
    // tip: the push is idempotent and restores the branch with a single BranchCreate, a
    // dispatch that goes through a stage (the shape live_push_journal uses).
    let rig = rig(HOLDER);
    rig.server.set_revision_policy(RevisionPolicy {
        branch_get: BranchAnswer::Present {
            latest: <[u8; 32]>::from(rig.fixture.committed_revision).to_vec(),
            // Any non-zero value: a zero metadata hash takes the initial-branch-creation path.
            metadata: vec![0x11; 32],
            deleted: true,
        },
        branch_create: RpcOutcome::Grant,
        branch_push: RpcOutcome::Grant,
    });

    let (status, log) = push(&rig, true);

    // An idempotent push changes no path, so there is nothing to look up a lock for; the refusal
    // itself is pinned by the tests above.
    assert_eq!(status, 0, "log: {log}");
    use lore_transport::AttemptStore;

    let path = rig.fixture.path.clone();
    let (parents, unresolved) = rig.runtime.block_on(async move {
        let guard = lore_revision::repository_fence::RepositoryMutationGuard::acquire(&path)
            .await
            .expect("a settled managed push leaves the worktree admissible");
        (
            guard.store().managed_parents().await.expect("read parents"),
            guard.store().unresolved().await.expect("read unresolved"),
        )
    });
    assert!(
        !parents.is_empty(),
        "the push must have run as a managed stage (status {status}): {log}"
    );
    assert!(
        parents.iter().all(|parent| parent.complete),
        "every stage is finished: {parents:?}"
    );
    assert!(unresolved.is_empty(), "{unresolved:?}");
}

/// With the check off the same push is not refused for the lock, and no lock lookup happens.
#[test]
fn a_push_without_the_check_is_not_refused_for_a_lock() {
    let rig = rig(CALLER);
    local_commit_ahead_of_remote(&rig);

    let (status, log) = push(&rig, false);

    assert_ne!(status, LOCK_NOT_OWNED, "log: {log}");
    assert_eq!(
        lock_status_calls(&rig),
        0,
        "no lock lookup when not refusing"
    );
}

/// `push_managed` (the unchanged entry point) never refuses.
#[test]
fn push_managed_does_not_refuse() {
    let rig = rig(CALLER);
    local_commit_ahead_of_remote(&rig);
    let (callback, seen) = capture();

    let status = rig.runtime.block_on(lore::branch::push_managed(
        rig.fixture.globals(),
        push_args(),
        callback,
        None,
    ));

    assert_ne!(status, LOCK_NOT_OWNED, "log: {}", joined(&seen));
    assert_eq!(lock_status_calls(&rig), 0);
}

/// A remote branch with no revisions yet is not checked: nobody can hold a lock on it.
#[test]
fn a_push_to_a_branch_with_no_remote_revisions_is_not_checked() {
    let rig = rig(CALLER);
    local_commit_ahead_of_remote(&rig);
    rig.server.set_revision_policy(RevisionPolicy {
        branch_get: BranchAnswer::Present {
            latest: vec![0; 32],
            metadata: vec![0x11; 32],
            deleted: false,
        },
        branch_create: RpcOutcome::Grant,
        branch_push: RpcOutcome::Grant,
    });

    let (status, log) = push(&rig, true);

    assert_ne!(status, LOCK_NOT_OWNED, "log: {log}");
    assert_eq!(
        lock_status_calls(&rig),
        0,
        "no lock lookup for a branch with no revisions"
    );
}

/// The service relay path carries the flag on both relayed argument structs, set and unset.
/// Since v0.11.0 (`f301c323`) the relay is positional bitcode with no field defaults: client and
/// service are one build, so every field is always encoded and "absent" has no wire form.
#[test]
fn the_relay_args_carry_the_flag_and_default_it_off() {
    for flag in [false, true] {
        let push = lore::branch::LoreManagedBranchPushArgs {
            args: lore::branch::LoreBranchPushArgs {
                branch: LoreString::default(),
                fast_forward_merge: 0,
            },
            refuse_locked_by_others: flag,
        };
        let read: lore::branch::LoreManagedBranchPushArgs =
            bitcode::decode(&bitcode::encode(&push)).expect("decoding relay push args");
        assert_eq!(read.refuse_locked_by_others, flag);

        let commit = lore::revision::LoreRevisionCommitArgs {
            message: LoreString::from_str("m"),
            refuse_locked_by_others: u8::from(flag),
            ..Default::default()
        };
        let read: lore::revision::LoreRevisionCommitArgs =
            bitcode::decode(&bitcode::encode(&commit)).expect("decoding relay commit args");
        assert_eq!(read.refuse_locked_by_others, u8::from(flag));
    }
    assert_eq!(
        lore::revision::LoreRevisionCommitArgs::default().refuse_locked_by_others,
        0,
        "a zeroed commit leaves the refusal off"
    );
}
/// Exact selection takes repository-relative paths (an absolute one is a `PathNormalization` error).
fn exact_options(_rig: &Rig) -> lore_revision::exact_selection::ExactSelectionOptions {
    use lore_revision::exact_selection::ExactSelectionOptions;
    use lore_revision::exact_selection::ExpectedFileAction;
    use lore_revision::exact_selection::FileMetadataSelection;
    use lore_revision::exact_selection::SelectedFile;
    ExactSelectionOptions {
        message: "exact".to_owned(),
        files: vec![SelectedFile {
            path: F.to_owned(),
            expected_effective_action: ExpectedFileAction::Delete,
            source_hash: None,
            file_metadata: FileMetadataSelection::Unchanged,
        }],
        revision_metadata: Vec::new(),
        stats: false,
    }
}

fn delete_f(rig: &Rig) {
    // Test fixture write; not subject to repository write-token discipline.
    #[allow(clippy::disallowed_methods)]
    std::fs::remove_file(rig.fixture.path.join(F)).expect("deleting the fixture file");
}

/// An exact-selection commit of a file another user holds is refused as `InvalidInput`, naming
/// the path and the holder, and no revision is made.
#[test]
fn an_exact_selection_commit_over_another_users_lock_is_refused() {
    let rig = rig(CALLER);
    delete_f(&rig);
    let (before, _) = anchors(&rig);
    let (callback, seen) = capture();

    let result = rig.runtime.block_on(
        lore::revision::commit_exact_selection_refusing_others_locks(
            rig.fixture.globals(),
            exact_options(&rig),
            callback,
            true,
        ),
    );

    let error = result.expect_err("another user's lock must refuse");
    // The status is LockNotOwned, as a staged commit's refusal is, not InvalidArguments (3).
    assert_eq!(error.code(), LOCK_NOT_OWNED);
    assert!(error.is_locked_by_others());
    assert_eq!(
        seen.lock()
            .expect("the capture mutex must not be poisoned")
            .complete_status,
        Some(LOCK_NOT_OWNED),
        "the Complete event carries the lock status"
    );
    match error.kind() {
        lore_revision::exact_selection::ExactSelectionErrorKind::InvalidInput { reason, paths } => {
            assert_eq!(paths, &vec![F.to_owned()]);
            assert!(reason.contains(F) && reason.contains(HOLDER), "{reason}");
            assert_eq!(&error.to_string(), reason, "the plain refusal, no prefix");
        }
        other => panic!("expected InvalidInput, got {other:?}"),
    }
    let (after, _) = anchors(&rig);
    assert_eq!(after, before, "no revision may be made");
}

/// With the check off the same selection commits.
#[test]
fn an_exact_selection_commit_without_the_check_succeeds() {
    let rig = rig(CALLER);
    delete_f(&rig);
    let (before, _) = anchors(&rig);
    let (callback, seen) = capture();

    let result = rig.runtime.block_on(
        lore::revision::commit_exact_selection_refusing_others_locks(
            rig.fixture.globals(),
            exact_options(&rig),
            callback,
            false,
        ),
    );

    let result = result.unwrap_or_else(|error| panic!("{error:?} / {}", joined(&seen)));
    assert_ne!(result.revision, before);
    assert_eq!(
        lock_status_calls(&rig),
        0,
        "no lock lookup without the flag"
    );
}

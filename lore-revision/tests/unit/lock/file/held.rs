// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift): the check that finds another user's locks on a change's files.
//!
//! The remote is the in-process stub of `live_fixture`; its `Status` answer is steered with
//! `LockServer::set_status_locks`, and the caller is the repository config identity.
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Hash;
use lore_base::types::LockData;
use lore_base::types::LockResource;
use lore_revision::commit::CommitError;
use lore_revision::interface::LoreArray;
use lore_revision::interface::LoreGlobalArgs;
use lore_revision::interface::LoreString;
use lore_revision::live_fixture::BranchAnswer;
use lore_revision::live_fixture::LiveRepository;
use lore_revision::live_fixture::LockRpc;
use lore_revision::live_fixture::LockServer;
use lore_revision::live_fixture::RevisionPolicy;
use lore_revision::live_fixture::fixture_execution_context;
use lore_revision::lock::file::held::HeldLocks;
use lore_revision::lock::file::held::UNATTRIBUTED_LOCK_OWNER;
use lore_revision::lock::file::held::held_by_others;
use lore_revision::lock::file::held::push_change_paths;
use lore_revision::lock::file::held::refuse_if_held_by_others;
use lore_revision::lock::file::held::staged_change_paths;
use lore_revision::lore::BranchId;
use lore_revision::repository::RepositoryAccess;
use lore_revision::repository::RepositoryContext;

const CALLER: &str = "user-b";
const HOLDER: &str = "user-a";
const F: &str = "f.file";
const G: &str = "g.file";

fn lock(path: &str, owner: &str) -> LockData {
    LockData {
        resource: LockResource {
            description: path.to_owned(),
            ..LockResource::default()
        },
        owner: owner.to_owned(),
        locked_at: 0,
    }
}

#[test]
fn refusal_message_names_every_path_and_owner_and_is_neutral() {
    let message =
        HeldLocks::refusal_message(&[lock("a/one.uasset", "alice"), lock("b/two.uasset", "bob")]);

    assert!(message.starts_with("2 file(s) in this change are locked by another user: "));
    assert!(
        message.contains("a/one.uasset (locked by alice)"),
        "{message}"
    );
    assert!(
        message.contains("b/two.uasset (locked by bob)"),
        "{message}"
    );
    assert!(
        message.ends_with("Ask the holder to release the lock"),
        "{message}"
    );
    assert!(
        !message.contains("--ignore-locks"),
        "the library message must not name a CLI flag: {message}"
    );
}

/// The `(path, owner)` of each `LockFileStatus` event a context's dispatcher saw.
type SeenHolders = Arc<std::sync::Mutex<Vec<(String, String)>>>;

/// A context whose dispatcher feeds `LockFileStatus` events to the returned list as
/// `(path, owner)`.
fn capturing_context() -> (Arc<lore_revision::interface::ExecutionContext>, SeenHolders) {
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = seen.clone();
    let callback: lore_revision::interface::LoreEventCallback =
        Some(Box::new(move |event: &lore_revision::event::LoreEvent| {
            if let lore_revision::event::LoreEvent::LockFileStatus(data) = event {
                sink.lock()
                    .expect("the capture mutex must not be poisoned")
                    .push((
                        data.path.as_str().to_owned(),
                        data.owner.as_str().to_owned(),
                    ));
            }
        }));
    let context = Arc::new(
        lore_revision::interface::ExecutionContext::new_client_with_user_id(
            LoreGlobalArgs::default(),
            lore_revision::relay::EventDispatcher::new(callback),
            CALLER.to_string(),
        ),
    );
    (context, seen)
}

/// Run `refuse_if_held_by_others` over `names` under a capturing context; returns the result and
/// the `(path, owner)` events seen.
fn refuse_capturing(rig: &Rig, names: &[&str]) -> (Result<(), CommitError>, Vec<(String, String)>) {
    let (context, seen) = capturing_context();
    let dispatch = context.clone();
    let result = rig.runtime.block_on(LORE_CONTEXT.scope(context, async {
        let repository = rig.fixture.connect(RepositoryAccess::ReadOnly).await;
        let (_, branch) = lore_revision::instance::load_current_anchor_boxed(&repository)
            .await
            .expect("branch");
        let result = refuse_if_held_by_others::<CommitError, _>(
            &repository,
            std::future::ready(Ok((branch, Some(paths(names))))),
            "commit",
        )
        .await;
        dispatch.dispatcher.drain().await;
        result
    }));
    let events = seen
        .lock()
        .expect("the capture mutex must not be poisoned")
        .clone();
    (result, events)
}

/// A refusal sends one `LockFileStatus` per refusing lock, in path order, before returning.
#[test]
fn a_refusal_sends_one_lock_file_status_event_per_lock_in_path_order() {
    let rig = rig(Some(CALLER));
    rig.server.set_status_locks(vec![
        (G.to_owned(), "user-c".to_owned()),
        (F.to_owned(), HOLDER.to_owned()),
    ]);

    let (result, events) = refuse_capturing(&rig, &[F, G]);

    assert!(
        matches!(result, Err(CommitError::LockNotOwned(_))),
        "{result:?}"
    );
    assert_eq!(
        events,
        vec![
            (F.to_owned(), HOLDER.to_owned()),
            (G.to_owned(), "user-c".to_owned()),
        ]
    );
}

/// No event is sent when nothing refuses: no lock, only the caller's own, or only unattributed.
#[test]
fn no_lock_file_status_event_is_sent_when_clear() {
    let rig = rig(Some(CALLER));
    for locks in [
        Vec::new(),
        vec![(F.to_owned(), CALLER.to_owned())],
        vec![(F.to_owned(), UNATTRIBUTED_LOCK_OWNER.to_owned())],
    ] {
        rig.server.set_status_locks(locks.clone());

        let (result, events) = refuse_capturing(&rig, &[F]);

        assert!(result.is_ok(), "{locks:?}: {result:?}");
        assert!(events.is_empty(), "{locks:?}: {events:?}");
    }
}

/// The connected repository, its branch and the fixture's server, for `identity`.
struct Rig {
    runtime: tokio::runtime::Handle,
    server: LockServer,
    fixture: LiveRepository,
}

fn rig(identity: Option<&str>) -> Rig {
    let runtime = lore_base::runtime::runtime();
    let server = runtime.block_on(LockServer::start());
    let fixture = runtime.block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
        match identity {
            Some(identity) => {
                LiveRepository::create_with_files_and_identity(
                    &server.remote_url(),
                    &[F, G],
                    identity,
                )
                .await
            }
            None => LiveRepository::create_with_files(&server.remote_url(), &[F, G]).await,
        }
    }));
    Rig {
        runtime,
        server,
        fixture,
    }
}

impl Rig {
    fn run<T>(&self, body: impl AsyncFnOnce(Arc<RepositoryContext>, BranchId) -> T) -> T {
        self.runtime
            .block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
                let repository = self.fixture.connect(RepositoryAccess::ReadOnly).await;
                let (_, branch) = lore_revision::instance::load_current_anchor_boxed(&repository)
                    .await
                    .expect("the current branch");
                body(repository, branch).await
            }))
    }
}

fn paths(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}

#[test]
fn a_lock_held_by_another_user_is_reported_and_the_callers_own_is_not() {
    let rig = rig(Some(CALLER));
    rig.server.set_status_locks(vec![
        (G.to_owned(), CALLER.to_owned()),
        (F.to_owned(), HOLDER.to_owned()),
    ]);

    let answer = rig
        .run(async |repository, branch| held_by_others(&repository, branch, &paths(&[F, G])).await);

    match answer {
        HeldLocks::ByOthers(locks) => {
            assert_eq!(locks.len(), 1, "{locks:?}");
            assert_eq!(locks[0].resource.description, F);
            assert_eq!(locks[0].owner, HOLDER);
        }
        other => panic!("expected ByOthers, got {other:?}"),
    }
}

#[test]
fn others_locks_are_sorted_by_path() {
    let rig = rig(Some(CALLER));
    rig.server.set_status_locks(vec![
        (G.to_owned(), HOLDER.to_owned()),
        (F.to_owned(), HOLDER.to_owned()),
    ]);

    let answer = rig
        .run(async |repository, branch| held_by_others(&repository, branch, &paths(&[G, F])).await);

    let HeldLocks::ByOthers(locks) = answer else {
        panic!("expected ByOthers, got {answer:?}");
    };
    let listed: Vec<_> = locks
        .iter()
        .map(|l| l.resource.description.clone())
        .collect();
    assert_eq!(listed, paths(&[F, G]));
}

#[test]
fn only_the_callers_own_locks_is_clear() {
    let rig = rig(Some(CALLER));
    rig.server
        .set_status_locks(vec![(F.to_owned(), CALLER.to_owned())]);

    let answer =
        rig.run(async |repository, branch| held_by_others(&repository, branch, &paths(&[F])).await);

    assert_eq!(answer, HeldLocks::Clear);
}

#[test]
fn no_paths_is_clear_without_asking_the_server() {
    let rig = rig(Some(CALLER));

    let answer = rig.run(async |repository, branch| held_by_others(&repository, branch, &[]).await);

    assert_eq!(answer, HeldLocks::Clear);
    assert!(rig.server.calls_for(LockRpc::Status).is_empty());
}

/// Without a known identity a holder cannot be told apart from the caller: unknown, not refused.
#[test]
fn an_unknown_caller_identity_is_unknown() {
    let rig = rig(None);
    rig.server
        .set_status_locks(vec![(F.to_owned(), HOLDER.to_owned())]);

    let answer =
        rig.run(async |repository, branch| held_by_others(&repository, branch, &paths(&[F])).await);

    assert!(matches!(answer, HeldLocks::Unknown(_)), "{answer:?}");
    assert!(
        rig.server.calls_for(LockRpc::Status).is_empty(),
        "no lookup is worth making when the answer could not be read"
    );
}

#[test]
fn offline_skips_the_check() {
    let rig = rig(Some(CALLER));
    rig.server
        .set_status_locks(vec![(F.to_owned(), HOLDER.to_owned())]);
    let offline = Arc::new(
        lore_revision::interface::ExecutionContext::new_client_with_user_id(
            LoreGlobalArgs {
                offline: 1,
                ..LoreGlobalArgs::default()
            },
            lore_revision::relay::EventDispatcher::no_dispatch(),
            CALLER.to_string(),
        ),
    );

    let result = rig.runtime.block_on(LORE_CONTEXT.scope(offline, async {
        let repository = rig.fixture.connect(RepositoryAccess::ReadOnly).await;
        let (_, branch) = lore_revision::instance::load_current_anchor_boxed(&repository)
            .await
            .expect("branch");
        refuse_if_held_by_others::<CommitError, _>(
            &repository,
            std::future::ready(Ok((branch, Some(paths(&[F]))))),
            "commit",
        )
        .await
    }));

    assert!(result.is_ok());
    assert!(rig.server.calls_for(LockRpc::Status).is_empty());
}

#[test]
fn a_positive_answer_refuses_with_lock_not_owned() {
    let rig = rig(Some(CALLER));
    rig.server
        .set_status_locks(vec![(F.to_owned(), HOLDER.to_owned())]);

    let result = rig.run(async |repository, branch| {
        refuse_if_held_by_others::<CommitError, _>(
            &repository,
            std::future::ready(Ok((branch, Some(paths(&[F, G]))))),
            "commit",
        )
        .await
    });

    let error = result.expect_err("another user's lock must refuse");
    assert!(
        matches!(error, CommitError::LockNotOwned(_)),
        "wrong error: {error:?}"
    );
}

#[test]
fn a_failed_path_lookup_or_nothing_to_check_goes_ahead() {
    let rig = rig(Some(CALLER));
    rig.server
        .set_status_locks(vec![(F.to_owned(), HOLDER.to_owned())]);

    let (failed, nothing) = rig.run(async |repository, branch| {
        let failed = refuse_if_held_by_others::<CommitError, _>(
            &repository,
            std::future::ready(Err("the base revision is not local".to_owned())),
            "commit",
        )
        .await;
        let nothing = refuse_if_held_by_others::<CommitError, _>(
            &repository,
            std::future::ready(Ok((branch, None))),
            "push",
        )
        .await;
        (failed, nothing)
    });

    assert!(failed.is_ok());
    assert!(nothing.is_ok());
    assert!(rig.server.calls_for(LockRpc::Status).is_empty());
}

#[test]
fn a_remote_branch_with_no_revisions_has_nothing_to_check() {
    let rig = rig(Some(CALLER));
    rig.server.set_revision_policy(RevisionPolicy {
        branch_get: BranchAnswer::Present {
            latest: vec![0; 32],
            metadata: vec![0x11; 32],
            deleted: false,
        },
        ..RevisionPolicy::default()
    });
    let local = rig.fixture.committed_revision;

    let answer =
        rig.run(async |repository, branch| push_change_paths(&repository, branch, local).await);

    assert_eq!(answer, Ok(None));
}

#[test]
fn a_remote_branch_at_the_local_tip_changes_no_paths() {
    let rig = rig(Some(CALLER));
    let local = rig.fixture.committed_revision;
    rig.server.set_revision_policy(RevisionPolicy {
        branch_get: BranchAnswer::Present {
            latest: <[u8; 32]>::from(local).to_vec(),
            metadata: vec![0x11; 32],
            deleted: false,
        },
        ..RevisionPolicy::default()
    });

    let answer =
        rig.run(async |repository, branch| push_change_paths(&repository, branch, local).await);

    assert_eq!(answer, Ok(Some(Vec::new())));
}

#[test]
fn a_remote_that_does_not_know_the_branch_is_a_lookup_error() {
    let rig = rig(Some(CALLER));
    let local: Hash = rig.fixture.committed_revision;

    let answer =
        rig.run(async |repository, branch| push_change_paths(&repository, branch, local).await);

    assert!(answer.is_err(), "{answer:?}");
}

#[test]
fn nothing_staged_changes_no_paths() {
    let rig = rig(Some(CALLER));

    let (_, changed) = rig
        .run(async |repository, _| staged_change_paths(&repository).await)
        .expect("reading the staged change");

    assert!(changed.is_empty(), "{changed:?}");
}

#[test]
fn a_staged_edit_names_its_path() {
    let rig = rig(Some(CALLER));
    let absolute = rig.fixture.path.join(F);
    // Test fixture write; not subject to repository write-token discipline.
    #[allow(clippy::disallowed_methods)]
    std::fs::write(&absolute, "edited").expect("editing the fixture file");
    rig.runtime
        .block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
            let token = lore_revision::repository::RepositoryWriteToken::acquire(
                rig.fixture.path.as_path(),
            )
            .await;
            let repository = lore_revision::repository::load_and_connect_with_token(
                rig.fixture.path.as_path(),
                RepositoryAccess::ReadWrite,
                Some(token.share()),
            )
            .await
            .expect("opening the repository for writing");
            lore_revision::file::stage::stage(
                repository.clone(),
                &token,
                LoreArray::from_vec(vec![LoreString::from(&absolute)]),
                lore_revision::stage::StageOptions {
                    case_change: lore_revision::stage::StageCaseChange::Error,
                    node_flags: lore_revision::node::NodeFlags::NoFlags,
                    file_id: None,
                    no_children: false,
                    scan: true,
                },
            )
            .await
            .expect("staging the edit");
            repository
                .flush(lore_storage::FlushOptions::SYNC_DATA)
                .await
                .expect("flushing the staged change");
        }));

    let (_, changed) = rig
        .run(async |repository, _| staged_change_paths(&repository).await)
        .expect("reading the staged change");

    assert_eq!(changed, paths(&[F]));
}

/// A lock whose holder the server does not record (auth off) never refuses on its own: it may be
/// the caller's own. The answer is "unknown", which lets the action go ahead.
#[test]
fn only_unattributed_locks_are_unknown_not_refused() {
    let rig = rig(Some(CALLER));
    rig.server
        .set_status_locks(vec![(F.to_owned(), UNATTRIBUTED_LOCK_OWNER.to_owned())]);

    let (answer, refusal) = rig.run(async |repository, branch| {
        let answer = held_by_others(&repository, branch, &paths(&[F])).await;
        let refusal = refuse_if_held_by_others::<CommitError, _>(
            &repository,
            std::future::ready(Ok((branch, Some(paths(&[F]))))),
            "commit",
        )
        .await;
        (answer, refusal)
    });

    assert!(matches!(answer, HeldLocks::Unknown(_)), "{answer:?}");
    assert!(refusal.is_ok());
}

/// Real other-owner locks alongside unattributed ones still refuse, naming only the real ones.
#[test]
fn a_real_holder_alongside_an_unattributed_lock_still_refuses_naming_only_the_real_one() {
    let rig = rig(Some(CALLER));
    rig.server.set_status_locks(vec![
        (F.to_owned(), UNATTRIBUTED_LOCK_OWNER.to_owned()),
        (G.to_owned(), HOLDER.to_owned()),
    ]);

    let answer = rig
        .run(async |repository, branch| held_by_others(&repository, branch, &paths(&[F, G])).await);

    let HeldLocks::ByOthers(locks) = answer else {
        panic!("expected ByOthers, got {answer:?}");
    };
    assert_eq!(locks.len(), 1, "{locks:?}");
    assert_eq!(locks[0].resource.description, G);
    assert_eq!(locks[0].owner, HOLDER);
}

async fn write_token_and_repository(
    rig: &Rig,
) -> (
    Arc<RepositoryContext>,
    lore_revision::repository::RepositoryWriteToken,
) {
    let token =
        lore_revision::repository::RepositoryWriteToken::acquire(rig.fixture.path.as_path()).await;
    let repository = lore_revision::repository::load_and_connect_with_token(
        rig.fixture.path.as_path(),
        RepositoryAccess::ReadWrite,
        Some(token.share()),
    )
    .await
    .expect("opening the repository for writing");
    (repository, token)
}

fn stage_options() -> lore_revision::stage::StageOptions {
    lore_revision::stage::StageOptions {
        case_change: lore_revision::stage::StageCaseChange::Error,
        node_flags: lore_revision::node::NodeFlags::NoFlags,
        file_id: None,
        no_children: false,
        scan: true,
    }
}

/// A staged deletion names the deleted path, so a lock on a deleted file refuses.
#[test]
fn a_staged_delete_names_the_deleted_path() {
    let rig = rig(Some(CALLER));
    let absolute = rig.fixture.path.join(F);
    // Test fixture write; not subject to repository write-token discipline.
    #[allow(clippy::disallowed_methods)]
    std::fs::remove_file(&absolute).expect("deleting the fixture file");
    rig.runtime
        .block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
            let (repository, token) = write_token_and_repository(&rig).await;
            lore_revision::file::stage::stage(
                repository.clone(),
                &token,
                LoreArray::from_vec(vec![LoreString::from(&absolute)]),
                stage_options(),
            )
            .await
            .expect("staging the delete");
            repository
                .flush(lore_storage::FlushOptions::SYNC_DATA)
                .await
                .expect("flushing");
        }));
    rig.server
        .set_status_locks(vec![(F.to_owned(), HOLDER.to_owned())]);

    let refusal = rig.run(async |repository, _| {
        refuse_if_held_by_others::<CommitError, _>(
            &repository,
            async {
                staged_change_paths(&repository)
                    .await
                    .map(|(branch, paths)| (branch, Some(paths)))
            },
            "commit",
        )
        .await
    });

    assert!(
        matches!(refusal, Err(CommitError::LockNotOwned(_))),
        "{refusal:?}"
    );
}

/// A staged move names both ends, so a lock on the moved file's source refuses.
#[test]
fn a_staged_move_names_its_source_and_target() {
    let rig = rig(Some(CALLER));
    let from = rig.fixture.path.join(F);
    let to = rig.fixture.path.join("moved.file");
    // Test fixture write; not subject to repository write-token discipline.
    #[allow(clippy::disallowed_methods)]
    std::fs::rename(&from, &to).expect("moving the fixture file");
    rig.runtime
        .block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
            let (repository, token) = write_token_and_repository(&rig).await;
            lore_revision::file::stage::stage_move(
                repository.clone(),
                &token,
                from.to_string_lossy().into_owned(),
                to.to_string_lossy().into_owned(),
                stage_options(),
            )
            .await
            .expect("staging the move");
            repository
                .flush(lore_storage::FlushOptions::SYNC_DATA)
                .await
                .expect("flushing");
        }));

    let (_, changed) = rig
        .run(async |repository, _| staged_change_paths(&repository).await)
        .expect("reading the staged change");
    assert!(
        changed.contains(&F.to_owned()),
        "source missing: {changed:?}"
    );
    assert!(
        changed.contains(&"moved.file".to_owned()),
        "target missing: {changed:?}"
    );

    rig.server
        .set_status_locks(vec![(F.to_owned(), HOLDER.to_owned())]);
    let answer = rig.run(async |repository, branch| {
        held_by_others(&repository, branch, &changed_or(&repository, branch).await).await
    });
    assert!(matches!(answer, HeldLocks::ByOthers(_)), "{answer:?}");
}

async fn changed_or(repository: &Arc<RepositoryContext>, _branch: BranchId) -> Vec<String> {
    staged_change_paths(repository).await.expect("paths").1
}

/// A local copy BEHIND the remote does not count the remote's own changes as its own: the diff
/// starts at the branch point, not the remote tip.
#[test]
fn a_push_from_behind_the_remote_changes_no_paths() {
    let rig = rig(Some(CALLER));
    let base = rig.fixture.committed_revision;
    let absolute = rig.fixture.path.join(F);
    // Test fixture write; not subject to repository write-token discipline.
    #[allow(clippy::disallowed_methods)]
    std::fs::write(&absolute, "changed upstream").expect("editing the fixture file");
    let tip = rig
        .runtime
        .block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
            let (repository, token) = write_token_and_repository(&rig).await;
            lore_revision::file::stage::stage(
                repository.clone(),
                &token,
                LoreArray::from_vec(vec![LoreString::from(&absolute)]),
                stage_options(),
            )
            .await
            .expect("staging the edit");
            let tip = Box::pin(lore_revision::commit::commit_boxed(
                repository.clone(),
                &token,
                lore_revision::commit::CommitOptions {
                    message: "upstream".to_owned(),
                    link_messages: std::collections::HashMap::new(),
                    link: None,
                    layer_messages: std::collections::HashMap::new(),
                    layer: None,
                },
            ))
            .await
            .expect("committing");
            repository
                .flush(lore_storage::FlushOptions::SYNC_DATA)
                .await
                .expect("flushing");
            tip
        }));
    assert_ne!(tip, base);
    // The remote is at `tip`; the local push candidate is the older `base`.
    rig.server.set_revision_policy(RevisionPolicy {
        branch_get: BranchAnswer::Present {
            latest: <[u8; 32]>::from(tip).to_vec(),
            metadata: vec![0x11; 32],
            deleted: false,
        },
        ..RevisionPolicy::default()
    });

    let answer =
        rig.run(async |repository, branch| push_change_paths(&repository, branch, base).await);

    assert_eq!(answer, Ok(Some(Vec::new())));
}

/// Stage the move of directory `dir` (holding `dir/a.file`) to `moved`.
fn stage_directory_move(rig: &Rig) {
    let from = rig.fixture.path.join("dir");
    let to = rig.fixture.path.join("moved");
    // Test fixture write; not subject to repository write-token discipline.
    #[allow(clippy::disallowed_methods)]
    std::fs::create_dir_all(&from).expect("creating the directory");
    #[allow(clippy::disallowed_methods)]
    std::fs::write(from.join("a.file"), "in a directory").expect("writing the child");
    rig.runtime
        .block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
            let (repository, token) = write_token_and_repository(rig).await;
            lore_revision::file::stage::stage(
                repository.clone(),
                &token,
                LoreArray::from_vec(vec![LoreString::from(&from)]),
                stage_options(),
            )
            .await
            .expect("staging the directory");
            Box::pin(lore_revision::commit::commit_boxed(
                repository.clone(),
                &token,
                lore_revision::commit::CommitOptions {
                    message: "dir".to_owned(),
                    link_messages: std::collections::HashMap::new(),
                    link: None,
                    layer_messages: std::collections::HashMap::new(),
                    layer: None,
                },
            ))
            .await
            .expect("committing the directory");
            #[allow(clippy::disallowed_methods)]
            std::fs::rename(&from, &to).expect("moving the directory");
            lore_revision::file::stage::stage_move(
                repository.clone(),
                &token,
                from.to_string_lossy().into_owned(),
                to.to_string_lossy().into_owned(),
                stage_options(),
            )
            .await
            .expect("staging the directory move");
            repository
                .flush(lore_storage::FlushOptions::SYNC_DATA)
                .await
                .expect("flushing");
        }));
}

/// A directory move names the child's OLD path too.
#[test]
fn a_staged_directory_move_names_the_childs_old_path() {
    let rig = rig(Some(CALLER));
    stage_directory_move(&rig);

    let (_, changed) = rig
        .run(async |repository, _| staged_change_paths(&repository).await)
        .expect("reading the staged change");

    for expected in ["dir/a.file", "moved/a.file"] {
        assert!(
            changed.contains(&expected.to_owned()),
            "{expected} missing: {changed:?}"
        );
    }
}

/// Another user's lock on the child's OLD path refuses the commit.
#[test]
fn a_lock_on_a_moved_directorys_child_old_path_refuses() {
    let rig = rig(Some(CALLER));
    stage_directory_move(&rig);
    rig.server
        .set_status_locks(vec![("dir/a.file".to_owned(), HOLDER.to_owned())]);

    let refusal = rig.run(async |repository, _| {
        refuse_if_held_by_others::<CommitError, _>(
            &repository,
            async {
                staged_change_paths(&repository)
                    .await
                    .map(|(branch, paths)| (branch, Some(paths)))
            },
            "commit",
        )
        .await
    });

    assert!(
        matches!(refusal, Err(CommitError::LockNotOwned(_))),
        "{refusal:?}"
    );
}

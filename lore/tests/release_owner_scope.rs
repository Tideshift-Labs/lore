// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! [CLIENT] Whose locks a no-paths `lock release --force` breaks.
//!
//! The release used to query every owner's locks on the branch and escalate each refused row to a
//! `ForceUnlock`, so an administrator silently broke the whole branch. Now the query names the
//! caller, rows owned by anyone else are dropped on the client too, and breaking other owners'
//! locks takes `--owner` or the `--all-owners` entry point, both of which list what they break.

use std::sync::Arc;
use std::sync::Mutex;

use lore::interface::LoreEventCallback;
use lore_base::runtime::LORE_CONTEXT;
use lore_revision::interface::LoreArray;
use lore_revision::interface::LoreEvent;
use lore_revision::interface::LoreString;
use lore_revision::live_fixture::LiveRepository;
use lore_revision::live_fixture::LockPolicy;
use lore_revision::live_fixture::LockRpc;
use lore_revision::live_fixture::LockServer;
use lore_revision::live_fixture::Refusal;
use lore_revision::live_fixture::RpcOutcome;
use lore_revision::live_fixture::fixture_execution_context;
use lore_transport::VolatileAttemptStore;
use lore_transport::attempt_store::AttemptStore;

const CALLER: &str = "fixture-user";
const OTHER: &str = "someone-else";

/// What the callback saw: warning text, and the paths of release events.
#[derive(Default)]
struct Seen {
    logs: Vec<String>,
    released: Vec<String>,
}

fn capture() -> (LoreEventCallback, Arc<Mutex<Seen>>) {
    // Routes `lore_warn!` into the execution context's event stream; without it no `Log` event
    // reaches the callback at all. Idempotent.
    lore::log::initialize();
    let seen = Arc::new(Mutex::new(Seen::default()));
    let sink = seen.clone();
    let callback: LoreEventCallback = Some(Box::new(move |event: &LoreEvent| {
        let mut seen = sink.lock().expect("the capture mutex must not be poisoned");
        match event {
            LoreEvent::Log(data) => seen.logs.push(data.message.as_str().to_owned()),
            LoreEvent::LockFileRelease(data) => seen.released.push(data.path.as_str().to_owned()),
            _ => {}
        }
    }));
    (callback, seen)
}

fn no_paths_args() -> lore::lock::LoreLockFileReleaseArgs {
    lore::lock::LoreLockFileReleaseArgs {
        paths: LoreArray::default(),
        branch: LoreString::default(),
        owner: LoreString::default(),
        owner_id: LoreString::default(),
    }
}

/// Every resource description the server ever saw in an `Unlock` or `ForceUnlock`.
fn broken_paths(server: &LockServer) -> Vec<String> {
    server
        .calls()
        .into_iter()
        .filter(|call| matches!(call.rpc, LockRpc::Unlock | LockRpc::ForceUnlock))
        .flat_map(|call| call.descriptions)
        .collect()
}

fn refuse_unlock_grant_force(query_result: Vec<(String, String)>) -> LockPolicy {
    LockPolicy {
        mint_ownership_tokens: false,
        unlock: RpcOutcome::Refuse(Refusal::PermissionDenied),
        force_unlock: RpcOutcome::Grant,
        query_result,
        ..LockPolicy::default()
    }
}

struct Rig {
    runtime: tokio::runtime::Handle,
    server: LockServer,
    fixture: LiveRepository,
}

/// A server and a two-file repository, optionally configured with a caller identity.
fn rig(identity: Option<&str>) -> Rig {
    let runtime = lore::runtime();
    let server = runtime.block_on(LockServer::start());
    let fixture = runtime.block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
        match identity {
            Some(identity) => {
                LiveRepository::create_with_files_and_identity(
                    &server.remote_url(),
                    &["a.file", "b.file"],
                    identity,
                )
                .await
            }
            None => {
                LiveRepository::create_with_files(&server.remote_url(), &["a.file", "b.file"]).await
            }
        }
    }));
    Rig {
        runtime,
        server,
        fixture,
    }
}

fn forced(fixture: &LiveRepository) -> lore::interface::LoreGlobalArgs {
    let mut globals = fixture.globals();
    globals.force = 1;
    globals
}

fn attempts() -> Arc<dyn AttemptStore> {
    Arc::new(VolatileAttemptStore::new())
}

/// The reported bug. Rows held by someone else are on the branch, the caller is refused on both
/// (it holds no token), and the stub grants `ForceUnlock` the way an admin's call would be. The
/// caller's own row may be force-released; the other owner's must never be named in any release.
#[test]
fn a_default_force_release_never_touches_another_owners_lock() {
    let rig = rig(Some(CALLER));
    let (a, b) = (
        rig.fixture.committed_files[0].clone(),
        rig.fixture.committed_files[1].clone(),
    );
    rig.server.set_policy(refuse_unlock_grant_force(vec![
        (a.clone(), OTHER.to_owned()),
        (b.clone(), CALLER.to_owned()),
    ]));
    let (callback, _) = capture();

    let status = rig
        .runtime
        .block_on(lore::lock::file_release_with_attempt_store(
            forced(&rig.fixture),
            no_paths_args(),
            callback,
            attempts(),
        ));

    assert_eq!(status, 0, "calls: {:?}", rig.server.calls());
    let queries = rig.server.calls_for(LockRpc::Query);
    assert_eq!(queries.len(), 1);
    assert_eq!(
        queries[0].owner, CALLER,
        "the query must name the caller, not ask for every owner"
    );
    let force_unlocks = rig.server.calls_for(LockRpc::ForceUnlock);
    assert_eq!(force_unlocks.len(), 1, "got {:?}", rig.server.calls());
    assert_eq!(force_unlocks[0].owner, CALLER);
    assert_eq!(force_unlocks[0].descriptions, vec![b]);
    assert!(
        !broken_paths(&rig.server).contains(&a),
        "{other}'s lock on {a} reached an Unlock or ForceUnlock: {:?}",
        rig.server.calls(),
        other = OTHER,
    );
}

/// As above against a server that ignores the owner filter: the client's own check on each row's
/// owner is the only thing standing between the caller and the other owner's lock.
#[test]
fn a_server_that_ignores_the_owner_filter_still_never_gets_another_owners_lock() {
    let rig = rig(Some(CALLER));
    let (a, b) = (
        rig.fixture.committed_files[0].clone(),
        rig.fixture.committed_files[1].clone(),
    );
    rig.server.set_policy(LockPolicy {
        query_ignores_owner: true,
        ..refuse_unlock_grant_force(vec![
            (a.clone(), OTHER.to_owned()),
            (b.clone(), CALLER.to_owned()),
        ])
    });
    let (callback, _) = capture();

    let status = rig
        .runtime
        .block_on(lore::lock::file_release_with_attempt_store(
            forced(&rig.fixture),
            no_paths_args(),
            callback,
            attempts(),
        ));

    assert_eq!(status, 0, "calls: {:?}", rig.server.calls());
    assert_eq!(rig.server.calls_for(LockRpc::Query)[0].owner, CALLER);
    let broken = broken_paths(&rig.server);
    assert!(
        !broken.contains(&a),
        "the other owner's row was sent despite the client-side check: {:?}",
        rig.server.calls()
    );
    assert!(
        broken.contains(&b),
        "the caller's own row must still be released: {:?}",
        rig.server.calls()
    );
}

/// The ordinary case: a user whose own lock has no token here clears it with `--force`.
#[test]
fn a_user_clears_their_own_tokenless_lock_with_force() {
    let rig = rig(Some(CALLER));
    let a = rig.fixture.committed_files[0].clone();
    rig.server.set_policy(refuse_unlock_grant_force(vec![(
        a.clone(),
        CALLER.to_owned(),
    )]));
    let (callback, seen) = capture();

    let status = rig
        .runtime
        .block_on(lore::lock::file_release_with_attempt_store(
            forced(&rig.fixture),
            no_paths_args(),
            callback,
            attempts(),
        ));

    assert_eq!(status, 0, "calls: {:?}", rig.server.calls());
    assert_eq!(rig.server.calls_for(LockRpc::ForceUnlock).len(), 1);
    assert_eq!(
        seen.lock().expect("capture mutex").released,
        vec![a],
        "the release must be reported for the cleared path"
    );
}

/// With no known caller the query would match every owner, which is the takeover this change
/// removes. The release must fail before any RPC.
#[test]
fn a_default_force_release_with_no_identity_fails_before_any_rpc() {
    let rig = rig(None);
    let a = rig.fixture.committed_files[0].clone();
    rig.server
        .set_policy(refuse_unlock_grant_force(vec![(a, OTHER.to_owned())]));
    let (callback, _) = capture();

    let status = rig
        .runtime
        .block_on(lore::lock::file_release_with_attempt_store(
            forced(&rig.fixture),
            no_paths_args(),
            callback,
            attempts(),
        ));

    assert_ne!(status, 0, "an unknown caller must not release anything");
    assert!(
        rig.server.calls().is_empty(),
        "no Query, Unlock or ForceUnlock may be sent, got {:?}",
        rig.server.calls()
    );
}

/// `--all-owners` is the explicit opt-in: it queries with no owner, says what it will break, and
/// escalates once per owner with only that owner's rows.
#[test]
fn all_owners_lists_what_it_breaks_and_force_releases_per_owner() {
    let rig = rig(None);
    let (a, b) = (
        rig.fixture.committed_files[0].clone(),
        rig.fixture.committed_files[1].clone(),
    );
    rig.server.set_policy(refuse_unlock_grant_force(vec![
        (a.clone(), "alice".to_owned()),
        (b.clone(), "bob".to_owned()),
    ]));
    let (callback, seen) = capture();

    let status = rig
        .runtime
        .block_on(lore::lock::file_release_all_owners_with_attempt_store(
            forced(&rig.fixture),
            no_paths_args(),
            callback,
            attempts(),
        ));

    assert_eq!(status, 0, "calls: {:?}", rig.server.calls());
    let queries = rig.server.calls_for(LockRpc::Query);
    assert_eq!(queries.len(), 1);
    assert_eq!(queries[0].owner, "", "all owners means no owner filter");

    let mut force_unlocks = rig
        .server
        .calls_for(LockRpc::ForceUnlock)
        .into_iter()
        .map(|call| (call.owner, call.descriptions))
        .collect::<Vec<_>>();
    force_unlocks.sort();
    assert_eq!(
        force_unlocks,
        vec![
            ("alice".to_owned(), vec![a.clone()]),
            ("bob".to_owned(), vec![b.clone()]),
        ]
    );

    let logs = seen.lock().expect("capture mutex").logs.clone();
    assert!(
        logs.iter()
            .any(|line| line.contains("Breaking 2 lock(s) held by any owner")),
        "missing the count line, got {logs:?}"
    );
    assert!(
        logs.contains(&format!("{a} held by alice")),
        "missing alice's line, got {logs:?}"
    );
    assert!(
        logs.contains(&format!("{b} held by bob")),
        "missing bob's line, got {logs:?}"
    );
}

/// The all-owners entry point refuses every shape that is not a bare `--force`.
#[test]
fn all_owners_refuses_paths_a_named_owner_and_a_missing_force() {
    let rig = rig(Some(CALLER));
    let a = rig.fixture.committed_files[0].clone();
    rig.server
        .set_policy(refuse_unlock_grant_force(vec![(a, OTHER.to_owned())]));

    let with_paths = lore::lock::LoreLockFileReleaseArgs {
        paths: LoreArray::from_vec(
            rig.fixture
                .committed_files_absolute
                .iter()
                .map(LoreString::from)
                .collect(),
        ),
        ..no_paths_args()
    };
    let with_owner = lore::lock::LoreLockFileReleaseArgs {
        owner_id: LoreString::from_str(OTHER),
        ..no_paths_args()
    };

    let cases = [
        ("paths", forced(&rig.fixture), with_paths),
        ("named owner", forced(&rig.fixture), with_owner),
        ("no --force", rig.fixture.globals(), no_paths_args()),
    ];
    for (name, globals, args) in cases {
        let (callback, _) = capture();
        let status = rig
            .runtime
            .block_on(lore::lock::file_release_all_owners_with_attempt_store(
                globals,
                args,
                callback,
                attempts(),
            ));
        assert_ne!(status, 0, "{name}: must be refused");
        assert!(
            rig.server.calls().is_empty(),
            "{name}: no RPC may be sent, got {:?}",
            rig.server.calls()
        );
    }
}

/// Naming an owner is the other explicit target: only that owner's rows are broken, after a
/// listing. `owner_id` skips the user-service name resolution.
#[test]
fn a_named_owner_lists_and_force_releases_only_that_owners_locks() {
    let rig = rig(Some(CALLER));
    let (a, b) = (
        rig.fixture.committed_files[0].clone(),
        rig.fixture.committed_files[1].clone(),
    );
    rig.server.set_policy(refuse_unlock_grant_force(vec![
        (a.clone(), OTHER.to_owned()),
        (b.clone(), CALLER.to_owned()),
    ]));
    let (callback, seen) = capture();

    let status = rig
        .runtime
        .block_on(lore::lock::file_release_with_attempt_store(
            forced(&rig.fixture),
            lore::lock::LoreLockFileReleaseArgs {
                owner_id: LoreString::from_str(OTHER),
                ..no_paths_args()
            },
            callback,
            attempts(),
        ));

    assert_eq!(status, 0, "calls: {:?}", rig.server.calls());
    assert_eq!(rig.server.calls_for(LockRpc::Query)[0].owner, OTHER);
    let force_unlocks = rig.server.calls_for(LockRpc::ForceUnlock);
    assert_eq!(force_unlocks.len(), 1);
    assert_eq!(force_unlocks[0].owner, OTHER);
    assert_eq!(force_unlocks[0].descriptions, vec![a.clone()]);
    assert!(!broken_paths(&rig.server).contains(&b));

    let logs = seen.lock().expect("capture mutex").logs.clone();
    assert!(
        logs.contains(&format!("{a} held by {OTHER}")),
        "missing the listing line, got {logs:?}"
    );
}

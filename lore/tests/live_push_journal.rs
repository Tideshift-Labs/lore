// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! The push entry point's attempt journal, driven against a remote that answers (WP-120).
//!
//! `push_with_attempt_store` forwards a caller-supplied store down to `lore_revision`'s push, and
//! that forwarding was the one unproven link in the chain. The helper's record-before-dispatch and
//! per-dispatch identity are pinned by unit tests in `lore-revision/src/dispatch.rs`, an in-scope
//! id reaching the wire was pinned at `f92a8eb`, and server persistence plus the receipt read were
//! pinned by a live-Postgres round trip. What none of them cover is whether the store handed to
//! the public entry point ever reaches those dispatches at all, because proving that needs a
//! repository whose remote answers. It now exists.

use std::sync::Arc;

use lore::interface::LoreEventCallback;
use lore_base::runtime::LORE_CONTEXT;
use lore_revision::interface::LoreEventCallbackConfig;
use lore_revision::interface::LoreString;
use lore_revision::live_fixture::BranchAnswer;
use lore_revision::live_fixture::LiveRepository;
use lore_revision::live_fixture::LockServer;
use lore_revision::live_fixture::RevisionPolicy;
use lore_revision::live_fixture::RevisionRpc;
use lore_revision::live_fixture::RpcOutcome;
use lore_revision::live_fixture::fixture_execution_context;
use lore_transport::VolatileAttemptStore;
use lore_transport::attempt_store::AttemptResolution;
use lore_transport::attempt_store::AttemptState;
use lore_transport::attempt_store::AttemptStore;
use lore_transport::outcome::AttemptId;
use lore_transport::outcome::GrpcRpc;

fn no_callback() -> LoreEventCallback {
    lore_revision::event::convert_event_callback(LoreEventCallbackConfig {
        user_context: 0,
        func: None,
    })
}

/// A caller-supplied store reaches the push's dispatches, and the id it journals is the id the
/// server is asked under.
///
/// The remote is steered into the one push shape that reaches an irreversible dispatch without
/// also needing every fragment-upload RPC modelled: it reports the branch's tip as exactly this
/// repository's local tip, so the push is idempotent, and reports the branch as tombstoned, so the
/// push restores it with a single `BranchCreate` before returning. That is one dispatch, which is
/// what makes the counting assertions below unambiguous.
///
/// Three claims are checked and they are not the same claim. The server saw exactly one
/// `BranchCreate`, so the plumbing carried the operation. That request carried an attempt id in
/// its header, and looking that exact id up in the caller's store finds a record, so the id the
/// caller journalled is the id the server was asked under rather than two independently minted
/// values that happen to coexist. And the record is resolved `Applied` rather than left standing,
/// because a successful dispatch that stayed unresolved would leave the caller reconciling a
/// mutation that already, provably, happened.
#[test]
fn push_with_attempt_store_journals_the_dispatch_it_forwards() {
    let runtime = lore::runtime();

    let server = runtime.block_on(LockServer::start());
    let fixture = runtime.block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
        LiveRepository::create(&server.remote_url()).await
    }));

    // Set after the fixture exists, because the answer that makes the push idempotent is the
    // repository's own tip and nothing knows it until the commit has happened.
    server.set_revision_policy(RevisionPolicy {
        branch_get: BranchAnswer::Present {
            latest: <[u8; 32]>::from(fixture.committed_revision).to_vec(),
            // Any non-zero value. A zero metadata hash would send the push down the
            // initial-branch-creation path instead, which needs fragments uploaded.
            metadata: vec![0x11; 32],
            deleted: true,
        },
        branch_create: RpcOutcome::Grant,
        branch_push: RpcOutcome::Grant,
    });

    let store = Arc::new(VolatileAttemptStore::new());
    let attempts: Arc<dyn AttemptStore> = store.clone();

    let status = runtime.block_on(lore::branch::push_with_attempt_store(
        fixture.globals(),
        lore::branch::LoreBranchPushArgs {
            branch: LoreString::default(),
            fast_forward_merge: 0,
        },
        no_callback(),
        attempts,
    ));

    assert_eq!(
        status,
        0,
        "the push must succeed; revision calls seen: {:?}",
        server.revision_calls()
    );

    let creates = server.revision_calls_for(RevisionRpc::BranchCreate);
    assert_eq!(
        creates.len(),
        1,
        "restoring a tombstoned branch at the same tip is exactly one dispatch, got {:?}",
        server.revision_calls()
    );

    let header = creates[0]
        .attempt_id
        .clone()
        .expect("the dispatch must carry an attempt id to the server");
    let attempt = AttemptId::from_uuid(
        uuid::Uuid::parse_str(&header).expect("the header must be a well-formed attempt id"),
    );

    let record = runtime
        .block_on(store.lookup(&attempt))
        .expect("reading the caller's store")
        .expect(
            "the id the server was asked under must be present in the caller's own store; if it \
             is not, the caller journalled one identity and the server was asked under another",
        );

    assert_eq!(
        record.operation,
        GrpcRpc::RevisionBranchCreate.wire_name(),
        "the record must name the RPC that was actually dispatched"
    );
    assert_eq!(
        record.repository, fixture.repository_id,
        "the record must name the repository the dispatch was scoped to"
    );
    assert!(
        matches!(
            record.state,
            AttemptState::Resolved(AttemptResolution::Applied)
        ),
        "a dispatch the server answered must be resolved Applied, was {:?}",
        record.state
    );
    assert!(
        runtime
            .block_on(store.unresolved())
            .expect("reading the caller's store")
            .is_empty(),
        "nothing may be left unresolved after a push whose every dispatch was answered"
    );
}

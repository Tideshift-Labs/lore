// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! The lock verbs' attempt journal, driven against a remote that answers (WP-120).

use std::sync::Arc;

use lore::interface::LoreEventCallback;
use lore_base::runtime::LORE_CONTEXT;
use lore_revision::interface::LoreArray;
use lore_revision::interface::LoreEventCallbackConfig;
use lore_revision::interface::LoreString;
use lore_revision::live_fixture::LiveRepository;
use lore_revision::live_fixture::LockRpc;
use lore_revision::live_fixture::LockServer;
use lore_revision::live_fixture::fixture_execution_context;
use lore_transport::VolatileAttemptStore;
use lore_transport::attempt_store::AttemptStore;

fn no_callback() -> LoreEventCallback {
    lore_revision::event::convert_event_callback(LoreEventCallbackConfig {
        user_context: 0,
        func: None,
    })
}

/// The fixture reaches a real lock dispatch, and the caller's store is what journals it.
///
/// This is the smoke test for the fixture itself as much as for the entry point: if the remote
/// were not resolving to `Connected`, the acquire would fail offline before it reached a single
/// dispatch and the server would have seen nothing.
#[test]
fn file_acquire_with_attempt_store_journals_the_lock_dispatch() {
    let runtime = lore::runtime();

    let server = runtime.block_on(LockServer::start());
    let fixture = runtime.block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
        LiveRepository::create(&server.remote_url()).await
    }));

    let store = Arc::new(VolatileAttemptStore::new());
    let attempts: Arc<dyn AttemptStore> = store.clone();

    let status = runtime.block_on(lore::lock::file_acquire_with_attempt_store(
        fixture.globals(),
        lore::lock::LoreLockFileAcquireArgs {
            paths: LoreArray::from_vec(
                fixture
                    .committed_files_absolute
                    .iter()
                    .map(LoreString::from)
                    .collect(),
            ),
            branch: LoreString::default(),
        },
        no_callback(),
        attempts,
    ));

    assert_eq!(status, 0, "the acquire must succeed against the fixture");

    let locks = server.calls_for(LockRpc::Lock);
    assert_eq!(
        locks.len(),
        1,
        "one batch of one path is one lock dispatch, got {:?}",
        server.calls()
    );
    assert!(
        locks[0].attempt_id.is_some(),
        "the dispatch must have carried an attempt id to the server"
    );
}

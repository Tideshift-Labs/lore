// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! [CLIENT] A lock verb whose answer was lost leaves the same ownership after recovery as a live
//! answer would have (WP-120). Without the token an applied acquire records, its owner cannot
//! release the lock, and only an administrator's force release clears it.
#![allow(clippy::disallowed_methods)] // Reads the fixture's own ownership document.

use std::future::Future;
use std::path::Path;
use std::sync::Arc;

use lore::interface::LoreEventCallback;
use lore_base::error::OutcomeUnknown;
use lore_base::runtime::LORE_CONTEXT;
use lore_revision::interface::LoreArray;
use lore_revision::interface::LoreEventCallbackConfig;
use lore_revision::interface::LoreString;
use lore_revision::live_fixture::LiveRepository;
use lore_revision::live_fixture::LockPolicy;
use lore_revision::live_fixture::LockRpc;
use lore_revision::live_fixture::LockServer;
use lore_revision::live_fixture::RpcOutcome;
use lore_revision::live_fixture::fixture_execution_context;
use lore_revision::repository_fence::RepositoryMutationGuard;
use lore_transport::AttemptStore;
use uuid::Uuid;

fn no_callback() -> LoreEventCallback {
    lore_revision::event::convert_event_callback(LoreEventCallbackConfig {
        user_context: 0,
        func: None,
    })
}

fn paths(fixture: &LiveRepository) -> LoreArray<LoreString> {
    LoreArray::from_vec(
        fixture
            .committed_files_absolute
            .iter()
            .map(LoreString::from)
            .collect(),
    )
}

/// The CLI's managed adoption (`lore-client`'s `commands::operation::managed`), which this crate
/// cannot depend on: admit (auto-settling what receipts decide), open a parent, run the verb under
/// it, and leave the parent open when the outcome is unknown.
async fn managed<F, Fut>(root: &Path, operation: &str, command: F) -> i32
where
    F: FnOnce(Arc<dyn AttemptStore>) -> Fut,
    Fut: Future<Output = i32>,
{
    let fence = lore::recovery::admit(root)
        .await
        .expect("admission settles or refuses before the verb");
    let parent = Uuid::now_v7();
    let store = fence
        .begin(parent, operation.to_owned(), "fixture".to_owned())
        .await
        .expect("a parent begins");
    let status = fence
        .run(lore_transport::with_managed_caller(
            parent,
            store.clone(),
            command(store.clone()),
        ))
        .await;
    store
        .complete_parent_body(parent)
        .await
        .expect("the body completes");
    if status != OutcomeUnknown::FFI_CODE {
        fence.finish(parent).await.expect("a decided parent closes");
    }
    status
}

async fn acquire(fixture: &LiveRepository) -> i32 {
    managed(&fixture.path, "lock-acquire", |store| {
        lore::lock::file_acquire_with_attempt_store(
            fixture.globals(),
            lore::lock::LoreLockFileAcquireArgs {
                paths: paths(fixture),
                branch: LoreString::default(),
            },
            no_callback(),
            store,
        )
    })
    .await
}

async fn release(fixture: &LiveRepository) -> i32 {
    managed(&fixture.path, "lock-release", |store| {
        lore::lock::file_release_with_attempt_store(
            fixture.globals(),
            lore::lock::LoreLockFileReleaseArgs {
                paths: paths(fixture),
                branch: LoreString::default(),
                owner: LoreString::default(),
                owner_id: LoreString::default(),
            },
            no_callback(),
            store,
        )
    })
    .await
}

/// `lore operation reconcile`, reading receipts over the fixture's real wire.
async fn reconcile(root: &Path) -> Result<(), lore_transport::ProtocolError> {
    let fence = RepositoryMutationGuard::recover(root)
        .await
        .expect("recovery opens the fence");
    lore::recovery::reconcile(&fence, |store, attempt| async move {
        lore::recovery::receipt_get(&store, &attempt).await
    })
    .await
}

/// Ownership rows in the store the lock verbs derive from the repository (`.lore/attempts`).
fn ownership_rows(root: &Path) -> usize {
    let Ok(document) = std::fs::read(root.join(".lore").join("attempts")) else {
        return 0;
    };
    // Byte 0 is the format version, not part of the JSON body.
    let json: serde_json::Value =
        serde_json::from_slice(&document[1..]).expect("the attempt store body is JSON");
    json.get("ownership")
        .and_then(serde_json::Value::as_array)
        .map_or(0, Vec::len)
}

/// A live fixture whose managed principal is selected, kept alive for the whole test.
struct Live {
    server: LockServer,
    fixture: LiveRepository,
    _connection: Arc<lore_transport::connection::Connection>,
}

fn live(runtime: &tokio::runtime::Handle, policy: LockPolicy) -> Live {
    runtime.block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
        let server = LockServer::start_with_policy(policy).await;
        let fixture = LiveRepository::create_managed(&format!("{}/", server.remote_url())).await;
        let connection = fixture.managed_connection().await;
        Live {
            server,
            fixture,
            _connection: connection,
        }
    }))
}

/// Assert the release presented the recovered token through the owner's own `Unlock`, never
/// escalating to an administrative force release, and cleared the row.
fn assert_released_with_token(live: &Live) {
    let unlocks = live.server.calls_for(LockRpc::Unlock);
    assert_eq!(unlocks.len(), 1, "one ordinary release");
    assert!(
        unlocks[0].all_resources_carried_a_token,
        "the release must present the token the recovered acquire was granted"
    );
    assert!(
        live.server.calls_for(LockRpc::ForceUnlock).is_empty(),
        "the owner's release must not need an administrative force release"
    );
    assert_eq!(ownership_rows(&live.fixture.path), 0);
}

#[test]
fn a_reconciled_lost_acquire_keeps_its_token_and_the_owner_releases_with_it() {
    let runtime = lore::runtime();
    let live = live(
        &runtime,
        LockPolicy {
            lock: RpcOutcome::ApplyThenLoseTheAnswer,
            ..LockPolicy::default()
        },
    );

    assert_eq!(
        runtime.block_on(acquire(&live.fixture)),
        OutcomeUnknown::FFI_CODE
    );
    assert_eq!(ownership_rows(&live.fixture.path), 0, "no answer, no token");

    runtime
        .block_on(reconcile(&live.fixture.path))
        .expect("the applied receipt settles the acquire");
    assert_eq!(
        ownership_rows(&live.fixture.path),
        1,
        "reconcile keeps the token the receipt returned"
    );

    assert_eq!(runtime.block_on(release(&live.fixture)), 0);
    assert_released_with_token(&live);
}

#[test]
fn write_admission_auto_settles_a_lost_acquire_with_its_token() {
    let runtime = lore::runtime();
    let live = live(
        &runtime,
        LockPolicy {
            lock: RpcOutcome::ApplyThenLoseTheAnswer,
            ..LockPolicy::default()
        },
    );

    assert_eq!(
        runtime.block_on(acquire(&live.fixture)),
        OutcomeUnknown::FFI_CODE
    );
    // No explicit reconcile: the release's own admission settles the blocked acquire first.
    assert_eq!(runtime.block_on(release(&live.fixture)), 0);
    assert_released_with_token(&live);
}

#[test]
fn a_reconciled_lost_release_clears_the_token() {
    let runtime = lore::runtime();
    let live = live(&runtime, LockPolicy::default());

    assert_eq!(runtime.block_on(acquire(&live.fixture)), 0);
    assert_eq!(ownership_rows(&live.fixture.path), 1);

    live.server.set_policy(LockPolicy {
        unlock: RpcOutcome::ApplyThenLoseTheAnswer,
        ..LockPolicy::default()
    });
    assert_eq!(
        runtime.block_on(release(&live.fixture)),
        OutcomeUnknown::FFI_CODE
    );
    assert_eq!(
        ownership_rows(&live.fixture.path),
        1,
        "an unknown release keeps the token"
    );

    runtime
        .block_on(reconcile(&live.fixture.path))
        .expect("the applied receipt settles the release");
    assert_eq!(
        ownership_rows(&live.fixture.path),
        0,
        "an applied release clears the token, as a confirmed live release does"
    );
}

/// A recovered release clears only the token it presented. A row that holds a newer token by the
/// time the receipt is read (here written directly, standing in for a later acquire) is kept.
#[test]
fn a_reconciled_lost_release_keeps_a_newer_token_for_the_same_row() {
    let runtime = lore::runtime();
    let live = live(&runtime, LockPolicy::default());
    assert_eq!(runtime.block_on(acquire(&live.fixture)), 0);

    live.server.set_policy(LockPolicy {
        unlock: RpcOutcome::ApplyThenLoseTheAnswer,
        ..LockPolicy::default()
    });
    assert_eq!(
        runtime.block_on(release(&live.fixture)),
        OutcomeUnknown::FFI_CODE
    );

    let document = std::fs::read(live.fixture.path.join(".lore").join("attempts")).unwrap();
    let json: serde_json::Value = serde_json::from_slice(&document[1..]).unwrap();
    let row = &json["ownership"][0];
    let newer = lore_transport::attempt_store::LockOwnership {
        attempt_id: lore_transport::AttemptId::new(),
        branch: row["branch"].as_str().unwrap().parse().unwrap(),
        resource_hash: row["resource"].as_str().unwrap().parse().unwrap(),
        token: lore_transport::attempt_store::OwnershipToken::from_wire(&[9; 32])
            .unwrap()
            .unwrap(),
    };
    let ownership = lore_revision::attempt_store::RepositoryAttemptStore::in_directory(
        live.fixture.path.join(".lore"),
    );
    runtime
        .block_on(ownership.record_ownership(&newer))
        .unwrap();

    runtime
        .block_on(reconcile(&live.fixture.path))
        .expect("the applied receipt settles the release");
    let kept = runtime
        .block_on(ownership.ownership_for(&newer.branch, &newer.resource_hash))
        .unwrap()
        .expect("the newer token survives");
    assert_eq!(kept.token, newer.token);
}

/// How a test alters the real receipt before recovery reads it.
type Tamper = fn(&mut lore_transport::DomainAttemptReceipt);

/// A receipt that binds a token to another principal, or leaves a requested lock without one,
/// stores nothing and keeps the acquire unresolved.
#[test]
fn a_receipt_that_does_not_bind_every_token_to_this_attempt_keeps_the_acquire_blocked() {
    let cases: [(&str, Tamper); 2] = [
        ("another owner", |receipt| {
            for acquired in &mut receipt.acquired_locks {
                acquired.lock.owner = "someone-else".to_owned();
            }
        }),
        ("a missing lock", |receipt| receipt.acquired_locks.clear()),
    ];
    let runtime = lore::runtime();
    for (case, tamper) in cases {
        let live = live(
            &runtime,
            LockPolicy {
                lock: RpcOutcome::ApplyThenLoseTheAnswer,
                ..LockPolicy::default()
            },
        );
        assert_eq!(
            runtime.block_on(acquire(&live.fixture)),
            OutcomeUnknown::FFI_CODE,
            "{case}"
        );

        let error = runtime
            .block_on(async {
                let fence = RepositoryMutationGuard::recover(&live.fixture.path)
                    .await
                    .expect("recovery opens the fence");
                lore::recovery::reconcile(&fence, |store, attempt| async move {
                    let mut receipt = lore::recovery::receipt_get(&store, &attempt).await?;
                    tamper(&mut receipt);
                    Ok(receipt)
                })
                .await
            })
            .expect_err("a token this attempt cannot own must not be kept");
        assert!(
            error.to_string().contains("lock ownership not recovered"),
            "{case}: {error}"
        );
        assert_eq!(ownership_rows(&live.fixture.path), 0, "{case}");

        let fence = runtime
            .block_on(RepositoryMutationGuard::recover(&live.fixture.path))
            .expect("recovery opens the fence");
        assert_eq!(
            runtime
                .block_on(fence.store().unresolved())
                .expect("the journal reads")
                .len(),
            1,
            "{case}: the acquire stays unresolved"
        );
    }
}

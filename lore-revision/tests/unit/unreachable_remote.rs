// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! A remote whose storage cannot be reached is reported as unreachable, not as a missing
//! repository, an internal failure, or an up-to-date head.
//!
//! [CLIENT]-class (`lore-revision`). A front that passes TCP and drops UDP leaves the revision and
//! repository services answering while the QUIC storage connect times out. Before these checks a
//! head sync at the remote's latest said "Already on branch latest" and exited 0, a state read
//! failed as internal (exit 255), and a repository metadata read said "Repository not found".
use std::sync::Arc;
use std::time::Duration;

use lore_base::error::Disconnected;
use lore_base::error::NoRemote;
use lore_base::error::NotAuthenticated;
use lore_base::error::NotAuthorized;
use lore_base::error::NotFound;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::BranchId;
use lore_base::types::Hash;
use lore_error_set::prelude::*;
use lore_revision::instance::load_current_anchor_boxed;
use lore_revision::interface::ExecutionContext;
use lore_revision::interface::LoreEvent;
use lore_revision::interface::LoreGlobalArgs;
use lore_revision::lore::RepositoryId;
use lore_revision::metadata::MetadataError;
use lore_revision::relay::EventDispatcher;
use lore_revision::repository::RemoteState;
use lore_revision::repository::RepositoryContext;
use lore_revision::repository::metadata_read_context;
use lore_revision::revision::sync::SyncError;
use lore_revision::revision::sync::SyncOptions;
use lore_revision::revision::sync::require_remote_reachable;
use lore_revision::revision::sync::sync_boxed;
use lore_revision::state::State;
use lore_revision::state::StateError;
use lore_transport::Connection;
use lore_transport::ProtocolError;
use parking_lot::Mutex;

use crate::fs::filesystem_provider::test_store_create;
use crate::helper::RepositoryContextCreationArgsExt;
use crate::helper::default_repository_creation_args;
use crate::helper::test_commit_tree;
use crate::helper::test_file_write;
use crate::helper::test_repository_create;
use crate::paged_remote::PagedRemote;
use crate::refusal::context_with_remote;

/// The exit code of `Disconnected`, which an embedder maps to offline.
const DISCONNECTED_CODE: i32 = 28;

fn disconnected() -> ProtocolError {
    ProtocolError::from(Disconnected)
}

async fn with_execution<F: Future>(body: F) -> F::Output {
    LORE_CONTEXT
        .scope(crate::helper::setup_test_execution(), body)
        .await
}

/// A context holding nothing whose remote is a connection whose storage connect answered `ready`.
async fn context_with_storage(ready: Result<(), ProtocolError>) -> Arc<RepositoryContext> {
    context_with_remote(
        RepositoryId::from(uuid::Uuid::now_v7()),
        RemoteState::Connected(Connection::detached_ready(Vec::new(), ready)),
    )
    .await
}

// -- the state read ----------------------------------------------------------------------------

/// A state the instance does not hold is read from the remote. Where the remote could not be
/// reached, the read fails as `Disconnected` (exit 28), which an embedder maps to offline, and not
/// as an internal failure (exit 255).
#[tokio::test]
async fn a_state_read_through_an_unreachable_remote_is_disconnected() {
    Box::pin(with_execution(async {
        let failed_connect = context_with_remote(
            RepositoryId::from(uuid::Uuid::now_v7()),
            RemoteState::Failed(disconnected()),
        )
        .await;
        let unreachable_storage = context_with_storage(Err(disconnected())).await;

        for (name, repository) in [
            ("the remote's connect failed", failed_connect),
            ("the remote's storage connect failed", unreachable_storage),
        ] {
            let Err(error) = State::deserialize(repository, Hash::from([7; 32])).await else {
                panic!("{name}: the remote cannot be reached");
            };
            assert!(
                matches!(error, StateError::Disconnected(_)),
                "{name}: {error:?}"
            );
            assert_eq!(error.ffi_code(), DISCONNECTED_CODE, "{name}: {error:?}");
        }
    }))
    .await;
}

// -- the metadata read context -----------------------------------------------------------------

/// A metadata read that failed because the remote could not be reached says so; every other
/// failure, and a success, keeps "Repository not found".
#[test]
fn a_metadata_read_context_blames_the_remote_only_for_a_disconnect() {
    let disconnected: Result<(), MetadataError> = Err(MetadataError::from(Disconnected));
    let missing: Result<(), MetadataError> = Err(MetadataError::from(NotFound));
    let refused: Result<(), MetadataError> = Err(MetadataError::from(NotAuthorized));
    let read: Result<(), MetadataError> = Ok(());

    assert_eq!(
        metadata_read_context(&disconnected),
        "Failed to read repository metadata from the remote"
    );
    for other in [&missing, &refused, &read] {
        assert_eq!(metadata_read_context(other), "Repository not found");
    }
}

// -- require_remote_reachable ------------------------------------------------------------------

/// Only a remote, or a remote's storage, that could not be reached fails the check. Everything
/// else passes: a refusal, which the sync reports as a warning, a connection with no remote, an
/// offline command, and a storage connect that failed for another reason.
#[tokio::test]
async fn the_reachability_check_fails_only_for_a_disconnect() {
    Box::pin(with_execution(async {
        let repository = || RepositoryId::from(uuid::Uuid::now_v7());
        let cases = [
            (
                "remote connect disconnected",
                context_with_remote(repository(), RemoteState::Failed(disconnected())).await,
                false,
            ),
            (
                "storage connect disconnected",
                context_with_storage(Err(disconnected())).await,
                false,
            ),
            (
                "storage reachable",
                context_with_storage(Ok(())).await,
                true,
            ),
            (
                "remote connect refused as unauthenticated",
                context_with_remote(
                    repository(),
                    RemoteState::Failed(ProtocolError::from(NotAuthenticated::new("refused"))),
                )
                .await,
                true,
            ),
            (
                "remote connect refused as unauthorized",
                context_with_remote(
                    repository(),
                    RemoteState::Failed(ProtocolError::from(NotAuthorized)),
                )
                .await,
                true,
            ),
            (
                "no remote",
                context_with_remote(
                    repository(),
                    RemoteState::Failed(ProtocolError::from(NoRemote)),
                )
                .await,
                true,
            ),
            (
                "offline",
                context_with_remote(repository(), RemoteState::Offline).await,
                true,
            ),
            (
                "storage connect refused",
                context_with_storage(Err(ProtocolError::from(NotAuthorized))).await,
                true,
            ),
            (
                "storage connect failed for another reason",
                context_with_storage(Err(ProtocolError::internal("the handshake failed"))).await,
                true,
            ),
        ];
        for (name, context, passes) in cases {
            let checked = require_remote_reachable(&context).await;
            if passes {
                assert!(checked.is_ok(), "{name}: {checked:?}");
            } else {
                let Err(error) = checked else {
                    panic!("{name}: an unreachable remote passed the check");
                };
                assert!(
                    matches!(error, SyncError::Disconnected(_)),
                    "{name}: {error:?}"
                );
                assert_eq!(error.ffi_code(), DISCONNECTED_CODE, "{name}: {error:?}");
            }
        }
    }))
    .await;
}

// -- a head sync -------------------------------------------------------------------------------

/// What an instance's remote is, for a sync.
enum Remote {
    /// A connection whose revision service answers the branch latest as the instance's own latest,
    /// and whose storage connect answered `ready`.
    AtLatest { ready: Result<(), ProtocolError> },
    /// A remote whose connect failed.
    Failed(ProtocolError),
}

/// What a sync of an instance on one local commit did: its result, and the `is_latest` of each
/// `RevisionSyncTarget` event it sent.
struct Synced {
    result: Result<(), SyncError>,
    targets: Vec<bool>,
}

/// A sync of an instance whose branch holds one local commit, against `remote`, with the options
/// `options` builds for the commit's revision. Bounded by five seconds so a sync that waits on a
/// handshake fails the test.
async fn sync_against(remote: Remote, options: impl FnOnce(Hash) -> SyncOptions) -> Synced {
    let (immutable, mutable, _) = test_store_create().await.expect("creating the stores");
    let targets = Arc::new(Mutex::new(Vec::new()));
    let execution = Arc::new(ExecutionContext::new_client(
        LoreGlobalArgs::default(),
        EventDispatcher::new(Some(Box::new({
            let targets = targets.clone();
            move |event: &LoreEvent| {
                if let LoreEvent::RevisionSyncTarget(data) = event {
                    targets.lock().push(data.is_latest != 0);
                }
            }
        }))),
    ));
    let result = LORE_CONTEXT
        .scope(execution.clone(), async move {
            let instance = test_repository_create(
                immutable.clone(),
                mutable.clone(),
                RepositoryId::from(uuid::Uuid::now_v7()),
            )
            .await;
            test_file_write(&instance.path.join("local.txt"), b"local");
            let local = test_commit_tree(&instance, "Local").await;
            let (_, branch) = load_current_anchor_boxed(&instance.repository)
                .await
                .expect("reading the current anchor");
            let remote = match remote {
                Remote::AtLatest { ready } => Ok(Connection::detached_revision(
                    Vec::new(),
                    ready,
                    instance.repository.id,
                    Arc::new(at_latest(branch, local.revision())),
                )),
                Remote::Failed(refusal) => Err(refusal),
            };
            let repository = Arc::new(
                RepositoryContext::new(
                    default_repository_creation_args(immutable, mutable)
                        .with_path(&instance.path)
                        .with_id(instance.repository.id)
                        .with_instance_id(instance.repository.instance_id)
                        .with_remote(remote),
                )
                .with_write_token(instance.write_token.share()),
            );
            let synced = sync_boxed(
                repository.clone(),
                &instance.write_token,
                options(local.revision()),
            );
            tokio::time::timeout(Duration::from_secs(5), synced)
                .await
                .expect("the sync ends within five seconds")
        })
        .await;
    LORE_CONTEXT
        .scope(execution.clone(), execution.dispatcher.drain())
        .await;
    let targets = targets.lock().clone();
    Synced { result, targets }
}

/// A remote whose latest of `branch` is `latest`.
fn at_latest(branch: BranchId, latest: Hash) -> PagedRemote {
    PagedRemote::new(branch, latest)
}

fn head() -> impl FnOnce(Hash) -> SyncOptions {
    |_| SyncOptions::default()
}

/// A head sync whose revision service answers the branch latest as the local latest but whose
/// storage cannot be reached fails as `Disconnected`, and does not send a target that claims the
/// instance is on the latest.
#[tokio::test]
async fn a_head_sync_fails_where_the_remotes_storage_is_unreachable() {
    let synced = sync_against(
        Remote::AtLatest {
            ready: Err(disconnected()),
        },
        head(),
    )
    .await;

    let Err(error) = &synced.result else {
        panic!(
            "the sync passed with unreachable storage: {:?}",
            synced.targets
        );
    };
    assert!(matches!(error, SyncError::Disconnected(_)), "{error:?}");
    assert_eq!(error.ffi_code(), DISCONNECTED_CODE, "{error:?}");
    assert!(
        synced.targets.is_empty(),
        "a target was sent: {:?}",
        synced.targets
    );
}

/// The same sync with reachable storage is as before: it passes, and says the instance is on the
/// latest.
#[tokio::test]
async fn a_head_sync_passes_where_the_remotes_storage_is_reachable() {
    let synced = sync_against(Remote::AtLatest { ready: Ok(()) }, head()).await;

    assert!(synced.result.is_ok(), "{:?}", synced.result);
    assert_eq!(synced.targets, [true]);
}

/// A remote that refuses the caller's login does not fail a head sync as unreachable: it is a
/// refusal, which the sync reports as before.
#[tokio::test]
async fn a_head_sync_does_not_fail_as_unreachable_on_a_refusal() {
    let synced = sync_against(
        Remote::Failed(ProtocolError::from(NotAuthenticated::new("refused"))),
        head(),
    )
    .await;

    assert!(synced.result.is_ok(), "{:?}", synced.result);
    assert_eq!(synced.targets.len(), 1, "{:?}", synced.targets);
}

/// A remote whose connect itself failed as `Disconnected` fails a head sync as unreachable, and
/// sends no target.
#[tokio::test]
async fn a_head_sync_fails_where_the_remotes_connect_is_disconnected() {
    let synced = sync_against(Remote::Failed(disconnected()), head()).await;

    let Err(error) = &synced.result else {
        panic!(
            "the sync passed with an unreachable remote: {:?}",
            synced.targets
        );
    };
    assert!(matches!(error, SyncError::Disconnected(_)), "{error:?}");
    assert_eq!(error.ffi_code(), DISCONNECTED_CODE, "{error:?}");
    assert!(
        synced.targets.is_empty(),
        "a target was sent: {:?}",
        synced.targets
    );
}

/// A reset keeps working against local history where the remote is unreachable, as before.
#[tokio::test]
async fn a_reset_sync_does_not_check_the_remote_is_reachable() {
    let synced = sync_against(Remote::Failed(disconnected()), |_| SyncOptions {
        reset: true,
        ..Default::default()
    })
    .await;

    assert!(synced.result.is_ok(), "{:?}", synced.result);
    assert_eq!(synced.targets.len(), 1, "{:?}", synced.targets);
}

/// A sync given a revision does not apply the check: the revision is resolved without the remote,
/// and the sync does not claim to have proved the remote reachable.
#[tokio::test]
async fn a_sync_given_a_revision_does_not_check_the_remote_is_reachable() {
    let synced = sync_against(
        Remote::AtLatest {
            ready: Err(disconnected()),
        },
        |local| SyncOptions {
            revision: Some(local.to_string()),
            ..Default::default()
        },
    )
    .await;

    assert!(synced.result.is_ok(), "{:?}", synced.result);
}

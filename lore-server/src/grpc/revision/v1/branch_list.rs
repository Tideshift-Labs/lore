// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::collections::HashSet;
use std::pin::Pin;
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::runtime::runtime;
use lore_base::types::KeyType;
use lore_proto::lore::revision::v1::BranchListRequest;
use lore_proto::lore::revision::v1::BranchListResponse;
use lore_revision::branch;
use lore_revision::lore::BranchId;
use lore_revision::repository::RepositoryContext;
use lore_telemetry::tracing::fields::BRANCH_ID;
use tokio::sync::mpsc;
use tokio_stream::Stream;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::wrappers::UnboundedReceiverStream;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::debug;
use tracing::info;
use tracing::warn;

use super::branch_record::build_branch;
use crate::grpc::extract_correlation_id;
use crate::grpc::get_repository;
use crate::grpc::get_user_id;
use crate::util::setup_execution;

type BranchListStream =
    Pin<Box<dyn Stream<Item = Result<BranchListResponse, Status>> + Send + 'static>>;

/// `lore.revision.v1.RevisionService.BranchList` handler.
///
/// Server-streams one `BranchListResponse` per matching branch. Live
/// branches are always emitted; deleted branches require
/// `include_deleted = true`. The optional `creator` filter is an exact
/// byte-for-byte case-sensitive match on `Branch.creator`.
///
/// Live branches are enumerated from the name → id (`BranchId`) keys —
/// the same source of truth the local client and legacy handler use.
/// This matters for repositories whose branches have a name → id mapping
/// but no `BranchMetadata` key in the typed list index (legacy or
/// partially-provisioned repos): such branches are still point-loadable
/// by id, so they appear in the live listing here but would be missed by
/// a `BranchMetadata` scan.
///
/// Deleted branches are only surfaced when `include_deleted = true`, via
/// a supplementary `BranchMetadata` scan: the metadata blob preserves the
/// branch id even after the name → id mapping is erased on delete, and
/// any id already seen in the live pass is skipped.
#[tracing::instrument(name = "BranchList::v1::handle", skip_all)]
pub async fn handler(
    request: Request<BranchListRequest>,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
) -> Result<Response<BranchListStream>, Status> {
    let repository_id = get_repository(request.metadata())?;
    let user_id = get_user_id(request.extensions());
    let correlation_id = extract_correlation_id(&request).unwrap_or_default();
    let req = request.into_inner();
    let creator_filter = req.creator;
    let include_deleted = req.include_deleted;

    let execution = setup_execution(module_path!(), correlation_id, user_id);
    let repository = Arc::new(RepositoryContext::new_server_context(
        immutable_store,
        mutable_store,
        repository_id,
    ));

    let (tx, rx) = mpsc::channel(64);

    runtime().spawn(LORE_CONTEXT.scope(execution, async move {
        stream_branches(repository, creator_filter, include_deleted, tx).await;
    }));

    Ok(Response::new(Box::pin(ReceiverStream::from(rx))))
}

async fn stream_branches(
    repository: Arc<RepositoryContext>,
    creator_filter: Option<String>,
    include_deleted: bool,
    tx: mpsc::Sender<Result<BranchListResponse, Status>>,
) {
    debug!(
        creator = ?creator_filter,
        include_deleted,
        "Listing branches",
    );

    let mut emitted: u64 = 0;
    let mut live_ids: HashSet<BranchId> = HashSet::new();

    let id_stream = match repository
        .read_mutable_store()
        .list(repository.id, KeyType::BranchId)
        .await
    {
        Ok(stream) => stream,
        Err(err) => {
            warn!(?err, "Failed to list branch id keys");
            let _ = tx.send(Err(Status::internal(err.to_string()))).await;
            return;
        }
    };
    let mut ids = UnboundedReceiverStream::new(id_stream.channel());

    while let Some((_key, id)) = ids.next().await {
        let branch_id: BranchId = id.to_context();
        live_ids.insert(branch_id);

        let metadata_hash = match branch::metadata_hash(repository.clone(), branch_id).await {
            Ok(hash) => hash,
            Err(err) => {
                info!({BRANCH_ID} = %branch_id, ?err, "Skipping branch: metadata hash load failed");
                continue;
            }
        };
        let metadata = match branch::load_metadata(repository.clone(), metadata_hash).await {
            Ok(metadata) => metadata,
            Err(err) => {
                info!({BRANCH_ID} = %branch_id, ?err, "Skipping branch: metadata load failed");
                continue;
            }
        };

        if let Some(ref required) = creator_filter {
            let creator = branch::creator(&metadata).unwrap_or_default();
            if creator != required.as_str() {
                continue;
            }
        }

        if !emit_branch(
            &repository,
            branch_id,
            &metadata,
            metadata_hash,
            false,
            &tx,
            &mut emitted,
        )
        .await
        {
            return;
        }
    }

    if include_deleted {
        let metadata_stream = match repository
            .read_mutable_store()
            .list(repository.id, KeyType::BranchMetadata)
            .await
        {
            Ok(stream) => stream,
            Err(err) => {
                warn!(?err, "Failed to list branch metadata keys");
                let _ = tx.send(Err(Status::internal(err.to_string()))).await;
                return;
            }
        };
        let mut entries = UnboundedReceiverStream::new(metadata_stream.channel());

        while let Some((_key, metadata_hash)) = entries.next().await {
            let metadata = match branch::load_metadata(repository.clone(), metadata_hash).await {
                Ok(metadata) => metadata,
                Err(err) => {
                    info!(?err, "Skipping entry: metadata load failed");
                    continue;
                }
            };

            let Ok(id_bytes) = metadata.get_binary(branch::ID) else {
                continue;
            };
            let branch_id: BranchId = id_bytes.into();

            if live_ids.contains(&branch_id) {
                continue;
            }

            if let Some(ref required) = creator_filter {
                let creator = branch::creator(&metadata).unwrap_or_default();
                if creator != required.as_str() {
                    continue;
                }
            }

            if !emit_branch(
                &repository,
                branch_id,
                &metadata,
                metadata_hash,
                true,
                &tx,
                &mut emitted,
            )
            .await
            {
                return;
            }
        }
    }

    debug!(emitted, "BranchList complete");
}

/// Build and send one branch record. Returns `false` if the receiver has
/// been dropped (caller should stop producing); a per-branch build
/// failure is logged and skipped, returning `true`.
async fn emit_branch(
    repository: &Arc<RepositoryContext>,
    branch_id: BranchId,
    metadata: &lore_revision::metadata::Metadata,
    metadata_hash: lore_base::types::Hash,
    deleted: bool,
    tx: &mpsc::Sender<Result<BranchListResponse, Status>>,
    emitted: &mut u64,
) -> bool {
    let response_branch = match build_branch(
        repository.clone(),
        branch_id,
        metadata,
        metadata_hash,
        deleted,
    )
    .await
    {
        Ok(branch) => branch,
        Err(status) => {
            info!({BRANCH_ID} = %branch_id, ?status, "Skipping branch: response build failed");
            return true;
        }
    };

    if tx
        .send(Ok(BranchListResponse {
            branch: Some(response_branch),
        }))
        .await
        .is_err()
    {
        // Client dropped the stream; stop producing.
        debug!(emitted = *emitted, "BranchList receiver dropped");
        return false;
    }
    *emitted += 1;
    true
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use lore_base::runtime::LORE_CONTEXT;
    use lore_base::types::BranchPoint;
    use lore_base::types::Hash;
    use lore_revision::branch;
    use lore_revision::branch::DEFAULT_HISTORY_STEP_SIZE;
    use lore_revision::lore::RepositoryId;
    use lore_revision::repository::RepositoryContext;
    use lore_revision::state;
    use lore_transport::grpc::REPOSITORY_ID_KEY;
    use rand::random;
    use tokio_stream::StreamExt;
    use tonic::Request;

    use super::*;
    use crate::grpc::get_write_token;
    use crate::grpc::handlers::branch_push;
    use crate::store::test_store_create;

    /// Creates a root-style branch (empty stack); not deletable.
    async fn create_root_branch(
        repository_context: &Arc<RepositoryContext>,
        name: &str,
        creator: &str,
    ) -> BranchId {
        let write_token = get_write_token();
        lore_revision::branch::create(
            repository_context.clone(),
            &write_token,
            BranchId::from(uuid::Uuid::now_v7()),
            name,
            branch::default_category(),
            creator,
            1,
            vec![],
            false,
            false,
        )
        .await
        .expect("Could not create root branch")
    }

    /// Pushes a real revision to `branch` so it can serve as a parent in
    /// subsequent `BranchPoint` entries (zero-revision parents are
    /// rejected unless the parent is the repository's default branch,
    /// which the test fixture doesn't initialise).
    async fn seed_revision(repository_context: &Arc<RepositoryContext>, branch: BranchId) -> Hash {
        let write_token = get_write_token();
        let state = state::State::new();
        state.set_parent_self(Hash::default());
        state.set_revision_number(1);
        let state_hash = state
            .serialize(repository_context.clone(), &write_token)
            .await
            .expect("Failed to serialize state");
        branch_push::push(
            repository_context.clone(),
            branch,
            state_hash,
            true,
            true,
            false,
            DEFAULT_HISTORY_STEP_SIZE,
            crate::grpc::server::RevisionListAcceleration::default(),
        )
        .await
        .expect("Failed to push latest revision")
        .revision
    }

    /// Creates a child branch off `parent@parent_revision` so it has a
    /// non-empty stack and can be deleted.
    async fn create_child_branch(
        repository_context: &Arc<RepositoryContext>,
        name: &str,
        creator: &str,
        parent: BranchId,
        parent_revision: Hash,
    ) -> BranchId {
        let write_token = get_write_token();
        lore_revision::branch::create(
            repository_context.clone(),
            &write_token,
            BranchId::from(uuid::Uuid::now_v7()),
            name,
            branch::default_category(),
            creator,
            1,
            vec![BranchPoint {
                branch: parent,
                revision: parent_revision,
            }],
            false,
            false,
        )
        .await
        .expect("Could not create child branch")
    }

    fn make_request(
        repository: RepositoryId,
        creator: Option<String>,
        include_deleted: bool,
    ) -> Request<BranchListRequest> {
        let mut request = Request::new(BranchListRequest {
            creator,
            include_deleted,
        });
        request.metadata_mut().insert_bin(
            REPOSITORY_ID_KEY,
            tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()),
        );
        request
    }

    async fn collect_response(
        response: Response<BranchListStream>,
    ) -> Vec<Result<BranchListResponse, Status>> {
        response.into_inner().collect().await
    }

    #[tokio::test]
    async fn list_streams_all_live_branches() {
        let repository = random::<RepositoryId>();
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution.clone(), async move {
            let repository_context = Arc::new(RepositoryContext::new_server_context(
                immutable_store.clone(),
                mutable_store.clone(),
                repository,
            ));
            let main = create_root_branch(&repository_context, "main", "alice").await;
            let main_latest = seed_revision(&repository_context, main).await;
            create_child_branch(&repository_context, "feature", "bob", main, main_latest).await;

            let response = handler(
                make_request(repository, None, false),
                immutable_store.clone(),
                mutable_store.clone(),
            )
            .await
            .expect("Request failed");

            let items: Vec<_> = collect_response(response)
                .await
                .into_iter()
                .map(|r| r.expect("stream item ok"))
                .collect();

            assert_eq!(items.len(), 2);
            let names: Vec<String> = items
                .iter()
                .map(|r| r.branch.as_ref().unwrap().name.clone())
                .collect();
            assert!(names.contains(&"main".to_string()));
            assert!(names.contains(&"feature".to_string()));
            assert!(items.iter().all(|r| !r.branch.as_ref().unwrap().deleted));
        }))
        .await;
    }

    #[tokio::test]
    async fn list_excludes_deleted_by_default() {
        let repository = random::<RepositoryId>();
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution.clone(), async move {
            let repository_context = Arc::new(RepositoryContext::new_server_context(
                immutable_store.clone(),
                mutable_store.clone(),
                repository,
            ));
            let main = create_root_branch(&repository_context, "main", "alice").await;
            let main_latest = seed_revision(&repository_context, main).await;
            let to_delete =
                create_child_branch(&repository_context, "feature", "bob", main, main_latest).await;
            branch::delete(repository_context.clone(), to_delete)
                .await
                .expect("delete should succeed");

            let response = handler(
                make_request(repository, None, false),
                immutable_store.clone(),
                mutable_store.clone(),
            )
            .await
            .expect("Request failed");

            let items: Vec<_> = collect_response(response)
                .await
                .into_iter()
                .map(|r| r.expect("stream item ok"))
                .collect();

            assert_eq!(items.len(), 1);
            assert_eq!(items[0].branch.as_ref().unwrap().name, "main");
        }))
        .await;
    }

    #[tokio::test]
    async fn list_includes_deleted_when_flag_set() {
        let repository = random::<RepositoryId>();
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution.clone(), async move {
            let repository_context = Arc::new(RepositoryContext::new_server_context(
                immutable_store.clone(),
                mutable_store.clone(),
                repository,
            ));
            let main = create_root_branch(&repository_context, "main", "alice").await;
            let main_latest = seed_revision(&repository_context, main).await;
            let to_delete =
                create_child_branch(&repository_context, "feature", "bob", main, main_latest).await;
            branch::delete(repository_context.clone(), to_delete)
                .await
                .expect("delete should succeed");

            let response = handler(
                make_request(repository, None, true),
                immutable_store.clone(),
                mutable_store.clone(),
            )
            .await
            .expect("Request failed");

            let items: Vec<_> = collect_response(response)
                .await
                .into_iter()
                .map(|r| r.expect("stream item ok"))
                .collect();

            assert_eq!(items.len(), 2);
            let deleted_count = items
                .iter()
                .filter(|r| r.branch.as_ref().unwrap().deleted)
                .count();
            assert_eq!(deleted_count, 1);
            let deleted_branch = items
                .iter()
                .find(|r| r.branch.as_ref().unwrap().deleted)
                .unwrap()
                .branch
                .as_ref()
                .unwrap();
            assert_eq!(deleted_branch.name, "feature");
            assert_eq!(deleted_branch.creator, "bob");
        }))
        .await;
    }

    #[tokio::test]
    async fn list_creator_filter_combines_with_include_deleted() {
        let repository = random::<RepositoryId>();
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution.clone(), async move {
            let repository_context = Arc::new(RepositoryContext::new_server_context(
                immutable_store.clone(),
                mutable_store.clone(),
                repository,
            ));
            let main = create_root_branch(&repository_context, "main", "alice").await;
            let main_latest = seed_revision(&repository_context, main).await;
            // Three branches by alice (one deleted), one by bob.
            create_child_branch(
                &repository_context,
                "alice-live",
                "alice",
                main,
                main_latest,
            )
            .await;
            let alice_dead = create_child_branch(
                &repository_context,
                "alice-dead",
                "alice",
                main,
                main_latest,
            )
            .await;
            create_child_branch(&repository_context, "bob-live", "bob", main, main_latest).await;
            branch::delete(repository_context.clone(), alice_dead)
                .await
                .expect("delete should succeed");

            // include_deleted=false → only live alice branches (main + alice-live = 2)
            let live_only = handler(
                make_request(repository, Some("alice".into()), false),
                immutable_store.clone(),
                mutable_store.clone(),
            )
            .await
            .expect("Request failed");
            let live_items: Vec<_> = collect_response(live_only)
                .await
                .into_iter()
                .map(|r| r.expect("stream item ok"))
                .collect();
            assert_eq!(live_items.len(), 2);
            assert!(
                live_items
                    .iter()
                    .all(|r| r.branch.as_ref().unwrap().creator == "alice")
            );
            assert!(
                live_items
                    .iter()
                    .all(|r| !r.branch.as_ref().unwrap().deleted)
            );

            // include_deleted=true → all alice branches including the deleted one (3)
            let with_deleted = handler(
                make_request(repository, Some("alice".into()), true),
                immutable_store.clone(),
                mutable_store.clone(),
            )
            .await
            .expect("Request failed");
            let all_items: Vec<_> = collect_response(with_deleted)
                .await
                .into_iter()
                .map(|r| r.expect("stream item ok"))
                .collect();
            assert_eq!(all_items.len(), 3);
            assert!(
                all_items
                    .iter()
                    .all(|r| r.branch.as_ref().unwrap().creator == "alice")
            );
            let dead_count = all_items
                .iter()
                .filter(|r| r.branch.as_ref().unwrap().deleted)
                .count();
            assert_eq!(dead_count, 1);
        }))
        .await;
    }

    #[tokio::test]
    async fn list_filters_by_creator() {
        let repository = random::<RepositoryId>();
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution.clone(), async move {
            let repository_context = Arc::new(RepositoryContext::new_server_context(
                immutable_store.clone(),
                mutable_store.clone(),
                repository,
            ));
            create_root_branch(&repository_context, "main", "alice").await;
            create_root_branch(&repository_context, "feature", "bob").await;
            create_root_branch(&repository_context, "extra", "alice").await;

            let response = handler(
                make_request(repository, Some("alice".into()), false),
                immutable_store.clone(),
                mutable_store.clone(),
            )
            .await
            .expect("Request failed");

            let items: Vec<_> = collect_response(response)
                .await
                .into_iter()
                .map(|r| r.expect("stream item ok"))
                .collect();

            assert_eq!(items.len(), 2);
            assert!(
                items
                    .iter()
                    .all(|r| r.branch.as_ref().unwrap().creator == "alice")
            );
        }))
        .await;
    }

    #[tokio::test]
    async fn list_delivers_items_incrementally() {
        let repository = random::<RepositoryId>();
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution.clone(), async move {
            let repository_context = Arc::new(RepositoryContext::new_server_context(
                immutable_store.clone(),
                mutable_store.clone(),
                repository,
            ));
            create_root_branch(&repository_context, "main", "alice").await;
            create_root_branch(&repository_context, "feature1", "alice").await;
            create_root_branch(&repository_context, "feature2", "bob").await;

            // The handler's Response is returned before the producer
            // task has touched the mutable store; pulling one item at a
            // time proves incremental delivery rather than batched
            // buffering of the full result.
            let response = handler(
                make_request(repository, None, false),
                immutable_store.clone(),
                mutable_store.clone(),
            )
            .await
            .expect("Request failed");

            let mut stream = response.into_inner();
            let first = stream.next().await.expect("first item ready");
            first.expect("first item ok");

            let second = stream.next().await.expect("second item ready");
            second.expect("second item ok");

            let third = stream.next().await.expect("third item ready");
            third.expect("third item ok");

            assert!(stream.next().await.is_none(), "expected end of stream");
        }))
        .await;
    }

    #[tokio::test]
    async fn list_empty_repository_yields_empty_stream() {
        let repository = random::<RepositoryId>();
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution.clone(), async move {
            let response = handler(
                make_request(repository, None, false),
                immutable_store.clone(),
                mutable_store.clone(),
            )
            .await
            .expect("Request failed");

            let items: Vec<_> = collect_response(response).await;
            assert!(items.is_empty());
        }))
        .await;
    }

    #[tokio::test]
    async fn list_fresh_branch_reports_protected_false() {
        let repository = random::<RepositoryId>();
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution.clone(), async move {
            let repository_context = Arc::new(RepositoryContext::new_server_context(
                immutable_store.clone(),
                mutable_store.clone(),
                repository,
            ));
            create_root_branch(&repository_context, "main", "alice").await;

            let response = handler(
                make_request(repository, None, false),
                immutable_store.clone(),
                mutable_store.clone(),
            )
            .await
            .expect("Request failed");

            let items: Vec<_> = collect_response(response)
                .await
                .into_iter()
                .map(|r| r.expect("stream item ok"))
                .collect();

            assert_eq!(items.len(), 1);
            assert!(
                !items[0].branch.as_ref().unwrap().protected,
                "fresh branch should report protected=false"
            );
        }))
        .await;
    }

    #[tokio::test]
    async fn list_protected_branch_reports_protected_true_sibling_reports_false() {
        let repository = random::<RepositoryId>();
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution.clone(), async move {
            let repository_context = Arc::new(RepositoryContext::new_server_context(
                immutable_store.clone(),
                mutable_store.clone(),
                repository,
            ));
            let main = create_root_branch(&repository_context, "main", "alice").await;
            let main_latest = seed_revision(&repository_context, main).await;
            let feature =
                create_child_branch(&repository_context, "feature", "bob", main, main_latest).await;

            branch::protect(repository_context.clone(), feature)
                .await
                .expect("protect should succeed");

            let response = handler(
                make_request(repository, None, false),
                immutable_store.clone(),
                mutable_store.clone(),
            )
            .await
            .expect("Request failed");

            let items: Vec<_> = collect_response(response)
                .await
                .into_iter()
                .map(|r| r.expect("stream item ok"))
                .collect();

            assert_eq!(items.len(), 2);

            let main_item = items
                .iter()
                .find(|r| r.branch.as_ref().unwrap().name == "main")
                .expect("main branch present");
            assert!(
                !main_item.branch.as_ref().unwrap().protected,
                "main (unprotected sibling) should report protected=false"
            );

            let feature_item = items
                .iter()
                .find(|r| r.branch.as_ref().unwrap().name == "feature")
                .expect("feature branch present");
            assert!(
                feature_item.branch.as_ref().unwrap().protected,
                "feature (protected) should report protected=true"
            );
        }))
        .await;
    }

    #[tokio::test]
    async fn list_branch_after_protect_then_unprotect_reports_protected_false() {
        let repository = random::<RepositoryId>();
        let (immutable_store, mutable_store, execution) =
            test_store_create().await.expect("Failed to create stores");

        Box::pin(LORE_CONTEXT.scope(execution.clone(), async move {
            let repository_context = Arc::new(RepositoryContext::new_server_context(
                immutable_store.clone(),
                mutable_store.clone(),
                repository,
            ));
            let main = create_root_branch(&repository_context, "main", "alice").await;

            branch::protect(repository_context.clone(), main)
                .await
                .expect("protect should succeed");
            branch::unprotect(repository_context.clone(), main)
                .await
                .expect("unprotect should succeed");

            let response = handler(
                make_request(repository, None, false),
                immutable_store.clone(),
                mutable_store.clone(),
            )
            .await
            .expect("Request failed");

            let items: Vec<_> = collect_response(response)
                .await
                .into_iter()
                .map(|r| r.expect("stream item ok"))
                .collect();

            assert_eq!(items.len(), 1);
            assert!(
                !items[0].branch.as_ref().unwrap().protected,
                "branch after protect+unprotect should report protected=false"
            );
        }))
        .await;
    }
}

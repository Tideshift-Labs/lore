// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_proto::BranchListRequest;
use lore_proto::BranchListResponse;
use lore_revision::branch;
use lore_revision::branch::BranchLatestStatus;
use lore_revision::repository;
use lore_revision::repository::RepositoryContext;
use lore_revision::repository::RepositoryMetadata;
use lore_server::grpc::get_write_token;
use lore_server::grpc::handlers::branch_list::*;
use lore_transport::grpc::REPOSITORY_ID_KEY;
use rand::random;
use tonic::Request;

use crate::store::test_support::test_store_create;

#[tokio::test]
async fn test_handle() {
    let repository = random::<Context>();
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");
    LORE_CONTEXT
        .scope(execution.clone(), async move {
            let repository = Arc::new(RepositoryContext::new_server_context(
                immutable_store.clone(),
                mutable_store.clone(),
                repository.into(),
            ));
            let write_token = get_write_token();
            // Create the main branch (without parent)
            let no_parent = Context::default(); // Zero, no parent
            let payload_main = random::<[u8; size_of::<Hash>()]>().to_vec();
            let hash_main = Hash::hash_buffer(&payload_main);
            let main = lore_revision::branch::create(
                repository.clone(),
                &write_token,
                Context::from(uuid::Uuid::now_v7()),
                lore_revision::branch::DEFAULT_DEFAULT_NAME,
                lore_revision::branch::default_category(),
                "MainCreator",
                1234,
                vec![],
                false,
                false,
            )
            .await
            .expect("Could not create main branch");

            let mut request = Request::new(BranchListRequest {});
            request.metadata_mut().insert_bin(
                REPOSITORY_ID_KEY,
                tonic::metadata::BinaryMetadataValue::from_bytes(repository.id.data()),
            );
            let response = handler(request, immutable_store.clone(), mutable_store.clone())
                .await
                .expect("Failed BranchList message handle");
            assert_eq!(
                BranchListResponse {
                    branches: [lore_proto::Branch {
                        id: main.into(),
                        name: lore_revision::branch::DEFAULT_DEFAULT_NAME.to_string(),
                        category: lore_revision::branch::default_category().to_string(),
                        parent_deprecated: Some(Context::default().into()),
                        latest: Hash::default().into(),
                        branch_point_deprecated: Some(Hash::default().into()),
                        creator: "MainCreator".to_string(),
                        created: 1234,
                        stack: vec![],
                    }]
                    .to_vec()
                },
                response.into_inner()
            );

            // Create another branch1
            let payload_branch1 = random::<[u8; size_of::<Hash>()]>().to_vec();
            let hash_branch1 = Hash::hash_buffer(&payload_branch1);
            let branch1 = lore_revision::branch::create(
                repository.clone(),
                &write_token,
                Context::from(uuid::Uuid::now_v7()),
                "branch1",
                lore_revision::branch::default_category(),
                "TestCreator",
                4321,
                vec![],
                false,
                false,
            )
            .await
            .expect("Could not create branch1 branch");

            // Update main branch
            branch::store_latest(
                repository.clone(),
                main,
                Hash::default(),
                hash_main,
                BranchLatestStatus::Convergent,
            )
            .await
            .expect("Failed to store latest");

            // Update branch1 branch
            branch::store_latest(
                repository.clone(),
                branch1,
                Hash::default(),
                hash_branch1,
                BranchLatestStatus::Convergent,
            )
            .await
            .expect("Failed to store latest");

            let mut request = Request::new(BranchListRequest {});
            request.metadata_mut().insert_bin(
                REPOSITORY_ID_KEY,
                tonic::metadata::BinaryMetadataValue::from_bytes(repository.id.data()),
            );
            let response = handler(request, immutable_store.clone(), mutable_store.clone())
                .await
                .expect("Failed BranchList message handle")
                .into_inner();

            assert!(response.branches.contains(&lore_proto::Branch {
                id: main.into(),
                name: lore_revision::branch::DEFAULT_DEFAULT_NAME.to_string(),
                category: lore_revision::branch::default_category().to_string(),
                parent_deprecated: Some(no_parent.into()),
                latest: hash_main.into(),
                branch_point_deprecated: Some(Hash::default().into()),
                creator: "MainCreator".to_string(),
                created: 1234,
                stack: vec![]
            }));

            assert!(response.branches.contains(&lore_proto::Branch {
                id: branch1.into(),
                name: "branch1".to_string(),
                category: lore_revision::branch::default_category().to_string(),
                parent_deprecated: Some(Context::default().into()),
                latest: hash_branch1.into(),
                branch_point_deprecated: Some(Hash::default().into()),
                creator: "TestCreator".to_string(),
                created: 4321,
                stack: vec![]
            }));
        })
        .await;
}

#[tokio::test]
async fn test_handle_no_branches() {
    let repository = random::<Context>();
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");
    LORE_CONTEXT
        .scope(execution.clone(), async move {
            let repository = Arc::new(RepositoryContext::new_server_context(
                immutable_store.clone(),
                mutable_store.clone(),
                repository.into(),
            ));
            let mut request = Request::new(BranchListRequest {});
            request.metadata_mut().insert_bin(
                REPOSITORY_ID_KEY,
                tonic::metadata::BinaryMetadataValue::from_bytes(repository.id.data()),
            );
            let response = handler(request, immutable_store.clone(), mutable_store.clone())
                .await
                .expect("Failed BranchList message handle");
            assert_eq!(
                BranchListResponse { branches: vec![] },
                response.into_inner()
            );
        })
        .await;
}

/// Wraps a real `MutableStore`, delegating every method except `store()`,
/// which always fails once wrapped. Mirrors the self-heal write's actual
/// failure mode under CR-029 enforcement (the domain-key bypass guard
/// rejects a `BranchId`-typed write on the generic mutable path — see
/// `lore-postgres/tests/domain_bypass.rs`) without depending on a live
/// Postgres store.
struct FailStoreWritesMutableStore {
    inner: Arc<dyn lore_storage::MutableStore>,
}

#[async_trait::async_trait]
impl lore_storage::MutableStore for FailStoreWritesMutableStore {
    async fn load(
        self: Arc<Self>,
        partition: lore_storage::Partition,
        key: Hash,
        key_type: lore_base::types::KeyType,
    ) -> Result<Hash, lore_storage::StoreError> {
        self.inner.clone().load(partition, key, key_type).await
    }

    async fn store(
        self: Arc<Self>,
        _partition: lore_storage::Partition,
        _key: Hash,
        _value: Hash,
        _key_type: lore_base::types::KeyType,
    ) -> Result<(), lore_storage::StoreError> {
        Err(lore_storage::StoreError::internal(
            "simulated domain-key bypass guard rejection",
        ))
    }

    async fn compare_and_swap(
        self: Arc<Self>,
        partition: lore_storage::Partition,
        key: Hash,
        expected: Hash,
        value: Hash,
        key_type: lore_base::types::KeyType,
    ) -> Result<Hash, lore_storage::StoreError> {
        self.inner
            .clone()
            .compare_and_swap(partition, key, expected, value, key_type)
            .await
    }

    async fn list(
        self: Arc<Self>,
        partition: lore_storage::Partition,
        key_type: lore_base::types::KeyType,
    ) -> Result<lore_storage::KeyValueStream, lore_storage::StoreError> {
        self.inner.clone().list(partition, key_type).await
    }

    async fn flush(self: Arc<Self>, sync_data: bool) -> Result<(), lore_storage::StoreError> {
        self.inner.clone().flush(sync_data).await
    }
}

// CR-029, self-heal writer pin (companion to `lore-postgres/tests/
// domain_bypass.rs`, which proves the guard itself rejects the write —
// this proves the call site at line 116 swallows that rejection rather
// than propagating it). The reviewer's defence for leaving this handler
// ungated is that a missing default-branch mapping is repaired
// best-effort; if a future cleanup ever turns the `if let Err(err) = ...`
// into a `?`, this test must go red.
#[tokio::test]
async fn default_branch_mapping_repair_failure_does_not_fail_the_list() {
    let repository_id = random::<Context>();
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");
    LORE_CONTEXT
        .scope(execution.clone(), async move {
            let repository = Arc::new(RepositoryContext::new_server_context(
                immutable_store.clone(),
                mutable_store.clone(),
                repository_id.into(),
            ));
            let write_token = get_write_token();
            let default_branch = Context::from(uuid::Uuid::now_v7());

            branch::create(
                repository.clone(),
                &write_token,
                default_branch,
                "main",
                branch::default_category(),
                "alice",
                0,
                vec![],
                false,
                false,
            )
            .await
            .expect("create default branch");

            // Publish repository metadata naming this branch the
            // default, then remove just the branch's listing entry (its
            // own metadata and latest pointer are untouched), so
            // `branch::list()` no longer enumerates it — reproducing
            // "default branch missing from list" directly rather than
            // needing an inconsistent real-world write sequence first.
            let repo_metadata_hash = repository::metadata_store(
                repository.clone(),
                RepositoryMetadata {
                    name: "my-repo".to_string(),
                    description: "a description".to_string(),
                    default_branch,
                    default_branch_name: "main".to_string(),
                    creator: "alice".to_string(),
                    created: 0,
                },
            )
            .await
            .expect("serialize repository metadata");
            repository::metadata_store_hash(repository.clone(), repo_metadata_hash)
                .await
                .expect("publish repository metadata pointer");

            let (listing_key, listing_key_type) =
                branch::mutable_key(repository.salt(), branch::ID, repository.id, default_branch);
            mutable_store
                .clone()
                .store(
                    repository.id,
                    listing_key,
                    Hash::default(),
                    listing_key_type,
                )
                .await
                .expect("remove the branch's listing entry");

            let faulty_mutable: Arc<dyn lore_storage::MutableStore> =
                Arc::new(FailStoreWritesMutableStore {
                    inner: mutable_store.clone(),
                });
            let repository = Arc::new(RepositoryContext::new_server_context(
                immutable_store,
                faulty_mutable,
                repository_id.into(),
            ));

            let response = branch_list_handler(repository)
                .await
                .expect("a failed default-branch mapping repair must not fail the list")
                .into_inner();

            assert!(
                response
                    .branches
                    .iter()
                    .any(|b| b.id.as_ref() == default_branch.data()),
                "the default branch must still be included despite the failed repair write"
            );
        })
        .await;
}

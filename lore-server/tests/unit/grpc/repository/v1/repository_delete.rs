// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_proto::lore::repository::v1::RepositoryDeleteRequest;
use lore_revision::lore::RepositoryId;
use lore_revision::repository;
use lore_revision::repository::RepositoryContext;
use lore_revision::repository::RepositoryMetadata;
use lore_server::auth::jwt::AuthorizationToken;
use lore_server::grpc::repository::v1::repository_delete::*;
use lore_telemetry::InstrumentProvider;
use rand::random;
use tonic::Request;

use crate::store::test_support::test_store_create;

struct TestInstrumentProvider;

impl InstrumentProvider for TestInstrumentProvider {
    fn namespace(&self) -> &'static str {
        "test"
    }
}

async fn seed_repository(
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
    id: RepositoryId,
    creator: &str,
) {
    let repository = Arc::new(RepositoryContext::new_server_context(
        immutable_store,
        mutable_store,
        id,
    ));
    let metadata_hash = repository::metadata_store(
        repository.clone(),
        RepositoryMetadata {
            name: "the-repository".to_string(),
            creator: creator.to_string(),
            ..Default::default()
        },
    )
    .await
    .expect("Failed to store repository metadata");
    repository::metadata_store_hash(repository.clone(), metadata_hash)
        .await
        .expect("Failed to store repository metadata hash");
    repository::store_name_to_id(repository, "the-repository", id)
        .await
        .expect("Failed to store repository name to id mapping");
}

fn delete_request(id: RepositoryId, token: AuthorizationToken) -> Request<RepositoryDeleteRequest> {
    let id_bytes: Context = id.into();
    let mut request = Request::new(RepositoryDeleteRequest {
        id: id_bytes.into(),
    });
    request.extensions_mut().insert(token);
    request
}

/// The creator check compares the recorded creator against the token's
/// `identity_claim` value, so a deployment recording
/// `preferred_username` lets the same user, presenting the same claim,
/// delete — while the subject the provider minted alongside is not what
/// is compared.
#[tokio::test]
async fn the_creator_check_compares_the_identity_claim() {
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");

    Box::pin(LORE_CONTEXT.scope(execution, async move {
        let id = random::<RepositoryId>();
        seed_repository(immutable_store.clone(), mutable_store.clone(), id, "alice").await;

        let by_subject = AuthorizationToken {
            user_id: "f7d3a1c2-0000-0000-0000-000000000000".to_string(),
            preferred_username: Some("alice".to_string()),
            ..Default::default()
        };
        let status = handler(
            delete_request(id, by_subject.clone()),
            None,
            immutable_store.clone(),
            mutable_store.clone(),
            &TestInstrumentProvider,
            None,
        )
        .await
        .expect_err("the subject is not the recorded creator");
        assert_eq!(status.code(), tonic::Code::PermissionDenied);

        let by_username = AuthorizationToken {
            identity: Some("alice".to_string()),
            ..by_subject
        };
        handler(
            delete_request(id, by_username),
            None,
            immutable_store,
            mutable_store,
            &TestInstrumentProvider,
            None,
        )
        .await
        .expect("the identity claim matches the recorded creator");
    }))
    .await;
}

fn make_request(repository_id: RepositoryId) -> Request<RepositoryDeleteRequest> {
    let id_bytes: Context = repository_id.into();
    Request::new(RepositoryDeleteRequest {
        id: bytes::Bytes::from(id_bytes),
    })
}

// TEST 3 (WP-116 guarded stop): confirms the ungoverned/legacy path at
// this fenced governed-mutation call site is not blocked by the CR-029
// gate. This file had NO test coverage of any kind before this addition.
// `admit_at_entry`'s own `Ok(None)` behavior is already pinned generically
// in `domain.rs`; this is the handler-specific companion. Narrow by
// design: a repository id that was never created only reaches the first
// statement of this handler's body (the `repository_load_id` lookup)
// before returning `NotFound` -- it does NOT exercise the rest of the
// handler (auth resource delete, name/metadata clearing, branch purge).
// `NotFound` is decisive proof the request got past the gate: a gate
// rejection here would be `Unimplemented` (an admitted-but-unwired
// operation) or `FailedPrecondition` (carriage supplied with no domain
// coordinator), never `NotFound`.
#[tokio::test]
async fn no_domain_coordinator_reaches_the_legacy_repository_lookup_not_blocked_by_the_gate() {
    let repository_id = random::<RepositoryId>();
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("test stores");

    let error = LORE_CONTEXT
        .scope(execution, async move {
            handler(
                make_request(repository_id),
                None, /* no auth_url */
                immutable_store,
                mutable_store,
                &TestInstrumentProvider,
                None, /* no domain coordinator */
            )
            .await
        })
        .await
        .expect_err("a never-created repository must be refused by the legacy delete logic");

    assert_eq!(error.code(), tonic::Code::NotFound);
    assert!(
        error
            .message()
            .contains(&format!("Repository {repository_id} not found"))
    );
}

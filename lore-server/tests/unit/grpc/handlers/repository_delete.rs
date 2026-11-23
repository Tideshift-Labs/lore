// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_proto::RepositoryDeleteRequest;
use lore_revision::lore::RepositoryId;
use lore_revision::repository;
use lore_revision::repository::RepositoryContext;
use lore_revision::repository::RepositoryMetadata;
use lore_server::auth::jwt::AuthorizationToken;
use lore_server::auth::jwt::ResourcePermission;
use lore_server::authnz::global_grants_authorizer::GlobalGrantsAuthorizer;
use lore_server::authnz::repository_authorizer::RawToken;
use lore_server::authnz::repository_authorizer::RepositoryAuthorizer;
use lore_server::authnz::repository_registry::RepositoryRegistry;
use lore_server::authnz::resource_grants_authorizer::ResourceGrantsAuthorizer;
use lore_server::grpc::handlers::repository_delete::*;
use lore_telemetry::InstrumentProvider;
use rand::random;
use tonic::Code;
use tonic::Request;

use crate::store::test_support::test_store_create;

struct TestInstrumentProvider;

impl InstrumentProvider for TestInstrumentProvider {
    fn namespace(&self) -> &'static str {
        "test"
    }
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
// statement of the legacy `repository_delete` logic (the
// `repository_query_id` lookup) before returning `NotFound` -- it does
// NOT exercise the rest of that function (name/metadata clearing, branch
// purge). `NotFound` is decisive proof the request got past the gate: a
// gate rejection here would be `Unimplemented` (an admitted-but-unwired
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
                &RepositoryRegistry::Unregistered,
                &global_grants(),
                immutable_store,
                mutable_store,
                &TestInstrumentProvider,
                None, /* no domain coordinator */
            )
            .await
        })
        .await
        .expect_err("a never-created repository must be refused by the legacy delete logic");

    assert_eq!(error.code(), Code::NotFound);
    assert!(error.message().contains("Repository does not exist"));
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

/// A verifier configured with global grants read from `groups`.
fn global_grants() -> Arc<dyn RepositoryAuthorizer> {
    Arc::new(GlobalGrantsAuthorizer::new(Some("groups".to_string())))
}

/// A Tier 2 verifier reading per-repository grants from `resources`.
fn resource_grants() -> Arc<dyn RepositoryAuthorizer> {
    Arc::new(ResourceGrantsAuthorizer::new(
        "resources".to_string(),
        "resource_id".to_string(),
        None,
        "urc-{id}".to_string(),
        "urc-*".to_string(),
    ))
}

/// A request to delete `repository` by its creator `alice`, whose verified
/// token holds `read` on `granted` only.
fn creator_request(
    repository: RepositoryId,
    granted: RepositoryId,
) -> Request<RepositoryDeleteRequest> {
    let mut request = delete_request(
        repository,
        AuthorizationToken {
            identity: Some("alice".to_string()),
            resources: Some(vec![ResourcePermission {
                resource_id: format!("urc-{granted}"),
                permission: vec!["read".to_string()],
            }]),
            ..Default::default()
        },
    );
    request
        .extensions_mut()
        .insert(RawToken("raw.jwt".to_string()));
    request
}

fn verified_delete_request(
    id: RepositoryId,
    groups: &[&str],
    is_service_account: bool,
) -> Request<RepositoryDeleteRequest> {
    let mut request = delete_request(
        id,
        AuthorizationToken {
            identity: Some("mallory".to_string()),
            groups: Some(groups.iter().map(ToString::to_string).collect()),
            is_service_account: Some(is_service_account),
            ..Default::default()
        },
    );
    request
        .extensions_mut()
        .insert(RawToken("raw.jwt".to_string()));
    request
}

/// `owner` lets a non-creator delete; `is_service_account` alone no longer
/// does.
#[tokio::test]
async fn owner_not_service_account_lets_a_non_creator_delete() {
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");

    Box::pin(LORE_CONTEXT.scope(execution, async move {
        let id = random::<RepositoryId>();
        seed_repository(immutable_store.clone(), mutable_store.clone(), id, "alice").await;

        let status = handler(
            verified_delete_request(id, &["write"], true),
            &RepositoryRegistry::Unregistered,
            &global_grants(),
            immutable_store.clone(),
            mutable_store.clone(),
            &TestInstrumentProvider,
            None,
        )
        .await
        .expect_err("a service account without owner or admin may not delete");
        assert_eq!(status.code(), tonic::Code::PermissionDenied);

        handler(
            verified_delete_request(id, &["owner"], false),
            &RepositoryRegistry::Unregistered,
            &global_grants(),
            immutable_store,
            mutable_store,
            &TestInstrumentProvider,
            None,
        )
        .await
        .expect("owner permits the delete");
    }))
    .await;
}

/// The creator may delete only while the authorizer lets them reach the
/// repository: on Tier 2 a creator whose token grants another repository
/// only is refused, and `read` on this one restores the creator's right.
#[tokio::test]
async fn the_creator_must_reach_the_repository_to_delete() {
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");

    Box::pin(LORE_CONTEXT.scope(execution, async move {
        let id = random::<RepositoryId>();
        seed_repository(immutable_store.clone(), mutable_store.clone(), id, "alice").await;

        let status = handler(
            creator_request(id, random::<RepositoryId>()),
            &RepositoryRegistry::Unregistered,
            &resource_grants(),
            immutable_store.clone(),
            mutable_store.clone(),
            &TestInstrumentProvider,
            None,
        )
        .await
        .expect_err("a creator with no grant on the repository may not delete");
        assert_eq!(status.code(), tonic::Code::PermissionDenied);

        handler(
            creator_request(id, id),
            &RepositoryRegistry::Unregistered,
            &resource_grants(),
            immutable_store,
            mutable_store,
            &TestInstrumentProvider,
            None,
        )
        .await
        .expect("a creator who reaches the repository may delete");
    }))
    .await;
}

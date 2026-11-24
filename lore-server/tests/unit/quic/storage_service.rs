// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! The urc/0.2 dispatcher asks each command's action before handling it:
//! from the grants connect stored, or of the authorizer with the
//! connection's token when there are none.
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use lore_base::types::Hash;
use lore_base::types::KeyType;
use lore_revision::lore::RepositoryId;
use lore_server::auth::jwk::JWKService;
use lore_server::auth::jwk::JWKServiceError;
use lore_server::auth::jwt::AuthorizationToken;
use lore_server::auth::jwt::JwtVerifier;
use lore_server::auth::jwt::ResourcePermission;
use lore_server::auth::jwt::TokenVerification;
use lore_server::authnz::repository_authorizer::ALLOW_ALL_ACTIONS;
use lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
use lore_server::authnz::repository_authorizer::AuthClientAuthorizer;
use lore_server::authnz::repository_authorizer::Grants;
use lore_server::authnz::repository_authorizer::PartitionGrants;
use lore_server::authnz::repository_authorizer::RawToken;
use lore_server::protocol::attribute_map::AttributeMap;
use lore_server::protocol::storage::connect::Connect;
use lore_server::protocol::storage::copy::Copy;
use lore_server::protocol::storage::messages::MessageHandleError;
use lore_server::protocol::storage::query::Query;
use lore_server::protocol::storage::requests;
use lore_server::protocol::storage::verify::Verify;
use lore_server::quic::QuicService;
use lore_server::quic::storage_service::*;
use rand::random;

use crate::store::test_support::test_store_create;

/// A `JWKService` that must never be called — `require_write`'s
/// fail-closed checks never reach `verify_token`/`get_key`; only
/// `token_verification.verifier().is_some()` matters for these tests.
#[derive(Debug)]
struct UnusedJwkService;

#[async_trait]
impl JWKService for UnusedJwkService {
    async fn get_key(
        &self,
        _kid: &str,
    ) -> Result<(jsonwebtoken::DecodingKey, jsonwebtoken::Algorithm), JWKServiceError> {
        unreachable!("require_write's fail-closed path never verifies a token")
    }

    fn get_cached_key(
        &self,
        _kid: &str,
    ) -> Option<(jsonwebtoken::DecodingKey, jsonwebtoken::Algorithm)> {
        unreachable!("require_write's fail-closed path never reads a cached key")
    }

    async fn refresh_key(
        &self,
        _kid: &str,
    ) -> Result<Option<(jsonwebtoken::DecodingKey, jsonwebtoken::Algorithm)>, JWKServiceError> {
        unreachable!("require_write's fail-closed path never refreshes a key")
    }
}

fn verifier_present() -> Arc<TokenVerification> {
    Arc::new(TokenVerification::Verify(JwtVerifier {
        jwk_service: Arc::new(UnusedJwkService),
        jwt_issuer: None,
        jwt_audience: None,
        jwt_typ: None,
        exchange_issuer: None,
    }))
}

async fn service_with_enforcement() -> StorageService {
    let (immutable_store, mutable_store, _execution) =
        test_store_create().await.expect("Failed to create stores");
    StorageService::new(
        verifier_present(),
        Arc::new(lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer),
        immutable_store.clone(),
        immutable_store,
        mutable_store,
        true,
    )
}

fn mutable_store_op() -> ParsedStorageRequest {
    ParsedStorageRequest::MutableStoreOp(requests::MutableStoreOp {
        key: Hash::default(),
        value: Hash::default(),
        key_type: KeyType::Untyped,
    })
}

/// CR-018 legacy (urc/0.2) path: `require_write` fails closed when a
/// verifier is configured and enforcement is on, but the connection
/// context carries neither a `RepositoryId` nor an `AuthorizationToken`
/// (the Connect handshake that would populate them never happened, or
/// was skipped). A write op must be denied, not silently let through.
mod require_write_fails_closed {
    use super::*;

    #[tokio::test]
    async fn denies_write_when_repository_and_token_are_both_missing() {
        let service = service_with_enforcement().await;
        let context = Arc::new(AttributeMap::default());

        let err = service
            .run_request_handler(context, mutable_store_op())
            .await
            .expect_err("missing repository and token must fail closed");

        assert!(
            matches!(err, MessageHandleError::NotConnected),
            "expected NotConnected, got {err:?}"
        );
    }

    #[tokio::test]
    async fn denies_write_when_token_is_missing_but_repository_is_present() {
        let service = service_with_enforcement().await;
        let context = Arc::new(AttributeMap::default());
        context.insert(random::<RepositoryId>());

        let err = service
            .run_request_handler(context, mutable_store_op())
            .await
            .expect_err("missing authorization token must fail closed");

        assert!(
            matches!(err, MessageHandleError::AuthorizationFailure(_)),
            "expected AuthorizationFailure, got {err:?}"
        );
    }

    #[tokio::test]
    async fn allows_write_when_enforcement_is_disabled_despite_missing_token() {
        // Same context shape as `denies_write_when_token_is_missing_but_
        // repository_is_present` (repository present, token absent) but
        // enforce_write_permission = false: fail-closed is itself gated
        // on the flag, mirroring the v4 dispatch gate's decision table.
        // (RepositoryId must still be present — that's a hard requirement
        // of the mutable-store handler itself, not the write-permission
        // gate under test here.)
        let (immutable_store, mutable_store, _execution) =
            test_store_create().await.expect("Failed to create stores");
        let service = StorageService::new(
            verifier_present(),
            Arc::new(lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer),
            immutable_store.clone(),
            immutable_store,
            mutable_store,
            false,
        );
        let context = Arc::new(AttributeMap::default());
        context.insert(random::<RepositoryId>());

        service
            .run_request_handler(context, mutable_store_op())
            .await
            .expect("enforcement disabled must bypass the fail-closed check");
    }
}

async fn service() -> StorageService {
    let (immutable_store, mutable_store, _execution) =
        test_store_create().await.expect("Failed to create stores");
    // The legacy tier answers an access token from its `resources` claim, so
    // the URL is never reached.
    StorageService::new(
        Arc::new(TokenVerification::Ignore),
        Arc::new(AuthClientAuthorizer::new(
            "https://auth.invalid".to_string(),
        )),
        immutable_store.clone(),
        immutable_store,
        mutable_store,
        false,
    )
}

/// A connected context with a token holding `actions` on `repository` and
/// no stored grants, so the dispatcher asks the authorizer.
fn connected(repository: RepositoryId, actions: &[&str]) -> Arc<AttributeMap> {
    let context = AttributeMap::default();
    context.insert(repository);
    context.insert(RawToken("raw.jwt".to_string()));
    context.insert(AuthorizationToken {
        resources: Some(vec![ResourcePermission {
            resource_id: format!("urc-{repository}"),
            permission: actions.iter().map(ToString::to_string).collect(),
        }]),
        ..Default::default()
    });
    context.into()
}

fn query() -> ParsedStorageRequest {
    ParsedStorageRequest::Query(Query::parse(Bytes::from(vec![0u8; 48])).unwrap())
}

/// An in-partition copy, so only the connection's own action is asked.
fn copy(repository: RepositoryId) -> ParsedStorageRequest {
    let mut bytes = repository.data().to_vec();
    bytes.extend_from_slice(&[0u8; 48]);
    ParsedStorageRequest::Copy(Copy::parse(Bytes::from(bytes)).unwrap())
}

fn refused(result: &Result<Vec<Bytes>, MessageHandleError>) -> bool {
    matches!(result, Err(MessageHandleError::AuthorizationFailure(_)))
}

/// Reads need nothing beyond the connection; writes need `write`.
#[tokio::test]
async fn a_write_command_needs_write() {
    let service = service().await;
    let repository = random::<RepositoryId>();

    let read_only = connected(repository, &["read"]);
    assert!(!refused(
        &service
            .run_request_handler(read_only.clone(), query())
            .await
    ));
    assert!(refused(
        &service
            .run_request_handler(read_only, copy(repository))
            .await
    ));

    let write_only = connected(repository, &["write"]);
    assert!(!refused(
        &service
            .run_request_handler(write_only.clone(), query())
            .await
    ));
    assert!(!refused(
        &service
            .run_request_handler(write_only, copy(repository))
            .await
    ));
}

/// Before connect no partition is named, so the dispatcher makes no
/// decision and the handler answers.
#[tokio::test]
async fn a_command_before_connect_is_left_to_the_handler() {
    let service = service().await;
    let result = service
        .run_request_handler(AttributeMap::default().into(), query())
        .await;
    assert!(!refused(&result), "{result:?}");
}

/// The path an authenticated connection takes: connect stored the enumerated
/// grants, and they answer with no token in the context at all.
#[tokio::test]
async fn stored_grants_answer_each_command() {
    let service = service().await;
    let repository = random::<RepositoryId>();
    let context = AttributeMap::default();
    context.insert(repository);
    context.insert(PartitionGrants {
        repository_id: repository,
        grants: Grants::Actions(["read".to_string()].into()),
    });
    let context: Arc<AttributeMap> = context.into();

    assert!(!refused(
        &service.run_request_handler(context.clone(), query()).await
    ));
    assert!(refused(
        &service.run_request_handler(context, copy(repository)).await
    ));
}

/// Without a verifier, connect still stores the allow-all grants, so a
/// command is a set lookup rather than an authorizer call.
#[tokio::test]
async fn connect_without_a_verifier_stores_the_allow_all_grants() {
    let (immutable_store, mutable_store, _execution) =
        test_store_create().await.expect("Failed to create stores");
    let service = StorageService::new(
        Arc::new(TokenVerification::Ignore),
        Arc::new(AllowAllRepositoryAuthorizer),
        immutable_store.clone(),
        immutable_store,
        mutable_store,
        false,
    );
    let repository = random::<RepositoryId>();
    let context: Arc<AttributeMap> = AttributeMap::default().into();

    service
        .run_request_handler(
            context.clone(),
            ParsedStorageRequest::Connect(
                Connect::parse(Bytes::copy_from_slice(repository.data())).unwrap(),
            ),
        )
        .await
        .expect("connect");

    let stored = context.get::<PartitionGrants>().expect("grants stored");
    assert_eq!(stored.repository_id, repository);
    assert_eq!(
        stored.grants,
        Grants::Actions(ALLOW_ALL_ACTIONS.iter().map(ToString::to_string).collect())
    );
}

/// Healing changes the server's store, so a healing verify needs `write`;
/// a plain verify is a read.
#[tokio::test]
async fn a_healing_verify_needs_write() {
    let service = service().await;
    let repository = random::<RepositoryId>();
    let verify = |heal| {
        ParsedStorageRequest::Verify(Verify {
            address: lore_revision::fragment::generate_random().1,
            heal,
        })
    };

    let read_only = connected(repository, &["read"]);
    assert!(!refused(
        &service
            .run_request_handler(read_only.clone(), verify(0))
            .await
    ));
    assert!(refused(
        &service.run_request_handler(read_only, verify(1)).await
    ));

    let writer = connected(repository, &["write"]);
    assert!(!refused(
        &service.run_request_handler(writer, verify(1)).await
    ));
}

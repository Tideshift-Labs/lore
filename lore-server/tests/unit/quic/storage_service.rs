// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use async_trait::async_trait;
use lore_base::types::Hash;
use lore_base::types::KeyType;
use lore_revision::lore::RepositoryId;
use lore_server::auth::jwk::JWKService;
use lore_server::auth::jwk::JWKServiceError;
use lore_server::auth::jwt::DEFAULT_IDENTITY_CLAIM;
use lore_server::auth::jwt::JwtVerifier;
use lore_server::protocol::attribute_map::AttributeMap;
use lore_server::protocol::storage::messages::MessageHandleError;
use lore_server::protocol::storage::requests;
use lore_server::quic::QuicService;
use lore_server::quic::storage_service::*;
use rand::random;

use crate::store::test_support::test_store_create;

/// A `JWKService` that must never be called — `require_write`'s
/// fail-closed checks never reach `verify_token`/`get_key`; only
/// `jwt_verifier.is_some()` matters for these tests.
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

fn verifier_present() -> Arc<Option<JwtVerifier>> {
    Arc::new(Some(JwtVerifier {
        jwk_service: Arc::new(UnusedJwkService),
        jwt_issuer: None,
        jwt_audience: None,
        jwt_typ: None,
        identity_claim: DEFAULT_IDENTITY_CLAIM.to_string(),
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

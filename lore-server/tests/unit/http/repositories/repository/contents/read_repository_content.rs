// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift, D-SC2): under `AuthClient`, an identity token (no
//! `resources` claim) may READ repository content over HTTP GET after an online
//! `CheckUserPermission`. The write side of the same decision is pinned in
//! `put_repository_content.rs`.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::http::HeaderName;
use axum::http::HeaderValue;
use axum::http::StatusCode;
use axum_test::TestServer;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_revision::fragment;
use lore_server::authnz::repository_authorizer::AuthClientAuthorizer;
use lore_server::http::server::LoreHttpServerSettings;
use lore_server::http::server::ServerHealth;
use lore_server::http::server::ServerState;
use lore_server::http::server::create_router;
use rand::random;

use crate::authnz::auth_client_fixture::start_stub;
use crate::authnz::auth_client_fixture::token;
use crate::authnz::auth_client_fixture::urc;
use crate::authnz::auth_client_fixture::verifier;
use crate::store::test_support::test_store_create;

/// An identity token reads repository A (the stub grants `read` on A only):
/// A answers 200 with the stored bytes, B answers 403 although the same bytes
/// are stored there too, and a request with no bearer answers 401.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_identity_token_reads_content_only_where_the_auth_service_grants_read() {
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");
    LORE_CONTEXT
        .scope(execution, async move {
            let repository_a = random::<Context>();
            let repository_b = random::<Context>();
            let (fragment, address, payload) = fragment::generate_random();
            for repository in [repository_a, repository_b] {
                immutable_store
                    .clone()
                    .put(
                        repository.into(),
                        address,
                        fragment,
                        Some(payload.clone()),
                        false,
                    )
                    .await
                    .expect("Failed to put data in immutable store");
            }

            let (url, calls) = start_stub(vec![(urc(repository_a.into()), vec!["read"])]).await;
            let state = ServerState {
                immutable_store: immutable_store.clone(),
                mutable_store,
                jwt_verifier: Some(verifier()),
                repository_authorizer: Arc::new(AuthClientAuthorizer::new(url)),
                max_file_size: 1024,
                presign_config: None,
                enforce_write_permission: true,
            };
            let health = ServerHealth::new_without_availability(immutable_store);
            let server = TestServer::new(create_router(
                state,
                health,
                &LoreHttpServerSettings::test_default(),
            ))
            .unwrap();
            let bearer = HeaderValue::from_str(&format!("Bearer {}", token(None))).unwrap();
            let authorization = HeaderName::from_static("authorization");

            let granted = server
                .get(&format!("/v1/repository/{repository_a}/content/{address}"))
                .add_header(authorization.clone(), bearer.clone())
                .await;
            assert_eq!(granted.status_code(), StatusCode::OK);
            assert_eq!(granted.as_bytes().as_ref(), payload.as_ref());
            // Positive control: the identity token was answered online.
            assert!(
                calls.load(Ordering::SeqCst) >= 1,
                "CheckUserPermission must have been asked"
            );

            let denied = server
                .get(&format!("/v1/repository/{repository_b}/content/{address}"))
                .add_header(authorization, bearer)
                .await;
            assert_eq!(denied.status_code(), StatusCode::FORBIDDEN);

            let anonymous = server
                .get(&format!("/v1/repository/{repository_a}/content/{address}"))
                .await;
            assert_eq!(anonymous.status_code(), StatusCode::UNAUTHORIZED);
        })
        .await;
}

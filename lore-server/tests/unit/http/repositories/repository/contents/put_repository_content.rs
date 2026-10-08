// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift, ADR-00011): the HTTP content upload keeps the fork
//! write gate. Upstream routes the HTTP surface through the shared
//! `RepositoryAuthorizer`, which only decides reachability; a write must still
//! carry `write` in the token's own `resources` claim.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use axum::http::HeaderName;
use axum::http::HeaderValue;
use axum::http::StatusCode;
use axum_test::TestServer;
use bytes::Bytes;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
use lore_server::authnz::repository_authorizer::AuthClientAuthorizer;
use lore_server::authnz::repository_authorizer::RepositoryAuthorizer;
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

const PAYLOAD: &[u8] = b"put-repository-content-payload";

/// Builds a server under `AuthClient` whose stub grants `stub_grants` on the
/// repository, PUTs [`PAYLOAD`] once with `bearer` (or with no header when
/// auth is off), and returns the status plus the stub's call count.
async fn put_status(
    authorizer: AuthorizerKind,
    stub_grants: Vec<&'static str>,
    bearer: impl FnOnce(Context) -> Option<String>,
    enforce_write_permission: bool,
) -> (StatusCode, usize) {
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");
    LORE_CONTEXT
        .scope(execution, async move {
            let repository = random::<Context>();
            let (url, calls) = start_stub(vec![(urc(repository.into()), stub_grants)]).await;
            let (jwt_verifier, repository_authorizer): (_, Arc<dyn RepositoryAuthorizer>) =
                match authorizer {
                    AuthorizerKind::AuthClient => {
                        (Some(verifier()), Arc::new(AuthClientAuthorizer::new(url)))
                    }
                    AuthorizerKind::AuthOff => (None, Arc::new(AllowAllRepositoryAuthorizer)),
                };
            let state = ServerState {
                immutable_store: immutable_store.clone(),
                mutable_store,
                jwt_verifier,
                repository_authorizer,
                max_file_size: 1024,
                presign_config: None,
                enforce_write_permission,
            };
            let health = ServerHealth::new_without_availability(immutable_store);
            let server = TestServer::new(create_router(
                state,
                health,
                &LoreHttpServerSettings::test_default(),
            ))
            .unwrap();
            let mut request = server
                .put(&format!("/v1/repository/{repository}/content"))
                .bytes(Bytes::from_static(PAYLOAD));
            if let Some(bearer) = bearer(repository) {
                request = request.add_header(
                    HeaderName::from_static("authorization"),
                    HeaderValue::from_str(&format!("Bearer {bearer}")).unwrap(),
                );
            }
            let status = request.await.status_code();
            (status, calls.load(Ordering::SeqCst))
        })
        .await
}

enum AuthorizerKind {
    AuthClient,
    AuthOff,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_only_claim_cannot_upload_content() {
    let (status, calls) = put_status(
        AuthorizerKind::AuthClient,
        vec!["read", "write"],
        |repository| Some(token(Some(vec![(urc(repository.into()), vec!["read"])]))),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // A claim token is answered from its claim; the stub is never asked.
    assert_eq!(calls, 0);
}

/// D-SC2: an identity token may read after `CheckUserPermission`, but a
/// write stays refused even when the auth service answers `write`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_identity_token_cannot_upload_even_when_the_auth_service_grants_write() {
    let (status, calls) = put_status(
        AuthorizerKind::AuthClient,
        vec!["read", "write", "owner"],
        |_| Some(token(None)),
        true,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // Positive control: the route layer did reach the auth service and was
    // admitted, so the refusal is the write gate, not reachability.
    assert!(calls >= 1, "CheckUserPermission must have been asked");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_claim_uploads_content() {
    let (status, _) = put_status(
        AuthorizerKind::AuthClient,
        vec![],
        |repository| {
            Some(token(Some(vec![(
                urc(repository.into()),
                vec!["read", "write"],
            )])))
        },
        true,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn enforcement_off_lets_a_read_only_claim_upload() {
    let (status, _) = put_status(
        AuthorizerKind::AuthClient,
        vec![],
        |repository| Some(token(Some(vec![(urc(repository.into()), vec!["read"])]))),
        false,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn auth_off_uploads_without_a_token() {
    let (status, _) = put_status(AuthorizerKind::AuthOff, vec![], |_| None, true).await;
    assert_eq!(status, StatusCode::OK);
}

/// The fork's production authorizer for `resource_claim = "resources"`,
/// built through the startup constructor.
fn resource_grants_authorizer() -> Arc<dyn RepositoryAuthorizer> {
    let auth: lore_server::settings::AuthSettings = toml::from_str(
        "jwt_issuer = \"https://auth.example.com\"\njwt_audience = [\"lore\"]\nresource_claim = \"resources\"",
    )
    .unwrap();
    lore_server::authnz::repository_authorizer::repository_authorizer(Some(&auth), None).unwrap()
}

/// PUTs [`PAYLOAD`] under `ResourceGrants`. `bearer` gets the repository the
/// path names; `path_repository` overrides the path segment (for an
/// unparseable id). Returns the status and whether the store gained a
/// fragment.
async fn put_under_resource_grants(
    bearer: impl FnOnce(Context) -> Option<String>,
    path_repository: Option<&str>,
) -> (StatusCode, bool) {
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");
    LORE_CONTEXT
        .scope(execution, async move {
            let repository = random::<Context>();
            let state = ServerState {
                immutable_store: immutable_store.clone(),
                mutable_store,
                jwt_verifier: Some(verifier()),
                repository_authorizer: resource_grants_authorizer(),
                max_file_size: 1024,
                presign_config: None,
                enforce_write_permission: true,
            };
            let health = ServerHealth::new_without_availability(immutable_store.clone());
            let server = TestServer::new(create_router(
                state,
                health,
                &LoreHttpServerSettings::test_default(),
            ))
            .unwrap();
            let before = immutable_store.clone().fragment_count().await;
            let path = path_repository.map_or_else(|| repository.to_string(), str::to_string);
            let mut request = server
                .put(&format!("/v1/repository/{path}/content"))
                .bytes(Bytes::from_static(PAYLOAD));
            if let Some(bearer) = bearer(repository) {
                request = request.add_header(
                    HeaderName::from_static("authorization"),
                    HeaderValue::from_str(&format!("Bearer {bearer}")).unwrap(),
                );
            }
            let status = request.await.status_code();
            let after = immutable_store.fragment_count().await;
            assert!(before.is_some(), "the test store must count fragments");
            (status, after != before)
        })
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resource_grants_read_only_claim_cannot_upload() {
    let (status, written) = put_under_resource_grants(
        |repository| Some(token(Some(vec![(urc(repository.into()), vec!["read"])]))),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(!written);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resource_grants_write_on_another_repository_cannot_upload() {
    let (status, written) = put_under_resource_grants(
        |_| {
            Some(token(Some(vec![(
                urc(random::<Context>().into()),
                vec!["read", "write"],
            )])))
        },
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(!written);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resource_grants_write_claim_uploads() {
    let (status, written) = put_under_resource_grants(
        |repository| {
            Some(token(Some(vec![(
                urc(repository.into()),
                vec!["read", "write"],
            )])))
        },
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        written,
        "positive control: an accepted upload stores a fragment"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resource_grants_wildcard_write_claim_uploads() {
    let (status, written) = put_under_resource_grants(
        |_| {
            Some(token(Some(vec![(
                "urc-*".to_string(),
                vec!["read", "write"],
            )])))
        },
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(written);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resource_grants_no_token_is_unauthorized() {
    let (status, written) = put_under_resource_grants(|_| None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(!written);
}

/// A wildcard write claim reaches the handler for any path, so an
/// unparseable repository id meets the handler's own 400, before any write.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resource_grants_unparseable_repository_is_rejected_without_writing() {
    let (status, written) = put_under_resource_grants(
        |_| {
            Some(token(Some(vec![(
                "urc-*".to_string(),
                vec!["read", "write"],
            )])))
        },
        Some("not-a-repository-id"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(!written);
}

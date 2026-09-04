// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The harness's own JWKS endpoint, and the tokens it mints against it.
//!
//! Both loreserver processes run auth-ON. That is not decoration: CR-029
//! carriage without a verified principal is refused outright
//! (`DomainContext::admit` returns `UNAUTHENTICATED`), so the governed path —
//! and therefore every outbox row this proof depends on — is unreachable on an
//! auth-off cell. WP-109 Phase 3 says the same thing from the other direction:
//! auth may be off only for a lower-level diagnostic.
//!
//! loreserver fetches its JWKS eagerly at startup and refuses to boot if the
//! endpoint is unreachable, so this server must be listening before either
//! process is spawned. It serves the committed Lorehub TEST document, whose
//! private half the runner also hands over; nothing here generates a key, so
//! there is no chance of a harness key drifting from the document.

use std::net::SocketAddr;
use std::path::Path;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use axum::Router;
use axum::http::header::CONTENT_TYPE;
use axum::response::IntoResponse;
use axum::routing;
use lore_base::lore_spawn;
use serde::Serialize;

use super::Env;

/// One entry of the token's `resources` claim.
///
/// `urc-*` is the wildcard `ResourcePermission::is_wildcard_resource` accepts
/// (`lore-server/src/auth/jwt.rs:49-51`), which is what lets one minted token
/// address every repository a case creates without the harness having to
/// re-mint per repository id.
#[derive(Serialize)]
struct Resource {
    resource_id: String,
    permission: Vec<String>,
}

/// The claim set `lore_server::auth::jwt::AuthorizationToken` deserializes.
///
/// Spelled out rather than reusing that struct because its `Serialize` impl is
/// an implementation detail of the server's own tests, and a proof that mints
/// its tokens through the type it is trying to exercise proves less.
#[derive(Serialize)]
struct Claims {
    sub: String,
    iss: String,
    iat: u64,
    exp: u64,
    aud: Vec<String>,
    env: String,
    name: String,
    preferred_username: String,
    resources: Vec<Resource>,
    groups: Vec<String>,
    is_service_account: bool,
    idp: String,
}

/// A running JWKS endpoint. Dropping it shuts the server down.
pub struct JwksServer {
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    url: String,
}

impl JwksServer {
    /// Bind and serve the document at `path`, then wait until it answers.
    ///
    /// The readiness wait is not politeness. loreserver's startup JWKS fetch is
    /// fail-fast, so a process spawned against a listener that has bound but
    /// not yet served exits with a key-fetch error that reads exactly like a
    /// misconfigured endpoint.
    pub async fn start(port: u16, path: &Path) -> Self {
        let document = std::fs::read(path)
            .unwrap_or_else(|error| panic!("read JWKS document {}: {error}", path.display()));
        let body = document.clone();
        let app = Router::new().route(
            "/.well-known/jwks.json",
            routing::get(move || {
                let body = body.clone();
                async move { ([(CONTENT_TYPE, "application/json")], body).into_response() }
            }),
        );
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .unwrap_or_else(|error| panic!("bind the harness JWKS endpoint on {addr}: {error}"));
        let (shutdown, stop) = tokio::sync::oneshot::channel();
        lore_spawn!(async move {
            let _ = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = stop.await;
                })
                .await;
        });

        let url = format!("http://127.0.0.1:{port}/.well-known/jwks.json");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if reqwest::get(&url)
                .await
                .is_ok_and(|response| response.status().is_success())
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the harness JWKS endpoint never answered on {url}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        Self {
            shutdown: Some(shutdown),
            url,
        }
    }

    pub fn url(&self) -> &str {
        &self.url
    }
}

impl Drop for JwksServer {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

/// Mints the bearer tokens both processes verify.
///
/// Holds the encoding key so a case can mint one token per principal without
/// re-reading the PEM, which matters because a governed operation's receipt
/// namespace is keyed by `(issuer, subject)` and two racing writers must be
/// able to be genuinely different principals.
pub struct TokenMinter {
    key: jsonwebtoken::EncodingKey,
    header: jsonwebtoken::Header,
    issuer: String,
    audience: String,
}

impl TokenMinter {
    pub fn from_env(env: &Env) -> Self {
        let pem = std::fs::read(&env.jwt_private_key).unwrap_or_else(|error| {
            panic!(
                "read the TEST signing key {}: {error}",
                env.jwt_private_key.display()
            )
        });
        let key = jsonwebtoken::EncodingKey::from_rsa_pem(&pem)
            .expect("the TEST signing key must be an RSA private key in PEM form");
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
        header.kid = Some(env.jwt_kid.clone());
        Self {
            key,
            header,
            issuer: env.jwt_issuer.clone(),
            audience: env.jwt_audience.clone(),
        }
    }

    /// A wildcard-resource token for `subject`, valid for an hour.
    ///
    /// An hour rather than minutes because a case that kills and restarts a
    /// process can span a slow release-binary boot, and an expiry that lands
    /// mid-case would surface as an unrelated `UNAUTHENTICATED`.
    ///
    /// Sufficient for every RPC whose permission check goes through
    /// `has_required_permission`, which honours the wildcard. It is NOT
    /// sufficient for obliterate — see [`Self::mint_for_repository`].
    pub fn mint(&self, subject: &str) -> String {
        self.mint_with(subject, Vec::new())
    }

    /// A token that also names one repository EXACTLY, with the obliterate
    /// permission.
    ///
    /// The wildcard is not enough here, and the reason is a real asymmetry in
    /// the server rather than a quirk of this harness. `can_obliterate` reads
    /// `user_permissions`, which walks the token's resources and returns the
    /// permissions of the entry whose parsed repository EQUALS the target
    /// (`lore-server/src/grpc/mod.rs:425-427,480-495`) — no wildcard match.
    /// Every other write path goes through `has_required_permission`, which
    /// uses `matches_repository` and does honour `urc-*`. A wildcard-only token
    /// is therefore refused for obliterate alone, with a bare "Permission
    /// denied" that reads like a harness misconfiguration.
    pub fn mint_for_repository(&self, subject: &str, repository_id: &[u8]) -> String {
        let hex: String = repository_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        self.mint_with(
            subject,
            vec![Resource {
                resource_id: format!("urc-{hex}"),
                permission: vec![
                    "read".to_owned(),
                    "write".to_owned(),
                    "obliterate".to_owned(),
                    "migrate".to_owned(),
                ],
            }],
        )
    }

    fn mint_with(&self, subject: &str, extra: Vec<Resource>) -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock follows the epoch")
            .as_secs();
        let mut resources = vec![Resource {
            resource_id: "urc-*".to_owned(),
            permission: vec!["read".to_owned(), "write".to_owned()],
        }];
        resources.extend(extra);
        let claims = Claims {
            sub: subject.to_owned(),
            iss: self.issuer.clone(),
            iat: now,
            exp: now + 3600,
            aud: vec![self.audience.clone()],
            env: "test".to_owned(),
            name: subject.to_owned(),
            preferred_username: subject.to_owned(),
            resources,
            groups: Vec::new(),
            is_service_account: false,
            idp: "wp109-two-process-harness".to_owned(),
        };
        jsonwebtoken::encode(&self.header, &claims, &self.key).expect("mint a harness token")
    }

    /// The issuer every minted token carries, which is also the
    /// `verified_issuer` half of a governed operation's receipt key.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
}

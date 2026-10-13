// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use bytes::Bytes;
use lore_base::types::*;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Server identity
// ---------------------------------------------------------------------------

/// What a server tells a client about itself through `AdminService.ServerInfo`.
///
/// Only the two fields a client can act on. `settings` and `host` are operator
/// diagnostics and stay off this type until something needs them, so a caller
/// cannot come to depend on a shape we have no reason to keep stable.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ServerInfo {
    /// The server's build version, e.g. `0.9.1-nightly+0`.
    pub version: String,
    /// The capabilities this server advertises.
    ///
    /// A capability ABSENT here is the only honest way for a client to learn
    /// that a rail it wants is not served — the alternative is attempting the
    /// operation and reading a refusal, or worse, taking a silent legacy path.
    ///
    /// Point-in-time, not live: loreserver computes this list once, when it
    /// builds its gRPC endpoint, so a server whose configuration changed while
    /// running keeps reporting what it started with until it restarts. Read a
    /// present capability as present; read an absent one as "not at boot".
    pub features: Vec<String>,
}

// ---------------------------------------------------------------------------
// Environment types
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(bound(deserialize = "'de: 'static"))]
pub struct EnvironmentConfig {
    pub endpoint: Option<Endpoint>,
    pub config: Option<EnvironmentServerConfig>,
    pub oidc: Option<Oidc>,
}

impl EnvironmentConfig {
    pub fn max_query_batch(&self) -> Option<usize> {
        self.config.as_ref().and_then(|c| c.max_query_batch)
    }

    /// The compression mode the server states it prefers, as the number it sent. The codec that
    /// number names is `lore_storage::CompressionMode`, which this crate does not depend on.
    pub fn compression_mode(&self) -> Option<u32> {
        self.config
            .as_ref()
            .and_then(|config| config.compression_mode.as_ref())
            .map(ServerCompressionMode::as_u32)
    }

    /// Per-service endpoint URL. If the environment's `endpoint.storage_url`
    /// is set and non-empty, it overrides `fallback`; otherwise `fallback` is
    /// returned unchanged. Same contract for the other `*_url` methods below.
    pub fn storage_url<'a>(&'a self, fallback: &'a str) -> &'a str {
        service_url_or(
            self.endpoint
                .as_ref()
                .and_then(|e| e.storage_url.as_deref()),
            fallback,
        )
    }

    pub fn revision_url<'a>(&'a self, fallback: &'a str) -> &'a str {
        service_url_or(
            self.endpoint
                .as_ref()
                .and_then(|e| e.revision_url.as_deref()),
            fallback,
        )
    }

    pub fn lock_url<'a>(&'a self, fallback: &'a str) -> &'a str {
        service_url_or(
            self.endpoint.as_ref().and_then(|e| e.lock_url.as_deref()),
            fallback,
        )
    }

    pub fn repository_url<'a>(&'a self, fallback: &'a str) -> &'a str {
        service_url_or(
            self.endpoint
                .as_ref()
                .and_then(|e| e.repository_url.as_deref()),
            fallback,
        )
    }

    pub fn notification_url<'a>(&'a self, fallback: &'a str) -> &'a str {
        service_url_or(
            self.endpoint
                .as_ref()
                .and_then(|e| e.notification_url.as_deref()),
            fallback,
        )
    }

    /// User directory endpoint: resolves user IDs to display names and back.
    /// Falls back to `auth_url` if empty.
    pub fn user_url<'a>(&'a self, fallback: &'a str) -> &'a str {
        service_url_or(
            self.endpoint.as_ref().and_then(|e| e.user_url.as_deref()),
            fallback,
        )
    }
}

fn service_url_or<'a>(override_url: Option<&'a str>, fallback: &'a str) -> &'a str {
    match override_url {
        Some(url) if !url.is_empty() => url,
        _ => fallback,
    }
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(bound(deserialize = "'de: 'static"))]
pub struct Endpoint {
    pub auth_url: Option<String>,
    pub repository_url: Option<String>,
    pub storage_url: Option<String>,
    pub revision_url: Option<String>,
    pub lock_url: Option<String>,
    pub notification_url: Option<String>,
    /// User directory endpoint: resolves user IDs to display names and back.
    /// Falls back to `auth_url` if empty.
    pub user_url: Option<String>,
}

/// The OIDC provider a server advertises.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(bound(deserialize = "'de: 'static"))]
pub struct Oidc {
    /// Issuer URL. The provider's endpoints come from its discovery document,
    /// `<issuer>/.well-known/openid-configuration`.
    pub issuer: String,
    /// The public client ID presented to the provider.
    pub client_id: String,
    /// Default scopes to request at login. Empty leaves the choice to the client.
    pub scopes: Vec<String>,
    /// Whether a client takes the OIDC path by default rather than `auth_url`.
    pub preferred: bool,
    /// Maps a partition to an RFC 8707 resource, `{id}` standing for the partition ID.
    pub resource_template: Option<String>,
    /// Maps a partition to a scope value, `{id}` standing for the partition ID.
    pub scope_template: Option<String>,
    /// The issuer of the RFC 8693 token-exchange endpoint that mints partition-scoped tokens.
    pub token_exchange_issuer: Option<String>,
    pub identity_claim: Option<String>,
}

impl Oidc {
    pub const DEFAULT_IDENTITY_CLAIM: &'static str = "sub";

    /// The claim recorded as the user identity: the advertised one, or `sub` when the server
    /// names none.
    pub fn identity_claim(&self) -> &str {
        match self.identity_claim.as_deref() {
            Some(claim) if !claim.is_empty() => claim,
            _ => Self::DEFAULT_IDENTITY_CLAIM,
        }
    }
}

/// A compression mode as it arrives from a server, held as the number it was sent as: the codec
/// it names is `lore_storage::CompressionMode`, which this crate does not depend on.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(bound(deserialize = "'de: 'static"))]
pub struct ServerCompressionMode(u32);

impl ServerCompressionMode {
    pub fn from_u32(value: u32) -> Self {
        ServerCompressionMode(value)
    }

    pub fn as_u32(&self) -> u32 {
        self.0
    }
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(bound(deserialize = "'de: 'static"))]
pub struct EnvironmentServerConfig {
    pub max_query_batch: Option<usize>,
    pub compression_mode: Option<ServerCompressionMode>,
}

// ---------------------------------------------------------------------------
// Protocol response types
// ---------------------------------------------------------------------------

pub struct BranchPushResponse {
    /// True if the server performed a fast-forward merge
    pub fast_forward_merged: bool,
    /// New branch latest revision identifier
    pub revision: Hash,
    /// Revision number of new branch latest revision
    pub revision_number: u64,
    /// Optional message from the server
    pub message: Option<String>,
}

pub struct BranchQueryResponse {
    /// Branch ID
    pub id: BranchId,
    /// Latest revision
    pub latest: Hash,
    /// Metadata hash
    pub metadata: Hash,
    /// Whether the branch has been deleted (name->id mapping removed)
    pub deleted: bool,
    /// FORK-LOCAL (WP-120). The branch's authoritative domain generation, set
    /// only by a cell with an armed domain coordinator. `None` means "no
    /// authority", never "generation zero".
    pub generation: Option<u64>,
}

pub struct BranchListResponse {
    /// Branch list
    pub list: Vec<BranchMetadata>,
}

pub struct RevisionListResponse {
    pub items: Vec<RevisionItem>,
    pub next_revision: Hash,
    pub previous_revision: Hash,
}

#[derive(Debug)]
pub struct RevisionItem {
    pub number: u64,
    pub signature: Hash,
    pub metadata: Hash,
    pub state: Bytes,
}

#[derive(Clone)]
pub enum RevisionListStart {
    Identifier(RevisionListIdentifier),
    Signature(Hash),
}

#[derive(Clone)]
pub struct RevisionListIdentifier {
    pub branch: BranchId,
    pub number: u64,
}

impl From<RevisionListIdentifier> for RevisionListStart {
    fn from(value: RevisionListIdentifier) -> Self {
        RevisionListStart::Identifier(value)
    }
}

impl From<Hash> for RevisionListStart {
    fn from(value: Hash) -> Self {
        RevisionListStart::Signature(value)
    }
}

/// FORK-LOCAL (WP-120). The generation counters of one (repository, branch)
/// lock namespace, as a branch-scoped lock `Query` on a fenced cell reports
/// them.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockNamespaceGeneration {
    pub repository_lock_generation: u64,
    pub branch_lock_generation: u64,
    pub last_applied_fence: u64,
}

impl From<lore_proto::lock::LockNamespaceGeneration> for LockNamespaceGeneration {
    fn from(value: lore_proto::lock::LockNamespaceGeneration) -> Self {
        Self {
            repository_lock_generation: value.repository_lock_generation,
            branch_lock_generation: value.branch_lock_generation,
            last_applied_fence: value.last_applied_fence,
        }
    }
}

/// FORK-LOCAL (WP-120). A lock query's rows plus the namespace generation read
/// before them. `namespace_generation` is `None` unless the query named exactly
/// one branch and the cell routes locks through the fenced authority.
#[derive(Default, Debug, Clone)]
pub struct LockQueryResult {
    pub locks: Vec<LockData>,
    pub namespace_generation: Option<LockNamespaceGeneration>,
}

#[derive(Default, Debug, Clone)]
pub struct RepositoryData {
    pub id: RepositoryId,
    pub name: String,
    pub metadata: Hash,
    /// FORK-LOCAL (WP-120). The repository's authoritative domain generation,
    /// set only by a `RepositoryGet` answered by a cell with an armed domain
    /// coordinator. `None` means "no authority", never "generation zero".
    pub generation: Option<u64>,
}

/// Result of a repository metadata compare-and-swap operation
#[derive(Default, Debug, Clone)]
pub struct MetadataSetResult {
    pub success: bool,
    pub current_hash: Hash,
}

// ---------------------------------------------------------------------------
// Authentication types
// ---------------------------------------------------------------------------

/// Result of an interactive login session initiation.
#[derive(Clone, Debug)]
pub struct AuthSession {
    /// Opaque session identifier for polling.
    pub session_code: String,
    /// URL the user should visit to authenticate.
    pub login_url: String,
}

/// Authentication token with user identity metadata.
///
/// Returned from login flows (interactive, token exchange, refresh).
/// This is the protocol-layer type -- transient, in-memory. The orchestration
/// layer converts it to `SerializedToken` (the token store's on-disk format)
/// when persisting to `tokenstore.toml`.
#[derive(Clone, Debug)]
pub struct AuthenticationToken {
    /// The bearer token string (typically a JWT, but opaque to the interface).
    pub token: String,
    /// Opaque user identity ID.
    pub user_id: String,
    /// Human-readable display name.
    pub user_name: String,
    /// Expiry as milliseconds since UNIX epoch.
    pub expires_ms: u64,
    /// Root domains this token is valid for.
    pub acceptable_root_domains: Vec<String>,
    /// Opaque backend-defined credential for obtaining a new authentication
    /// token without re-authenticating. `None` if the auth backend does not
    /// support refresh. A backend may return the same value or rotate it.
    pub refresh_token: Option<String>,
}

/// Authorization token scoped to a specific resource.
///
/// Returned from `exchange_for_repository` or `exchange_for_custom_resource`.
/// Shorter-lived than the authentication token and re-obtained via exchange
/// when expired.
#[derive(Clone, Debug)]
pub struct AuthorizationToken {
    /// The bearer token string.
    pub token: String,
    /// Expiry as milliseconds since UNIX epoch.
    pub expires_ms: u64,
    /// Root domains this token is valid for.
    pub acceptable_root_domains: Vec<String>,
}

/// Resolved user identity information.
#[derive(Clone, Debug)]
pub struct ResolvedUser {
    /// Opaque user identity ID.
    pub user_id: String,
    /// Human-readable display name.
    pub user_name: String,
}

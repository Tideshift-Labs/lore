// SPDX-FileCopyrightText: 2026 Tideshift Labs
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT

//! The durable [`AttemptStore`] the CLI and the embedding library use (WP-120, CR-029, CR-030).
//!
//! [`lore_transport::attempt_store`] defines the shape and ships only a volatile, test-only
//! implementation, on the argument that a store which acknowledges a write before it is durable
//! gives a caller permission to dispatch a mutation it can never ask about. This is the durable
//! one: a small versioned root and separate attempt files, atomically published and guarded
//! across processes by the same `FSLock` sidecar the token cache uses. Settled history is not
//! rewritten for each child dispatch. Version-one roots migrate before their first use.
//!
//! # Why it lives beside the repository rather than in the user's config directory
//!
//! Everything it holds is scoped to one repository. A lock ownership token is issued for a
//! `(branch, resource)` in one repository; an attempt record names the repository it targets. Two
//! clones of the same repository are two working trees with two independent sets of held locks,
//! and a per-user store would make them collide. `.lore/` is also what a caller deletes when it
//! discards a working tree, which is the correct lifetime for a token that only that working tree
//! ever had a use for.
//!
//! # The token is a credential at rest
//!
//! The 32 bytes CR-030 issues on acquire are the whole authority to release the lock they name.
//! Three things follow, and all three are load-bearing rather than hygienic:
//!
//! * on unix the file is created `0o600` before anything is written into it, so the token is
//!   never briefly group- or world-readable, and it is created fresh rather than opened, so a
//!   file left lying at that path cannot contribute its own looser mode;
//! * nothing in this module logs a token, and [`lore_transport::OwnershipToken`]'s `Debug` is
//!   redacted, so a token cannot reach a log through a formatted record either;
//! * a file this module cannot parse is an **error**, never an empty store. Reading a damaged
//!   store as empty would silently drop every token in it, and the locks those tokens released
//!   would become releasable only by an administrator. That is exactly the failure CR-030's
//!   token exists to prevent, so it must be loud.
//!
//! The token is stored in the clear. It is not encrypted the way the authentication token cache
//! encrypts its contents, and the reason is that the encryption there buys something this cannot:
//! that cache's key lives in the OS secure store, outside the file, so a stolen file alone is
//! useless. A key kept beside this file in the same working tree would be taken with it. Anyone
//! who can read `.lore/` can already read the repository's whole contents and the anchor that
//! says what it is, so the file mode is the boundary that actually holds.
//!
//! **That boundary holds on unix only.** Windows has no mode and nothing here sets an ACL, so the
//! file inherits whatever the working tree's directory grants. On a non-system drive that
//! commonly includes read for `BUILTIN\Users`, which means another local account can read a token
//! and release a lock it does not hold. It is a real gap and it is stated rather than papered
//! over: closing it needs an explicit DACL on `.lore/`, which is a decision about the whole
//! directory rather than about this one file, and it is not this lane's to make.

use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use lore_base::fs::lock::FSLock;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_base::types::RepositoryId;
use lore_transport::attempt_store::AttemptRecord;
use lore_transport::attempt_store::AttemptResolution;
use lore_transport::attempt_store::AttemptState;
use lore_transport::attempt_store::AttemptStore;
use lore_transport::attempt_store::LockOwnership;
use lore_transport::attempt_store::OwnershipToken;
use lore_transport::caller_operation::CallerRecoveryContext;
use lore_transport::caller_operation::ManagedAttemptIntent;
use lore_transport::domain_receipt::DomainReceiptQuery;
use lore_transport::error::ProtocolError;
use lore_transport::outcome::AttemptId;
use serde::Deserialize;
use serde::Serialize;
use uuid::Uuid;

use crate::repository::RepositoryContext;

mod operations;
mod persistence;
#[cfg(test)]
mod phase_diagnostics;
#[cfg(test)]
mod publication_tests;

pub(crate) use persistence::BOOTSTRAP_LOCK_FILE;
pub(crate) use persistence::ensure_directory;
pub(crate) use persistence::is_directory_temporary;

/// File name of the store inside the repository's dot directory.
pub const ATTEMPT_STORE_FILE: &str = "attempts";

/// The first byte of the file.
///
/// A version *byte* rather than a field inside the document, so a reader decides whether it can
/// read the format before it tries to parse it. A future version that changed the body's shape
/// would otherwise be met by a parser that fails with a message about the body, and the honest
/// answer is that the file is newer than this client.
pub const ATTEMPT_STORE_VERSION: u8 = 2;

/// Suffix of the sibling file a write lands in before it replaces the store.
///
/// The same suffix the realize path uses for its own atomic replacements, so the working-tree
/// conventions that already ignore it keep working.
const TEMP_SUFFIX: &str = ".~loretemp";

/// A durable [`AttemptStore`] backed by a root and child files in a repository's dot directory.
///
/// Cheap to construct and does no I/O until a method is called, so a caller can build one on a
/// path-less context path and only discover the problem where it matters.
pub struct RepositoryAttemptStore {
    /// `None` for a path-less repository context — a server-side handler, or an in-memory
    /// revision-tree handle.
    ///
    /// Resolved at construction and reported at first use, rather than refused at construction.
    /// Construction happens where a caller often has no error channel (inside the closure a
    /// read-call wrapper hands a repository to), and every use has one.
    path: Option<PathBuf>,
    /// Serialises this process's own read-modify-write spans.
    ///
    /// The `FSLock` below already serialises across processes, and would serialise these too, by
    /// polling. This exists because an acquire dispatches its batches concurrently and each one
    /// records its own tokens, so without it two tasks in one process would take turns through a
    /// retry loop with a sleep in it — correct, but paying wall-clock time to discover a
    /// contention this process can settle for free.
    write_guard: tokio::sync::Mutex<()>,
}

impl RepositoryAttemptStore {
    /// The store belonging to one repository's working tree.
    ///
    /// Uses the repository's own dot directory rather than a literal `.lore`, so a repository
    /// still in the legacy `.urc` format keeps its store beside the rest of its state.
    pub fn for_repository(repository: &RepositoryContext) -> Self {
        Self {
            path: repository.path.as_deref().map(|root| {
                root.join(repository.format.dot_dir())
                    .join(ATTEMPT_STORE_FILE)
            }),
            write_guard: tokio::sync::Mutex::new(()),
        }
    }

    /// The store inside an explicit dot directory.
    ///
    /// The seam a test uses against a temporary directory, and the seam an embedding caller uses
    /// when it knows the directory but holds no [`RepositoryContext`].
    pub fn in_directory(dot_directory: impl Into<PathBuf>) -> Self {
        Self {
            path: Some(dot_directory.into().join(ATTEMPT_STORE_FILE)),
            write_guard: tokio::sync::Mutex::new(()),
        }
    }

    /// The file this store reads and writes, for a context that has one.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// The file this store reads and writes, or the reason there is none.
    fn require_path(&self) -> Result<&Path, ProtocolError> {
        self.path.as_deref().ok_or_else(|| {
            ProtocolError::internal(
                "The attempt store has no working-tree path: this repository context is path-less",
            )
        })
    }

    /// Take the cross-process guard for a whole load-modify-store span.
    ///
    /// Held across the read *and* the write, never around each separately: another process may
    /// record its own ownership between the two, and a guard that spanned only the write would
    /// let this process's stale copy overwrite it.
    async fn guard(&self) -> Result<FSLock, ProtocolError> {
        let path = self.require_path()?;
        if let Some(parent) = path.parent() {
            #[cfg(test)]
            let _ensure = phase_diagnostics::start(Some(path), "ensure_directory_inclusive");
            ensure_directory(parent).await?;
        }
        #[cfg(test)]
        let _lock = phase_diagnostics::start(Some(path), "journal_fslock_wait");
        FSLock::acquire_file_lock(path).await.map_err(|error| {
            ProtocolError::internal(format!(
                "Failed to lock the attempt store {}: {error}",
                path.display()
            ))
        })
    }

    /// One guarded load-modify-store span.
    async fn update<F>(&self, change: F) -> Result<(), ProtocolError>
    where
        F: FnOnce(&mut StoredDocument),
    {
        let _in_process = self.write_guard.lock().await;
        let guard = self.guard().await?;
        let mut document = self.load_for_write(&guard)?;
        change(&mut document);
        self.store(&guard, &document)
    }

    /// One guarded read.
    async fn read(&self) -> Result<StoredDocument, ProtocolError> {
        let _in_process = self.write_guard.lock().await;
        let guard = self.guard().await?;
        self.load(&guard)
    }
}

/// Build the store a repository's own lock verbs use.
///
/// A free function rather than a method so a caller reaches for one type by intent: the CLI and
/// the embedding library want "the store for this repository", while the desktop injects its own
/// implementation of the same trait and never calls this.
pub fn repository_attempt_store(repository: &RepositoryContext) -> Arc<dyn AttemptStore> {
    Arc::new(RepositoryAttemptStore::for_repository(repository))
}

// ---------------------------------------------------------------------------
// On-disk shapes
//
// Deliberately separate types from the transport's. The file is a format this crate owns and has
// to keep readable across versions; the transport's types are free to change shape with the
// contract they express. Binding the two together with `derive(Serialize)` upstream would make
// every field rename a silent format break.
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize, Serialize)]
struct StoredDocument {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    generation: Option<String>,
    #[serde(default)]
    parents: Vec<ManagedParent>,
    #[serde(default)]
    managed: Vec<StoredManagedIntent>,
    #[serde(default)]
    attempts: Vec<StoredAttempt>,
    #[serde(default)]
    ownership: Vec<StoredOwnership>,
}

/// Durable parent identity. A missing namespace means no child was admitted yet.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ManagedParent {
    pub version: u32,
    pub id: String,
    pub root: String,
    pub operation: String,
    pub normalized_intent: String,
    pub namespace: Option<ManagedNamespace>,
    pub complete: bool,
    /// Parent uncertainty is independent of every named child receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_uncertainty_code: Option<i32>,
    /// Recovery cannot infer that the workflow body returned from child settlement.
    #[serde(default)]
    pub body_completed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct ManagedNamespace {
    pub repository: String,
    pub endpoint: String,
    pub issuer: String,
    pub subject: String,
    pub capabilities: String,
}

#[derive(Clone, Deserialize, Serialize, Debug, PartialEq, Eq)]
struct StoredManagedIntent {
    attempt: String,
    parent: String,
    rpc: String,
    canonical_request: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredAttempt {
    attempt_id: String,
    state: StoredState,
    operation: String,
    /// Hex, as [`RepositoryId`] renders and parses it.
    repository: String,
    recorded_at_unix_millis: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt: Option<StoredReceipt>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum StoredState {
    Unresolved,
    AdjudicatedUnknown,
    Resolved { resolution: StoredResolution },
}

impl StoredState {
    fn is_unresolved(&self) -> bool {
        !matches!(self, Self::Resolved { .. })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum StoredResolution {
    Applied,
    NotApplied,
    Conflicted,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredReceipt {
    org_uuid: String,
    /// Hex. Every byte string on this rail is hex rather than base64 so a stored record can be
    /// compared against a server-side row by eye.
    initiating_principal_namespace: String,
    operation_id: String,
    method: String,
    scope: String,
    fingerprint_version: u32,
    fingerprint: String,
    canonical_intent_digest: String,
    authorization_revision: u64,
    consumed_ticket_sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct StoredOwnership {
    attempt_id: String,
    /// Hex branch id.
    branch: String,
    /// Hex resource hash.
    resource: String,
    /// Hex ownership token. The credential this whole file is careful about.
    token: String,
}

impl From<&AttemptState> for StoredState {
    fn from(state: &AttemptState) -> Self {
        match state {
            AttemptState::Unresolved => Self::Unresolved,
            AttemptState::AdjudicatedUnknown => Self::AdjudicatedUnknown,
            AttemptState::Resolved(resolution) => Self::Resolved {
                resolution: match resolution {
                    AttemptResolution::Applied => StoredResolution::Applied,
                    AttemptResolution::NotApplied => StoredResolution::NotApplied,
                    AttemptResolution::Conflicted => StoredResolution::Conflicted,
                },
            },
        }
    }
}

impl From<StoredState> for AttemptState {
    fn from(state: StoredState) -> Self {
        match state {
            StoredState::Unresolved => Self::Unresolved,
            StoredState::AdjudicatedUnknown => Self::AdjudicatedUnknown,
            StoredState::Resolved { resolution } => Self::Resolved(match resolution {
                StoredResolution::Applied => AttemptResolution::Applied,
                StoredResolution::NotApplied => AttemptResolution::NotApplied,
                StoredResolution::Conflicted => AttemptResolution::Conflicted,
            }),
        }
    }
}

impl TryFrom<&AttemptRecord> for StoredAttempt {
    type Error = ProtocolError;

    fn try_from(record: &AttemptRecord) -> Result<Self, Self::Error> {
        Ok(Self {
            attempt_id: record.attempt_id.to_string(),
            state: StoredState::from(&record.state),
            operation: record.operation.clone(),
            repository: record.repository.to_string(),
            recorded_at_unix_millis: record.recorded_at_unix_millis,
            receipt: record.receipt.as_ref().map(StoredReceipt::from),
        })
    }
}

impl TryFrom<&StoredAttempt> for AttemptRecord {
    type Error = ProtocolError;

    fn try_from(stored: &StoredAttempt) -> Result<Self, Self::Error> {
        Ok(Self {
            attempt_id: parse_attempt_id(&stored.attempt_id)?,
            state: AttemptState::from(stored.state),
            operation: stored.operation.clone(),
            repository: parse_hex_typed::<RepositoryId>(&stored.repository, "repository")?,
            recorded_at_unix_millis: stored.recorded_at_unix_millis,
            receipt: stored
                .receipt
                .as_ref()
                .map(DomainReceiptQuery::try_from)
                .transpose()?,
        })
    }
}

impl From<&DomainReceiptQuery> for StoredReceipt {
    fn from(receipt: &DomainReceiptQuery) -> Self {
        Self {
            org_uuid: receipt.org_uuid.to_string(),
            initiating_principal_namespace: hex::encode(&receipt.initiating_principal_namespace),
            operation_id: receipt.operation_id.to_string(),
            method: receipt.method.clone(),
            scope: hex::encode(&receipt.scope),
            fingerprint_version: receipt.fingerprint_version,
            fingerprint: hex::encode(&receipt.fingerprint),
            canonical_intent_digest: hex::encode(&receipt.canonical_intent_digest),
            authorization_revision: receipt.authorization_revision,
            consumed_ticket_sha256: hex::encode(&receipt.consumed_ticket_sha256),
        }
    }
}

impl TryFrom<&StoredReceipt> for DomainReceiptQuery {
    type Error = ProtocolError;

    fn try_from(stored: &StoredReceipt) -> Result<Self, Self::Error> {
        Ok(Self {
            org_uuid: parse_uuid(&stored.org_uuid, "org_uuid")?,
            initiating_principal_namespace: parse_hex_bytes(
                &stored.initiating_principal_namespace,
                "initiating_principal_namespace",
            )?,
            operation_id: parse_uuid(&stored.operation_id, "operation_id")?,
            method: stored.method.clone(),
            scope: parse_hex_bytes(&stored.scope, "scope")?,
            fingerprint_version: stored.fingerprint_version,
            fingerprint: parse_hex_bytes(&stored.fingerprint, "fingerprint")?,
            canonical_intent_digest: parse_hex_bytes(
                &stored.canonical_intent_digest,
                "canonical_intent_digest",
            )?,
            authorization_revision: stored.authorization_revision,
            consumed_ticket_sha256: parse_hex_bytes(
                &stored.consumed_ticket_sha256,
                "consumed_ticket_sha256",
            )?,
        })
    }
}

impl From<&LockOwnership> for StoredOwnership {
    fn from(ownership: &LockOwnership) -> Self {
        Self {
            attempt_id: ownership.attempt_id.to_string(),
            branch: ownership.branch.to_string(),
            resource: ownership.resource_hash.to_string(),
            token: hex::encode(ownership.token.as_bytes()),
        }
    }
}

impl TryFrom<&StoredOwnership> for LockOwnership {
    type Error = ProtocolError;

    fn try_from(stored: &StoredOwnership) -> Result<Self, Self::Error> {
        let token = parse_hex_bytes(&stored.token, "ownership token")?;
        // Routed back through the same width check the wire uses. A record that cannot produce a
        // presentable token is an error rather than a `None`: answering "no token held" for a
        // lock this client *did* acquire would send a tokenless release and strand the row.
        let token = OwnershipToken::from_wire(&token)?.ok_or_else(|| {
            ProtocolError::internal("The attempt store holds an empty lock ownership token")
        })?;
        Ok(Self {
            attempt_id: parse_attempt_id(&stored.attempt_id)?,
            branch: parse_hex_typed::<Context>(&stored.branch, "branch")?,
            resource_hash: parse_hex_typed::<Hash>(&stored.resource, "resource hash")?,
            token,
        })
    }
}

/// Read one attempt identity back.
///
/// Text rather than a serde-native UUID so the file stays one flat, eyeball-readable shape: every
/// identity in it is a string, and reading a record back needs no feature flag on `uuid`.
fn parse_attempt_id(value: &str) -> Result<AttemptId, ProtocolError> {
    Ok(AttemptId::from_uuid(parse_uuid(value, "attempt id")?))
}

fn parse_uuid(value: &str, field: &str) -> Result<Uuid, ProtocolError> {
    Uuid::parse_str(value)
        .map_err(|error| ProtocolError::internal(format!("Invalid stored {field}: {error}")))
}

fn parse_hex_bytes(value: &str, field: &str) -> Result<bytes::Bytes, ProtocolError> {
    hex::decode(value)
        .map(bytes::Bytes::from)
        .map_err(|error| ProtocolError::internal(format!("Invalid stored {field}: {error}")))
}

fn parse_hex_typed<T>(value: &str, field: &str) -> Result<T, ProtocolError>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    value
        .parse::<T>()
        .map_err(|error| ProtocolError::internal(format!("Invalid stored {field}: {error}")))
}

/// Look up whatever ownership this client holds for a batch of resources, in order.
///
/// A free helper because both lock verbs need exactly this and neither wants the `Option` nesting
/// at its call site: a resource with no token is the ordinary case on a cell that issues none.
/// Batched rather than per-resource so a release covering a whole branch is one store read.
pub async fn held_tokens(
    ownership: &Arc<dyn AttemptStore>,
    resources: &[(Context, Hash)],
) -> Result<Vec<Option<OwnershipToken>>, ProtocolError> {
    Ok(ownership
        .ownership_for_batch(resources)
        .await?
        .into_iter()
        .map(|held| held.map(|held| held.token))
        .collect())
}

/// The client clock, in the units [`AttemptRecord`] records.
pub fn now_unix_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or_default()
}

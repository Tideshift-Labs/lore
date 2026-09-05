// SPDX-FileCopyrightText: 2026 Tideshift Labs
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT

//! The durable [`AttemptStore`] the CLI and the embedding library use (WP-120, CR-029, CR-030).
//!
//! [`lore_transport::attempt_store`] defines the shape and ships only a volatile, test-only
//! implementation, on the argument that a store which acknowledges a write before it is durable
//! gives a caller permission to dispatch a mutation it can never ask about. This is the durable
//! one: a single file under the repository's `.lore/` directory, written whole, replaced
//! atomically, and guarded across processes by the same `FSLock` sidecar the token cache uses.
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
use lore_transport::domain_receipt::DomainReceiptQuery;
use lore_transport::error::ProtocolError;
use lore_transport::outcome::AttemptId;
use serde::Deserialize;
use serde::Serialize;
use uuid::Uuid;

use crate::repository::RepositoryContext;

/// File name of the store inside the repository's dot directory.
pub const ATTEMPT_STORE_FILE: &str = "attempts";

/// The first byte of the file.
///
/// A version *byte* rather than a field inside the document, so a reader decides whether it can
/// read the format before it tries to parse it. A future version that changed the body's shape
/// would otherwise be met by a parser that fails with a message about the body, and the honest
/// answer is that the file is newer than this client.
pub const ATTEMPT_STORE_VERSION: u8 = 1;

/// Suffix of the sibling file a write lands in before it replaces the store.
///
/// The same suffix the realize path uses for its own atomic replacements, so the working-tree
/// conventions that already ignore it keep working.
const TEMP_SUFFIX: &str = ".~loretemp";

/// A durable [`AttemptStore`] backed by one file in a repository's dot directory.
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
            std::fs::create_dir_all(parent).map_err(|error| {
                ProtocolError::internal(format!(
                    "Failed to create the attempt store directory {}: {error}",
                    parent.display()
                ))
            })?;
        }
        FSLock::acquire_file_lock(path).await.map_err(|error| {
            ProtocolError::internal(format!(
                "Failed to lock the attempt store {}: {error}",
                path.display()
            ))
        })
    }

    /// Read the whole store. A missing file is an empty store; an unreadable one is an error.
    fn load(&self, _guard: &FSLock) -> Result<StoredDocument, ProtocolError> {
        let path = self.require_path()?;
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(StoredDocument::default());
            }
            Err(error) => {
                return Err(ProtocolError::internal(format!(
                    "Failed to read the attempt store {}: {error}",
                    path.display()
                )));
            }
        };

        // An empty file is the one damaged shape that is safely read as empty: it is what a
        // crash between create and write leaves behind, and it holds nothing that could be lost.
        if bytes.is_empty() {
            return Ok(StoredDocument::default());
        }

        let Some((version, body)) = bytes.split_first() else {
            return Ok(StoredDocument::default());
        };
        if *version != ATTEMPT_STORE_VERSION {
            return Err(ProtocolError::internal(format!(
                "The attempt store {} is version {version}, and this client reads version {}",
                path.display(),
                ATTEMPT_STORE_VERSION
            )));
        }

        serde_json::from_slice(body).map_err(|error| {
            ProtocolError::internal(format!(
                "Failed to parse the attempt store {}: {error}",
                path.display()
            ))
        })
    }

    /// Replace the whole store atomically.
    ///
    /// The disallowed-methods lint asks repository-level filesystem writes to go through a
    /// `RepositoryWriteToken`-gated helper, and this is a deliberate, narrow exception rather
    /// than an oversight. That token gates mutations of the *working tree*, and is minted by
    /// `repository_call_write`; the lock verbs are read calls and correctly hold none, because
    /// acquiring a lock changes no tracked content. What this writes is client-side metadata
    /// inside `.lore/`, under its own `FSLock` sidecar — the same arrangement, and the same
    /// exception, that the authentication token cache makes for its own guarded store. The allow
    /// is on this one function so a filesystem write added anywhere else in this module is still
    /// caught.
    #[allow(clippy::disallowed_methods)]
    fn store(&self, _guard: &FSLock, document: &StoredDocument) -> Result<(), ProtocolError> {
        let mut bytes = Vec::with_capacity(1024);
        bytes.push(ATTEMPT_STORE_VERSION);
        serde_json::to_writer(&mut bytes, document).map_err(|error| {
            ProtocolError::internal(format!("Failed to serialize the attempt store: {error}"))
        })?;

        let path = self.require_path()?;
        let mut temporary = path.to_path_buf().into_os_string();
        temporary.push(TEMP_SUFFIX);
        let temporary = PathBuf::from(temporary);

        write_private_file(&temporary, &bytes)?;

        // `rename` replaces on both platforms, so a reader either sees the whole previous file or
        // the whole new one. It never sees a truncated store, which for this file would read as
        // "no token for that lock".
        std::fs::rename(&temporary, path).map_err(|error| {
            let _ = std::fs::remove_file(&temporary);
            ProtocolError::internal(format!(
                "Failed to replace the attempt store {}: {error}",
                path.display()
            ))
        })?;

        sync_parent_directory(path);
        Ok(())
    }

    /// One guarded load-modify-store span.
    async fn update<F>(&self, change: F) -> Result<(), ProtocolError>
    where
        F: FnOnce(&mut StoredDocument),
    {
        let _in_process = self.write_guard.lock().await;
        let guard = self.guard().await?;
        let mut document = self.load(&guard)?;
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

/// Create a file only this user can read, then write the whole body into it.
///
/// Two things here are load-bearing for a file that holds bearer tokens.
///
/// **`create_new`, after removing whatever was there.** The unix `mode` applies only when the
/// open actually creates the file, so opening an existing path with `create(true)` would write
/// tokens into a file that kept *its* mode — a stale temporary from an aborted write on an older
/// build, an extracted archive, or a symlink someone left pointing elsewhere. Removing first and
/// refusing to open anything that survives that makes the mode unconditional and takes the
/// symlink-follow with it.
///
/// **The mode is set at creation rather than afterwards.** A `set_permissions` following the
/// write leaves a window in which the token is readable by anyone who can reach the directory.
///
/// Neither applies on Windows, which has no mode; see this module's own note on what does and
/// does not hold there.
#[allow(clippy::disallowed_methods)]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), ProtocolError> {
    use std::io::Write;

    // Not `?`: absence is the ordinary case and is not a failure. A path that cannot be removed
    // fails the `create_new` below, with a message naming the real problem.
    let _ = std::fs::remove_file(path);

    let mut options = std::fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(path).map_err(|error| {
        ProtocolError::internal(format!(
            "Failed to open the attempt store temporary {}: {error}",
            path.display()
        ))
    })?;

    // The temporary is removed on any failure. Leaving one behind is not merely untidy: it is a
    // file holding whatever bytes did land, at whatever point the write stopped, sitting beside
    // the store until something else happens to overwrite it.
    let written = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| {
            ProtocolError::internal(format!(
                "Failed to write the attempt store temporary {}: {error}",
                path.display()
            ))
        });
    if written.is_err() {
        drop(file);
        let _ = std::fs::remove_file(path);
    }
    written
}

/// Flush the directory entry a rename just created.
///
/// `sync_all` on the temporary persists its *contents*; on several filesystems the rename that
/// gives those contents their name is a separate metadata operation that a crash can still lose.
/// The trait this implements promises a record survives a crash once the write returns, and
/// without this that promise covers the bytes but not the name they are reachable under — which
/// for this file reads back as an empty store, which reads as "no token for that lock".
///
/// A directory that cannot be opened or synced is not fatal. Some platforms do not permit either
/// on a directory handle, and on those the rename is already durable or the guarantee was never
/// available to ask for; failing the whole write there would refuse to store a token this client
/// has already been issued, which is worse than the weaker guarantee.
fn sync_parent_directory(path: &Path) {
    if let Some(parent) = path.parent()
        && let Ok(directory) = std::fs::File::open(parent)
    {
        let _ = directory.sync_all();
    }
}

#[async_trait]
impl AttemptStore for RepositoryAttemptStore {
    async fn record(&self, record: &AttemptRecord) -> Result<(), ProtocolError> {
        let stored = StoredAttempt::try_from(record)?;
        self.update(|document| {
            match document
                .attempts
                .iter_mut()
                .find(|held| held.attempt_id == stored.attempt_id)
            {
                // Re-recording one id is a caller retrying its own write, and the contract says
                // to overwrite rather than duplicate or refuse.
                Some(existing) => *existing = stored,
                None => document.attempts.push(stored),
            }
        })
        .await
    }

    async fn lookup(&self, attempt: &AttemptId) -> Result<Option<AttemptRecord>, ProtocolError> {
        let document = self.read().await?;
        document
            .attempts
            .iter()
            .find(|held| held.attempt_id == attempt.to_string())
            .map(AttemptRecord::try_from)
            .transpose()
    }

    async fn unresolved(&self) -> Result<Vec<AttemptRecord>, ProtocolError> {
        let document = self.read().await?;
        let mut records = document
            .attempts
            .iter()
            .filter(|held| held.state.is_unresolved())
            .map(AttemptRecord::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        // Tie-broken by the attempt id, which is a v7 and so itself mint-ordered: a client clock
        // can repeat a millisecond or step backwards, and an order that changed between two reads
        // of an unchanged store would be a poor thing to show an operator.
        records.sort_by(|left, right| {
            left.recorded_at_unix_millis
                .cmp(&right.recorded_at_unix_millis)
                .then_with(|| left.attempt_id.as_uuid().cmp(&right.attempt_id.as_uuid()))
        });
        Ok(records)
    }

    async fn record_ownership(&self, ownership: &LockOwnership) -> Result<(), ProtocolError> {
        let stored = StoredOwnership::from(ownership);
        self.update(|document| {
            match document
                .ownership
                .iter_mut()
                .find(|held| held.branch == stored.branch && held.resource == stored.resource)
            {
                // One resource holds one token. A renewal mints a new one and the old one is
                // dead, so keeping both would leave a caller choosing between them.
                Some(existing) => *existing = stored,
                None => document.ownership.push(stored),
            }
        })
        .await
    }

    async fn ownership_for(
        &self,
        branch: &Context,
        resource_hash: &Hash,
    ) -> Result<Option<LockOwnership>, ProtocolError> {
        let document = self.read().await?;
        document
            .ownership
            .iter()
            .find(|held| {
                held.branch == branch.to_string() && held.resource == resource_hash.to_string()
            })
            .map(LockOwnership::try_from)
            .transpose()
    }

    /// One read for the whole batch, which is the reason the trait defaults this rather than
    /// leaving every caller to loop: a release rebuilt from a branch-wide `Query` asks about every
    /// lock on the branch, and the default would take the file lock once per resource.
    async fn ownership_for_batch(
        &self,
        resources: &[(Context, Hash)],
    ) -> Result<Vec<Option<LockOwnership>>, ProtocolError> {
        let document = self.read().await?;
        let mut held = Vec::with_capacity(resources.len());
        for (branch, resource_hash) in resources {
            let branch = branch.to_string();
            let resource = resource_hash.to_string();
            held.push(
                document
                    .ownership
                    .iter()
                    .find(|stored| stored.branch == branch && stored.resource == resource)
                    .map(LockOwnership::try_from)
                    .transpose()?,
            );
        }
        Ok(held)
    }

    async fn clear_ownership(
        &self,
        branch: &Context,
        resource_hash: &Hash,
    ) -> Result<(), ProtocolError> {
        let branch = branch.to_string();
        let resource = resource_hash.to_string();
        self.update(|document| {
            document
                .ownership
                .retain(|held| !(held.branch == branch && held.resource == resource));
        })
        .await
    }

    /// One rewrite for the whole batch. The default's loop would take the file lock, rewrite the
    /// document and fsync once per released resource, which on a branch-wide release is quadratic
    /// in the number of locks held.
    async fn clear_ownership_batch(
        &self,
        resources: &[(Context, Hash)],
    ) -> Result<(), ProtocolError> {
        if resources.is_empty() {
            return Ok(());
        }
        let cleared = resources
            .iter()
            .map(|(branch, resource_hash)| (branch.to_string(), resource_hash.to_string()))
            .collect::<Vec<_>>();
        self.update(|document| {
            document.ownership.retain(|held| {
                !cleared
                    .iter()
                    .any(|(branch, resource)| held.branch == *branch && held.resource == *resource)
            });
        })
        .await
    }

    async fn resolve(
        &self,
        attempt: &AttemptId,
        resolution: AttemptResolution,
    ) -> Result<(), ProtocolError> {
        let attempt = attempt.to_string();
        let state = StoredState::from(&AttemptState::Resolved(resolution));
        self.update(|document| {
            if let Some(existing) = document
                .attempts
                .iter_mut()
                .find(|held| held.attempt_id == attempt)
            {
                existing.state = state;
            }
            document.ownership.retain(|held| held.attempt_id != attempt);
        })
        .await
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
    #[serde(default)]
    attempts: Vec<StoredAttempt>,
    #[serde(default)]
    ownership: Vec<StoredOwnership>,
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

// SPDX-FileCopyrightText: 2026 Khurram Virani
// SPDX-License-Identifier: MIT

//! Publication-atomic exact-selection commit transaction for CLIENT repositories.
//!
//! One client [`RepositoryWriteToken`] spans input validation, construction of an
//! unpublished staged state, file-metadata mutation, commit admission, and anchor
//! publication. Rejection preserves the published current, staged, and branch-latest
//! anchors. Immutable fragments and delta objects, plus commit lifecycle events, may
//! precede a post-rehash admission rejection and remain unreachable.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::fmt;
use std::future::Future;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::PoisonError;

use bytes::Bytes;
use lore_error_set::FfiError;
use lore_error_set::HasTrace;
use lore_error_set::Trace;
use md5::Digest;
use md5::Md5;
use serde::Deserialize;
use serde::Serialize;
use thiserror::Error;

use crate::change::FileAction;
use crate::commit;
use crate::event::EventError;
use crate::file::stage::stage_state;
use crate::fs::filesystem_provider::with_operation;
use crate::immutable;
use crate::interface::LoreArray;
use crate::interface::LoreError;
use crate::interface::LoreMetadataType;
use crate::interface::LoreString;
use crate::lore::Hash;
use crate::lore::TypedBytes;
use crate::metadata::Metadata;
use crate::node::Node;
use crate::node::NodeFileMetadata;
use crate::node::NodeFileMetadataBlock;
use crate::node::NodeID;
use crate::node::NodeIDExt;
use crate::node::ROOT_NODE;
use crate::node::{self};
use crate::repository::RepositoryContext;
use crate::repository::RepositoryError;
use crate::repository::RepositoryWriteToken;
use crate::stage::StageCaseChange;
use crate::stage::StageOptions;
use crate::state::State;
use crate::state::StateNodeChildrenWithNameIterator;
use crate::state::{self};
use crate::util::path::RelativePath;

#[lore_macro::test_pub]
const MAX_SELECTED_FILES: usize = 100_000;
#[lore_macro::test_pub]
const MAX_REPOSITORY_RELATIVE_PATH_BYTES: usize = 4_096;
#[lore_macro::test_pub]
const MAX_METADATA_ENTRIES_PER_SCOPE: usize = 1_024;
#[lore_macro::test_pub]
const MAX_METADATA_KEY_BYTES: usize = 1_024;
#[lore_macro::test_pub]
const MAX_METADATA_VALUE_BYTES: usize = 4 * 1_024 * 1_024;
#[lore_macro::test_pub]
const MAX_BINARY_METADATA_PAYLOAD_BYTES: u64 = 64 * 1_024 * 1_024;
#[lore_macro::test_pub]
const MAX_AGGREGATE_INPUT_BYTES: usize = 64 * 1_024 * 1_024;

// Event callbacks run asynchronously. Fault tests need a per-task boundary after
// staging has finished and before the commit path reads selected file content.
#[cfg(feature = "test-util")]
tokio::task_local! {
    pub static AFTER_EXACT_STAGE: std::cell::RefCell<Option<Box<dyn FnOnce() + Send>>>;
}

/// Effective file action authorized by an exact-selection caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ExpectedFileAction {
    Add,
    Modify,
    Delete,
}

/// Metadata input formats supported by exact-selection v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ExactMetadataType {
    String,
    Numeric,
    /// `value` names a file whose bytes become an immutable metadata payload.
    Binary,
}

/// One exact metadata entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileMetadataEntry {
    pub key: String,
    pub value: String,
    pub value_type: ExactMetadataType,
}

/// File-metadata policy for one selected path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind", content = "entries")]
pub enum FileMetadataSelection {
    Unchanged,
    Exact(Vec<FileMetadataEntry>),
    Clear,
}

/// One caller-authorized file row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectedFile {
    pub path: String,
    pub expected_effective_action: ExpectedFileAction,
    pub source_hash: Option<String>,
    pub file_metadata: FileMetadataSelection,
}

/// Inputs for one exact-selection revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExactSelectionOptions {
    pub message: String,
    pub files: Vec<SelectedFile>,
    /// Revision metadata is separate from selected-file membership.
    #[serde(default)]
    pub revision_metadata: Vec<FileMetadataEntry>,
    #[serde(default)]
    pub stats: bool,
}

/// Normalized action row returned in deterministic path order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExactActionRow {
    pub path: String,
    pub action: ExpectedFileAction,
}

/// File metadata hash admitted for a selected path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExactFileMetadataHash {
    pub path: String,
    pub hash: String,
}

/// Successful transaction result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExactSelectionResult {
    pub revision: Hash,
    pub generated_actions: Vec<ExactActionRow>,
    pub effective_actions: Vec<ExactActionRow>,
    pub committed_file_metadata_hashes: Vec<ExactFileMetadataHash>,
}

/// Expected-versus-actual action mismatch for one normalized path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExactActionMismatch {
    pub path: String,
    pub expected: ExpectedFileAction,
    pub actual: ExpectedFileAction,
}

/// Exact staged file-metadata mismatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExactMetadataMismatch {
    pub path: String,
    pub expected_hash: String,
    pub staged_hash: String,
}

/// Immutable content digest mismatch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExactSourceHashMismatch {
    pub path: String,
    pub expected: String,
    pub actual: String,
}

/// Structured, deterministic exact-selection failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    tag = "kind"
)]
pub enum ExactSelectionErrorKind {
    InvalidInput {
        reason: String,
        paths: Vec<String>,
    },
    PathNormalization {
        path: String,
        reason: String,
    },
    StagedRepairFailure {
        reason: String,
    },
    GeneratedSelectionMismatch {
        expected: Vec<ExactActionRow>,
        actual: Vec<ExactActionRow>,
        missing: Vec<ExactActionRow>,
        extras: Vec<ExactActionRow>,
        action_mismatches: Vec<ExactActionMismatch>,
    },
    SemanticSelectionMismatch {
        expected: Vec<ExactActionRow>,
        actual: Vec<ExactActionRow>,
        missing: Vec<ExactActionRow>,
        extras: Vec<ExactActionRow>,
        action_mismatches: Vec<ExactActionMismatch>,
    },
    UnselectedFileMetadata {
        paths: Vec<String>,
    },
    DuplicateMetadataKey {
        path: String,
        key: String,
    },
    StagedMetadataHashMismatch {
        mismatches: Vec<ExactMetadataMismatch>,
    },
    MetadataInputRead {
        path: String,
        key: String,
        input: String,
        reason: String,
    },
    MalformedSourceHash {
        path: String,
        value: String,
    },
    MissingImmutableContent {
        path: String,
        reason: String,
    },
    UnexpectedContentDigest {
        path: String,
    },
    SourceHashMismatch {
        mismatches: Vec<ExactSourceHashMismatch>,
    },
    PreFragmentationFileRead {
        path: String,
        reason: String,
    },
    UnsupportedTopology {
        reason: String,
    },
    PublicationFailure {
        anchors_restored: bool,
        reason: String,
    },
    Internal {
        operation: String,
        reason: String,
    },
}

impl fmt::Display for ExactSelectionErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput { reason, .. } => {
                write!(f, "invalid exact-selection input: {reason}")
            }
            Self::PathNormalization { path, reason } => {
                write!(f, "invalid exact-selection path {path}: {reason}")
            }
            Self::StagedRepairFailure { reason } => write!(f, "staged repair failed: {reason}"),
            Self::GeneratedSelectionMismatch { .. } => write!(f, "generated selection mismatch"),
            Self::SemanticSelectionMismatch { .. } => write!(f, "semantic selection mismatch"),
            Self::UnselectedFileMetadata { .. } => write!(f, "unselected file metadata"),
            Self::DuplicateMetadataKey { path, key } => {
                write!(f, "duplicate metadata key {key} for {path}")
            }
            Self::StagedMetadataHashMismatch { .. } => {
                write!(f, "staged metadata hash mismatch")
            }
            Self::MetadataInputRead { path, key, .. } => {
                write!(f, "metadata input read failed for {path}:{key}")
            }
            Self::MalformedSourceHash { path, .. } => {
                write!(f, "malformed source hash for {path}")
            }
            Self::MissingImmutableContent { path, .. } => {
                write!(f, "missing immutable content for {path}")
            }
            Self::UnexpectedContentDigest { path } => {
                write!(f, "delete carries an unexpected content digest for {path}")
            }
            Self::SourceHashMismatch { .. } => write!(f, "source hash mismatch"),
            Self::PreFragmentationFileRead { path, .. } => {
                write!(f, "pre-fragmentation file read failed for {path}")
            }
            Self::UnsupportedTopology { reason } => write!(f, "unsupported topology: {reason}"),
            Self::PublicationFailure {
                anchors_restored,
                reason,
            } => {
                if *anchors_restored {
                    write!(
                        f,
                        "exact-selection publication failed; original anchors restored: {reason}"
                    )
                } else {
                    write!(
                        f,
                        "exact-selection publication and anchor restoration failed: {reason}"
                    )
                }
            }
            Self::Internal { operation, reason } => write!(f, "{operation}: {reason}"),
        }
    }
}

/// Error wrapper carrying a Lore trace without weakening the structured payload.
#[derive(Debug, Clone, Error)]
#[error("{kind}")]
pub struct ExactSelectionError {
    kind: Box<ExactSelectionErrorKind>,
    trace: Trace,
}

impl ExactSelectionError {
    pub fn new(kind: ExactSelectionErrorKind) -> Self {
        Self {
            kind: Box::new(kind),
            trace: Trace::default(),
        }
    }

    pub fn kind(&self) -> &ExactSelectionErrorKind {
        &self.kind
    }

    pub fn into_kind(self) -> ExactSelectionErrorKind {
        *self.kind
    }

    fn internal(operation: impl Into<String>, reason: impl fmt::Display) -> Self {
        Self::new(ExactSelectionErrorKind::Internal {
            operation: operation.into(),
            reason: reason.to_string(),
        })
    }

    /// Stable Lore status code for bindings that also retain the typed kind.
    pub fn code(&self) -> i32 {
        self.ffi_code()
    }
}

#[lore_macro::test_pub]
fn map_exact_finalize_error(err: commit::ExactFinalizeError) -> ExactSelectionError {
    match err {
        commit::ExactFinalizeError::BeforePublication { source } => {
            ExactSelectionError::internal("publishing exact selection", source)
        }
        commit::ExactFinalizeError::Publication {
            anchors_restored,
            reason,
        } => ExactSelectionError::new(ExactSelectionErrorKind::PublicationFailure {
            anchors_restored,
            reason,
        }),
    }
}

impl From<RepositoryError> for ExactSelectionError {
    fn from(err: RepositoryError) -> Self {
        Self::internal("opening repository", err)
    }
}

impl FfiError for ExactSelectionError {
    fn ffi_code(&self) -> i32 {
        match self.kind() {
            ExactSelectionErrorKind::InvalidInput { .. }
            | ExactSelectionErrorKind::PathNormalization { .. }
            | ExactSelectionErrorKind::GeneratedSelectionMismatch { .. }
            | ExactSelectionErrorKind::SemanticSelectionMismatch { .. }
            | ExactSelectionErrorKind::UnselectedFileMetadata { .. }
            | ExactSelectionErrorKind::DuplicateMetadataKey { .. }
            | ExactSelectionErrorKind::StagedMetadataHashMismatch { .. }
            | ExactSelectionErrorKind::MalformedSourceHash { .. }
            | ExactSelectionErrorKind::UnexpectedContentDigest { .. }
            | ExactSelectionErrorKind::SourceHashMismatch { .. }
            | ExactSelectionErrorKind::UnsupportedTopology { .. } => {
                LoreError::InvalidArguments as i32
            }
            _ => LoreError::Internal as i32,
        }
    }
}

impl HasTrace for ExactSelectionError {
    fn trace(&self) -> &Trace {
        &self.trace
    }
}

impl EventError for ExactSelectionError {
    fn translated(&self) -> LoreError {
        match self.kind() {
            ExactSelectionErrorKind::InvalidInput { .. }
            | ExactSelectionErrorKind::PathNormalization { .. }
            | ExactSelectionErrorKind::GeneratedSelectionMismatch { .. }
            | ExactSelectionErrorKind::SemanticSelectionMismatch { .. }
            | ExactSelectionErrorKind::UnselectedFileMetadata { .. }
            | ExactSelectionErrorKind::DuplicateMetadataKey { .. }
            | ExactSelectionErrorKind::StagedMetadataHashMismatch { .. }
            | ExactSelectionErrorKind::MalformedSourceHash { .. }
            | ExactSelectionErrorKind::UnexpectedContentDigest { .. }
            | ExactSelectionErrorKind::SourceHashMismatch { .. }
            | ExactSelectionErrorKind::UnsupportedTopology { .. } => LoreError::InvalidArguments,
            _ => LoreError::Internal,
        }
    }

    fn inner(&self) -> String {
        self.to_string()
    }
}

#[derive(Clone)]
#[lore_macro::test_pub]
struct PreparedMetadataEntry {
    key: String,
    value: PreparedMetadataValue,
}

#[derive(Clone)]
#[lore_macro::test_pub]
enum PreparedMetadataValue {
    String(String),
    Numeric(u64),
    Binary(Bytes),
}

#[derive(Clone)]
#[lore_macro::test_pub]
struct NormalizedSelectedFile {
    row: ExactActionRow,
    source_hash: Option<String>,
    file_metadata: FileMetadataSelection,
    prepared_metadata: Vec<PreparedMetadataEntry>,
}

#[lore_macro::test_pub]
fn validate_input_bounds(
    message: &str,
    files: &[SelectedFile],
    revision_metadata: &[FileMetadataEntry],
) -> Result<(), ExactSelectionError> {
    if files.len() > MAX_SELECTED_FILES {
        return Err(ExactSelectionError::new(
            ExactSelectionErrorKind::InvalidInput {
                reason: format!(
                    "selected file count {} exceeds limit {MAX_SELECTED_FILES}",
                    files.len()
                ),
                paths: Vec::new(),
            },
        ));
    }
    if revision_metadata.len() > MAX_METADATA_ENTRIES_PER_SCOPE {
        return Err(ExactSelectionError::new(
            ExactSelectionErrorKind::InvalidInput {
                reason: format!(
                    "revision metadata entry count {} exceeds limit {MAX_METADATA_ENTRIES_PER_SCOPE}",
                    revision_metadata.len()
                ),
                paths: Vec::new(),
            },
        ));
    }

    let mut aggregate = 0usize;
    let mut add_bytes = |count: usize| -> Result<(), ExactSelectionError> {
        aggregate = aggregate.checked_add(count).ok_or_else(|| {
            ExactSelectionError::new(ExactSelectionErrorKind::InvalidInput {
                reason: "aggregate input size overflow".into(),
                paths: Vec::new(),
            })
        })?;
        if aggregate > MAX_AGGREGATE_INPUT_BYTES {
            return Err(ExactSelectionError::new(
                ExactSelectionErrorKind::InvalidInput {
                    reason: format!(
                        "aggregate input size exceeds limit {MAX_AGGREGATE_INPUT_BYTES} bytes"
                    ),
                    paths: Vec::new(),
                },
            ));
        }
        Ok(())
    };

    let validate_metadata = |entry: &FileMetadataEntry| -> Result<(), ExactSelectionError> {
        if entry.key.len() > MAX_METADATA_KEY_BYTES {
            return Err(ExactSelectionError::new(
                ExactSelectionErrorKind::InvalidInput {
                    reason: format!("metadata key exceeds limit {MAX_METADATA_KEY_BYTES} bytes"),
                    paths: Vec::new(),
                },
            ));
        }
        if entry.value.len() > MAX_METADATA_VALUE_BYTES {
            return Err(ExactSelectionError::new(
                ExactSelectionErrorKind::InvalidInput {
                    reason: format!(
                        "metadata value exceeds limit {MAX_METADATA_VALUE_BYTES} bytes"
                    ),
                    paths: Vec::new(),
                },
            ));
        }
        Ok(())
    };

    add_bytes(message.len())?;
    for file in files {
        if file.path.len() > MAX_REPOSITORY_RELATIVE_PATH_BYTES {
            return Err(ExactSelectionError::new(
                ExactSelectionErrorKind::PathNormalization {
                    path: file.path.clone(),
                    reason: format!(
                        "path exceeds limit {MAX_REPOSITORY_RELATIVE_PATH_BYTES} bytes"
                    ),
                },
            ));
        }
        add_bytes(file.path.len() + file.source_hash.as_ref().map_or(0, String::len))?;
        if let FileMetadataSelection::Exact(entries) = &file.file_metadata {
            if entries.len() > MAX_METADATA_ENTRIES_PER_SCOPE {
                return Err(ExactSelectionError::new(
                    ExactSelectionErrorKind::InvalidInput {
                        reason: format!(
                            "file metadata entry count for {} exceeds limit {MAX_METADATA_ENTRIES_PER_SCOPE}",
                            file.path
                        ),
                        paths: vec![file.path.clone()],
                    },
                ));
            }
            for entry in entries {
                validate_metadata(entry)?;
                add_bytes(entry.key.len() + entry.value.len())?;
            }
        }
    }
    for entry in revision_metadata {
        validate_metadata(entry)?;
        add_bytes(entry.key.len() + entry.value.len())?;
    }
    Ok(())
}

#[lore_macro::test_pub]
async fn normalize_selected_files(
    repository_root: &Path,
    files: Vec<SelectedFile>,
) -> Result<Vec<NormalizedSelectedFile>, ExactSelectionError> {
    if files.is_empty() {
        return Err(ExactSelectionError::new(
            ExactSelectionErrorKind::InvalidInput {
                reason: "at least one selected file is required".into(),
                paths: Vec::new(),
            },
        ));
    }

    let mut normalized_paths = BTreeSet::new();
    let mut candidates = Vec::with_capacity(files.len());
    for file in files {
        let input_path = PathBuf::from(&file.path);
        if input_path
            .components()
            .any(|component| matches!(component, Component::Prefix(_) | Component::RootDir))
        {
            return Err(ExactSelectionError::new(
                ExactSelectionErrorKind::PathNormalization {
                    path: file.path,
                    reason: "path must be repository-relative".into(),
                },
            ));
        }
        let joined = repository_root.join(&input_path);
        let joined = joined.to_string_lossy();
        let relative =
            RelativePath::new_from_user_path(repository_root, &joined).map_err(|err| {
                ExactSelectionError::new(ExactSelectionErrorKind::PathNormalization {
                    path: file.path.clone(),
                    reason: err.to_string(),
                })
            })?;
        if relative.is_empty() {
            return Err(ExactSelectionError::new(
                ExactSelectionErrorKind::PathNormalization {
                    path: file.path,
                    reason: "repository root is not a file selection".into(),
                },
            ));
        }
        let path = relative.as_str().to_string();
        if !normalized_paths.insert(path.clone()) {
            return Err(ExactSelectionError::new(
                ExactSelectionErrorKind::InvalidInput {
                    reason: "duplicate selected path".into(),
                    paths: vec![path],
                },
            ));
        }
        candidates.push((path, file));
    }

    let mut normalized = BTreeMap::<String, NormalizedSelectedFile>::new();
    let mut binary_metadata_bytes = 0u64;
    for (path, file) in candidates {
        match file.expected_effective_action {
            ExpectedFileAction::Add | ExpectedFileAction::Modify => {
                let Some(source_hash) = file.source_hash.as_ref() else {
                    return Err(ExactSelectionError::new(
                        ExactSelectionErrorKind::MalformedSourceHash {
                            path,
                            value: String::new(),
                        },
                    ));
                };
                let valid = source_hash.len() == 32
                    && source_hash
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
                if !valid {
                    return Err(ExactSelectionError::new(
                        ExactSelectionErrorKind::MalformedSourceHash {
                            path,
                            value: source_hash.clone(),
                        },
                    ));
                }
            }
            ExpectedFileAction::Delete => {
                if file.source_hash.is_some() {
                    return Err(ExactSelectionError::new(
                        ExactSelectionErrorKind::UnexpectedContentDigest { path },
                    ));
                }
                if file.file_metadata != FileMetadataSelection::Unchanged {
                    return Err(ExactSelectionError::new(
                        ExactSelectionErrorKind::InvalidInput {
                            reason: "Delete supports fileMetadata=Unchanged only in v1".into(),
                            paths: vec![path],
                        },
                    ));
                }
            }
        }

        let mut prepared_metadata = Vec::new();
        if let FileMetadataSelection::Exact(entries) = &file.file_metadata {
            let mut keys = BTreeSet::new();
            for entry in entries {
                if entry.key.is_empty() || !keys.insert(entry.key.clone()) {
                    return Err(ExactSelectionError::new(
                        ExactSelectionErrorKind::DuplicateMetadataKey {
                            path: path.clone(),
                            key: entry.key.clone(),
                        },
                    ));
                }
                let value = match entry.value_type {
                    ExactMetadataType::String => PreparedMetadataValue::String(entry.value.clone()),
                    ExactMetadataType::Numeric => {
                        let parsed = entry.value.parse::<u64>().map_err(|_err| {
                            ExactSelectionError::new(ExactSelectionErrorKind::InvalidInput {
                                reason: format!("metadata key {} requires a u64 value", entry.key),
                                paths: vec![path.clone()],
                            })
                        })?;
                        PreparedMetadataValue::Numeric(parsed)
                    }
                    ExactMetadataType::Binary => {
                        let source = PathBuf::from(&entry.value);
                        let source = if source.is_absolute() {
                            source
                        } else {
                            repository_root.join(source)
                        };
                        let file = lore_io::IoDriver::global()
                            .open(&source, &lore_io::OpenOptions::new().read(true))
                            .await
                            .map_err(|err| {
                                ExactSelectionError::new(
                                    ExactSelectionErrorKind::MetadataInputRead {
                                        path: path.clone(),
                                        key: entry.key.clone(),
                                        input: source.display().to_string(),
                                        reason: err.to_string(),
                                    },
                                )
                            })?;
                        let remaining =
                            MAX_BINARY_METADATA_PAYLOAD_BYTES.saturating_sub(binary_metadata_bytes);
                        let payload = file
                            .read_at(remaining.saturating_add(1) as usize, 0)
                            .await
                            .map_err(|err| {
                                ExactSelectionError::new(
                                    ExactSelectionErrorKind::MetadataInputRead {
                                        path: path.clone(),
                                        key: entry.key.clone(),
                                        input: source.display().to_string(),
                                        reason: err.to_string(),
                                    },
                                )
                            })?;
                        if payload.len() as u64 > MAX_BINARY_METADATA_PAYLOAD_BYTES {
                            return Err(ExactSelectionError::new(
                                ExactSelectionErrorKind::MetadataInputRead {
                                    path: path.clone(),
                                    key: entry.key.clone(),
                                    input: source.display().to_string(),
                                    reason: format!(
                                        "binary metadata payload exceeds limit {MAX_BINARY_METADATA_PAYLOAD_BYTES} bytes"
                                    ),
                                },
                            ));
                        }
                        binary_metadata_bytes = binary_metadata_bytes
                            .checked_add(payload.len() as u64)
                            .ok_or_else(|| {
                                ExactSelectionError::new(ExactSelectionErrorKind::InvalidInput {
                                    reason: "aggregate binary metadata size overflow".into(),
                                    paths: vec![path.clone()],
                                })
                            })?;
                        if binary_metadata_bytes > MAX_BINARY_METADATA_PAYLOAD_BYTES {
                            return Err(ExactSelectionError::new(
                                ExactSelectionErrorKind::InvalidInput {
                                    reason: format!(
                                        "aggregate binary metadata size exceeds limit {MAX_BINARY_METADATA_PAYLOAD_BYTES} bytes"
                                    ),
                                    paths: vec![path.clone()],
                                },
                            ));
                        }
                        PreparedMetadataValue::Binary(payload)
                    }
                };
                prepared_metadata.push(PreparedMetadataEntry {
                    key: entry.key.clone(),
                    value,
                });
            }
        }

        let candidate = NormalizedSelectedFile {
            row: ExactActionRow {
                path: path.clone(),
                action: file.expected_effective_action,
            },
            source_hash: file.source_hash,
            file_metadata: file.file_metadata,
            prepared_metadata,
        };
        normalized.insert(path, candidate);
    }
    Ok(normalized.into_values().collect())
}

fn validate_revision_metadata(entries: &[FileMetadataEntry]) -> Result<(), ExactSelectionError> {
    let mut keys = BTreeSet::new();
    for entry in entries {
        if !keys.insert(entry.key.clone()) {
            return Err(ExactSelectionError::new(
                ExactSelectionErrorKind::DuplicateMetadataKey {
                    path: "<revision>".into(),
                    key: entry.key.clone(),
                },
            ));
        }
        match entry.value_type {
            ExactMetadataType::String => {}
            ExactMetadataType::Numeric => {
                if entry.value.parse::<u64>().is_err() {
                    return Err(ExactSelectionError::new(
                        ExactSelectionErrorKind::InvalidInput {
                            reason: format!(
                                "revision metadata key {} requires an unsigned integer",
                                entry.key
                            ),
                            paths: Vec::new(),
                        },
                    ));
                }
            }
            ExactMetadataType::Binary => {
                return Err(ExactSelectionError::new(
                    ExactSelectionErrorKind::InvalidInput {
                        reason: format!(
                            "binary revision metadata key {} is excluded from exact-selection v1",
                            entry.key
                        ),
                        paths: Vec::new(),
                    },
                ));
            }
        }
    }
    Ok(())
}

async fn file_metadata_hash(
    repository: Arc<RepositoryContext>,
    state: Arc<State>,
    path: &str,
) -> Result<Option<Hash>, ExactSelectionError> {
    let link = match state.find_node_link(repository.clone(), path).await {
        Ok(link) => link,
        Err(state::StateError::NodeNotFound(_)) => return Ok(None),
        Err(err) => {
            return Err(ExactSelectionError::internal(
                "finding file metadata node",
                err,
            ));
        }
    };
    if !link.is_valid() {
        return Ok(None);
    }
    if link.repository != repository.id {
        return Err(ExactSelectionError::new(
            ExactSelectionErrorKind::UnsupportedTopology {
                reason: format!("selected path {path} resolves through a link"),
            },
        ));
    }
    let metadata_node = node::node_to_file_metadata(link.node);
    let block = state
        .block_file_metadata(repository, NodeFileMetadataBlock::index(metadata_node))
        .await
        .map_err(|err| ExactSelectionError::internal("reading file metadata block", err))?;
    Ok(Some(
        block
            .read()
            .node(NodeFileMetadata::index(metadata_node))
            .metadata,
    ))
}

async fn collect_live_file_metadata(
    repository: Arc<RepositoryContext>,
    state: Arc<State>,
) -> Result<BTreeMap<String, Hash>, ExactSelectionError> {
    let mut result = BTreeMap::new();
    let mut directories = VecDeque::from([(String::new(), ROOT_NODE)]);
    while let Some((parent_path, parent_id)) = directories.pop_front() {
        let mut children =
            StateNodeChildrenWithNameIterator::new(state.clone(), repository.clone(), parent_id)
                .await
                .map_err(|err| ExactSelectionError::internal("walking file metadata tree", err))?;
        while let Some((child_id, child, name)) = children
            .next()
            .await
            .map_err(|err| ExactSelectionError::internal("reading file metadata tree", err))?
        {
            if child.is_staged_delete() || child.is_discarded() {
                continue;
            }
            let path = if parent_path.is_empty() {
                name.freeze()
            } else {
                format!("{parent_path}/{}", name.freeze())
            };
            if child.is_file() {
                let metadata_node = node::node_to_file_metadata(child_id);
                let block = state
                    .block_file_metadata(
                        repository.clone(),
                        NodeFileMetadataBlock::index(metadata_node),
                    )
                    .await
                    .map_err(|err| {
                        ExactSelectionError::internal("reading file metadata block", err)
                    })?;
                let hash = block
                    .read()
                    .node(NodeFileMetadata::index(metadata_node))
                    .metadata;
                result.insert(path, hash);
            } else if child.is_directory() {
                directories.push_back((path, child_id));
            }
        }
    }
    Ok(result)
}

async fn set_file_metadata_hash(
    repository: Arc<RepositoryContext>,
    state: Arc<State>,
    path: &str,
    hash: Hash,
) -> Result<(), ExactSelectionError> {
    let link = state
        .find_node_link(repository.clone(), path)
        .await
        .map_err(|err| ExactSelectionError::internal("finding staged metadata node", err))?;
    if !link.is_valid() {
        return Err(ExactSelectionError::new(
            ExactSelectionErrorKind::UnselectedFileMetadata {
                paths: vec![path.to_string()],
            },
        ));
    }
    if link.repository != repository.id {
        return Err(ExactSelectionError::new(
            ExactSelectionErrorKind::UnsupportedTopology {
                reason: format!("selected path {path} resolves through a link"),
            },
        ));
    }
    let metadata_node = node::node_to_file_metadata(link.node);
    let block_index = NodeFileMetadataBlock::index(metadata_node);
    let block = state
        .block_file_metadata(repository, block_index)
        .await
        .map_err(|err| ExactSelectionError::internal("reading staged metadata block", err))?;
    let dirtied = {
        let mut writer = block.write();
        let node = writer.node(NodeFileMetadata::index(metadata_node));
        if node.metadata == hash {
            false
        } else {
            node.metadata = hash;
            writer.mark_dirty()
        }
    };
    if dirtied {
        state.block_file_metadata_modified(block, block_index);
        state.mark_dirty();
    }
    Ok(())
}

async fn serialize_exact_metadata(
    repository: Arc<RepositoryContext>,
    entries: &[PreparedMetadataEntry],
) -> Result<Hash, ExactSelectionError> {
    let mut metadata = Metadata::new();
    for entry in entries {
        match &entry.value {
            PreparedMetadataValue::String(value) => metadata
                .set_string(&entry.key, value)
                .map_err(|err| ExactSelectionError::internal("setting string metadata", err))?,
            PreparedMetadataValue::Numeric(value) => metadata
                .set_u64(&entry.key, *value)
                .map_err(|err| ExactSelectionError::internal("setting numeric metadata", err))?,
            PreparedMetadataValue::Binary(payload) => {
                let address = immutable::write(
                    repository.clone(),
                    crate::lore::Context::default(),
                    payload.clone(),
                    immutable::write_options_from_repository(repository.clone()),
                )
                .await
                .map_err(|err| ExactSelectionError::internal("writing binary metadata", err))?;
                metadata
                    .set_address(&entry.key, address)
                    .map_err(|err| ExactSelectionError::internal("setting binary metadata", err))?;
            }
        }
    }
    metadata
        .serialize(repository)
        .await
        .map_err(|err| ExactSelectionError::internal("serializing exact file metadata", err))
}

#[lore_macro::test_pub]
fn compare_action_sets(
    expected: &[ExactActionRow],
    actual: &[ExactActionRow],
) -> (
    Vec<ExactActionRow>,
    Vec<ExactActionRow>,
    Vec<ExactActionMismatch>,
) {
    let expected_map: BTreeMap<_, _> = expected
        .iter()
        .map(|row| (row.path.clone(), row.action))
        .collect();
    let actual_map: BTreeMap<_, _> = actual
        .iter()
        .map(|row| (row.path.clone(), row.action))
        .collect();
    let missing = expected_map
        .iter()
        .filter(|(path, _)| !actual_map.contains_key(*path))
        .map(|(path, action)| ExactActionRow {
            path: path.clone(),
            action: *action,
        })
        .collect();
    let extras = actual_map
        .iter()
        .filter(|(path, _)| !expected_map.contains_key(*path))
        .map(|(path, action)| ExactActionRow {
            path: path.clone(),
            action: *action,
        })
        .collect();
    let action_mismatches = expected_map
        .iter()
        .filter_map(|(path, expected_action)| {
            actual_map.get(path).and_then(|actual_action| {
                (*actual_action != *expected_action).then(|| ExactActionMismatch {
                    path: path.clone(),
                    expected: *expected_action,
                    actual: *actual_action,
                })
            })
        })
        .collect();
    (missing, extras, action_mismatches)
}

#[derive(Clone, Copy)]
#[lore_macro::test_pub]
enum ActionAuthority {
    Generated,
    Semantic,
}

#[lore_macro::test_pub]
fn validate_action_membership(
    expected: &[ExactActionRow],
    actual: &[ExactActionRow],
    authority: ActionAuthority,
) -> Result<(), ExactSelectionError> {
    let (missing, extras, action_mismatches) = compare_action_sets(expected, actual);
    if missing.is_empty() && extras.is_empty() && action_mismatches.is_empty() {
        return Ok(());
    }
    let kind = match authority {
        ActionAuthority::Generated => ExactSelectionErrorKind::GeneratedSelectionMismatch {
            expected: expected.to_vec(),
            actual: actual.to_vec(),
            missing,
            extras,
            action_mismatches,
        },
        ActionAuthority::Semantic => ExactSelectionErrorKind::SemanticSelectionMismatch {
            expected: expected.to_vec(),
            actual: actual.to_vec(),
            missing,
            extras,
            action_mismatches,
        },
    };
    Err(ExactSelectionError::new(kind))
}

#[lore_macro::test_pub]
async fn map_immutable_read<F>(path: &str, read: F) -> Result<Bytes, ExactSelectionError>
where
    F: Future<Output = Result<Bytes, String>>,
{
    read.await.map_err(|reason| {
        ExactSelectionError::new(ExactSelectionErrorKind::MissingImmutableContent {
            path: path.to_string(),
            reason,
        })
    })
}

fn semantic_node_equal(left: &Node, right: &Node) -> bool {
    left.is_file() == right.is_file()
        && left.is_link() == right.is_link()
        && left.mode == right.mode
        && left.address == right.address
        && left.size == right.size
}

#[lore_macro::test_pub]
fn validate_metadata_membership(
    selected: &[NormalizedSelectedFile],
    expected_metadata: &BTreeMap<String, Hash>,
    current_metadata: &BTreeMap<String, Hash>,
    staged_metadata: &BTreeMap<String, Hash>,
) -> Result<Vec<ExactFileMetadataHash>, ExactSelectionError> {
    let selected_paths: BTreeSet<_> = selected.iter().map(|file| &file.row.path).collect();
    let metadata_paths: BTreeSet<_> = current_metadata
        .keys()
        .chain(staged_metadata.keys())
        .cloned()
        .collect();
    let unselected_metadata: Vec<_> = metadata_paths
        .into_iter()
        .filter(|path| {
            current_metadata.get(path).copied().unwrap_or_default()
                != staged_metadata.get(path).copied().unwrap_or_default()
                && !selected_paths.contains(path)
        })
        .collect();
    if !unselected_metadata.is_empty() {
        return Err(ExactSelectionError::new(
            ExactSelectionErrorKind::UnselectedFileMetadata {
                paths: unselected_metadata,
            },
        ));
    }

    let mut mismatches = Vec::new();
    let mut committed = Vec::new();
    for (path, expected_hash) in expected_metadata {
        let is_delete = selected
            .binary_search_by(|file| file.row.path.as_str().cmp(path.as_str()))
            .is_ok_and(|index| selected[index].row.action == ExpectedFileAction::Delete);
        let actual = if is_delete {
            current_metadata.get(path)
        } else {
            staged_metadata.get(path)
        }
        .copied()
        .unwrap_or_default();
        if actual != *expected_hash {
            mismatches.push(ExactMetadataMismatch {
                path: path.clone(),
                expected_hash: expected_hash.to_string(),
                staged_hash: actual.to_string(),
            });
        }
        committed.push(ExactFileMetadataHash {
            path: path.clone(),
            hash: expected_hash.to_string(),
        });
    }
    if !mismatches.is_empty() {
        return Err(ExactSelectionError::new(
            ExactSelectionErrorKind::StagedMetadataHashMismatch { mismatches },
        ));
    }
    Ok(committed)
}

#[derive(Clone)]
pub(crate) struct ExactSelectionAdmission {
    selected: Arc<Vec<NormalizedSelectedFile>>,
    expected_metadata: Arc<BTreeMap<String, Hash>>,
    result: Arc<Mutex<Option<Result<ExactSelectionResult, ExactSelectionError>>>>,
}

impl ExactSelectionAdmission {
    fn new(
        selected: Vec<NormalizedSelectedFile>,
        expected_metadata: BTreeMap<String, Hash>,
    ) -> Self {
        debug_assert!(
            selected
                .windows(2)
                .all(|pair| pair[0].row.path < pair[1].row.path),
            "normalized exact selection must remain sorted by path"
        );
        Self {
            selected: Arc::new(selected),
            expected_metadata: Arc::new(expected_metadata),
            result: Arc::new(Mutex::new(None)),
        }
    }

    pub(crate) fn store(&self, result: Result<ExactSelectionResult, ExactSelectionError>) {
        *self.result.lock().unwrap_or_else(PoisonError::into_inner) = Some(result);
    }

    pub(crate) fn requires_content(&self, path: &str) -> bool {
        self.selected
            .binary_search_by(|file| file.row.path.as_str().cmp(path))
            .is_ok_and(|index| self.selected[index].row.action != ExpectedFileAction::Delete)
    }

    pub(crate) fn store_pre_fragmentation_read_failure(
        &self,
        path: &str,
        reason: impl fmt::Display,
    ) {
        let candidate =
            ExactSelectionError::new(ExactSelectionErrorKind::PreFragmentationFileRead {
                path: path.to_string(),
                reason: reason.to_string(),
            });
        let mut result = self.result.lock().unwrap_or_else(PoisonError::into_inner);
        let replace = match result.as_ref().map(Result::as_ref) {
            Some(Err(existing)) => match existing.kind() {
                ExactSelectionErrorKind::PreFragmentationFileRead {
                    path: existing_path,
                    ..
                } => existing_path.as_str() > path,
                _ => true,
            },
            _ => true,
        };
        if replace {
            *result = Some(Err(candidate));
        }
    }

    fn take(&self) -> Option<Result<ExactSelectionResult, ExactSelectionError>> {
        self.result
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    pub(crate) async fn validate(
        &self,
        repository: Arc<RepositoryContext>,
        state_current: Arc<State>,
        state_staged: Arc<State>,
        node_paths: &BTreeMap<NodeID, String>,
    ) -> Result<(), ExactSelectionError> {
        let delta = state_staged
            .delta_block(repository.clone())
            .await
            .map_err(|err| ExactSelectionError::internal("reading generated delta", err))?;
        let mut generated = Vec::new();
        for item in delta
            .to_aligned::<crate::node::NodeDelta>()
            .as_type_slice::<crate::node::NodeDelta>()
        {
            let Some(path) = node_paths.get(&item.node) else {
                continue;
            };
            let action = match item.action {
                value if value == FileAction::Add as u16 => ExpectedFileAction::Add,
                value if value == FileAction::Delete as u16 => ExpectedFileAction::Delete,
                value if value == FileAction::Keep as u16 => ExpectedFileAction::Modify,
                _ => {
                    return Err(ExactSelectionError::new(
                        ExactSelectionErrorKind::UnsupportedTopology {
                            reason: format!("generated non-v1 action for {path}"),
                        },
                    ));
                }
            };
            generated.push(ExactActionRow {
                path: path.clone(),
                action,
            });
        }
        generated.sort();
        generated.dedup();
        let expected: Vec<_> = self.selected.iter().map(|file| file.row.clone()).collect();
        validate_action_membership(&expected, &generated, ActionAuthority::Generated)?;

        let mut effective = Vec::new();
        for row in &generated {
            match row.action {
                ExpectedFileAction::Add | ExpectedFileAction::Delete => effective.push(row.clone()),
                ExpectedFileAction::Modify => {
                    let staged_link = state_staged
                        .find_node_link(repository.clone(), &row.path)
                        .await
                        .map_err(|err| ExactSelectionError::internal("finding staged node", err))?;
                    let current_link = state_current
                        .find_node_link(repository.clone(), &row.path)
                        .await
                        .map_err(|err| {
                            ExactSelectionError::internal("finding current node", err)
                        })?;
                    if !staged_link.is_valid() || !current_link.is_valid() {
                        continue;
                    }
                    let staged_node = state_staged
                        .node(repository.clone(), staged_link.node)
                        .await
                        .map_err(|err| ExactSelectionError::internal("reading staged node", err))?;
                    let current_node = state_current
                        .node(repository.clone(), current_link.node)
                        .await
                        .map_err(|err| {
                            ExactSelectionError::internal("reading current node", err)
                        })?;
                    if !semantic_node_equal(&staged_node, &current_node) {
                        effective.push(row.clone());
                    }
                }
            }
        }
        validate_action_membership(&expected, &effective, ActionAuthority::Semantic)?;

        let current_metadata =
            collect_live_file_metadata(repository.clone(), state_current.clone()).await?;
        let staged_metadata =
            collect_live_file_metadata(repository.clone(), state_staged.clone()).await?;
        let committed_file_metadata_hashes = validate_metadata_membership(
            &self.selected,
            &self.expected_metadata,
            &current_metadata,
            &staged_metadata,
        )?;

        let mut source_mismatches = Vec::new();
        for selected in self.selected.iter() {
            if selected.row.action == ExpectedFileAction::Delete {
                continue;
            }
            let link = match state_staged
                .find_node_link(repository.clone(), &selected.row.path)
                .await
            {
                Ok(link) => link,
                Err(state::StateError::NodeNotFound(_)) => {
                    return Err(ExactSelectionError::new(
                        ExactSelectionErrorKind::MissingImmutableContent {
                            path: selected.row.path.clone(),
                            reason: "staged node is absent".into(),
                        },
                    ));
                }
                Err(err) => {
                    return Err(ExactSelectionError::internal(
                        "finding immutable content node",
                        err,
                    ));
                }
            };
            if !link.is_valid() {
                return Err(ExactSelectionError::new(
                    ExactSelectionErrorKind::MissingImmutableContent {
                        path: selected.row.path.clone(),
                        reason: "staged node is absent".into(),
                    },
                ));
            }
            let node = state_staged
                .node(repository.clone(), link.node)
                .await
                .map_err(|err| {
                    ExactSelectionError::internal("reading immutable content node", err)
                })?;
            let payload = map_immutable_read(&selected.row.path, async {
                immutable::read(
                    repository.clone(),
                    node.address,
                    None,
                    immutable::read_options_from_repository(&repository).with_cache(),
                )
                .await
                .map_err(|err| err.to_string())
            })
            .await?;
            let actual = hex::encode(Md5::digest(&payload));
            let expected_hash = selected.source_hash.as_deref().unwrap_or_default();
            if actual != expected_hash {
                source_mismatches.push(ExactSourceHashMismatch {
                    path: selected.row.path.clone(),
                    expected: expected_hash.to_string(),
                    actual,
                });
            }
        }
        if !source_mismatches.is_empty() {
            return Err(ExactSelectionError::new(
                ExactSelectionErrorKind::SourceHashMismatch {
                    mismatches: source_mismatches,
                },
            ));
        }

        self.store(Ok(ExactSelectionResult {
            revision: Hash::default(),
            generated_actions: generated,
            effective_actions: effective,
            committed_file_metadata_hashes,
        }));
        Ok(())
    }
}

pub(crate) async fn admission_node_paths(
    repository: Arc<RepositoryContext>,
    state_current: Arc<State>,
    state_staged: Arc<State>,
) -> Result<BTreeMap<NodeID, String>, ExactSelectionError> {
    let changes = state::diff_collect(
        repository.clone(),
        state_current,
        repository,
        state_staged,
        None,
        crate::filter::FilterMode::Full,
    )
    .await
    .map_err(|err| ExactSelectionError::internal("collecting exact staged changes", err))?;
    let mut paths = BTreeMap::new();
    for change in changes {
        if change
            .is_directory()
            .await
            .map_err(|err| ExactSelectionError::internal("classifying exact staged change", err))?
        {
            continue;
        }
        if change.from.mapping.node.is_valid_node_id() {
            let path = change
                .move_source()
                .unwrap_or(change.path())
                .as_str()
                .to_string();
            paths.insert(change.from.mapping.node, path);
        }
        if change.to.mapping.node.is_valid_node_id() {
            paths.insert(change.to.mapping.node, change.path().as_str().to_string());
        }
    }
    Ok(paths)
}

/// Executes one exact-selection transaction under a caller-owned CLIENT token.
pub async fn commit_exact_selection(
    repository: Arc<RepositoryContext>,
    token: &RepositoryWriteToken,
    options: ExactSelectionOptions,
) -> Result<ExactSelectionResult, ExactSelectionError> {
    if matches!(token, RepositoryWriteToken::Server) {
        return Err(ExactSelectionError::new(
            ExactSelectionErrorKind::UnsupportedTopology {
                reason: "exact-selection v1 requires RepositoryWriteToken::Client".into(),
            },
        ));
    }
    let repository_root = repository
        .require_path()
        .map_err(|err| ExactSelectionError::internal("resolving repository root", err))?
        .to_path_buf();
    validate_input_bounds(&options.message, &options.files, &options.revision_metadata)?;
    let selected = normalize_selected_files(&repository_root, options.files).await?;
    validate_revision_metadata(&options.revision_metadata)?;

    let layers = crate::layer::list(repository.clone())
        .await
        .map_err(|err| ExactSelectionError::internal("inspecting repository layers", err))?;
    if !layers.is_empty() {
        return Err(ExactSelectionError::new(
            ExactSelectionErrorKind::UnsupportedTopology {
                reason: "repositories with configured layers are excluded from v1".into(),
            },
        ));
    }

    let (current_revision, current_branch) = crate::instance::load_current_anchor(&repository)
        .await
        .map_err(|err| ExactSelectionError::internal("loading current anchor", err))?;
    let branch_latest = crate::branch::load_latest(repository.clone(), current_branch)
        .await
        .map_err(|err| ExactSelectionError::internal("loading branch latest", err))?;
    if !branch_latest.is_zero() && branch_latest != current_revision {
        return Err(ExactSelectionError::new(
            ExactSelectionErrorKind::StagedRepairFailure {
                reason: "branch latest advanced beyond current".into(),
            },
        ));
    }

    let state_current = State::deserialize(repository.clone(), current_revision)
        .await
        .map_err(|err| ExactSelectionError::internal("deserializing current state", err))?;
    let links = state_current
        .link_list(repository.clone())
        .await
        .map_err(|err| ExactSelectionError::internal("inspecting repository links", err))?;
    if !links.is_empty() {
        return Err(ExactSelectionError::new(
            ExactSelectionErrorKind::UnsupportedTopology {
                reason: "repositories with links are excluded from v1".into(),
            },
        ));
    }
    let original_staged_revision = crate::instance::load_staged_revision(&repository)
        .await
        .map_err(|err| ExactSelectionError::internal("loading staged anchor", err))?;
    let state_original = match original_staged_revision {
        Some(revision) => State::deserialize(repository.clone(), revision)
            .await
            .map_err(|err| ExactSelectionError::internal("deserializing staged state", err))?,
        None => state_current.clone(),
    };
    if state_original.is_merge_or_cherry_pick_or_revert() {
        return Err(ExactSelectionError::new(
            ExactSelectionErrorKind::UnsupportedTopology {
                reason: "merge, cherry-pick, and revert topology is excluded from v1".into(),
            },
        ));
    }

    let mut inherited_metadata = BTreeMap::new();
    for file in &selected {
        let hash = file_metadata_hash(repository.clone(), state_current.clone(), &file.row.path)
            .await?
            .unwrap_or_default();
        inherited_metadata.insert(file.row.path.clone(), hash);
    }

    // Start from current, not the published staged state. This repairs every unrelated
    // staged content and metadata row without ever publishing an intermediate anchor.
    let state_staged = State::deserialize(repository.clone(), current_revision)
        .await
        .map_err(|err| {
            ExactSelectionError::new(ExactSelectionErrorKind::StagedRepairFailure {
                reason: err.to_string(),
            })
        })?;
    let absolute_paths = selected
        .iter()
        .map(|file| LoreString::from_path(repository_root.join(&file.row.path)))
        .collect();
    // Exact selection must not trust the size+mtime fast path. Clear the local
    // witness for selected content so staging re-hashes same-size files even when
    // their timestamp was restored to the cached value.
    for file in &selected {
        if file.row.action != ExpectedFileAction::Delete {
            let path = RelativePath::new_from_initial_path(&file.row.path).map_err(|err| {
                ExactSelectionError::internal("clearing the selected file witness", err)
            })?;
            state::file_modified_time_clear(repository.clone(), &path).await;
        }
    }
    stage_state(
        repository.clone(),
        token,
        LoreArray::from_vec(absolute_paths),
        StageOptions {
            case_change: StageCaseChange::Rename,
            ..Default::default()
        },
        state_current.clone(),
        state_staged.clone(),
        current_revision,
        false,
    )
    .await
    .map_err(|err| ExactSelectionError::internal("staging exact selection", err))?;

    #[cfg(feature = "test-util")]
    let _ = AFTER_EXACT_STAGE.try_with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });

    // Even an empty/restored-to-base staging pass must enter admission with the
    // current revision as its parent. A freshly deserialized current state still
    // names its own historical parent, which the ordinary commit path correctly
    // rejects as stale but which would hide the exact-selection semantic mismatch.
    state_staged.set_revision_number(0);
    state_staged.set_parent_self(current_revision);
    state_staged.set_parent_other(Hash::default());
    state_staged.set_metadata_hash(Hash::default());

    let mut expected_metadata = BTreeMap::new();
    for file in &selected {
        let hash = match &file.file_metadata {
            FileMetadataSelection::Unchanged => inherited_metadata
                .get(&file.row.path)
                .copied()
                .ok_or_else(|| {
                    ExactSelectionError::internal(
                        "reading inherited file metadata",
                        format!("missing normalized path {}", file.row.path),
                    )
                })?,
            FileMetadataSelection::Exact(_) => {
                serialize_exact_metadata(repository.clone(), &file.prepared_metadata).await?
            }
            FileMetadataSelection::Clear => Hash::default(),
        };
        if file.row.action != ExpectedFileAction::Delete {
            set_file_metadata_hash(
                repository.clone(),
                state_staged.clone(),
                &file.row.path,
                hash,
            )
            .await?;
            expected_metadata.insert(file.row.path.clone(), hash);
        } else {
            // A delete has no staged file node. Its prior metadata remains historical and
            // may be found through Lore's parent fallback; it is not a live metadata action.
            expected_metadata.insert(file.row.path.clone(), hash);
        }
    }

    let keys = options
        .revision_metadata
        .iter()
        .map(|entry| LoreString::from_str(&entry.key))
        .collect();
    let values = options
        .revision_metadata
        .iter()
        .map(|entry| LoreString::from_str(&entry.value))
        .collect();
    let formats = options
        .revision_metadata
        .iter()
        .map(|entry| match entry.value_type {
            ExactMetadataType::String => LoreMetadataType::String,
            ExactMetadataType::Numeric => LoreMetadataType::Numeric,
            ExactMetadataType::Binary => LoreMetadataType::Binary,
        })
        .collect();
    let metadata = commit::build_commit_metadata(
        repository.clone(),
        &state_staged,
        current_branch,
        options.message.clone(),
        LoreArray::from_vec(keys),
        LoreArray::from_vec(values),
        LoreArray::from_vec(formats),
    )
    .await
    .map_err(|err| ExactSelectionError::internal("building revision metadata", err))?;

    let admission = ExactSelectionAdmission::new(selected, expected_metadata);
    // Held to the end of the call, as `commit()` holds its own: the statistics
    // event reads the fragment counters, which settle only once the commit has
    // drained its background writes.
    let reporting = commit::CommitReporting::from_globals().with_call_stats(options.stats);
    let _stats_report = reporting.report();
    // The commit reads the working tree through one filesystem operation, opened and finalized
    // around it the way commit() does (upstream v0.10.1 routes working-tree reads through the
    // filesystem provider).
    let committed = with_operation(repository.file_system(), async |operation| {
        commit::commit_staged_revision(
            &operation,
            repository.clone(),
            token.share(),
            state_current.clone(),
            state_staged.clone(),
            RelativePath::new(),
            crate::node::ROOT_NODE,
            metadata.clone(),
            Arc::new(HashMap::new()),
            current_branch,
            reporting,
            Some(admission.clone()),
        )
        .await
    })
    .await;
    let (signature, modified_times) = match committed {
        Ok(committed) => committed,
        Err(err) => {
            if let Some(Err(exact)) = admission.take() {
                return Err(exact);
            }
            return Err(ExactSelectionError::internal(
                "committing exact selection",
                err,
            ));
        }
    };

    let mut result = admission
        .take()
        .ok_or_else(|| ExactSelectionError::internal("exact admission", "missing result"))??;
    result.revision = signature;

    commit::finalize_exact_commit(
        repository.clone(),
        &state_staged,
        signature,
        current_branch,
        commit::ExactAnchorSnapshot {
            branch_latest,
            current: current_revision,
            staged: original_staged_revision.unwrap_or_default(),
        },
    )
    .await
    .map_err(map_exact_finalize_error)?;

    // This path composes commit's pieces directly instead of going through
    // `commit()`, so the modified-time cache that `commit()` writes has to be
    // written here too; otherwise the next stage re-hashes every file this
    // commit already read. Stored after finalize, as `commit()` orders it, so a
    // revision that failed to finalize records nothing.
    modified_times.store(repository.clone()).await;

    crate::event::metadata::send(&metadata);
    Ok(result)
}

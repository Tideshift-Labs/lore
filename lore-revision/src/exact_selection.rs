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

const MAX_SELECTED_FILES: usize = 100_000;
const MAX_REPOSITORY_RELATIVE_PATH_BYTES: usize = 4_096;
const MAX_METADATA_ENTRIES_PER_SCOPE: usize = 1_024;
const MAX_METADATA_KEY_BYTES: usize = 1_024;
const MAX_METADATA_VALUE_BYTES: usize = 4 * 1_024 * 1_024;
const MAX_BINARY_METADATA_PAYLOAD_BYTES: u64 = 64 * 1_024 * 1_024;
const MAX_AGGREGATE_INPUT_BYTES: usize = 64 * 1_024 * 1_024;

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
struct PreparedMetadataEntry {
    key: String,
    value: PreparedMetadataValue,
}

#[derive(Clone)]
enum PreparedMetadataValue {
    String(String),
    Numeric(u64),
    Binary(Bytes),
}

#[derive(Clone)]
struct NormalizedSelectedFile {
    row: ExactActionRow,
    source_hash: Option<String>,
    file_metadata: FileMetadataSelection,
    prepared_metadata: Vec<PreparedMetadataEntry>,
}

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
                        let parsed = entry.value.parse::<u64>().map_err(|_| {
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
                name.freeze().to_string()
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
enum ActionAuthority {
    Generated,
    Semantic,
}

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
        if change.from.node.is_valid_node_id() {
            let path = change
                .from_path
                .as_ref()
                .unwrap_or(&change.path)
                .as_str()
                .to_string();
            paths.insert(change.from.node, path);
        }
        if change.to.node.is_valid_node_id() {
            paths.insert(change.to.node, change.path.as_str().to_string());
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
            state::file_modified_time_clear(repository.clone(), &file.row.path).await;
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
    let signature = commit::commit_staged_revision(
        repository.clone(),
        token.share(),
        state_current.clone(),
        state_staged.clone(),
        metadata.clone(),
        None,
        Arc::new(HashMap::new()),
        current_branch,
        options.stats,
        Some(admission.clone()),
    )
    .await;
    let signature = match signature {
        Ok(signature) => signature,
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
    crate::event::metadata::send(&metadata);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::sync::Mutex;

    use async_trait::async_trait;
    use lore_base::error::NoRemote;
    use lore_base::runtime::LORE_CONTEXT;
    use lore_base::types::Partition;
    use lore_storage::LocalMutableStore;
    use lore_storage::MutableStore;
    use lore_storage::MutableStoreSettings;
    use lore_storage::StoreError;
    use lore_storage::store_types::KeyType;
    use lore_storage::store_types::KeyValueStream;
    use lore_transport::ProtocolError;

    use super::*;
    use crate::branch;
    use crate::interface::ExecutionContext;
    use crate::interface::LoreGlobalArgs;
    use crate::lore::BranchId;
    use crate::lore::RepositoryId;
    use crate::relay::EventDispatcher;
    use crate::repository::RepositoryContextCreationArgs;
    use crate::repository::RepositoryFormat;

    #[derive(Clone, Copy, Debug, PartialEq)]
    struct StoreCall {
        partition: Partition,
        key: Hash,
        value: Hash,
        key_type: KeyType,
        injected_failure: bool,
    }

    #[derive(Default)]
    struct FaultState {
        fail_calls: BTreeSet<usize>,
        calls: Vec<StoreCall>,
    }

    #[derive(Clone, Default)]
    struct StoreFaultControl {
        state: Arc<Mutex<FaultState>>,
    }

    impl StoreFaultControl {
        fn arm(&self, fail_calls: impl IntoIterator<Item = usize>) {
            let mut state = self.state.lock().expect("lock mutable-store fault state");
            state.fail_calls = fail_calls.into_iter().collect();
            state.calls.clear();
        }

        fn observe_store(
            &self,
            partition: Partition,
            key: Hash,
            value: Hash,
            key_type: KeyType,
        ) -> bool {
            let mut state = self.state.lock().expect("lock mutable-store fault state");
            let call_number = state.calls.len() + 1;
            let injected_failure = state.fail_calls.contains(&call_number);
            state.calls.push(StoreCall {
                partition,
                key,
                value,
                key_type,
                injected_failure,
            });
            injected_failure
        }

        fn calls(&self) -> Vec<StoreCall> {
            self.state
                .lock()
                .expect("read mutable-store fault calls")
                .calls
                .clone()
        }
    }

    struct FaultInjectingMutableStore {
        inner: Arc<LocalMutableStore>,
        control: StoreFaultControl,
    }

    #[async_trait]
    impl MutableStore for FaultInjectingMutableStore {
        async fn load(
            self: Arc<Self>,
            partition: Partition,
            key: Hash,
            key_type: KeyType,
        ) -> Result<Hash, StoreError> {
            self.inner.clone().load(partition, key, key_type).await
        }

        async fn store(
            self: Arc<Self>,
            partition: Partition,
            key: Hash,
            value: Hash,
            key_type: KeyType,
        ) -> Result<(), StoreError> {
            if self.control.observe_store(partition, key, value, key_type) {
                return Err(StoreError::internal(format!(
                    "injected real mutable-store call {}",
                    self.control.calls().len()
                )));
            }
            self.inner
                .clone()
                .store(partition, key, value, key_type)
                .await
        }

        async fn compare_and_swap(
            self: Arc<Self>,
            partition: Partition,
            key: Hash,
            expected: Hash,
            value: Hash,
            key_type: KeyType,
        ) -> Result<Hash, StoreError> {
            self.inner
                .clone()
                .compare_and_swap(partition, key, expected, value, key_type)
                .await
        }

        async fn list(
            self: Arc<Self>,
            partition: Partition,
            key_type: KeyType,
        ) -> Result<KeyValueStream, StoreError> {
            self.inner.clone().list(partition, key_type).await
        }

        async fn flush(self: Arc<Self>, sync_data: bool) -> Result<(), StoreError> {
            self.inner.clone().flush(sync_data).await
        }
    }

    #[derive(Debug)]
    struct DurableAnchorEvidence {
        original: commit::ExactAnchorSnapshot,
        published: commit::ExactAnchorSnapshot,
        reopened: commit::ExactAnchorSnapshot,
        calls: Vec<StoreCall>,
        public_error: ExactSelectionError,
    }

    async fn exercise_real_store_publication_failure(
        fail_calls: impl IntoIterator<Item = usize>,
    ) -> DurableAnchorEvidence {
        let tempdir = tempfile::tempdir().expect("create real mutable-store fixture");
        let store_path = tempdir.path().join("store");
        let repository_path = tempdir.path().join("repository");
        std::fs::create_dir_all(&repository_path).expect("create repository fixture path");

        let immutable = lore_storage::LocalImmutableStore::new(
            Some(store_path.clone()),
            lore_storage::ImmutableStoreSettings::default(),
        )
        .await
        .expect("create disk-backed immutable store");
        let real_mutable = Arc::new(
            LocalMutableStore::new(
                Some(&store_path),
                MutableStoreSettings::default(),
                immutable.clone(),
            )
            .await
            .expect("create disk-backed mutable store"),
        );
        let control = StoreFaultControl::default();
        let faulting_mutable = Arc::new(FaultInjectingMutableStore {
            inner: real_mutable,
            control: control.clone(),
        });

        let repository_id = RepositoryId::from(uuid::Uuid::now_v7());
        let instance_id = crate::instance::InstanceId::generate();
        let branch = BranchId::from(uuid::Uuid::now_v7());
        let token = RepositoryWriteToken::acquire(&repository_path).await;
        let repository = Arc::new(
            RepositoryContext::new(RepositoryContextCreationArgs {
                path: Some(repository_path.clone()),
                immutable_store: immutable.clone(),
                mutable_store: faulting_mutable.clone(),
                id: repository_id,
                instance_id,
                remote: Err(ProtocolError::from(NoRemote)),
                filter: Arc::default(),
                format: RepositoryFormat::Lore,
                filesystem_provider: None,
            })
            .with_write_token(token),
        );

        let original = commit::ExactAnchorSnapshot {
            branch_latest: Hash::from([1_u8; 32]),
            current: Hash::from([2_u8; 32]),
            staged: Hash::from([3_u8; 32]),
        };
        let published = commit::ExactAnchorSnapshot {
            branch_latest: Hash::from([4_u8; 32]),
            current: Hash::from([4_u8; 32]),
            staged: Hash::default(),
        };

        branch::store_latest_anchor(repository.clone(), branch, original.branch_latest)
            .await
            .expect("seed branch-latest anchor");
        crate::instance::store_current_anchor(&repository, original.current)
            .await
            .expect("seed current anchor");
        crate::instance::store_current_anchor_branch(&repository, branch)
            .await
            .expect("seed current branch anchor");
        crate::instance::store_staged_anchor(&repository, original.staged)
            .await
            .expect("seed staged anchor");
        faulting_mutable
            .clone()
            .flush(true)
            .await
            .expect("persist original anchors");

        let staged_state = Arc::new(State::new());
        staged_state
            .tree(repository.clone())
            .await
            .expect("initialize empty staged tree");
        control.arm(fail_calls);

        let internal_error = commit::finalize_exact_commit(
            repository.clone(),
            &staged_state,
            published.current,
            branch,
            original,
        )
        .await
        .expect_err("injected authoritative publication must reject");
        let public_error = map_exact_finalize_error(internal_error);
        let calls = control.calls();

        faulting_mutable
            .clone()
            .flush(true)
            .await
            .expect("persist post-compensation anchors");
        drop(staged_state);
        drop(repository);
        drop(faulting_mutable);

        let reopened_mutable = Arc::new(
            LocalMutableStore::new(
                Some(&store_path),
                MutableStoreSettings::default(),
                immutable.clone(),
            )
            .await
            .expect("reopen disk-backed mutable store"),
        );
        let reopened_repository = Arc::new(RepositoryContext::new(RepositoryContextCreationArgs {
            path: Some(repository_path),
            immutable_store: immutable,
            mutable_store: reopened_mutable,
            id: repository_id,
            instance_id,
            remote: Err(ProtocolError::from(NoRemote)),
            filter: Arc::default(),
            format: RepositoryFormat::Lore,
            filesystem_provider: None,
        }));
        let reopened = commit::ExactAnchorSnapshot {
            branch_latest: branch::load_latest(reopened_repository.clone(), branch)
                .await
                .expect("reload durable branch-latest anchor"),
            current: crate::instance::load_current_anchor(&reopened_repository)
                .await
                .expect("reload durable current anchor")
                .0,
            staged: crate::instance::load_staged_revision(&reopened_repository)
                .await
                .expect("reload durable staged anchor")
                .unwrap_or_default(),
        };

        DurableAnchorEvidence {
            original,
            published,
            reopened,
            calls,
            public_error,
        }
    }

    fn selected_input(path: String) -> SelectedFile {
        SelectedFile {
            path,
            expected_effective_action: ExpectedFileAction::Delete,
            source_hash: None,
            file_metadata: FileMetadataSelection::Unchanged,
        }
    }

    fn metadata_input(key: String, value: String) -> FileMetadataEntry {
        FileMetadataEntry {
            key,
            value,
            value_type: ExactMetadataType::String,
        }
    }

    fn assert_invalid_input(error: ExactSelectionError, reason: &str) {
        assert!(
            matches!(
                error.kind(),
                ExactSelectionErrorKind::InvalidInput { reason: actual, .. }
                    if actual.contains(reason)
            ),
            "unexpected bounds error: {error:?}"
        );
    }

    fn action(path: &str, action: ExpectedFileAction) -> ExactActionRow {
        ExactActionRow {
            path: path.to_string(),
            action,
        }
    }

    fn normalized(path: &str, expected_action: ExpectedFileAction) -> NormalizedSelectedFile {
        NormalizedSelectedFile {
            row: action(path, expected_action),
            source_hash: None,
            file_metadata: FileMetadataSelection::Unchanged,
            prepared_metadata: Vec::new(),
        }
    }

    #[test]
    fn finalize_publication_failure_maps_public_kind_json_and_internal_code() {
        for anchors_restored in [true, false] {
            let reason = format!("injected anchors_restored={anchors_restored}");
            let error = map_exact_finalize_error(commit::ExactFinalizeError::Publication {
                anchors_restored,
                reason: reason.clone(),
            });

            assert_eq!(
                error.kind(),
                &ExactSelectionErrorKind::PublicationFailure {
                    anchors_restored,
                    reason: reason.clone(),
                }
            );
            assert_eq!(error.code(), LoreError::Internal as i32);
            assert_eq!(
                serde_json::to_value(error.kind()).expect("serialize public exact error kind"),
                serde_json::json!({
                    "kind": "publicationFailure",
                    "anchorsRestored": anchors_restored,
                    "reason": reason,
                })
            );
        }
    }

    #[tokio::test]
    async fn real_store_one_shot_publication_failure_restores_durable_anchors() {
        LORE_CONTEXT
            .scope(
                Arc::new(ExecutionContext::new_client_with_user_id(
                    LoreGlobalArgs::default().set_offline(),
                    EventDispatcher::no_dispatch(),
                    "exact-real-store-restore-test".to_string(),
                )),
                async {
                    let evidence = exercise_real_store_publication_failure([2]).await;

                    assert!(
                        matches!(
                            evidence.public_error.kind(),
                            ExactSelectionErrorKind::PublicationFailure {
                                anchors_restored: true,
                                reason,
                            } if reason.contains("injected real mutable-store call 2")
                        ),
                        "one-shot real-store failure must report truthful recovery: {:?}",
                        evidence.public_error
                    );
                    assert_eq!(evidence.reopened, evidence.original);
                    assert_eq!(
                        evidence
                            .calls
                            .iter()
                            .map(|call| (call.value, call.injected_failure))
                            .collect::<Vec<_>>(),
                        vec![
                            (evidence.published.branch_latest, false),
                            (evidence.published.current, true),
                            (evidence.original.branch_latest, false),
                            (evidence.original.current, false),
                            (evidence.original.staged, false),
                        ]
                    );
                    assert_eq!(evidence.calls[0].key, evidence.calls[2].key);
                    assert_eq!(evidence.calls[1].key, evidence.calls[3].key);
                    assert_ne!(evidence.calls[0].key, evidence.calls[1].key);
                    assert_ne!(evidence.calls[0].key, evidence.calls[4].key);
                    assert_ne!(evidence.calls[1].key, evidence.calls[4].key);
                },
            )
            .await;
    }

    #[tokio::test]
    async fn real_store_persistent_restoration_failure_reports_durable_partial_state() {
        LORE_CONTEXT
            .scope(
                Arc::new(ExecutionContext::new_client_with_user_id(
                    LoreGlobalArgs::default().set_offline(),
                    EventDispatcher::no_dispatch(),
                    "exact-real-store-failed-restore-test".to_string(),
                )),
                async {
                    let evidence = exercise_real_store_publication_failure([2, 3, 4, 5]).await;

                    assert!(
                        matches!(
                            evidence.public_error.kind(),
                            ExactSelectionErrorKind::PublicationFailure {
                                anchors_restored: false,
                                reason,
                            } if reason.contains("injected real mutable-store call 5")
                        ),
                        "persistent real-store failure must report failed recovery: {:?}",
                        evidence.public_error
                    );
                    assert_eq!(
                        evidence.reopened,
                        commit::ExactAnchorSnapshot {
                            branch_latest: evidence.published.branch_latest,
                            current: evidence.original.current,
                            staged: evidence.original.staged,
                        }
                    );
                    assert_eq!(
                        evidence
                            .calls
                            .iter()
                            .map(|call| (call.value, call.injected_failure))
                            .collect::<Vec<_>>(),
                        vec![
                            (evidence.published.branch_latest, false),
                            (evidence.published.current, true),
                            (evidence.original.branch_latest, true),
                            (evidence.original.branch_latest, true),
                            (evidence.original.branch_latest, true),
                            (evidence.original.current, false),
                            (evidence.original.staged, false),
                        ]
                    );
                    assert_eq!(evidence.calls[0].key, evidence.calls[2].key);
                    assert_eq!(evidence.calls[2].key, evidence.calls[3].key);
                    assert_eq!(evidence.calls[3].key, evidence.calls[4].key);
                    assert_eq!(evidence.calls[1].key, evidence.calls[5].key);
                    assert_ne!(evidence.calls[0].key, evidence.calls[1].key);
                    assert_ne!(evidence.calls[0].key, evidence.calls[6].key);
                    assert_ne!(evidence.calls[1].key, evidence.calls[6].key);
                },
            )
            .await;
    }

    #[test]
    fn input_bounds_accept_and_reject_selected_count_and_path_bytes_at_boundary() {
        let selected = selected_input("a".to_string());
        let mut files = vec![selected; MAX_SELECTED_FILES];
        validate_input_bounds("", &files, &[]).expect("selected count at limit must pass bounds");
        files.push(selected_input("a".to_string()));
        assert_invalid_input(
            validate_input_bounds("", &files, &[])
                .expect_err("selected count over limit must reject"),
            "selected file count",
        );

        let exact_path = "é".repeat(MAX_REPOSITORY_RELATIVE_PATH_BYTES / 2);
        let exact = vec![selected_input(exact_path)];
        validate_input_bounds("", &exact, &[]).expect("path byte count at limit must pass bounds");
        let over_path = format!("{}a", exact[0].path);
        let error = validate_input_bounds("", &[selected_input(over_path.clone())], &[])
            .expect_err("path byte count over limit must reject");
        assert_eq!(
            error.kind(),
            &ExactSelectionErrorKind::PathNormalization {
                path: over_path,
                reason: format!("path exceeds limit {MAX_REPOSITORY_RELATIVE_PATH_BYTES} bytes"),
            }
        );
    }

    #[test]
    fn input_bounds_accept_and_reject_file_and_revision_metadata_counts_at_boundary() {
        let entry = metadata_input("key".to_string(), "value".to_string());
        let mut file_entries = vec![entry.clone(); MAX_METADATA_ENTRIES_PER_SCOPE];
        let mut files = vec![selected_input("asset.bin".to_string())];
        files[0].file_metadata = FileMetadataSelection::Exact(file_entries.clone());
        validate_input_bounds("", &files, &[]).expect("file metadata count at limit must pass");
        file_entries.push(entry.clone());
        files[0].file_metadata = FileMetadataSelection::Exact(file_entries);
        assert_invalid_input(
            validate_input_bounds("", &files, &[])
                .expect_err("file metadata count over limit must reject"),
            "file metadata entry count",
        );

        let mut revision_entries = vec![entry; MAX_METADATA_ENTRIES_PER_SCOPE];
        validate_input_bounds("", &[], &revision_entries)
            .expect("revision metadata count at limit must pass");
        revision_entries.push(metadata_input("key".to_string(), "value".to_string()));
        assert_invalid_input(
            validate_input_bounds("", &[], &revision_entries)
                .expect_err("revision metadata count over limit must reject"),
            "revision metadata entry count",
        );
    }

    #[test]
    fn input_bounds_measure_metadata_key_and_value_limits_in_utf8_bytes() {
        let exact_key = "é".repeat(MAX_METADATA_KEY_BYTES / 2);
        validate_input_bounds("", &[], &[metadata_input(exact_key.clone(), String::new())])
            .expect("metadata key byte count at limit must pass");
        assert_invalid_input(
            validate_input_bounds(
                "",
                &[],
                &[metadata_input(format!("{exact_key}a"), String::new())],
            )
            .expect_err("metadata key byte count over limit must reject"),
            "metadata key exceeds limit",
        );

        let exact_value = "é".repeat(MAX_METADATA_VALUE_BYTES / 2);
        validate_input_bounds(
            "",
            &[],
            &[metadata_input("key".to_string(), exact_value.clone())],
        )
        .expect("metadata value byte count at limit must pass");
        assert_invalid_input(
            validate_input_bounds(
                "",
                &[],
                &[metadata_input("key".to_string(), format!("{exact_value}a"))],
            )
            .expect_err("metadata value byte count over limit must reject"),
            "metadata value exceeds limit",
        );
    }

    #[test]
    fn input_bounds_accept_and_reject_aggregate_bytes_at_boundary() {
        let mut file = selected_input("a".to_string());
        file.source_hash = Some("x".repeat(MAX_AGGREGATE_INPUT_BYTES - file.path.len()));
        validate_input_bounds("", &[file.clone()], &[])
            .expect("aggregate input byte count at limit must pass");
        file.source_hash
            .as_mut()
            .expect("source hash exists")
            .push('x');
        assert_invalid_input(
            validate_input_bounds("", &[file], &[])
                .expect_err("aggregate input byte count over limit must reject"),
            "aggregate input size exceeds limit",
        );
    }

    #[test]
    fn input_bounds_include_commit_message_in_aggregate_bytes() {
        let mut message = "m".repeat(MAX_AGGREGATE_INPUT_BYTES);
        validate_input_bounds(&message, &[], &[])
            .expect("message at aggregate byte limit must pass bounds");
        message.push('m');
        assert_invalid_input(
            validate_input_bounds(&message, &[], &[])
                .expect_err("message over aggregate byte limit must reject"),
            "aggregate input size exceeds limit",
        );
    }

    #[tokio::test]
    #[allow(clippy::disallowed_methods)] // Cleans an isolated temp fixture, not a repository path.
    async fn binary_metadata_read_is_capped_one_byte_past_limit() {
        let root =
            std::env::temp_dir().join(format!("lore-exact-binary-bound-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&root).expect("create binary bounds fixture");
        let source = root.join("oversized.bin");
        let file = std::fs::File::create(&source).expect("create sparse binary metadata source");
        file.set_len(MAX_BINARY_METADATA_PAYLOAD_BYTES + 1)
            .expect("size sparse binary metadata source");
        drop(file);

        let selected = SelectedFile {
            path: "asset.bin".to_string(),
            expected_effective_action: ExpectedFileAction::Add,
            source_hash: Some("00000000000000000000000000000000".to_string()),
            file_metadata: FileMetadataSelection::Exact(vec![FileMetadataEntry {
                key: "payload".to_string(),
                value: source.display().to_string(),
                value_type: ExactMetadataType::Binary,
            }]),
        };
        let error = match normalize_selected_files(&root, vec![selected]).await {
            Ok(_) => panic!("binary metadata source over cap must reject"),
            Err(error) => error,
        };
        let _ = std::fs::remove_dir_all(&root);

        assert!(
            matches!(
                error.kind(),
                ExactSelectionErrorKind::MetadataInputRead { path, key, reason, .. }
                    if path == "asset.bin"
                        && key == "payload"
                        && reason.contains("binary metadata payload exceeds limit")
            ),
            "unexpected capped binary read error: {error:?}"
        );
    }

    #[test]
    fn admission_result_is_extracted_before_anchor_publication() {
        let source = include_str!("exact_selection.rs");
        let extraction = source
            .rfind("let mut result = admission")
            .expect("exact transaction extracts admission result");
        let publication = source
            .rfind("commit::finalize_exact_commit(")
            .expect("exact transaction publishes authoritative anchors");

        assert!(
            extraction < publication,
            "fallible admission extraction must precede authoritative anchor publication"
        );
    }

    #[test]
    fn action_comparison_reports_missing_extra_and_mismatch_rows_deterministically() {
        let expected = vec![
            action("action.bin", ExpectedFileAction::Delete),
            action("missing.bin", ExpectedFileAction::Modify),
        ];
        let actual = vec![
            action("action.bin", ExpectedFileAction::Modify),
            action("extra.bin", ExpectedFileAction::Add),
        ];

        let (missing, extras, mismatches) = compare_action_sets(&expected, &actual);

        assert_eq!(
            (missing, extras, mismatches,),
            (
                vec![action("missing.bin", ExpectedFileAction::Modify)],
                vec![action("extra.bin", ExpectedFileAction::Add)],
                vec![ExactActionMismatch {
                    path: "action.bin".to_string(),
                    expected: ExpectedFileAction::Delete,
                    actual: ExpectedFileAction::Modify,
                }],
            )
        );
    }

    #[test]
    fn semantic_action_membership_reports_the_semantic_authority() {
        let expected = vec![
            action("action.bin", ExpectedFileAction::Delete),
            action("missing.bin", ExpectedFileAction::Modify),
        ];
        let actual = vec![
            action("action.bin", ExpectedFileAction::Modify),
            action("extra.bin", ExpectedFileAction::Add),
        ];

        let error = validate_action_membership(&expected, &actual, ActionAuthority::Semantic)
            .expect_err("semantic membership mismatch must reject");

        assert_eq!(
            error.kind(),
            &ExactSelectionErrorKind::SemanticSelectionMismatch {
                expected,
                actual,
                missing: vec![action("missing.bin", ExpectedFileAction::Modify)],
                extras: vec![action("extra.bin", ExpectedFileAction::Add)],
                action_mismatches: vec![ExactActionMismatch {
                    path: "action.bin".to_string(),
                    expected: ExpectedFileAction::Delete,
                    actual: ExpectedFileAction::Modify,
                }],
            }
        );
    }

    #[tokio::test]
    async fn immutable_read_failure_reports_selected_path_and_cause() {
        let error = map_immutable_read("missing.bin", async {
            Err("injected immutable absence".to_string())
        })
        .await
        .expect_err("missing immutable content must reject");

        assert_eq!(
            error.kind(),
            &ExactSelectionErrorKind::MissingImmutableContent {
                path: "missing.bin".to_string(),
                reason: "injected immutable absence".to_string(),
            }
        );
    }

    #[test]
    fn metadata_membership_rejects_changed_unselected_path() {
        let selected = vec![normalized("selected.bin", ExpectedFileAction::Modify)];
        let expected_metadata =
            BTreeMap::from([("selected.bin".to_string(), Hash::from([1_u8; 32]))]);
        let current_metadata = BTreeMap::from([
            ("selected.bin".to_string(), Hash::from([1_u8; 32])),
            ("unselected.bin".to_string(), Hash::from([2_u8; 32])),
        ]);
        let staged_metadata = BTreeMap::from([
            ("selected.bin".to_string(), Hash::from([1_u8; 32])),
            ("unselected.bin".to_string(), Hash::from([3_u8; 32])),
        ]);

        let error = validate_metadata_membership(
            &selected,
            &expected_metadata,
            &current_metadata,
            &staged_metadata,
        )
        .expect_err("changed unselected metadata must reject");

        assert_eq!(
            error.kind(),
            &ExactSelectionErrorKind::UnselectedFileMetadata {
                paths: vec!["unselected.bin".to_string()],
            }
        );
    }

    #[test]
    fn metadata_membership_rejects_staged_hash_mismatch() {
        let selected = vec![normalized("selected.bin", ExpectedFileAction::Modify)];
        let expected_hash = Hash::from([1_u8; 32]);
        let staged_hash = Hash::from([2_u8; 32]);
        let expected_metadata = BTreeMap::from([("selected.bin".to_string(), expected_hash)]);
        let current_metadata = BTreeMap::new();
        let staged_metadata = BTreeMap::from([("selected.bin".to_string(), staged_hash)]);

        let error = validate_metadata_membership(
            &selected,
            &expected_metadata,
            &current_metadata,
            &staged_metadata,
        )
        .expect_err("staged metadata hash mismatch must reject");

        assert_eq!(
            error.kind(),
            &ExactSelectionErrorKind::StagedMetadataHashMismatch {
                mismatches: vec![ExactMetadataMismatch {
                    path: "selected.bin".to_string(),
                    expected_hash: expected_hash.to_string(),
                    staged_hash: staged_hash.to_string(),
                }],
            }
        );
    }
}

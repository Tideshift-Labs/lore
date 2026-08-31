// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-029's frozen canonical intent preimages for governed mutations.
//!
//! This is the only Lore-side definition of the six intent families. Handlers
//! construct a normalized [`CanonicalIntent`] only after their ordinary wire
//! validation; the coordinator receives only the resulting digest.

use std::convert::TryFrom;

const REPOSITORY_CREATE_DOMAIN: &[u8] = b"lore-repository-create-intent-v1\0";
const REPOSITORY_DELETE_DOMAIN: &[u8] = b"lore-repository-delete-intent-v1\0";
const REPOSITORY_METADATA_CAS_DOMAIN: &[u8] = b"lore-repository-metadata-cas-intent-v1\0";
const BRANCH_METADATA_CAS_DOMAIN: &[u8] = b"lore-branch-metadata-cas-intent-v1\0";
const BRANCH_PUSH_DOMAIN: &[u8] = b"lore-branch-push-intent-v1\0";
const OBLITERATE_DOMAIN: &[u8] = b"lore-obliterate-intent-v1\0";

/// Maximum repository/default-branch/creator text size in UTF-8 bytes.
pub const CREATE_SHORT_TEXT_MAX: usize = 1_000;
/// Maximum repository description size in UTF-8 bytes.
pub const CREATE_DESCRIPTION_MAX: usize = 65_536;
/// Frozen maximum repository-create preimage length.
pub const REPOSITORY_CREATE_MAX_PREIMAGE: usize = 68_635;

/// One normalized caller-known governed mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalIntent<'a> {
    /// Repository create across v0, v1, and forwarded-v1 entry shapes.
    RepositoryCreate {
        repository_id: &'a [u8],
        name: &'a str,
        description: &'a str,
        default_branch_id: &'a [u8],
        default_branch_name: &'a str,
        /// `None` is creator mode 0; `Some(nonempty)` is mode 1.
        creator: Option<&'a str>,
        /// `None` is server-created mode 0; `Some(value)` is v0 caller time.
        caller_created: Option<u64>,
    },
    RepositoryDelete {
        repository_id: &'a [u8],
    },
    RepositoryMetadataCas {
        repository_id: &'a [u8],
        expected_hash: &'a [u8],
        new_hash: &'a [u8],
    },
    BranchMetadataCas {
        repository_id: &'a [u8],
        branch_id: &'a [u8],
        expected_hash: &'a [u8],
        new_hash: &'a [u8],
    },
    BranchPush {
        repository_id: &'a [u8],
        branch_id: &'a [u8],
        requested_revision: &'a [u8],
        force: bool,
        fast_forward_merge: bool,
    },
    Obliterate {
        repository_id: &'a [u8],
        address_hash: &'a [u8],
        address_context: &'a [u8],
    },
}

/// A normalized intent could not be encoded under the frozen contract.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CanonicalIntentError {
    #[error("{field} has {actual} bytes, expected {expected}")]
    WrongWidth {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("{field} has {actual} UTF-8 bytes, expected {minimum}..={maximum}")]
    TextLength {
        field: &'static str,
        minimum: usize,
        maximum: usize,
        actual: usize,
    },
    #[error("canonical intent field {field} is too large to frame")]
    FramingOverflow { field: &'static str },
}

fn fixed<'a>(
    field: &'static str,
    value: &'a [u8],
    expected: usize,
) -> Result<&'a [u8], CanonicalIntentError> {
    if value.len() != expected {
        return Err(CanonicalIntentError::WrongWidth {
            field,
            expected,
            actual: value.len(),
        });
    }
    Ok(value)
}

fn text<'a>(
    field: &'static str,
    value: &'a str,
    minimum: usize,
    maximum: usize,
) -> Result<&'a [u8], CanonicalIntentError> {
    let bytes = value.as_bytes();
    if bytes.len() < minimum || bytes.len() > maximum {
        return Err(CanonicalIntentError::TextLength {
            field,
            minimum,
            maximum,
            actual: bytes.len(),
        });
    }
    Ok(bytes)
}

fn framed(
    out: &mut Vec<u8>,
    field: &'static str,
    bytes: &[u8],
) -> Result<(), CanonicalIntentError> {
    let len =
        u32::try_from(bytes.len()).map_err(|_| CanonicalIntentError::FramingOverflow { field })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// Build the exact frozen preimage. Validation completes before bytes are
/// returned, so no caller can hash a partial or invalid record accidentally.
pub fn canonical_intent_preimage(
    intent: &CanonicalIntent<'_>,
) -> Result<Vec<u8>, CanonicalIntentError> {
    let mut out = Vec::new();
    match intent {
        CanonicalIntent::RepositoryCreate {
            repository_id,
            name,
            description,
            default_branch_id,
            default_branch_name,
            creator,
            caller_created,
        } => {
            let repository_id = fixed("repository_id", repository_id, 16)?;
            let name = text("name", name, 1, CREATE_SHORT_TEXT_MAX)?;
            let description = text("description", description, 0, CREATE_DESCRIPTION_MAX)?;
            let default_branch_id = fixed("default_branch_id", default_branch_id, 16)?;
            let default_branch_name = text(
                "default_branch_name",
                default_branch_name,
                1,
                CREATE_SHORT_TEXT_MAX,
            )?;
            let creator = match creator {
                Some(value) => Some(text("explicit_creator", value, 1, CREATE_SHORT_TEXT_MAX)?),
                None => None,
            };

            out.reserve(REPOSITORY_CREATE_MAX_PREIMAGE.min(256));
            out.extend_from_slice(REPOSITORY_CREATE_DOMAIN);
            framed(&mut out, "repository_id", repository_id)?;
            framed(&mut out, "name", name)?;
            framed(&mut out, "description", description)?;
            framed(&mut out, "default_branch_id", default_branch_id)?;
            framed(&mut out, "default_branch_name", default_branch_name)?;
            out.push(u8::from(creator.is_some()));
            framed(&mut out, "explicit_creator", creator.unwrap_or_default())?;
            out.push(u8::from(caller_created.is_some()));
            out.extend_from_slice(&caller_created.unwrap_or_default().to_be_bytes());
        }
        CanonicalIntent::RepositoryDelete { repository_id } => {
            out.extend_from_slice(REPOSITORY_DELETE_DOMAIN);
            framed(
                &mut out,
                "repository_id",
                fixed("repository_id", repository_id, 16)?,
            )?;
        }
        CanonicalIntent::RepositoryMetadataCas {
            repository_id,
            expected_hash,
            new_hash,
        } => {
            out.extend_from_slice(REPOSITORY_METADATA_CAS_DOMAIN);
            framed(
                &mut out,
                "repository_id",
                fixed("repository_id", repository_id, 16)?,
            )?;
            framed(
                &mut out,
                "expected_hash",
                fixed("expected_hash", expected_hash, 32)?,
            )?;
            framed(&mut out, "new_hash", fixed("new_hash", new_hash, 32)?)?;
        }
        CanonicalIntent::BranchMetadataCas {
            repository_id,
            branch_id,
            expected_hash,
            new_hash,
        } => {
            out.extend_from_slice(BRANCH_METADATA_CAS_DOMAIN);
            framed(
                &mut out,
                "repository_id",
                fixed("repository_id", repository_id, 16)?,
            )?;
            framed(&mut out, "branch_id", fixed("branch_id", branch_id, 16)?)?;
            framed(
                &mut out,
                "expected_hash",
                fixed("expected_hash", expected_hash, 32)?,
            )?;
            framed(&mut out, "new_hash", fixed("new_hash", new_hash, 32)?)?;
        }
        CanonicalIntent::BranchPush {
            repository_id,
            branch_id,
            requested_revision,
            force,
            fast_forward_merge,
        } => {
            out.extend_from_slice(BRANCH_PUSH_DOMAIN);
            framed(
                &mut out,
                "repository_id",
                fixed("repository_id", repository_id, 16)?,
            )?;
            framed(&mut out, "branch_id", fixed("branch_id", branch_id, 16)?)?;
            framed(
                &mut out,
                "requested_revision",
                fixed("requested_revision", requested_revision, 32)?,
            )?;
            out.push(u8::from(*force));
            out.push(u8::from(*fast_forward_merge));
        }
        CanonicalIntent::Obliterate {
            repository_id,
            address_hash,
            address_context,
        } => {
            out.extend_from_slice(OBLITERATE_DOMAIN);
            framed(
                &mut out,
                "repository_id",
                fixed("repository_id", repository_id, 16)?,
            )?;
            framed(
                &mut out,
                "address.hash",
                fixed("address.hash", address_hash, 32)?,
            )?;
            framed(
                &mut out,
                "address.context",
                fixed("address.context", address_context, 16)?,
            )?;
        }
    }
    Ok(out)
}

/// Hash the exact frozen preimage with unkeyed BLAKE3-256.
pub fn canonical_intent_digest(
    intent: &CanonicalIntent<'_>,
) -> Result<Vec<u8>, CanonicalIntentError> {
    Ok(blake3::hash(&canonical_intent_preimage(intent)?)
        .as_bytes()
        .to_vec())
}

#[cfg(test)]
mod tests;

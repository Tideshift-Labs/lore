// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Closed configuration for the in-process cell dispatch authority.
//!
//! CR-033's revised specification (D1) makes the authority in-process: it runs on the cell's own
//! PostgreSQL pool, so it configures no listener and no TLS material. What survives is the bounded,
//! fail-closed parse of the `LORE_OBJECT_DISPATCH_` environment surface and the revision pin that
//! rejects a stale operator environment instead of silently accepting it.
//!
//! The prefix test is bytewise and runs *before* Unicode conversion, so a prefixed but non-Unicode
//! variable name fails closed rather than escaping the allowlist through a lossy comparison.

use std::ffi::OsStr;
use std::ffi::OsString;

use thiserror::Error;

pub const CELL_AUTHORITY_CONFIG_REVISION: &str = "object-store-cell-dispatch-authority-v1";
pub const CELL_AUTHORITY_CONFIG_REVISION_ENV: &str = "LORE_OBJECT_DISPATCH_CONFIG_REVISION";
const ENV_PREFIX: &str = "LORE_OBJECT_DISPATCH_";

fn has_object_dispatch_prefix(key: &OsStr) -> bool {
    if let Some(key) = key.to_str() {
        return key.starts_with(ENV_PREFIX);
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        key.as_bytes().starts_with(ENV_PREFIX.as_bytes())
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let mut key = key.encode_wide();
        ENV_PREFIX
            .encode_utf16()
            .all(|expected| key.next() == Some(expected))
    }
}

/// The cell dispatch authority's whole configuration surface.
///
/// Every field is a closed, non-secret value. Nothing here names a connection, a credential, a
/// filesystem path, or a provider route: the authority inherits its database session from
/// `lore-postgres` and its spool root from the drain worker that owns it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CellAuthorityConfig {
    config_revision: String,
}

impl CellAuthorityConfig {
    pub fn from_env() -> Result<Self, CellAuthorityConfigError> {
        let mut prefixed = Vec::new();
        for (key, value) in std::env::vars_os() {
            if !has_object_dispatch_prefix(&key) {
                continue;
            }
            let key = key
                .into_string()
                .map_err(|_| CellAuthorityConfigError::NonUnicodeKey)?;
            let value = value
                .into_string()
                .map_err(|_| CellAuthorityConfigError::NonUnicodeValue)?;
            prefixed.push((key, value));
        }
        Self::from_prefixed_vars(prefixed)
    }

    pub fn from_prefixed_vars<I, K, V>(vars: I) -> Result<Self, CellAuthorityConfigError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<OsString>,
        V: Into<OsString>,
    {
        let mut revision = None;
        for (key, value) in vars {
            let key = key.into();
            if !has_object_dispatch_prefix(&key) {
                continue;
            }
            let key = key
                .into_string()
                .map_err(|_| CellAuthorityConfigError::NonUnicodeKey)?;
            let value = value
                .into()
                .into_string()
                .map_err(|_| CellAuthorityConfigError::NonUnicodeValue)?;
            match key.as_str() {
                CELL_AUTHORITY_CONFIG_REVISION_ENV => {
                    if revision.replace(value).is_some() {
                        return Err(CellAuthorityConfigError::DuplicateVariable);
                    }
                }
                _ => return Err(CellAuthorityConfigError::UnknownVariable),
            }
        }

        let config_revision = revision.ok_or(CellAuthorityConfigError::MissingRevision)?;
        if config_revision != CELL_AUTHORITY_CONFIG_REVISION {
            return Err(CellAuthorityConfigError::RevisionMismatch);
        }
        Ok(Self { config_revision })
    }

    pub fn config_revision(&self) -> &str {
        &self.config_revision
    }
}

#[derive(Debug, PartialEq, Eq, Error)]
pub enum CellAuthorityConfigError {
    #[error("object-dispatch cell authority configuration contains a non-Unicode variable name")]
    NonUnicodeKey,
    #[error("object-dispatch cell authority configuration contains a non-Unicode value")]
    NonUnicodeValue,
    #[error("object-dispatch cell authority configuration contains an unknown variable")]
    UnknownVariable,
    #[error("object-dispatch cell authority configuration repeats a variable")]
    DuplicateVariable,
    #[error("object-dispatch cell authority configuration revision is missing")]
    MissingRevision,
    #[error("object-dispatch cell authority configuration revision does not match the binary")]
    RevisionMismatch,
}

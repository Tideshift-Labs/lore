// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Closed process configuration for the source-dark service shell.

use std::ffi::OsStr;
use std::ffi::OsString;
use std::fmt;
use std::net::SocketAddr;

use thiserror::Error;

pub const SERVICE_CONFIG_REVISION: &str = "object-store-dispatch-service-shell-v1";
pub const SERVICE_CONFIG_REVISION_ENV: &str = "LORE_OBJECT_DISPATCH_SERVICE_CONFIG_REVISION";
pub const LISTEN_ADDR_ENV: &str = "LORE_OBJECT_DISPATCH_LISTEN_ADDR";
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

#[derive(Clone, PartialEq, Eq)]
pub struct ServiceConfig {
    service_config_revision: String,
    listen_addr: SocketAddr,
}

impl fmt::Debug for ServiceConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceConfig")
            .field("service_config_revision", &self.service_config_revision)
            .field("listen_addr", &self.listen_addr)
            .finish()
    }
}

impl ServiceConfig {
    pub fn from_env() -> Result<Self, ServiceConfigError> {
        let mut prefixed = Vec::new();
        for (key, value) in std::env::vars_os() {
            if !has_object_dispatch_prefix(&key) {
                continue;
            }
            let key = key
                .into_string()
                .map_err(|_| ServiceConfigError::NonUnicodeKey)?;
            let value = value
                .into_string()
                .map_err(|_| ServiceConfigError::NonUnicodeValue)?;
            prefixed.push((key, value));
        }
        Self::from_prefixed_vars(prefixed)
    }

    pub fn from_prefixed_vars<I, K, V>(vars: I) -> Result<Self, ServiceConfigError>
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<OsString>,
        V: Into<OsString>,
    {
        let mut revision = None;
        let mut listen_addr = None;
        for (key, value) in vars {
            let key = key.into();
            if !has_object_dispatch_prefix(&key) {
                continue;
            }
            let key = key
                .into_string()
                .map_err(|_| ServiceConfigError::NonUnicodeKey)?;
            let value = value
                .into()
                .into_string()
                .map_err(|_| ServiceConfigError::NonUnicodeValue)?;
            match key.as_str() {
                SERVICE_CONFIG_REVISION_ENV => {
                    if revision.replace(value).is_some() {
                        return Err(ServiceConfigError::DuplicateVariable);
                    }
                }
                LISTEN_ADDR_ENV => {
                    if listen_addr.replace(value).is_some() {
                        return Err(ServiceConfigError::DuplicateVariable);
                    }
                }
                _ => return Err(ServiceConfigError::UnknownVariable),
            }
        }

        let service_config_revision = revision.ok_or(ServiceConfigError::MissingRevision)?;
        if service_config_revision != SERVICE_CONFIG_REVISION {
            return Err(ServiceConfigError::RevisionMismatch);
        }
        let listen_addr = listen_addr
            .ok_or(ServiceConfigError::MissingListenAddress)?
            .parse::<SocketAddr>()
            .map_err(|_| ServiceConfigError::InvalidListenAddress)?;
        if listen_addr.port() == 0 || !listen_addr.ip().is_loopback() {
            return Err(ServiceConfigError::UnsafeListenAddress);
        }

        Ok(Self {
            service_config_revision,
            listen_addr,
        })
    }

    pub fn service_config_revision(&self) -> &str {
        &self.service_config_revision
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }
}

#[derive(Debug, PartialEq, Eq, Error)]
pub enum ServiceConfigError {
    #[error("object-dispatch service configuration contains a non-Unicode variable name")]
    NonUnicodeKey,
    #[error("object-dispatch service configuration contains a non-Unicode value")]
    NonUnicodeValue,
    #[error("object-dispatch service configuration contains an unknown variable")]
    UnknownVariable,
    #[error("object-dispatch service configuration repeats a variable")]
    DuplicateVariable,
    #[error("object-dispatch service configuration revision is missing")]
    MissingRevision,
    #[error("object-dispatch service configuration revision does not match the binary")]
    RevisionMismatch,
    #[error("object-dispatch service listen address is missing")]
    MissingListenAddress,
    #[error("object-dispatch service listen address is invalid")]
    InvalidListenAddress,
    #[error("source-dark object-dispatch service must use a nonzero loopback listen address")]
    UnsafeListenAddress,
}

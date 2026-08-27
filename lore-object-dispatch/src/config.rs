// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Closed process configuration for the source-dark service shell.

use std::ffi::OsStr;
use std::ffi::OsString;
use std::fmt;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;

use thiserror::Error;

pub const SERVICE_CONFIG_REVISION: &str = "object-store-dispatch-service-mtls-shell-v1";
pub const SERVICE_CONFIG_REVISION_ENV: &str = "LORE_OBJECT_DISPATCH_SERVICE_CONFIG_REVISION";
pub const LISTEN_ADDR_ENV: &str = "LORE_OBJECT_DISPATCH_LISTEN_ADDR";
pub const SERVER_CERT_CHAIN_PEM_PATH_ENV: &str = "LORE_OBJECT_DISPATCH_SERVER_CERT_CHAIN_PEM_PATH";
pub const SERVER_PRIVATE_KEY_PEM_PATH_ENV: &str =
    "LORE_OBJECT_DISPATCH_SERVER_PRIVATE_KEY_PEM_PATH";
pub const CLIENT_CA_PEM_PATH_ENV: &str = "LORE_OBJECT_DISPATCH_CLIENT_CA_PEM_PATH";
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
    server_cert_chain_pem_path: PathBuf,
    server_private_key_pem_path: PathBuf,
    client_ca_pem_path: PathBuf,
}

impl fmt::Debug for ServiceConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceConfig")
            .field("service_config_revision", &self.service_config_revision)
            .field("listen_addr", &self.listen_addr)
            .field("server_cert_chain_pem_path", &"[REDACTED]")
            .field("server_private_key_pem_path", &"[REDACTED]")
            .field("client_ca_pem_path", &"[REDACTED]")
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
        let mut server_cert_chain_pem_path = None;
        let mut server_private_key_pem_path = None;
        let mut client_ca_pem_path = None;
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
                SERVER_CERT_CHAIN_PEM_PATH_ENV => {
                    if server_cert_chain_pem_path.replace(value).is_some() {
                        return Err(ServiceConfigError::DuplicateVariable);
                    }
                }
                SERVER_PRIVATE_KEY_PEM_PATH_ENV => {
                    if server_private_key_pem_path.replace(value).is_some() {
                        return Err(ServiceConfigError::DuplicateVariable);
                    }
                }
                CLIENT_CA_PEM_PATH_ENV => {
                    if client_ca_pem_path.replace(value).is_some() {
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
        let server_cert_chain_pem_path = required_absolute_path(
            server_cert_chain_pem_path,
            ServiceConfigError::MissingServerCertificate,
        )?;
        let server_private_key_pem_path = required_absolute_path(
            server_private_key_pem_path,
            ServiceConfigError::MissingServerPrivateKey,
        )?;
        let client_ca_pem_path = required_absolute_path(
            client_ca_pem_path,
            ServiceConfigError::MissingClientCertificateAuthority,
        )?;
        if server_cert_chain_pem_path == server_private_key_pem_path
            || server_cert_chain_pem_path == client_ca_pem_path
            || server_private_key_pem_path == client_ca_pem_path
        {
            return Err(ServiceConfigError::DuplicateTlsPath);
        }

        Ok(Self {
            service_config_revision,
            listen_addr,
            server_cert_chain_pem_path,
            server_private_key_pem_path,
            client_ca_pem_path,
        })
    }

    pub fn service_config_revision(&self) -> &str {
        &self.service_config_revision
    }

    pub fn listen_addr(&self) -> SocketAddr {
        self.listen_addr
    }

    pub fn server_cert_chain_pem_path(&self) -> &Path {
        &self.server_cert_chain_pem_path
    }

    pub fn server_private_key_pem_path(&self) -> &Path {
        &self.server_private_key_pem_path
    }

    pub fn client_ca_pem_path(&self) -> &Path {
        &self.client_ca_pem_path
    }
}

fn required_absolute_path(
    value: Option<String>,
    missing: ServiceConfigError,
) -> Result<PathBuf, ServiceConfigError> {
    let value = value.ok_or(missing)?;
    if value.is_empty() {
        return Err(ServiceConfigError::InvalidTlsPath);
    }
    let path = PathBuf::from(value);
    if !path.is_absolute() {
        return Err(ServiceConfigError::UnsafeTlsPath);
    }
    Ok(path)
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
    #[error("object-dispatch server certificate chain path is missing")]
    MissingServerCertificate,
    #[error("object-dispatch server private key path is missing")]
    MissingServerPrivateKey,
    #[error("object-dispatch client certificate authority path is missing")]
    MissingClientCertificateAuthority,
    #[error("object-dispatch TLS material path is invalid")]
    InvalidTlsPath,
    #[error("object-dispatch TLS material path must be absolute")]
    UnsafeTlsPath,
    #[error("object-dispatch TLS material paths must be distinct")]
    DuplicateTlsPath,
}

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Exact client-certificate identity mapping for the source-dark service boundary.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;
use std::sync::Arc;

use rustls::pki_types::CertificateDer;
use thiserror::Error;
use tonic::Request;
use tonic::Status;
use tonic::service::Interceptor;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::FromDer;
use x509_parser::prelude::X509Certificate;

const MAX_ID_BYTES: usize = 256;
const MAX_URI_SAN_BYTES: usize = 2048;
const MAX_ALLOWED_CELLS: usize = 4096;
pub const UNAUTHENTICATED_CALLER_MESSAGE: &str = "object-store dispatch caller is not authorized";

#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizedCallerEntry {
    pub uri_san: String,
    pub service_instance_id: String,
    pub provider_boundary_id: String,
    pub allowed_cell_ids: Vec<String>,
}

impl fmt::Debug for AuthorizedCallerEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedCallerEntry")
            .field("uri_san", &"[REDACTED]")
            .field("service_instance_id", &"[REDACTED]")
            .field("provider_boundary_id", &"[REDACTED]")
            .field("allowed_cell_count", &self.allowed_cell_ids.len())
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct AuthenticatedCaller {
    service_instance_id: String,
    uri_san: String,
    provider_boundary_id: String,
    allowed_cell_ids: Arc<[String]>,
}

impl fmt::Debug for AuthenticatedCaller {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedCaller")
            .field("service_instance_id", &"[REDACTED]")
            .field("uri_san", &"[REDACTED]")
            .field("provider_boundary_id", &"[REDACTED]")
            .field("allowed_cell_count", &self.allowed_cell_ids.len())
            .finish()
    }
}

impl AuthenticatedCaller {
    pub fn service_instance_id(&self) -> &str {
        &self.service_instance_id
    }

    pub fn uri_san(&self) -> &str {
        &self.uri_san
    }

    pub fn provider_boundary_id(&self) -> &str {
        &self.provider_boundary_id
    }

    pub fn allowed_cell_ids(&self) -> &[String] {
        &self.allowed_cell_ids
    }

    pub fn allows_cell(&self, cell_id: &str) -> bool {
        self.allowed_cell_ids
            .binary_search_by(|candidate| candidate.as_str().cmp(cell_id))
            .is_ok()
    }
}

#[derive(Clone, Default)]
pub struct AuthorizedCallerRegistry {
    by_uri_san: Arc<BTreeMap<String, AuthenticatedCaller>>,
}

impl fmt::Debug for AuthorizedCallerRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedCallerRegistry")
            .field("registered_caller_count", &self.by_uri_san.len())
            .finish()
    }
}

impl AuthorizedCallerRegistry {
    pub fn new(entries: Vec<AuthorizedCallerEntry>) -> Result<Self, CallerRegistryError> {
        let mut by_uri_san = BTreeMap::new();
        for entry in entries {
            validate_uri_san(&entry.uri_san)?;
            validate_id(&entry.service_instance_id)?;
            validate_id(&entry.provider_boundary_id)?;
            if entry.allowed_cell_ids.is_empty() || entry.allowed_cell_ids.len() > MAX_ALLOWED_CELLS
            {
                return Err(CallerRegistryError::InvalidAllowedCellSet);
            }

            let mut unique_cells = BTreeSet::new();
            for cell_id in entry.allowed_cell_ids {
                validate_id(&cell_id)?;
                if !unique_cells.insert(cell_id) {
                    return Err(CallerRegistryError::DuplicateAllowedCell);
                }
            }
            let caller = AuthenticatedCaller {
                service_instance_id: entry.service_instance_id,
                uri_san: entry.uri_san.clone(),
                provider_boundary_id: entry.provider_boundary_id,
                allowed_cell_ids: unique_cells.into_iter().collect::<Vec<_>>().into(),
            };
            if by_uri_san.insert(entry.uri_san, caller).is_some() {
                return Err(CallerRegistryError::DuplicateUriSan);
            }
        }
        Ok(Self {
            by_uri_san: Arc::new(by_uri_san),
        })
    }

    pub fn deny_all() -> Self {
        Self::default()
    }

    pub fn authenticate_peer_certs(
        &self,
        peer_certs: Option<&[CertificateDer<'static>]>,
    ) -> Result<AuthenticatedCaller, CallerAuthenticationError> {
        let leaf = peer_certs
            .and_then(|certificates| certificates.first())
            .ok_or(CallerAuthenticationError::MissingCertificate)?;
        let (remaining, certificate) = X509Certificate::from_der(leaf.as_ref())
            .map_err(|_| CallerAuthenticationError::MalformedCertificate)?;
        if !remaining.is_empty() {
            return Err(CallerAuthenticationError::MalformedCertificate);
        }
        let subject_alternative_name = certificate
            .subject_alternative_name()
            .map_err(|_| CallerAuthenticationError::MalformedCertificate)?
            .ok_or(CallerAuthenticationError::MissingUriSan)?;

        let mut matched = None;
        let mut saw_uri_san = false;
        for name in &subject_alternative_name.value.general_names {
            let GeneralName::URI(uri_san) = name else {
                continue;
            };
            saw_uri_san = true;
            let Some(caller) = self.by_uri_san.get(*uri_san) else {
                continue;
            };
            if matched.replace(caller.clone()).is_some() {
                return Err(CallerAuthenticationError::AmbiguousIdentity);
            }
        }
        if !saw_uri_san {
            return Err(CallerAuthenticationError::MissingUriSan);
        }
        matched.ok_or(CallerAuthenticationError::UnregisteredIdentity)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct MtlsCellInterceptor {
    registry: AuthorizedCallerRegistry,
}

impl MtlsCellInterceptor {
    pub(crate) fn new(registry: AuthorizedCallerRegistry) -> Self {
        Self { registry }
    }
}

impl Interceptor for MtlsCellInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        let peer_certs = request.peer_certs();
        let caller = self
            .registry
            .authenticate_peer_certs(peer_certs.as_deref().map(Vec::as_slice))
            .map_err(|_| Status::unauthenticated(UNAUTHENTICATED_CALLER_MESSAGE))?;
        request.extensions_mut().insert(caller);
        Ok(request)
    }
}

fn validate_uri_san(value: &str) -> Result<(), CallerRegistryError> {
    if value.is_empty()
        || value.len() > MAX_URI_SAN_BYTES
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_control())
        || !value.contains(':')
    {
        return Err(CallerRegistryError::InvalidUriSan);
    }
    Ok(())
}

pub(crate) fn validate_id(value: &str) -> Result<(), CallerRegistryError> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || bytes.len() > MAX_ID_BYTES
        || !bytes[0].is_ascii_alphanumeric()
        || !bytes.iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'/' | b'-')
        })
    {
        return Err(CallerRegistryError::InvalidId);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum CallerRegistryError {
    #[error("object-dispatch caller registry contains an invalid URI SAN")]
    InvalidUriSan,
    #[error("object-dispatch caller registry contains an invalid canonical ID")]
    InvalidId,
    #[error("object-dispatch caller registry repeats a URI SAN")]
    DuplicateUriSan,
    #[error("object-dispatch caller registry has an invalid allowed-cell set")]
    InvalidAllowedCellSet,
    #[error("object-dispatch caller registry repeats an allowed cell")]
    DuplicateAllowedCell,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum CallerAuthenticationError {
    #[error("object-dispatch caller certificate is missing")]
    MissingCertificate,
    #[error("object-dispatch caller certificate is malformed")]
    MalformedCertificate,
    #[error("object-dispatch caller certificate has no URI SAN")]
    MissingUriSan,
    #[error("object-dispatch caller certificate identity is not registered")]
    UnregisteredIdentity,
    #[error("object-dispatch caller certificate identity is ambiguous")]
    AmbiguousIdentity,
}

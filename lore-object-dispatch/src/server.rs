// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Loopback-only, mandatory-mTLS transport for the source-dark service.

use std::fmt;
use std::future::Future;
use std::io::Read;
use std::net::TcpListener;
use std::path::Path;

use lore_proto::lore::object_dispatch::v1::object_store_dispatch_service_server::ObjectStoreDispatchServiceServer;
use thiserror::Error;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Certificate;
use tonic::transport::Identity;
use tonic::transport::Server;
use tonic::transport::ServerTlsConfig;

use crate::AuthorizedCallerRegistry;
use crate::ServiceConfig;
use crate::SourceDarkObjectStoreDispatchService;
use crate::auth::MtlsCellInterceptor;

pub const MAX_TLS_PEM_BYTES: u64 = 1_048_576;

#[derive(Clone)]
pub struct ServiceTlsConfig {
    server_identity: Identity,
    client_ca: Certificate,
}

impl fmt::Debug for ServiceTlsConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceTlsConfig")
            .field("server_identity", &"[REDACTED]")
            .field("client_ca", &"[REDACTED]")
            .finish()
    }
}

impl ServiceTlsConfig {
    pub fn from_pem_files(
        server_cert_chain_path: &Path,
        server_private_key_path: &Path,
        client_ca_path: &Path,
    ) -> Result<Self, ServiceTlsConfigError> {
        let server_cert_chain =
            read_tls_file(server_cert_chain_path, TlsMaterialKind::ServerCertificate)?;
        let server_private_key =
            read_tls_file(server_private_key_path, TlsMaterialKind::ServerPrivateKey)?;
        let client_ca = read_tls_file(client_ca_path, TlsMaterialKind::ClientCa)?;
        Self::from_pem(server_cert_chain, server_private_key, client_ca)
    }

    pub fn from_pem(
        server_cert_chain: Vec<u8>,
        server_private_key: Vec<u8>,
        client_ca: Vec<u8>,
    ) -> Result<Self, ServiceTlsConfigError> {
        if server_cert_chain.is_empty() {
            return Err(ServiceTlsConfigError::EmptyServerCertificate);
        }
        if server_private_key.is_empty() {
            return Err(ServiceTlsConfigError::EmptyServerPrivateKey);
        }
        if client_ca.is_empty() {
            return Err(ServiceTlsConfigError::EmptyClientCa);
        }
        Ok(Self {
            server_identity: Identity::from_pem(server_cert_chain, server_private_key),
            client_ca: Certificate::from_pem(client_ca),
        })
    }

    fn server_tls_config(&self) -> ServerTlsConfig {
        ServerTlsConfig::new()
            .identity(self.server_identity.clone())
            .client_ca_root(self.client_ca.clone())
    }
}

#[derive(Clone, Copy)]
enum TlsMaterialKind {
    ServerCertificate,
    ServerPrivateKey,
    ClientCa,
}

impl TlsMaterialKind {
    fn read_error(self, error: std::io::Error) -> ServiceTlsConfigError {
        match self {
            Self::ServerCertificate => ServiceTlsConfigError::ReadServerCertificate(error),
            Self::ServerPrivateKey => ServiceTlsConfigError::ReadServerPrivateKey(error),
            Self::ClientCa => ServiceTlsConfigError::ReadClientCa(error),
        }
    }
}

fn read_tls_file(path: &Path, kind: TlsMaterialKind) -> Result<Vec<u8>, ServiceTlsConfigError> {
    let metadata = std::fs::metadata(path).map_err(|error| kind.read_error(error))?;
    if !metadata.is_file() {
        return Err(ServiceTlsConfigError::NonRegularTlsMaterial);
    }
    if metadata.len() > MAX_TLS_PEM_BYTES {
        return Err(ServiceTlsConfigError::OversizedTlsMaterial);
    }

    let mut file = std::fs::File::open(path).map_err(|error| kind.read_error(error))?;
    let opened_metadata = file.metadata().map_err(|error| kind.read_error(error))?;
    if !opened_metadata.is_file() {
        return Err(ServiceTlsConfigError::NonRegularTlsMaterial);
    }
    if opened_metadata.len() > MAX_TLS_PEM_BYTES {
        return Err(ServiceTlsConfigError::OversizedTlsMaterial);
    }

    let mut bytes = Vec::with_capacity(opened_metadata.len() as usize);
    file.by_ref()
        .take(MAX_TLS_PEM_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| kind.read_error(error))?;
    if bytes.len() as u64 > MAX_TLS_PEM_BYTES {
        return Err(ServiceTlsConfigError::OversizedTlsMaterial);
    }
    Ok(bytes)
}

pub async fn serve(
    config: &ServiceConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), ServiceServerError> {
    serve_with_registry(config, AuthorizedCallerRegistry::deny_all(), shutdown).await
}

pub async fn serve_with_registry(
    config: &ServiceConfig,
    registry: AuthorizedCallerRegistry,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), ServiceServerError> {
    let tls = ServiceTlsConfig::from_pem_files(
        config.server_cert_chain_pem_path(),
        config.server_private_key_pem_path(),
        config.client_ca_pem_path(),
    )
    .map_err(ServiceServerError::TlsMaterial)?;
    let listener = TcpListener::bind(config.listen_addr()).map_err(ServiceServerError::Bind)?;
    serve_prebound_with_tls(
        listener,
        SourceDarkObjectStoreDispatchService::new(),
        tls,
        registry,
        shutdown,
    )
    .await
}

pub async fn serve_prebound_with_tls(
    listener: TcpListener,
    service: SourceDarkObjectStoreDispatchService,
    tls: ServiceTlsConfig,
    registry: AuthorizedCallerRegistry,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), ServiceServerError> {
    if !listener
        .local_addr()
        .map_err(ServiceServerError::Listener)?
        .ip()
        .is_loopback()
    {
        return Err(ServiceServerError::UnsafeListener);
    }
    listener
        .set_nonblocking(true)
        .map_err(ServiceServerError::Listener)?;
    let listener =
        tokio::net::TcpListener::from_std(listener).map_err(ServiceServerError::Listener)?;
    let interceptor = MtlsCellInterceptor::new(registry);
    let mut server = Server::builder()
        .tls_config(tls.server_tls_config())
        .map_err(ServiceServerError::TlsConfiguration)?;
    server
        .add_service(ObjectStoreDispatchServiceServer::with_interceptor(
            service,
            interceptor,
        ))
        .serve_with_incoming_shutdown(TcpListenerStream::new(listener), shutdown)
        .await
        .map_err(ServiceServerError::Transport)
}

#[derive(Debug, Error)]
pub enum ServiceTlsConfigError {
    #[error("object-dispatch server certificate could not be read")]
    ReadServerCertificate(#[source] std::io::Error),
    #[error("object-dispatch server private key could not be read")]
    ReadServerPrivateKey(#[source] std::io::Error),
    #[error("object-dispatch client certificate authority could not be read")]
    ReadClientCa(#[source] std::io::Error),
    #[error("object-dispatch server certificate is empty")]
    EmptyServerCertificate,
    #[error("object-dispatch server private key is empty")]
    EmptyServerPrivateKey,
    #[error("object-dispatch client certificate authority is empty")]
    EmptyClientCa,
    #[error("object-dispatch TLS material source must be a regular file")]
    NonRegularTlsMaterial,
    #[error("object-dispatch TLS material exceeds the configured byte bound")]
    OversizedTlsMaterial,
}

impl PartialEq for ServiceTlsConfigError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::ReadServerCertificate(left), Self::ReadServerCertificate(right))
            | (Self::ReadServerPrivateKey(left), Self::ReadServerPrivateKey(right))
            | (Self::ReadClientCa(left), Self::ReadClientCa(right)) => left.kind() == right.kind(),
            (Self::EmptyServerCertificate, Self::EmptyServerCertificate)
            | (Self::EmptyServerPrivateKey, Self::EmptyServerPrivateKey)
            | (Self::EmptyClientCa, Self::EmptyClientCa)
            | (Self::NonRegularTlsMaterial, Self::NonRegularTlsMaterial)
            | (Self::OversizedTlsMaterial, Self::OversizedTlsMaterial) => true,
            _ => false,
        }
    }
}

impl Eq for ServiceTlsConfigError {}

#[derive(Debug, Error)]
pub enum ServiceServerError {
    #[error("object-dispatch service TLS material is invalid")]
    TlsMaterial(#[source] ServiceTlsConfigError),
    #[error("object-dispatch service TLS configuration is invalid")]
    TlsConfiguration(#[source] tonic::transport::Error),
    #[error("object-dispatch service could not bind its listener")]
    Bind(#[source] std::io::Error),
    #[error("object-dispatch service listener is invalid")]
    Listener(#[source] std::io::Error),
    #[error("source-dark object-dispatch service listener must be loopback")]
    UnsafeListener,
    #[error("object-dispatch gRPC transport failed")]
    Transport(#[source] tonic::transport::Error),
}

impl PartialEq for ServiceServerError {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::TlsMaterial(left), Self::TlsMaterial(right)) => left == right,
            (Self::Bind(left), Self::Bind(right))
            | (Self::Listener(left), Self::Listener(right)) => left.kind() == right.kind(),
            (Self::TlsConfiguration(_), Self::TlsConfiguration(_))
            | (Self::UnsafeListener, Self::UnsafeListener)
            | (Self::Transport(_), Self::Transport(_)) => true,
            _ => false,
        }
    }
}

impl Eq for ServiceServerError {}

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Local-only transport shell for the source-dark service.

use std::future::Future;
use std::net::TcpListener;

use lore_proto::lore::object_dispatch::v1::object_store_dispatch_service_server::ObjectStoreDispatchServiceServer;
use thiserror::Error;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

use crate::ServiceConfig;
use crate::SourceDarkObjectStoreDispatchService;

pub async fn serve(
    config: &ServiceConfig,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<(), ServiceServerError> {
    let listener = TcpListener::bind(config.listen_addr()).map_err(ServiceServerError::Bind)?;
    serve_prebound(listener, shutdown).await
}

pub async fn serve_prebound(
    listener: TcpListener,
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
    Server::builder()
        .add_service(ObjectStoreDispatchServiceServer::new(
            SourceDarkObjectStoreDispatchService::new(),
        ))
        .serve_with_incoming_shutdown(TcpListenerStream::new(listener), shutdown)
        .await
        .map_err(ServiceServerError::Transport)
}

#[derive(Debug, Error)]
pub enum ServiceServerError {
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
            (Self::Bind(left), Self::Bind(right))
            | (Self::Listener(left), Self::Listener(right)) => left.kind() == right.kind(),
            (Self::UnsafeListener, Self::UnsafeListener)
            | (Self::Transport(_), Self::Transport(_)) => true,
            _ => false,
        }
    }
}

impl Eq for ServiceServerError {}

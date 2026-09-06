// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use lore_base::lore_debug;
use lore_base::types::Address;
use lore_base::types::RepositoryId;
use lore_proto::AdminServiceClient;
use lore_proto::ObliterateRequest;

use super::AuthorizedService;
use super::AuthzInterceptor;
use super::Channel;
use super::GRPCAuthRef;
use super::RequestScopedCounter;
use super::grpc_retry;
use super::handle_error;
use super::inject_authn_bearer;
use crate::error::ProtocolError;

#[derive(Clone)]
pub struct AdminService {
    client: AdminServiceClient<AuthorizedService>,
    /// Kept beside the client so a governed mutation can stamp the human's own
    /// authentication bearer per dispatch.
    auth: GRPCAuthRef,
    pub request_inflight: Arc<AtomicU64>,
}

impl AdminService {
    pub fn new(channel: Channel, repository: RepositoryId, auth: GRPCAuthRef) -> Self {
        let client = AdminServiceClient::with_interceptor(
            channel,
            AuthzInterceptor {
                repository,
                auth: auth.clone(),
            },
        );

        Self {
            client,
            auth,
            request_inflight: Arc::new(AtomicU64::new(0)),
        }
    }

    pub async fn obliterate(&self, address: Address) -> Result<(), ProtocolError> {
        lore_debug!("Initiating remote obliterate for address {address}");

        let mut retry = grpc_retry();
        let _response = loop {
            let _counter = RequestScopedCounter::new(self.request_inflight.clone());

            // `repository.obliterate` is a governed direct family.
            let mut request = tonic::Request::new(ObliterateRequest {
                address: Some(address.into()),
            });
            inject_authn_bearer(&mut request, &self.auth)?;

            let mut client = self.client.clone();

            match client.obliterate(request).await {
                Ok(response) => {
                    break response.into_inner();
                }
                Err(status) => {
                    handle_error(&mut retry, status).await?;
                }
            }
        };

        Ok(())
    }
}

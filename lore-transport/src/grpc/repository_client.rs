// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_base::error::NotFound;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_base::types::RepositoryId;
use lore_proto::lore::repository::v1 as repository_v1;
use lore_proto::lore::repository::v1::repository_service_client::RepositoryServiceClient;
use tokio_stream::StreamExt;

use super::AuthenticatedService;
use super::AuthnInterceptor;
use super::Channel;
use super::GRPCAuthRef;
use super::grpc_retry;
use super::handle_error;
use super::inject_authn_bearer;
use crate::error::ProtocolError;
use crate::types::MetadataSetResult;
use crate::types::RepositoryData;

#[derive(Clone)]
pub struct RepositoryService {
    client: RepositoryServiceClient<AuthenticatedService>,
    /// Kept beside the client so a governed mutation can stamp the human's own
    /// authentication bearer per dispatch.
    ///
    /// This service runs under [`AuthnInterceptor`], so its `authorization`
    /// header already carries that same token. The header is sent anyway: the
    /// server reads one key for every governed family, and leaving these two
    /// verbs to be recognised by which interceptor happens to sit in front of
    /// them is exactly the coupling that produced the defect this fixes.
    auth: GRPCAuthRef,
}

impl RepositoryService {
    pub fn new(channel: Channel, auth: GRPCAuthRef) -> Self {
        let client = RepositoryServiceClient::with_interceptor(
            channel,
            AuthnInterceptor { auth: auth.clone() },
        );

        Self { client, auth }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        id: RepositoryId,
        name: &str,
        description: &str,
        default_branch_id: Context,
        default_branch_name: &str,
        creator: &str,
        _created: u64,
    ) -> Result<RepositoryData, ProtocolError> {
        let mut retry = grpc_retry();
        let response = loop {
            let request = repository_v1::RepositoryCreateRequest {
                id: id.into(),
                name: name.to_string(),
                description: description.to_string(),
                default_branch_id: default_branch_id.into(),
                default_branch_name: default_branch_name.to_string(),
                creator: Some(creator.to_string()),
            };

            let mut client = self.client.clone();

            match client.repository_create(request).await {
                Ok(response) => {
                    break response.into_inner();
                }
                Err(status) => {
                    handle_error(&mut retry, status).await?;
                }
            }
        };

        let repository = response.repository.ok_or_else(|| {
            ProtocolError::internal("RepositoryCreate response missing repository")
        })?;
        Ok(RepositoryData {
            id: repository.id.into(),
            name: repository.name,
            metadata: repository.metadata.into(),
        })
    }

    pub async fn delete(&self, id: RepositoryId) -> Result<(), ProtocolError> {
        let mut retry = grpc_retry();
        let _response = loop {
            // `repository.delete` is a governed direct family.
            let mut request =
                tonic::Request::new(repository_v1::RepositoryDeleteRequest { id: id.into() });
            inject_authn_bearer(&mut request, &self.auth)?;

            let mut client = self.client.clone();

            match client.repository_delete(request).await {
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

    pub async fn query(
        &self,
        id: Option<RepositoryId>,
        name: Option<&str>,
    ) -> Result<RepositoryData, ProtocolError> {
        if id.is_none() && name.is_none() {
            return Err(ProtocolError::internal(
                "query: No query parameters specified",
            ));
        }

        let mut retry = grpc_retry();
        let response = loop {
            let query = if let Some(id) = id {
                repository_v1::repository_get_request::Query::Id(id.into())
            } else {
                repository_v1::repository_get_request::Query::Name(
                    name.unwrap_or_default().to_string(),
                )
            };
            let request = repository_v1::RepositoryGetRequest { query: Some(query) };

            let mut client = self.client.clone();

            match client.repository_get(request).await {
                Ok(response) => {
                    break response.into_inner();
                }
                Err(status) => {
                    handle_error(&mut retry, status).await?;
                }
            }
        };

        if let Some(repository) = response.repository {
            Ok(RepositoryData {
                id: repository.id.into(),
                name: repository.name,
                metadata: repository.metadata.into(),
            })
        } else {
            Err(ProtocolError::from(NotFound))
        }
    }

    pub async fn list(&self) -> Result<Vec<RepositoryData>, ProtocolError> {
        let mut retry = grpc_retry();
        let repositories = loop {
            let request = repository_v1::RepositoryListRequest { creator: None };

            let mut client = self.client.clone();

            match client.repository_list(request).await {
                Ok(response) => {
                    let mut stream = response.into_inner();
                    let mut entries: Vec<RepositoryData> = Vec::new();
                    let mut stream_err: Option<tonic::Status> = None;
                    while let Some(item) = stream.next().await {
                        match item {
                            Ok(message) => {
                                if let Some(repository) = message.repository {
                                    entries.push(RepositoryData {
                                        id: repository.id.into(),
                                        name: repository.name,
                                        metadata: repository.metadata.into(),
                                    });
                                }
                            }
                            Err(status) => {
                                stream_err = Some(status);
                                break;
                            }
                        }
                    }
                    if let Some(status) = stream_err {
                        handle_error(&mut retry, status).await?;
                        continue;
                    }
                    break entries;
                }
                Err(status) => {
                    handle_error(&mut retry, status).await?;
                }
            }
        };

        Ok(repositories)
    }

    pub async fn metadata_get(&self, id: RepositoryId) -> Result<Hash, ProtocolError> {
        let mut retry = grpc_retry();
        let response = loop {
            let request = repository_v1::RepositoryMetadataGetRequest { id: id.into() };

            let mut client = self.client.clone();

            match client.repository_metadata_get(request).await {
                Ok(response) => {
                    break response.into_inner();
                }
                Err(status) => {
                    handle_error(&mut retry, status).await?;
                }
            }
        };

        Ok(response.metadata.into())
    }

    pub async fn metadata_set(
        &self,
        id: RepositoryId,
        expected: Hash,
        new: Hash,
    ) -> Result<MetadataSetResult, ProtocolError> {
        let mut retry = grpc_retry();
        let response = loop {
            // `repository.metadata-set` is a governed direct family.
            let mut request = tonic::Request::new(repository_v1::RepositoryMetadataSetRequest {
                id: id.into(),
                expected: expected.into(),
                updated: new.into(),
            });
            inject_authn_bearer(&mut request, &self.auth)?;

            let mut client = self.client.clone();

            match client.repository_metadata_set(request).await {
                Ok(response) => {
                    break response.into_inner();
                }
                Err(status) => {
                    handle_error(&mut retry, status).await?;
                }
            }
        };

        // v1 signals CAS miss in-band: response.metadata == request.updated on hit, otherwise it is the unchanged current pointer
        let current_hash: Hash = response.metadata.into();
        let success = current_hash == new;

        Ok(MetadataSetResult {
            success,
            current_hash,
        })
    }
}

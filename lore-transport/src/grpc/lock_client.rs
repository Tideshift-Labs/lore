// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use lore_base::lore_debug;
use lore_base::types::Context;
use lore_base::types::LockData;
use lore_base::types::LockResource;
use lore_base::types::RepositoryId;
use lore_proto::lock::AdminLockRequest;
use lore_proto::lock::ForceUnlockRequest;
use lore_proto::lock::LockRequest;
use lore_proto::lock::QueryRequest;
use lore_proto::lock::StatusRequest;
use lore_proto::lock::UnlockRequest;
use lore_proto::lock::lock_service_client::LockServiceClient;
use prost::Message;
use tonic::Code;

use super::AuthorizedService;
use super::AuthzInterceptor;
use super::Channel;
use super::GRPCAuthRef;
use super::RequestScopedCounter;
use super::grpc_retry;
use super::handle_error;
use super::inject_authn_bearer;
use crate::attempt_store::AcquiredLock;
use crate::attempt_store::FencedLockResource;
use crate::attempt_store::OwnershipToken;
use crate::error::ProtocolError;

/// Project one request resource onto the wire, carrying the token the caller holds for it.
///
/// The only producer of a non-empty `expected_ownership_token`. Every other conversion in the
/// workspace fills that field with its default, deliberately: a legacy `LockResource` has no
/// token to carry, and this is the seam where one is added (CR-030, WP-120).
fn fenced_resource_to_wire(resource: &FencedLockResource) -> lore_proto::lock::Resource {
    let mut wire = lore_proto::lock::Resource::from(&resource.resource);
    if let Some(token) = resource.expected_ownership_token.as_ref() {
        wire.expected_ownership_token = token.as_bytes().clone();
    }
    wire
}

/// Read one granted lock off the wire, keeping the token it was minted with.
///
/// A malformed token width fails the whole acquire rather than being dropped: the alternative is
/// reporting a lock acquired that nothing can later release.
fn wire_to_acquired_lock(lock: lore_proto::lock::Lock) -> Result<AcquiredLock, ProtocolError> {
    let ownership_token = OwnershipToken::from_wire(lock.ownership_token.as_ref())?;
    Ok(AcquiredLock {
        lock: LockData::from(lock),
        ownership_token,
    })
}

#[derive(Debug, Clone)]
pub struct LockService {
    repository: RepositoryId,
    client: LockServiceClient<AuthorizedService>,
    /// Kept beside the client so a governed mutation can stamp the human's own
    /// authentication bearer per dispatch. The lock reads on this same client
    /// (`query`, `status`) deliberately do not.
    auth: GRPCAuthRef,
    pub request_inflight: Arc<AtomicU64>,
}

impl LockService {
    pub fn new(channel: Channel, repository: RepositoryId, auth: GRPCAuthRef) -> Self {
        let client = LockServiceClient::with_interceptor(
            channel,
            AuthzInterceptor {
                repository,
                auth: auth.clone(),
            },
        )
        .max_decoding_message_size(32 * 1024 * 1024); // 32MiB

        Self {
            repository,
            client,
            auth,
            request_inflight: Arc::new(AtomicU64::new(0)),
        }
    }

    pub async fn lock(
        &self,
        resources: &[FencedLockResource],
        owner: Option<&str>,
    ) -> Result<Vec<AcquiredLock>, ProtocolError> {
        lore_debug!("Locking resources");

        if crate::caller_operation::current_caller_operation().is_some() {
            let resources = resources.iter().map(fenced_resource_to_wire).collect();
            let mut client = self.client.clone();
            let locks = if let Some(owner) = owner {
                let message = AdminLockRequest {
                    resources,
                    owner: owner.to_string(),
                };
                let canonical = message.encode_to_vec();
                crate::caller_operation::dispatch(
                    self.repository,
                    crate::outcome::GrpcRpc::LockAdminLock,
                    canonical,
                    crate::caller_operation::current_transport_endpoint(),
                    super::authorization_snapshot(&self.auth),
                    async {
                        let mut request = tonic::Request::new(message);
                        inject_authn_bearer(&mut request, &self.auth)?;
                        Ok(client
                            .admin_lock(request)
                            .await
                            .map_err(ProtocolError::from)?
                            .into_inner()
                            .locks)
                    },
                )
                .await?
            } else {
                let message = LockRequest { resources };
                let canonical = message.encode_to_vec();
                crate::caller_operation::dispatch(
                    self.repository,
                    crate::outcome::GrpcRpc::LockLock,
                    canonical,
                    crate::caller_operation::current_transport_endpoint(),
                    super::authorization_snapshot(&self.auth),
                    async {
                        let mut request = tonic::Request::new(message);
                        inject_authn_bearer(&mut request, &self.auth)?;
                        Ok(client
                            .lock(request)
                            .await
                            .map_err(ProtocolError::from)?
                            .into_inner()
                            .locks)
                    },
                )
                .await?
            };
            return locks.into_iter().map(wire_to_acquired_lock).collect();
        }

        let _counter = RequestScopedCounter::new(self.request_inflight.clone());

        let mut retry = grpc_retry();
        let locks = loop {
            let resources = resources.iter().map(fenced_resource_to_wire).collect();

            // Both arms are governed direct families: `lock.admin-acquire` when
            // the caller locks on another's behalf, `lock.acquire` otherwise.
            if let Some(owner) = owner {
                let mut request = tonic::Request::new(AdminLockRequest {
                    resources,
                    owner: owner.to_string(),
                });
                inject_authn_bearer(&mut request, &self.auth)?;

                let mut client = self.client.clone();
                match client.admin_lock(request).await {
                    Ok(response) => {
                        break response.into_inner().locks;
                    }
                    Err(status) => handle_error(&mut retry, status).await?,
                }
            } else {
                let mut request = tonic::Request::new(LockRequest { resources });
                inject_authn_bearer(&mut request, &self.auth)?;

                let mut client = self.client.clone();
                match client.lock(request).await {
                    Ok(response) => {
                        break response.into_inner().locks;
                    }
                    Err(status) => handle_error(&mut retry, status).await?,
                }
            }
        };

        locks.into_iter().map(wire_to_acquired_lock).collect()
    }

    pub async fn query(
        &self,
        branch: Option<Context>,
        owner: Option<&str>,
        description: Option<&str>,
    ) -> Result<Vec<LockData>, ProtocolError> {
        lore_debug!("Querying resources");

        let _counter = RequestScopedCounter::new(self.request_inflight.clone());

        let mut retry = grpc_retry();
        let locks = loop {
            let request = QueryRequest {
                branch: branch.map(Context::into),
                owner: owner.map(str::to_string),
                description: description.map(str::to_string),
            };

            let mut client = self.client.clone();
            match client.query(request).await {
                Ok(response) => {
                    break response.into_inner().result;
                }
                Err(status) => handle_error(&mut retry, status).await?,
            }
        };

        Ok(locks.into_iter().map(Into::into).collect())
    }

    pub async fn status(&self, resources: &[LockResource]) -> Result<Vec<LockData>, ProtocolError> {
        lore_debug!("Fetching resource lock status");

        let _counter = RequestScopedCounter::new(self.request_inflight.clone());

        let mut retry = grpc_retry();
        let locks = loop {
            let request = StatusRequest {
                resources: resources.iter().map(Into::into).collect(),
            };

            let mut client = self.client.clone();

            match client.status(request).await {
                Ok(response) => {
                    break response.into_inner().locks;
                }
                Err(status) => handle_error(&mut retry, status).await?,
            }
        };

        Ok(locks.into_iter().map(Into::into).collect())
    }

    pub async fn unlock(
        &self,
        resources: &[FencedLockResource],
    ) -> Result<Vec<LockResource>, ProtocolError> {
        lore_debug!("Releasing resources");

        if crate::caller_operation::current_caller_operation().is_some() {
            let message = UnlockRequest {
                resources: resources.iter().map(fenced_resource_to_wire).collect(),
            };
            let result = crate::caller_operation::dispatch_recorded_result(
                self.repository,
                crate::outcome::GrpcRpc::LockUnlock,
                message.encode_to_vec(),
                crate::caller_operation::current_transport_endpoint(),
                super::authorization_snapshot(&self.auth),
                async {
                    let mut request = tonic::Request::new(message);
                    inject_authn_bearer(&mut request, &self.auth)?;
                    let mut client = self.client.clone();
                    let response = client
                        .unlock(request)
                        .await
                        .map_err(ProtocolError::from)?
                        .into_inner();
                    Ok(response.resources.into_iter().map(Into::into).collect())
                },
            )
            .await?;
            // Dispatch settles the original attempt before applying this ordinary-unlock
            // compatibility rule. Unknown outcomes and administrative releases stay errors.
            return match result {
                Err(error) if error.is_not_found() => Ok(vec![]),
                other => other,
            };
        }

        let _counter = RequestScopedCounter::new(self.request_inflight.clone());

        let mut retry = grpc_retry();
        let resources = loop {
            // `lock.release` is a governed direct family.
            let mut request = tonic::Request::new(UnlockRequest {
                resources: resources.iter().map(fenced_resource_to_wire).collect(),
            });
            inject_authn_bearer(&mut request, &self.auth)?;

            let mut client = self.client.clone();

            match client.unlock(request).await {
                Ok(response) => {
                    break response.into_inner().resources;
                }
                Err(status) => {
                    if status.code() == Code::NotFound {
                        return Ok(vec![]);
                    }
                    handle_error(&mut retry, status).await?;
                }
            }
        };

        Ok(resources.into_iter().map(Into::into).collect())
    }

    /// Administratively release locks held by `owner` (CR-030, WP-120).
    ///
    /// No ownership token is sent. The authority here is the caller's administrative permission,
    /// not possession of a secret, and an administrator holds no other owner's token because no
    /// read path issues one.
    ///
    /// `NotFound` is deliberately not swallowed the way [`Self::unlock`] swallows it. An owner
    /// releasing its own lock is content for the row to be already gone; an administrator taking
    /// a named owner's lock away asked about one specific row and should be told it was not
    /// there, because the alternative reading is that the takeover silently did nothing.
    pub async fn force_unlock(
        &self,
        resources: &[LockResource],
        owner: &str,
    ) -> Result<Vec<LockResource>, ProtocolError> {
        lore_debug!("Force-releasing resources");

        if crate::caller_operation::current_caller_operation().is_some() {
            let message = ForceUnlockRequest {
                resources: resources.iter().map(Into::into).collect(),
                owner: owner.to_string(),
            };
            return crate::caller_operation::dispatch(
                self.repository,
                crate::outcome::GrpcRpc::LockForceUnlock,
                message.encode_to_vec(),
                crate::caller_operation::current_transport_endpoint(),
                super::authorization_snapshot(&self.auth),
                async {
                    let mut request = tonic::Request::new(message);
                    inject_authn_bearer(&mut request, &self.auth)?;
                    let mut client = self.client.clone();
                    let response = client
                        .force_unlock(request)
                        .await
                        .map_err(ProtocolError::from)?
                        .into_inner();
                    Ok(response.resources.into_iter().map(Into::into).collect())
                },
            )
            .await;
        }

        let _counter = RequestScopedCounter::new(self.request_inflight.clone());

        let mut retry = grpc_retry();
        let resources = loop {
            // `lock.force-release` is a governed direct family.
            let mut request = tonic::Request::new(ForceUnlockRequest {
                resources: resources.iter().map(Into::into).collect(),
                owner: owner.to_string(),
            });
            inject_authn_bearer(&mut request, &self.auth)?;

            let mut client = self.client.clone();

            match client.force_unlock(request).await {
                Ok(response) => {
                    break response.into_inner().resources;
                }
                Err(status) => handle_error(&mut retry, status).await?,
            }
        };

        Ok(resources.into_iter().map(Into::into).collect())
    }
}

#[cfg(test)]
#[path = "lock_client_tests.rs"]
mod tests;

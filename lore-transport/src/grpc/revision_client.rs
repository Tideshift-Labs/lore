// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use lore_base::lore_debug;
use lore_base::lore_warn;
use lore_base::types::BranchId;
use lore_base::types::BranchPoint;
use lore_base::types::Hash;
use lore_base::types::RepositoryId;
use lore_proto::lore::model::v1 as model_v1;
use lore_proto::lore::revision::v1 as revision_v1;
use lore_proto::lore::revision::v1::revision_service_client::RevisionServiceClient;
use prost::Message;
use tokio_stream::StreamExt;

use super::AuthorizedService;
use super::AuthzInterceptor;
use super::Channel;
use super::GRPCAuthRef;
use super::REVISION_LIST_STRATEGY_HEADER;
use super::RequestScopedCounter;
use super::grpc_retry;
use super::handle_branch_push_error;
use super::handle_error;
use super::inject_authn_bearer;
use crate::error::BranchPushError;
use crate::error::ProtocolError;
use crate::types::BranchListResponse;
use crate::types::BranchPushResponse;
use crate::types::BranchQueryResponse;
use crate::types::BranchRecord;
use crate::types::MetadataSetResult;
use crate::types::RevisionItem;
use crate::types::RevisionListResponse;
use crate::types::RevisionListStart;

#[derive(Clone)]
pub struct RevisionService {
    client: RevisionServiceClient<AuthorizedService>,
    repository: RepositoryId,
    /// Kept beside the client so a governed mutation can stamp the human's own
    /// authentication bearer per dispatch. The interceptor holds its own clone
    /// and keeps sending the exchanged authorization token on every RPC.
    auth: GRPCAuthRef,
    pub request_inflight: Arc<AtomicU64>,
}

impl RevisionService {
    pub fn new(channel: Channel, repository: RepositoryId, auth: GRPCAuthRef) -> Self {
        let client = RevisionServiceClient::with_interceptor(
            channel,
            AuthzInterceptor {
                repository,
                auth: auth.clone(),
            },
        );

        Self {
            client,
            repository,
            auth,
            request_inflight: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Creates the branch `branch` at the remote with the given name, category, creator and stack,
    /// and returns the remote's record of it.
    pub async fn branch_create(
        &self,
        branch: BranchId,
        name: &str,
        category: &str,
        creator: &str,
        stack: &[BranchPoint],
    ) -> Result<BranchRecord, ProtocolError> {
        lore_debug!("Creating remote branch {name} ({branch}) with stack {stack:?}");
        if crate::caller_operation::current_caller_operation().is_some() {
            let message = revision_v1::BranchCreateRequest {
                id: branch.into(),
                name: name.to_owned(),
                creator: Some(creator.to_owned()),
                category: category.to_owned(),
                stack: stack.iter().map(model_v1::BranchPoint::from).collect(),
            };
            return crate::caller_operation::dispatch(
                self.repository,
                crate::outcome::GrpcRpc::RevisionBranchCreate,
                message.encode_to_vec(),
                crate::caller_operation::current_transport_endpoint(),
                super::authorization_snapshot(&self.auth),
                async {
                    let mut request = tonic::Request::new(message);
                    inject_authn_bearer(&mut request, &self.auth)?;
                    let attempt = crate::outcome::current_dispatch_attempt().ok_or_else(|| {
                        ProtocolError::internal("BranchCreate managed attempt missing")
                    })?;
                    let _counter = RequestScopedCounter::new(self.request_inflight.clone());
                    let mut client = self.client.clone();
                    let response = client
                        .branch_create(request)
                        .await
                        .map_err(ProtocolError::from)?
                        .into_inner();
                    decode_created_branch(response, branch).map_err(|_err| {
                        crate::outcome::outcome_unknown("BranchCreate malformed response", &attempt)
                    })
                },
            )
            .await;
        }
        let _counter = RequestScopedCounter::new(self.request_inflight.clone());

        let mut retry = grpc_retry();
        let response = loop {
            let mut request = tonic::Request::new(revision_v1::BranchCreateRequest {
                id: branch.into(),
                name: name.to_string(),
                creator: Some(creator.to_string()),
                category: category.to_string(),
                stack: stack.iter().map(model_v1::BranchPoint::from).collect(),
            });
            inject_authn_bearer(&mut request, &self.auth)?;

            let mut client = self.client.clone();

            match client.branch_create(request).await {
                Ok(response) => {
                    break response.into_inner();
                }
                Err(status) => {
                    handle_error(&mut retry, status).await?;
                }
            }
        };

        decode_created_branch(response, branch)
    }

    pub async fn branch_delete(&self, branch: BranchId) -> Result<(), ProtocolError> {
        lore_debug!("Deleting remote branch {}", branch);
        let _counter = RequestScopedCounter::new(self.request_inflight.clone());

        let mut retry = grpc_retry();
        let _response = loop {
            // Not one of the ten families the platform's operation verifier
            // accepts, and yet it carries the bearer, because the header tracks
            // which calls enter loreserver's admission gate rather than which
            // families the verifier names. `branch_delete`'s handler calls
            // `admit_at_entry` exactly as `branch_push` does (WP-119 writer
            // inventory B4). Omitting the header here would replace WP-116's
            // "this family is not wired" refusal with a carriage refusal telling
            // the operator to upgrade a client that is already current.
            let mut request =
                tonic::Request::new(revision_v1::BranchDeleteRequest { id: branch.into() });
            inject_authn_bearer(&mut request, &self.auth)?;

            let mut client = self.client.clone();

            match client.branch_delete(request).await {
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

    /// The records of the remote's live branches, and its archived ones when `include_deleted` is
    /// set, limited to those `creator` created when it is given.
    pub async fn branch_list(
        &self,
        creator: Option<&str>,
        include_deleted: bool,
    ) -> Result<BranchListResponse, ProtocolError> {
        self.branch_list_with_limit(creator, include_deleted, None)
            .await
            .and_then(|response| {
                response.ok_or_else(|| {
                    ProtocolError::internal("unbounded branch listing exceeded a limit")
                })
            })
    }

    /// The records of the remote's live branches, or `None` when it has more than `limit`.
    pub async fn branch_list_bounded(
        &self,
        limit: usize,
    ) -> Result<Option<BranchListResponse>, ProtocolError> {
        self.branch_list_with_limit(None, false, Some(limit)).await
    }

    async fn branch_list_with_limit(
        &self,
        creator: Option<&str>,
        include_deleted: bool,
        limit: Option<usize>,
    ) -> Result<Option<BranchListResponse>, ProtocolError> {
        lore_debug!("List branches: creator[{creator:?}] / include_deleted[{include_deleted}]");
        let _counter = RequestScopedCounter::new(self.request_inflight.clone());

        let mut retry = grpc_retry();
        let list = loop {
            let request = revision_v1::BranchListRequest {
                creator: creator.map(str::to_string),
                include_deleted,
            };

            let mut client = self.client.clone();

            let status = match client.branch_list(request).await {
                Ok(response) => match collect_branch_list(response.into_inner(), limit).await {
                    Ok(response) => break response,
                    Err(status) => status,
                },
                Err(status) => status,
            };
            // Not in `handle_error`: a command that sends many calls at once would warn for each.
            if let Some(reason) = first_throttle_reason(&retry.retry, &status) {
                lore_warn!("Remote is throttling the branch listing: {reason}");
            }
            handle_error(&mut retry, status).await?;
        };

        Ok(list)
    }

    /// The remote's record of the branch with id `branch`, or of the live branch named `name` when
    /// `branch` is `None`. The record carries the queried id where the answer has none.
    pub async fn branch_query(
        &self,
        branch: Option<BranchId>,
        name: Option<&str>,
    ) -> Result<BranchQueryResponse, ProtocolError> {
        lore_debug!(
            "Query branch: id[{:?}] / name[{:?}] in repository {}",
            branch,
            name,
            self.repository
        );
        let _counter = RequestScopedCounter::new(self.request_inflight.clone());

        let mut retry = grpc_retry();
        let (branch_record, generation) = loop {
            let query = if let Some(branch) = branch {
                revision_v1::branch_get_request::Query::Id(branch.into())
            } else {
                revision_v1::branch_get_request::Query::Name(name.unwrap_or_default().to_string())
            };
            let request = revision_v1::BranchGetRequest { query: Some(query) };

            let mut client = self.client.clone();

            match client.branch_get(request).await {
                Ok(response) => match response.into_inner() {
                    revision_v1::BranchGetResponse {
                        branch: Some(branch),
                        branch_generation,
                    } => break (branch, branch_generation),
                    revision_v1::BranchGetResponse { branch: None, .. } => {
                        return Err(ProtocolError::internal("BranchGet response missing branch"));
                    }
                },
                Err(status) => {
                    handle_error(&mut retry, status).await?;
                }
            }
        };

        let mut record = branch_record_from_v1(branch_record);
        if record.id.is_zero()
            && let Some(branch) = branch
        {
            record.id = branch;
        }
        lore_debug!(
            "Query branch: id[{:?}] / name[{:?}] in repository {} complete: ID {} latest {} metadata {}",
            branch,
            name,
            self.repository,
            record.id,
            record.latest,
            record.metadata,
        );

        record.generation = generation;
        Ok(record)
    }

    pub async fn branch_push(
        &self,
        branch: BranchId,
        revision: Hash,
        force: bool,
        fast_forward_merge: bool,
    ) -> Result<BranchPushResponse, BranchPushError> {
        lore_debug!("Pushing branch: {} at {}", branch, revision);
        // FORK-LOCAL (Tideshift, WP-120): the managed path journals and settles through
        // `caller_operation::dispatch`, which speaks `ProtocolError`. The remote's marked refusal
        // of a push onto a moved latest is kept aside and mapped by `branch_push_error` once the
        // attempt is settled (a refusal settles as not applied), so it stays `BranchAdvanced`.
        // An unknown outcome keeps its own variant through the strict forward.
        if crate::caller_operation::current_caller_operation().is_some() {
            let message = revision_v1::BranchPushRequest {
                id: branch.into(),
                revision_signature: revision.into(),
                force,
                fast_forward_merge,
            };
            let refusal: std::sync::Mutex<Option<tonic::Status>> = std::sync::Mutex::new(None);
            // `dispatch_recorded_result`, not `dispatch`: a journal failure (the outer error) is
            // returned as it is, and only the RPC's own refusal is read as `BranchAdvanced`.
            let result = crate::caller_operation::dispatch_recorded_result(
                self.repository,
                crate::outcome::GrpcRpc::RevisionBranchPush,
                message.encode_to_vec(),
                crate::caller_operation::current_transport_endpoint(),
                super::authorization_snapshot(&self.auth),
                async {
                    let mut request = tonic::Request::new(message);
                    inject_authn_bearer(&mut request, &self.auth)?;
                    let mut client = self.client.clone();
                    let response = match client.branch_push(request).await {
                        Ok(response) => response.into_inner(),
                        Err(status) => {
                            // CR-019's lock refusal is kept aside the same way, so it stays
                            // `LockNotOwned` rather than `NotAuthorized` once settled.
                            if matches!(
                                crate::error::branch_push_error(status.clone()),
                                BranchPushError::BranchAdvanced(_)
                                    | BranchPushError::LockNotOwned(_)
                            ) && let Ok(mut kept) = refusal.lock()
                            {
                                *kept = Some(status.clone());
                            }
                            return Err(ProtocolError::from(status));
                        }
                    };
                    Ok(BranchPushResponse {
                        fast_forward_merged: response.fast_forward_merged,
                        revision: response.revision_signature.into(),
                        revision_number: response.revision_number,
                        message: response.message,
                    })
                },
            )
            .await
            .map_err(BranchPushError::from)?;
            return match result {
                Ok(response) => Ok(response),
                Err(err) if !err.is_outcome_unknown() => {
                    match refusal.lock().ok().and_then(|mut kept| kept.take()) {
                        Some(status) => Err(crate::error::branch_push_error(status)),
                        None => Err(BranchPushError::from(err)),
                    }
                }
                Err(err) => Err(BranchPushError::from(err)),
            };
        }
        let _counter = RequestScopedCounter::new(self.request_inflight.clone());

        let mut retry = grpc_retry();
        let response = loop {
            // `branch.push` is a governed direct family, so it carries the human
            // authn bearer beside the exchanged authorization token. Built inside
            // the loop so a token the refresher replaced mid-retry is picked up.
            let mut request = tonic::Request::new(revision_v1::BranchPushRequest {
                id: branch.into(),
                revision_signature: revision.into(),
                force,
                fast_forward_merge,
            });
            inject_authn_bearer(&mut request, &self.auth).map_err(ProtocolError::from)?;

            let mut client = self.client.clone();
            match client.branch_push(request).await {
                Ok(response) => {
                    break response.into_inner();
                }
                Err(status) => handle_branch_push_error(&mut retry, status).await?,
            }
        };

        Ok(BranchPushResponse {
            fast_forward_merged: response.fast_forward_merged,
            revision: response.revision_signature.into(),
            revision_number: response.revision_number,
            message: response.message,
        })
    }

    pub async fn revision_list(
        &self,
        signature: impl Into<RevisionListStart>,
    ) -> Result<RevisionListResponse, ProtocolError> {
        let _counter = RequestScopedCounter::new(self.request_inflight.clone());

        let signature = signature.into();

        let mut retry = grpc_retry();
        let response = loop {
            let start = match signature.clone() {
                RevisionListStart::Identifier(ident) => {
                    revision_v1::revision_list_request::Start::Identifier(
                        model_v1::RevisionIdentifier {
                            branch_id: ident.branch.into(),
                            number: ident.number,
                        },
                    )
                }
                RevisionListStart::Signature(sig) => {
                    revision_v1::revision_list_request::Start::Signature(sig.into())
                }
            };
            let request = revision_v1::RevisionListRequest { start: Some(start) };

            let mut client = self.client.clone();

            match client.revision_list(request).await {
                Ok(response) => {
                    if let Some(strategy) = response.metadata().get(REVISION_LIST_STRATEGY_HEADER) {
                        lore_debug!(
                            "Revision list strategy: {}",
                            strategy.to_str().unwrap_or("unknown")
                        );
                    }
                    break response.into_inner();
                }
                Err(status) => handle_error(&mut retry, status).await?,
            }
        };

        let revision_v1::RevisionListResponse {
            items,
            signature_forward,
            signature_backward,
        } = response;
        Ok(RevisionListResponse {
            items: items
                .into_iter()
                .map(|item| RevisionItem {
                    number: item.number,
                    signature: item.signature.into(),
                    metadata: item.metadata.into(),
                    state: item.state,
                })
                .collect(),
            next_revision: signature_backward.map_or_default(Into::into),
            previous_revision: signature_forward.map_or_default(Into::into),
        })
    }

    pub async fn branch_metadata_get(&self, branch: BranchId) -> Result<Hash, ProtocolError> {
        lore_debug!("Getting branch metadata for {}", branch);
        let _counter = RequestScopedCounter::new(self.request_inflight.clone());

        let mut retry = grpc_retry();
        let response = loop {
            let request = revision_v1::BranchMetadataGetRequest { id: branch.into() };

            let mut client = self.client.clone();

            match client.branch_metadata_get(request).await {
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

    pub async fn branch_metadata_set(
        &self,
        branch: BranchId,
        expected: Hash,
        new: Hash,
    ) -> Result<MetadataSetResult, ProtocolError> {
        lore_debug!("Setting branch metadata for {}", branch);
        let _counter = RequestScopedCounter::new(self.request_inflight.clone());

        let mut retry = grpc_retry();
        let response = loop {
            // `branch.metadata-set` is a governed direct family. See `branch_push`.
            let mut request = tonic::Request::new(revision_v1::BranchMetadataSetRequest {
                id: branch.into(),
                expected: expected.into(),
                updated: new.into(),
            });
            inject_authn_bearer(&mut request, &self.auth)?;

            let mut client = self.client.clone();

            match client.branch_metadata_set(request).await {
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

/// The record a branch create answered with, refused unless it names xpected and carries
/// well-formed hashes.
fn decode_created_branch(
    response: revision_v1::BranchCreateResponse,
    expected: BranchId,
) -> Result<BranchRecord, ProtocolError> {
    let branch = response
        .branch
        .ok_or_else(|| ProtocolError::internal("BranchCreate response missing branch"))?;
    if branch.id.as_ref() != expected.data().as_slice()
        || branch.latest.len() != 32
        || branch.metadata.len() != 32
    {
        return Err(ProtocolError::internal(
            "BranchCreate response has invalid identifiers",
        ));
    }
    Ok(branch_record_from_v1(branch))
}

/// The branch record a response carries, taking its strings as they arrived.
#[lore_macro::test_pub]
fn branch_record_from_v1(branch: model_v1::Branch) -> BranchRecord {
    BranchRecord {
        id: BranchId::from(branch.id),
        name: branch.name,
        category: branch.category,
        creator: branch.creator,
        created: branch.created,
        latest: branch.latest.into(),
        metadata: branch.metadata.into(),
        deleted: branch.deleted,
        stack: branch.stack.into_iter().map(BranchPoint::from).collect(),
        // Only a branch query carries the domain generation (WP-120).
        generation: None,
    }
}

/// The remote's reason for the first `RESOURCE_EXHAUSTED` answer of a call. `None` for a later
/// answer of the same call, which would repeat the reason, and where the remote gave none.
#[lore_macro::test_pub]
fn first_throttle_reason<'a>(
    retry: &crate::util::Retry,
    status: &'a tonic::Status,
) -> Option<&'a str> {
    // FORK-LOCAL (Tideshift): a sourced `RESOURCE_EXHAUSTED` is a lost answer (an h2
    // `ENHANCE_YOUR_CALM`), not the server throttling, so it gets no throttle warning.
    (status.code() == tonic::Code::ResourceExhausted
        && std::error::Error::source(status).is_none()
        && retry.counter() == 0
        && !status.message().is_empty())
    .then(|| status.message())
}

#[lore_macro::test_pub]
async fn collect_branch_list(
    mut stream: impl tokio_stream::Stream<Item = Result<revision_v1::BranchListResponse, tonic::Status>>
    + Unpin,
    limit: Option<usize>,
) -> Result<Option<BranchListResponse>, tonic::Status> {
    let mut entries = Vec::new();
    while let Some(item) = stream.next().await {
        if let Some(branch) = item?.branch {
            if limit.is_some_and(|limit| entries.len() == limit) {
                return Ok(None);
            }
            entries.push(branch_record_from_v1(branch));
        }
    }
    Ok(Some(BranchListResponse { list: entries }))
}

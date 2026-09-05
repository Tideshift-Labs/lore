// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Ordinary, ungoverned gRPC clients: create, read, lock, obliterate.
//!
//! Everything here is a stock request — a bearer token and the repository in
//! binary metadata, nothing else. That is deliberate: these are the calls a
//! released client can actually make, so a case built on them is evidence about
//! the product rather than about the harness. The one call that needs more,
//! the governed push, lives in [`super::carriage`] and says why.

use lore_proto::LockServiceClient;
use lore_proto::lock::LockRequest;
use lore_proto::lock::LockResponse;
use lore_proto::lock::Resource;
use lore_proto::lock::UnlockRequest;
use lore_proto::lock::UnlockResponse;
use lore_proto::lore::repository::v1::RepositoryCreateRequest;
use lore_proto::lore::repository::v1::RepositoryCreateResponse;
use lore_proto::lore::repository::v1::RepositoryGetRequest;
use lore_proto::lore::repository::v1::RepositoryGetResponse;
use lore_proto::lore::repository::v1::repository_get_request;
use lore_proto::lore::repository::v1::repository_service_client::RepositoryServiceClient;
use lore_server::grpc::domain_operation_metadata::ATTEMPT_ID_KEY;
use tonic::Request;
use tonic::Status;
use tonic::metadata::BinaryMetadataValue;

const PARTITION_ID_KEY: &str = "lore-partition-bin";
const REPOSITORY_ID_KEY: &str = "urc-repository-id-bin";

/// Attach the bearer token, and the repository when the call is repo-scoped.
///
/// `RepositoryCreate` runs under the authn-only interceptor and reads its
/// target from the body, so it needs no repository metadata; sending it anyway
/// is harmless and keeps one helper instead of two that could drift.
fn decorate<T>(request: &mut Request<T>, token: &str, repository: Option<&[u8]>) {
    let metadata = request.metadata_mut();
    metadata.insert(
        "authorization",
        format!("Bearer {token}")
            .parse()
            .expect("a bearer header is ASCII"),
    );
    if let Some(repository) = repository {
        metadata.insert_bin(
            PARTITION_ID_KEY,
            BinaryMetadataValue::from_bytes(repository),
        );
        metadata.insert_bin(
            REPOSITORY_ID_KEY,
            BinaryMetadataValue::from_bytes(repository),
        );
    }
}

/// Create a repository through one process.
#[allow(clippy::too_many_arguments)]
pub async fn repository_create(
    endpoint: String,
    token: &str,
    repository_id: &[u8],
    name: &str,
    default_branch_id: &[u8],
    default_branch_name: &str,
) -> Result<RepositoryCreateResponse, Status> {
    let mut client = RepositoryServiceClient::connect(endpoint)
        .await
        .map_err(|error| Status::unavailable(format!("dial the process: {error}")))?;
    let mut request = Request::new(RepositoryCreateRequest {
        id: repository_id.to_vec().into(),
        name: name.to_owned(),
        description: "WP-109 Phase 3 two-process proof".to_owned(),
        default_branch_id: default_branch_id.to_vec().into(),
        default_branch_name: default_branch_name.to_owned(),
        creator: Some("wp109-harness".to_owned()),
    });
    decorate(&mut request, token, Some(repository_id));
    client
        .repository_create(request)
        .await
        .map(|response| response.into_inner())
}

/// Read a repository back through one process, by id.
pub async fn repository_get(
    endpoint: String,
    token: &str,
    repository_id: &[u8],
) -> Result<RepositoryGetResponse, Status> {
    let mut client = RepositoryServiceClient::connect(endpoint)
        .await
        .map_err(|error| Status::unavailable(format!("dial the process: {error}")))?;
    let mut request = Request::new(RepositoryGetRequest {
        query: Some(repository_get_request::Query::Id(
            repository_id.to_vec().into(),
        )),
    });
    decorate(&mut request, token, Some(repository_id));
    client
        .repository_get(request)
        .await
        .map(|response| response.into_inner())
}

/// Acquire one lock through a process.
///
/// A refusal is a gRPC status, not a field on the response
/// (`lore-server/src/grpc/lock_service.rs:87` maps `LockNotOwned` to
/// `FAILED_PRECONDITION`), so the `Result` is returned rather than unwrapped.
pub async fn lock_acquire(
    endpoint: String,
    token: &str,
    repository_id: &[u8],
    branch_id: &[u8],
    hash: &[u8],
    description: &str,
) -> Result<LockResponse, Status> {
    let mut client = LockServiceClient::connect(endpoint)
        .await
        .map_err(|error| Status::unavailable(format!("dial the process: {error}")))?;
    let mut request = Request::new(LockRequest {
        resources: vec![Resource {
            branch: branch_id.to_vec().into(),
            hash: hash.to_vec().into(),
            description: description.to_owned(),
            // A first acquire presents no token; the server mints one and
            // returns it on the response's `Lock.ownership_token`.
            expected_ownership_token: Default::default(),
        }],
    });
    decorate(&mut request, token, Some(repository_id));
    client
        .lock(request)
        .await
        .map(|response| response.into_inner())
}

/// Release one lock through a process.
///
/// `ownership_token`: empty is correct for the UNARMED cell most cases run against -- the legacy
/// lock store ignores the field entirely. An armed cell REQUIRES it and answers
/// `INVALID_ARGUMENT` without one; a case that arms fenced routing takes the token off the
/// acquire response's `Lock.ownership_token` and threads it here (CR-030, WP-120).
#[allow(clippy::too_many_arguments)]
pub async fn lock_release(
    endpoint: String,
    token: &str,
    repository_id: &[u8],
    branch_id: &[u8],
    hash: &[u8],
    ownership_token: &[u8],
) -> Result<UnlockResponse, Status> {
    let mut client = LockServiceClient::connect(endpoint)
        .await
        .map_err(|error| Status::unavailable(format!("dial the process: {error}")))?;
    let mut request = Request::new(UnlockRequest {
        resources: vec![Resource {
            branch: branch_id.to_vec().into(),
            hash: hash.to_vec().into(),
            description: String::new(),
            expected_ownership_token: ownership_token.to_vec().into(),
        }],
    });
    decorate(&mut request, token, Some(repository_id));
    client
        .unlock(request)
        .await
        .map(|response| response.into_inner())
}

/// Push a branch with NO governed carriage, the way a released client does.
///
/// This is the whole released-client shape WP-120 built: no operation id, no
/// fingerprint, no prepare token — only a bearer, the repository, and the
/// client's own attempt identity. On an enforcing cell with a configured
/// verifier, loreserver mints the operation identity itself, asks the
/// authorizer whether this human may perform this mutation, and runs the same
/// prepare-then-consume rail a mediated operation runs.
///
/// `attempt_id` travels as ASCII in `lore-attempt-id` (not a `-bin` key, and
/// not the raw sixteen bytes): `extract_attempt_id` reads it with `read_ascii`
/// and parses it with `Uuid::parse_str`. It must be a UUIDv7 — the receipt rail
/// classifies replay by the embedded timestamp, so a non-v7 value is refused
/// rather than filed as an identity nothing can order.
pub async fn branch_push_no_carriage(
    endpoint: String,
    token: &str,
    repository_id: &[u8],
    branch_id: &[u8],
    revision: &[u8],
    attempt_id: uuid::Uuid,
) -> Result<lore_proto::lore::revision::v1::BranchPushResponse, Status> {
    let mut client =
        lore_proto::lore::revision::v1::revision_service_client::RevisionServiceClient::connect(
            endpoint,
        )
        .await
        .map_err(|error| Status::unavailable(format!("dial the process: {error}")))?;
    let mut request = Request::new(lore_proto::lore::revision::v1::BranchPushRequest {
        id: branch_id.to_vec().into(),
        revision_signature: revision.to_vec().into(),
        force: false,
        fast_forward_merge: false,
    });
    decorate(&mut request, token, Some(repository_id));
    request.metadata_mut().insert(
        ATTEMPT_ID_KEY,
        attempt_id
            .to_string()
            .parse()
            .expect("a UUID's text form is ASCII"),
    );
    client
        .branch_push(request)
        .await
        .map(|response| response.into_inner())
}

/// Read back the receipt for one attempt, by the identity the client minted.
///
/// The one method on the private `DomainOperationService` an ordinary human may
/// call. Every sibling demands the control-plane service account; this one
/// takes the receipt namespace from the verified JWT and the request carries
/// nothing but the attempt id, so a caller cannot name a namespace and an
/// attempt belonging to someone else answers exactly as one that never existed.
///
/// Mounted on the same gRPC port as everything else here, and only on a cell
/// with a domain coordinator, JWT authentication, and a configured `auth_url`
/// (`grpc::server::domain_operation_service_available`).
pub async fn attempt_receipt_get(
    endpoint: String,
    token: &str,
    attempt_id: uuid::Uuid,
) -> Result<lore_proto::lore::domain::v1::DomainOperationAttemptReceiptGetResponse, Status> {
    let mut client =
        lore_proto::lore::domain::v1::domain_operation_service_client::DomainOperationServiceClient::connect(endpoint)
            .await
            .map_err(|error| Status::unavailable(format!("dial the process: {error}")))?;
    let mut request = Request::new(
        lore_proto::lore::domain::v1::DomainOperationAttemptReceiptGetRequest {
            client_attempt_id: attempt_id.as_bytes().to_vec().into(),
        },
    );
    // No repository metadata: this RPC is scoped by the verified principal, not
    // by a partition, and sending one would suggest otherwise.
    decorate(&mut request, token, None);
    client
        .domain_operation_attempt_receipt_get(request)
        .await
        .map(|response| response.into_inner())
}

/// Obliterate one address through a process.
///
/// `AdminService` is mounted without an interceptor and authenticates in band
/// (`lore-server/src/grpc/handlers/obliterate.rs:40-50`), so the bearer header
/// is still what the call is admitted on.
pub async fn obliterate(
    endpoint: String,
    token: &str,
    repository_id: &[u8],
    hash: &[u8],
    context: &[u8],
) -> Result<(), Status> {
    let mut client = lore_proto::AdminServiceClient::connect(endpoint)
        .await
        .map_err(|error| Status::unavailable(format!("dial the process: {error}")))?;
    let mut request = Request::new(lore_proto::model::ObliterateRequest {
        address: Some(lore_proto::model::Address {
            hash: hash.to_vec().into(),
            context: context.to_vec().into(),
        }),
    });
    decorate(&mut request, token, Some(repository_id));
    client.obliterate(request).await.map(|_| ())
}

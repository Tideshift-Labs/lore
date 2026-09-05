// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Governed carriage, and the gRPC clients that carry it.
//!
//! # Why the harness mints its own carriage
//!
//! A branch push appends an outbox row only on the governed path
//! (`lore-server/src/grpc/handlers/branch_push.rs:550`), and the governed path
//! is entered only when the request carries CR-029 operation identity in gRPC
//! request metadata: a UUIDv7 operation id, a versioned fingerprint, and a
//! 32-byte single-use prepare token.
//!
//! The prepare token comes from `domain_operation_prepare`. In production that
//! call is made by the control plane through the private
//! `lore.domain.v1.DomainOperationService`, which loreserver mounts only when
//! `[environment.endpoint] auth_url` is set and which then verifies every
//! prepare through an auth-grpc ReBAC callback
//! (`lore-server/src/grpc/server.rs:100-106,729-746`). There is no released
//! client that mints carriage, so no stock client can produce an outbox row —
//! that is a real gap, reported as such, not something this harness papers
//! over. What it does instead is what `run-domain-enforcement-live.ps1`'s cases
//! do: prepare the operation directly against the coordinator, on the same
//! database, and then send the resulting carriage over the wire.
//!
//! The binding is not free-form. `canonical_intent_digest` is recomputed
//! server-side from the request and compared, so the harness has to agree with
//! the server byte for byte or the operation is refused. The fingerprint, by
//! contrast, is opaque to the server — it splits the version byte, checks the
//! length, and stores it — so it is caller-chosen here and only has to match
//! between the prepared row and the header.

use lore_postgres::domain::coordinator::DomainTransactionStore;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptKey;
use lore_proto::lore::repository::v1::RepositoryCreateRequest;
use lore_proto::lore::repository::v1::RepositoryCreateResponse;
use lore_proto::lore::repository::v1::repository_service_client::RepositoryServiceClient;
use lore_proto::lore::revision::v1::BranchPushRequest;
use lore_proto::lore::revision::v1::BranchPushResponse;
use lore_proto::lore::revision::v1::revision_service_client::RevisionServiceClient;
use lore_server::domain_intent::CanonicalIntent;
use lore_server::domain_intent::canonical_intent_digest;
use lore_server::grpc::domain_operation_metadata::FINGERPRINT_KEY;
use lore_server::grpc::domain_operation_metadata::FINGERPRINT_VERSION_V1;
use lore_server::grpc::domain_operation_metadata::OPERATION_ID_KEY;
use lore_server::grpc::domain_operation_metadata::PREPARE_TOKEN_KEY;
use lore_server::grpc::domain_operation_metadata::scope_key_repository_create;
use lore_server::grpc::domain_operation_metadata::scope_key_target_repository;
use tonic::Request;
use tonic::Status;
use tonic::metadata::BinaryMetadataValue;
use uuid::NoContext;
use uuid::Timestamp;
use uuid::Uuid;

use super::backend::SharedBackend;

/// The metadata key both the partition interceptor and the repository lookup
/// read, from `lore-transport/src/grpc/mod.rs:63-64`.
const PARTITION_ID_KEY: &str = "lore-partition-bin";
const REPOSITORY_ID_KEY: &str = "urc-repository-id-bin";

/// The method name the server binds a governed push under.
///
/// It has to match `.complete_governed(admitted, PLATFORM_METHOD_BRANCH_PUSH, ..)`
/// exactly: the binding is compared, not merely recorded. Sourced from the
/// server's own reserved-method table (fork commit 870e4ca) rather than
/// retyped here, so it cannot drift a third time.
const PUSH_METHOD: &str = lore_server::domain::PLATFORM_METHOD_BRANCH_PUSH;

/// The method name the server binds a governed repository create under.
/// Sourced from the server's own reserved-method table for the same reason
/// [`PUSH_METHOD`] is.
const CREATE_METHOD: &str = lore_server::domain::PLATFORM_METHOD_REPOSITORY_CREATE;

/// A prepared governed operation, ready to be put on the wire.
#[derive(Debug, Clone)]
pub struct Carriage {
    pub operation_id: Uuid,
    pub fingerprint: [u8; 32],
    pub prepare_token: [u8; 32],
}

/// Prepare a governed branch push against the shared coordinator.
///
/// `subject` and the minter's issuer become the receipt namespace, so two
/// racing writers that pass different subjects here are genuinely different
/// principals rather than one principal retrying.
#[allow(clippy::too_many_arguments)]
pub async fn prepare_push(
    backend: &SharedBackend,
    issuer: &str,
    subject: &str,
    repository_id: &[u8],
    branch_id: &[u8],
    requested_revision: &[u8],
    force: bool,
    fast_forward_merge: bool,
    fingerprint_seed: u8,
) -> Carriage {
    let scope = scope_key_target_repository(repository_id)
        .expect("a 16-byte repository id yields a canonical scope key");
    let digest = canonical_intent_digest(&CanonicalIntent::BranchPush {
        repository_id,
        branch_id,
        requested_revision,
        force,
        fast_forward_merge,
    })
    .expect("the canonical branch-push intent must encode");
    prepare_bound(
        backend,
        issuer,
        subject,
        scope,
        PUSH_METHOD,
        digest,
        fingerprint_seed,
    )
    .await
}

/// Prepare a governed repository create.
///
/// The governed cases need this, not merely the ordinary create RPC, because a
/// governed push reads the repository and branch out of the DOMAIN projection
/// and refuses `NOT_FOUND` when either is absent
/// (`lore-server/src/grpc/handlers/branch_push.rs:421-434`). A legacy create
/// writes the generic mutable store and no domain row at all, so a push after
/// one would be refused for a reason that has nothing to do with the race.
///
/// The `creator` argument must be exactly what the request body carries: the
/// server recomputes the digest from the wire values, and `Some("")` and `None`
/// are different intents.
#[allow(clippy::too_many_arguments)]
pub async fn prepare_repository_create(
    backend: &SharedBackend,
    issuer: &str,
    subject: &str,
    repository_id: &[u8],
    name: &str,
    description: &str,
    default_branch_id: &[u8],
    default_branch_name: &str,
    creator: Option<&str>,
    fingerprint_seed: u8,
) -> Carriage {
    let scope = scope_key_repository_create(repository_id)
        .expect("a 16-byte repository id yields a canonical create scope key");
    let digest = canonical_intent_digest(&CanonicalIntent::RepositoryCreate {
        repository_id,
        name,
        description,
        default_branch_id,
        default_branch_name,
        creator,
        caller_created: None,
    })
    .expect("the canonical repository-create intent must encode");
    prepare_bound(
        backend,
        issuer,
        subject,
        scope,
        CREATE_METHOD,
        digest,
        fingerprint_seed,
    )
    .await
}

/// The shared tail of both prepare helpers.
async fn prepare_bound(
    backend: &SharedBackend,
    issuer: &str,
    subject: &str,
    scope: Vec<u8>,
    method: &str,
    canonical_intent_digest: Vec<u8>,
    fingerprint_seed: u8,
) -> Carriage {
    // The operation id must be a UUIDv7 whose timestamp the coordinator will
    // accept, and the coordinator's clock is the database's, not this machine's.
    // Reading it is one round trip and removes a whole class of clock-skew
    // failure that would present as an unexplained refusal.
    let clock = backend
        .domain
        .domain_operation_clock_get()
        .await
        .expect("read the coordinator's database clock");
    let elapsed = clock
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .expect("the database clock follows the epoch");
    let operation_id = Uuid::new_v7(Timestamp::from_unix(
        NoContext,
        elapsed.as_secs(),
        elapsed.subsec_nanos(),
    ));

    let fingerprint = [fingerprint_seed; 32];
    let key = ReceiptKey {
        verified_issuer: issuer.to_owned(),
        authenticated_subject: subject.to_owned(),
        tenant_scope_key: scope.clone(),
        operation_id,
    };
    let binding = OperationBinding {
        method: method.to_owned(),
        scope,
        fingerprint_version: i32::from(FINGERPRINT_VERSION_V1),
        fingerprint: fingerprint.to_vec(),
        canonical_intent_digest,
    };
    let prepared = backend
        .domain
        .domain_operation_prepare(&key, &binding, None)
        .await
        .expect("prepare the governed operation");
    let PrepareResult::Prepared { token, .. } = prepared else {
        panic!("an admissible governed operation must prepare, got {prepared:?}");
    };
    Carriage {
        operation_id,
        fingerprint,
        prepare_token: token,
    }
}

/// A governed `RepositoryCreate` request.
///
/// Every argument is a distinct field of the frozen canonical create intent,
/// and each one has to match what `prepare_repository_create` hashed or the
/// server refuses the binding. Grouping them into a struct would move the
/// pairing further from the call site without removing a single value.
#[allow(clippy::too_many_arguments)]
pub fn create_request(
    token: &str,
    repository_id: &[u8],
    name: &str,
    description: &str,
    default_branch_id: &[u8],
    default_branch_name: &str,
    creator: Option<&str>,
    carriage: &Carriage,
) -> Request<RepositoryCreateRequest> {
    let mut request = Request::new(RepositoryCreateRequest {
        id: repository_id.to_vec().into(),
        name: name.to_owned(),
        description: description.to_owned(),
        default_branch_id: default_branch_id.to_vec().into(),
        default_branch_name: default_branch_name.to_owned(),
        creator: creator.map(str::to_owned),
    });
    decorate(request.metadata_mut(), token, repository_id, Some(carriage));
    request
}

/// Send one governed `RepositoryCreate`.
pub async fn repository_create(
    endpoint: String,
    request: Request<RepositoryCreateRequest>,
) -> Result<RepositoryCreateResponse, Status> {
    let mut client = RepositoryServiceClient::connect(endpoint)
        .await
        .map_err(|error| Status::unavailable(format!("dial the process: {error}")))?;
    client
        .repository_create(request)
        .await
        .map(|response| response.into_inner())
}

/// Attach the bearer token, the repository, and any carriage.
fn decorate(
    metadata: &mut tonic::metadata::MetadataMap,
    token: &str,
    repository_id: &[u8],
    carriage: Option<&Carriage>,
) {
    metadata.insert(
        "authorization",
        format!("Bearer {token}")
            .parse()
            .expect("a bearer header is ASCII"),
    );
    metadata.insert_bin(
        PARTITION_ID_KEY,
        BinaryMetadataValue::from_bytes(repository_id),
    );
    metadata.insert_bin(
        REPOSITORY_ID_KEY,
        BinaryMetadataValue::from_bytes(repository_id),
    );
    if let Some(carriage) = carriage {
        metadata.insert_bin(
            OPERATION_ID_KEY,
            BinaryMetadataValue::from_bytes(carriage.operation_id.as_bytes()),
        );
        let mut fingerprint = Vec::with_capacity(33);
        fingerprint.push(FINGERPRINT_VERSION_V1);
        fingerprint.extend_from_slice(&carriage.fingerprint);
        metadata.insert_bin(
            FINGERPRINT_KEY,
            BinaryMetadataValue::from_bytes(&fingerprint),
        );
        metadata.insert_bin(
            PREPARE_TOKEN_KEY,
            BinaryMetadataValue::from_bytes(&carriage.prepare_token),
        );
    }
}

/// A `BranchPush` request addressed at one repository, optionally governed.
///
/// The repository travels in metadata, not the body: `get_repository` reads it
/// from `lore-partition-bin`, falling back to `urc-repository-id-bin`, and both
/// carry the same sixteen raw bytes.
pub fn push_request(
    token: &str,
    repository_id: &[u8],
    branch_id: &[u8],
    revision: &[u8],
    force: bool,
    fast_forward_merge: bool,
    carriage: Option<&Carriage>,
) -> Request<BranchPushRequest> {
    let mut request = Request::new(BranchPushRequest {
        id: branch_id.to_vec().into(),
        revision_signature: revision.to_vec().into(),
        force,
        fast_forward_merge,
    });
    decorate(request.metadata_mut(), token, repository_id, carriage);
    request
}

/// A connected revision client, so a racing case can pay the dial cost BEFORE
/// the overlap it is trying to create.
///
/// Dialling inside the race would be a real defect in the proof twice over: the
/// two RPCs would no longer overlap (one client is still doing TCP and HTTP/2
/// setup while the other is already committing), and a dial failure would be
/// indistinguishable from the CAS refusal the losing writer is supposed to get.
pub type RevisionClient = RevisionServiceClient<tonic::transport::Channel>;

/// Dial one process's revision service, failing loudly rather than turning a
/// connection problem into something a case could mistake for a refusal.
pub async fn connect_revision(endpoint: String) -> RevisionClient {
    RevisionServiceClient::connect(endpoint.clone())
        .await
        .unwrap_or_else(|error| panic!("dial the revision service at {endpoint}: {error}"))
}

/// Send one `BranchPush` on an already-connected client.
///
/// The `Result` is handed back rather than unwrapped because a *refusal* is the
/// expected outcome for the losing writer in every race here, and collapsing it
/// into a panic would make the losing half of the proof unobservable.
pub async fn branch_push_on(
    client: &mut RevisionClient,
    request: Request<BranchPushRequest>,
) -> Result<BranchPushResponse, Status> {
    client
        .branch_push(request)
        .await
        .map(|response| response.into_inner())
}

/// Dial and send, for the cases that are not racing anything.
pub async fn branch_push(
    endpoint: String,
    request: Request<BranchPushRequest>,
) -> Result<BranchPushResponse, Status> {
    let mut client = connect_revision(endpoint).await;
    branch_push_on(&mut client, request).await
}

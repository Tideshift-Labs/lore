// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Pre-body caller admission. A capability grants no authentication or authorization.
use std::task::Context;
use std::task::Poll;

use futures::future::Either;
use futures::future::Ready;
use futures::future::ready;
use http::HeaderMap;
use http::Request;
use http::Response;
use serde::Deserialize;
use tonic::Status;
use tonic::body::Body;
use tower::Layer;
use tower::Service;

pub const CAPABILITIES_HEADER: &str = "lore-caller-capabilities-v1";
pub const ADMISSION_HEADER: &str = "lore-client-admission-v1";
pub const REQUIRED_CAPABILITY: &str = "outcome_unknown_v1";

#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CallerCapabilityPolicy {
    #[default]
    CompatibleSingleReplica,
    RequireOutcomeUnknownV1,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RpcClass {
    Read,
    Mutation,
}

/// Only the server-installed extension controls optional read-side repairs.
pub fn read_repairs_allowed(extensions: &http::Extensions) -> bool {
    extensions.get::<CallerCapabilityPolicy>()
        != Some(&CallerCapabilityPolicy::RequireOutcomeUnknownV1)
}

/// Explicit inventory of mounted public services. Unknown paths never inherit admission.
/// Verify is a mutation because its healing path can write.
pub const RPC_INVENTORY: &[(&str, RpcClass)] = &[
    ("/urc.rpc.StorageService/Get", RpcClass::Read),
    ("/urc.rpc.StorageService/Ping", RpcClass::Read),
    ("/urc.rpc.StorageService/Put", RpcClass::Mutation),
    ("/urc.rpc.StorageService/Query", RpcClass::Read),
    ("/urc.rpc.StorageService/Verify", RpcClass::Mutation),
    ("/urc.rpc.StorageService/Copy", RpcClass::Mutation),
    ("/urc.rpc.StorageService/MutableLoad", RpcClass::Read),
    ("/urc.rpc.StorageService/MutableStore", RpcClass::Mutation),
    (
        "/urc.rpc.StorageService/MutableCompareAndSwap",
        RpcClass::Mutation,
    ),
    ("/urc.rpc.RevisionService/BranchCreate", RpcClass::Mutation),
    ("/urc.rpc.RevisionService/BranchDelete", RpcClass::Mutation),
    ("/urc.rpc.RevisionService/BranchQuery", RpcClass::Read),
    ("/urc.rpc.RevisionService/BranchGet", RpcClass::Read),
    ("/urc.rpc.RevisionService/BranchList", RpcClass::Read),
    ("/urc.rpc.RevisionService/BranchPush", RpcClass::Mutation),
    ("/urc.rpc.RevisionService/BranchProtect", RpcClass::Mutation),
    (
        "/urc.rpc.RevisionService/BranchUnprotect",
        RpcClass::Mutation,
    ),
    ("/urc.rpc.RevisionService/BranchDiff", RpcClass::Read),
    (
        "/urc.rpc.RevisionService/BranchRevisionList",
        RpcClass::Read,
    ),
    ("/urc.rpc.RevisionService/BranchMetadataGet", RpcClass::Read),
    (
        "/urc.rpc.RevisionService/BranchMetadataSet",
        RpcClass::Mutation,
    ),
    ("/urc.rpc.RevisionService/RevisionDescribe", RpcClass::Read),
    ("/urc.rpc.RevisionService/RevisionDiff", RpcClass::Read),
    (
        "/urc.rpc.RevisionService/RevisionStateHistory",
        RpcClass::Read,
    ),
    ("/urc.rpc.RevisionService/RevisionTree", RpcClass::Read),
    ("/urc.rpc.RevisionService/RevisionList", RpcClass::Read),
    (
        "/urc.rpc.RepositoryService/RepositoryCreate",
        RpcClass::Mutation,
    ),
    (
        "/urc.rpc.RepositoryService/RepositoryDelete",
        RpcClass::Mutation,
    ),
    ("/urc.rpc.RepositoryService/RepositoryQuery", RpcClass::Read),
    ("/urc.rpc.RepositoryService/RepositoryList", RpcClass::Read),
    (
        "/urc.rpc.RepositoryService/RepositoryMetadataGet",
        RpcClass::Read,
    ),
    (
        "/urc.rpc.RepositoryService/RepositoryMetadataSet",
        RpcClass::Mutation,
    ),
    ("/urc.rpc.EnvironmentService/Get", RpcClass::Read),
    ("/urc.rpc.AdminService/ServerInfo", RpcClass::Read),
    ("/urc.rpc.AdminService/Obliterate", RpcClass::Mutation),
    ("/urc.lock.LockService/Lock", RpcClass::Mutation),
    ("/urc.lock.LockService/Query", RpcClass::Read),
    ("/urc.lock.LockService/Status", RpcClass::Read),
    ("/urc.lock.LockService/Unlock", RpcClass::Mutation),
    ("/urc.lock.LockService/AdminLock", RpcClass::Mutation),
    ("/urc.lock.LockService/ForceUnlock", RpcClass::Mutation),
    (
        "/lore.notification.NotificationService/Subscribe",
        RpcClass::Read,
    ),
    (
        "/lore.notification.NotificationService/Publish",
        RpcClass::Mutation,
    ),
    ("/lore.storage.v1.StorageService/Get", RpcClass::Read),
    (
        "/lore.storage.v1.StorageService/GetMetadata",
        RpcClass::Read,
    ),
    (
        "/lore.storage.v1.StorageService/GetResolved",
        RpcClass::Read,
    ),
    (
        "/lore.storage.v1.StorageService/PutResolved",
        RpcClass::Mutation,
    ),
    ("/lore.storage.v1.StorageService/Put", RpcClass::Mutation),
    ("/lore.storage.v1.StorageService/Query", RpcClass::Read),
    ("/lore.storage.v1.StorageService/Verify", RpcClass::Mutation),
    ("/lore.storage.v1.StorageService/Copy", RpcClass::Mutation),
    (
        "/lore.storage.v1.StorageService/MutableLoad",
        RpcClass::Read,
    ),
    (
        "/lore.storage.v1.StorageService/MutableStore",
        RpcClass::Mutation,
    ),
    (
        "/lore.storage.v1.StorageService/MutableCompareAndSwap",
        RpcClass::Mutation,
    ),
    (
        "/lore.revision.v1.RevisionService/BranchCreate",
        RpcClass::Mutation,
    ),
    (
        "/lore.revision.v1.RevisionService/BranchDelete",
        RpcClass::Mutation,
    ),
    (
        "/lore.revision.v1.RevisionService/BranchGet",
        RpcClass::Read,
    ),
    (
        "/lore.revision.v1.RevisionService/BranchList",
        RpcClass::Read,
    ),
    (
        "/lore.revision.v1.RevisionService/BranchPush",
        RpcClass::Mutation,
    ),
    (
        "/lore.revision.v1.RevisionService/BranchMetadataGet",
        RpcClass::Read,
    ),
    (
        "/lore.revision.v1.RevisionService/BranchMetadataSet",
        RpcClass::Mutation,
    ),
    (
        "/lore.revision.v1.RevisionService/RevisionList",
        RpcClass::Read,
    ),
    (
        "/lore.repository.v1.RepositoryService/RepositoryCreate",
        RpcClass::Mutation,
    ),
    (
        "/lore.repository.v1.RepositoryService/RepositoryDelete",
        RpcClass::Mutation,
    ),
    (
        "/lore.repository.v1.RepositoryService/RepositoryGet",
        RpcClass::Read,
    ),
    (
        "/lore.repository.v1.RepositoryService/RepositoryList",
        RpcClass::Read,
    ),
    (
        "/lore.repository.v1.RepositoryService/RepositoryMetadataGet",
        RpcClass::Read,
    ),
    (
        "/lore.repository.v1.RepositoryService/RepositoryMetadataSet",
        RpcClass::Mutation,
    ),
    (
        "/lore.repository.v1.RepositoryService/RepositoryStorageStats",
        RpcClass::Read,
    ),
    (
        "/lore.environment.v1.EnvironmentService/EnvironmentGet",
        RpcClass::Read,
    ),
    (
        "/lore.thin_client.v1.ThinClientService/ContentDiff",
        RpcClass::Read,
    ),
    (
        "/lore.thin_client.v1.ThinClientService/RevisionInfo",
        RpcClass::Read,
    ),
    (
        "/lore.thin_client.v1.ThinClientService/RevisionDiff",
        RpcClass::Read,
    ),
    (
        "/lore.thin_client.v1.ThinClientService/RevisionTree",
        RpcClass::Read,
    ),
    (
        "/lore.domain.v1.DomainOperationService/DomainOperationClockGet",
        RpcClass::Read,
    ),
    (
        "/lore.domain.v1.DomainOperationService/DomainOperationPrepare",
        RpcClass::Mutation,
    ),
    (
        "/lore.domain.v1.DomainOperationService/DomainOperationReceiptGet",
        RpcClass::Read,
    ),
    (
        "/lore.domain.v1.DomainOperationService/DomainOperationAttemptReceiptGet",
        RpcClass::Read,
    ),
    (
        "/lore.domain.v1.DomainOperationService/DomainOperationVerifiedStaleFinalize",
        RpcClass::Mutation,
    ),
    (
        "/lore.domain.v1.DomainOperationService/DomainOperationTerminalStatusAttach",
        RpcClass::Mutation,
    ),
    (
        "/lore.domain.v1.DomainOperationService/DomainOperationProofNamespaceMaterialize",
        RpcClass::Mutation,
    ),
    (
        "/lore.domain.v1.DomainOperationService/DomainOperationProofNamespaceRetire",
        RpcClass::Mutation,
    ),
];

pub fn classify_rpc(path: &str) -> Option<RpcClass> {
    RPC_INVENTORY
        .iter()
        .find_map(|(known, class)| (*known == path).then_some(*class))
}

pub fn unsupported_client() -> Status {
    let mut status = Status::failed_precondition("unsupported client capability");
    status.metadata_mut().insert(
        ADMISSION_HEADER,
        tonic::metadata::MetadataValue::from_static("unsupported-client"),
    );
    status
}

/// Validate singleton canonical ASCII carriage without reading or allocating from the body.
pub fn declares_outcome_unknown(headers: &HeaderMap) -> Result<bool, Status> {
    let mut values = headers.get_all(CAPABILITIES_HEADER).iter();
    let Some(value) = values.next() else {
        return Ok(false);
    };
    if values.next().is_some() || value.as_bytes().len() > 1024 {
        return Err(unsupported_client());
    }
    let value = value.to_str().map_err(|_| unsupported_client())?;
    let mut previous: Option<&str> = None;
    let mut declared = false;
    for (index, token) in value.split(',').enumerate() {
        let bytes = token.as_bytes();
        if index >= 16
            || bytes.is_empty()
            || bytes.len() > 64
            || !bytes[0].is_ascii_lowercase()
            || !bytes
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
            || previous.is_some_and(|prior| prior >= token)
        {
            return Err(unsupported_client());
        }
        previous = Some(token);
        declared |= token == REQUIRED_CAPABILITY;
    }
    Ok(declared)
}

pub fn admit(
    policy: CallerCapabilityPolicy,
    path: &str,
    headers: &HeaderMap,
) -> Result<(), Status> {
    if policy == CallerCapabilityPolicy::CompatibleSingleReplica {
        return Ok(());
    }
    match classify_rpc(path) {
        Some(RpcClass::Read) => Ok(()),
        // Only v1 branch creation has a governed receipt path; branch deletion
        // still refuses its unfrozen canonical intent/tombstone proof.
        Some(RpcClass::Mutation)
            if matches!(
                path,
                "/urc.rpc.RevisionService/BranchCreate"
                    | "/urc.rpc.RevisionService/BranchDelete"
                    | "/lore.revision.v1.RevisionService/BranchDelete"
            ) =>
        {
            Err(unsupported_client())
        }
        Some(RpcClass::Mutation) if declares_outcome_unknown(headers)? => {
            if matches!(
                path.rsplit('/').next(),
                Some("RepositoryCreate" | "RepositoryDelete" | "BranchCreate" | "BranchDelete")
            ) {
                let metadata = tonic::metadata::MetadataMap::from_headers(headers.clone());
                let attempt = super::domain_operation_metadata::extract_attempt_id(&metadata)
                    .map_err(|error| Status::invalid_argument(error.to_string()))?;
                if attempt.is_none() {
                    return Err(Status::invalid_argument(
                        "lifecycle mutation requires lore-attempt-id",
                    ));
                }
            }
            Ok(())
        }
        _ => Err(unsupported_client()),
    }
}

#[derive(Clone, Copy, Debug)]
pub struct CallerCapabilityLayer {
    policy: CallerCapabilityPolicy,
}

impl CallerCapabilityLayer {
    pub fn new(policy: CallerCapabilityPolicy) -> Self {
        Self { policy }
    }
}

impl<S> Layer<S> for CallerCapabilityLayer {
    type Service = CallerCapabilityService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        CallerCapabilityService {
            inner,
            policy: self.policy,
        }
    }
}

#[derive(Clone, Debug)]
pub struct CallerCapabilityService<S> {
    inner: S,
    policy: CallerCapabilityPolicy,
}

impl<S, B> Service<Request<B>> for CallerCapabilityService<S>
where
    S: Service<Request<B>, Response = Response<Body>>,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Either<S::Future, Ready<Result<Self::Response, Self::Error>>>;
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }
    fn call(&mut self, mut request: Request<B>) -> Self::Future {
        match admit(self.policy, request.uri().path(), request.headers()) {
            Ok(()) => {
                request.extensions_mut().insert(self.policy);
                Either::Left(self.inner.call(request))
            }
            Err(status) => Either::Right(ready(Ok(status.into_http()))),
        }
    }
}

/// Serving must not expose the legacy Postgres stats path, which repairs shared metering.
/// `coordinated` comes from the constructed store's route, not its requested configuration.
pub(crate) fn validate_serving_fragment_route(
    policy: CallerCapabilityPolicy,
    postgres: bool,
    coordinated: bool,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        policy != CallerCapabilityPolicy::RequireOutcomeUnknownV1 || !postgres || coordinated,
        "required caller capability policy requires the coordinated Postgres fragment route"
    );
    Ok(())
}

/// Run before storage or listeners start. These transports have no equivalent gate yet.
pub fn validate_settings(settings: &crate::settings::Settings) -> anyhow::Result<()> {
    let server = &settings.server;
    if !server.grpc.as_ref().is_some_and(|grpc| {
        grpc.caller_capability_policy == CallerCapabilityPolicy::RequireOutcomeUnknownV1
    }) {
        return Ok(());
    }
    anyhow::ensure!(
        server
            .auth
            .as_ref()
            .and_then(|auth| auth.jwk.as_ref())
            .is_some(),
        "required caller capability policy requires JWT authentication"
    );
    anyhow::ensure!(
        !server
            .quic
            .as_ref()
            .is_some_and(|endpoint| endpoint.enabled)
            && !server
                .quic_internal
                .as_ref()
                .is_some_and(|endpoint| endpoint.enabled)
            && !server
                .grpc_internal
                .as_ref()
                .is_some_and(|endpoint| endpoint.enabled),
        "required caller capability policy forbids unguarded QUIC and internal replication ingress"
    );
    anyhow::ensure!(
        server
            .grpc_public_services
            .as_ref()
            .and_then(|services| services.forwarded_requests.as_ref())
            .is_none(),
        "required caller capability policy forbids forwarded requests"
    );
    anyhow::ensure!(
        settings.immutable_store.mode != "replicated"
            && settings.immutable_store.mode != "remote"
            && settings.mutable_store.mode != "remote",
        "required caller capability policy forbids remote and replicated store forwarding"
    );
    if let Some(composite) = &settings.immutable_store.composite {
        anyhow::ensure!(
            composite.replica_factory.is_none()
                && composite.replica.as_ref().is_none_or(Vec::is_empty),
            "required caller capability policy forbids composite replication"
        );
        for store in std::iter::once(&composite.local).chain(composite.durable.iter()) {
            anyhow::ensure!(
                store.mode != "remote" && store.mode != "replicated",
                "required caller capability policy forbids composite store forwarding"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "caller_capabilities_tests.rs"]
pub(crate) mod tests;

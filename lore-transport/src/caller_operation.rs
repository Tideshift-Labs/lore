// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! Explicit managed product adoption, scoped to one durable parent operation.

use std::future::Future;
use std::sync::Arc;

use lore_base::types::RepositoryId;
use uuid::Uuid;

use crate::ProtocolError;
use crate::attempt_store::AttemptRecord;
use crate::attempt_store::AttemptResolution;
use crate::attempt_store::AttemptState;
use crate::attempt_store::AttemptStore;
use crate::outcome::AttemptId;
use crate::outcome::GrpcRpc;
use crate::outcome::OUTCOME_UNKNOWN_CAPABILITY_V1;

pub const CALLER_CAPABILITIES_METADATA_KEY: &str = "lore-caller-capabilities-v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallerRecoveryContext {
    pub repository: RepositoryId,
    pub endpoint: String,
    pub verified_issuer: String,
    pub authenticated_subject: String,
    pub caller_capabilities: String,
}

/// Select the gRPC dial scheme without changing the recorded recovery namespace.
/// Managed endpoints name the actual HTTP transport, whereas the connection registry
/// selects gRPC by `grpc`/`grpcs`. Pin HTTP's effective port before changing schemes.
pub fn recovery_dial_url(endpoint: &str) -> Result<String, ProtocolError> {
    let invalid = || ProtocolError::internal("invalid managed recovery endpoint");
    if endpoint.contains(['@', '\\'])
        || endpoint
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err(invalid());
    }
    let (_, authority_and_path) = endpoint.split_once("://").ok_or_else(invalid)?;
    let (authority, path) = authority_and_path
        .split_once('/')
        .unwrap_or((authority_and_path, ""));
    if authority.is_empty() || !path.is_empty() {
        return Err(invalid());
    }
    let url = url::Url::parse(endpoint).map_err(|_err| invalid())?;
    let scheme = match url.scheme() {
        "http" | "grpc" => "grpc",
        "https" | "grpcs" => "grpcs",
        _ => return Err(invalid()),
    };
    if !endpoint.starts_with(&format!("{}://", url.scheme()))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(invalid());
    }
    let host = url
        .host_str()
        .filter(|host| !host.is_empty())
        .ok_or_else(invalid)?;
    if matches!(url.scheme(), "grpc" | "grpcs") {
        // Preserve the registry's existing gRPC default-port semantics.
        return Ok(url.to_string());
    }
    let port = url.port_or_known_default().ok_or_else(invalid)?;
    Ok(format!("{scheme}://{host}:{port}/"))
}

/// Exact server receipt methods for the supported managed recovery RPCs.
/// Public Lock selects acquire or renew from its recorded ownership tokens;
/// admin acquisition and methods without a receipt reader are not interchangeable.
pub fn recovery_receipt_method_matches(recorded_rpc: &str, receipt_method: &str) -> bool {
    matches!(
        (recorded_rpc, receipt_method),
        ("RevisionService.BranchPush", "branch.push")
            | ("RevisionService.BranchCreate", "branch.create")
            | ("LockService.Lock", "lock.acquire" | "lock.renew")
            | ("LockService.Unlock", "lock.release")
            | ("LockService.ForceUnlock", "lock.force_release")
    )
}

/// The lock resources a managed lock child named, with the ownership token each presented, read
/// back from the canonical request it journalled before dispatch. Recovery uses this to bind a
/// receipt to what the attempt asked for; it never resends the request.
pub fn recorded_lock_resources(
    recorded_rpc: &str,
    canonical_request: &[u8],
) -> Result<Vec<crate::attempt_store::FencedLockResource>, ProtocolError> {
    use prost::Message;
    let invalid = |error: prost::DecodeError| {
        ProtocolError::internal(format!(
            "recorded {recorded_rpc} request does not decode: {error}"
        ))
    };
    let resources = if recorded_rpc == GrpcRpc::LockLock.wire_name() {
        lore_proto::lock::LockRequest::decode(canonical_request)
            .map_err(invalid)?
            .resources
    } else if recorded_rpc == GrpcRpc::LockUnlock.wire_name() {
        lore_proto::lock::UnlockRequest::decode(canonical_request)
            .map_err(invalid)?
            .resources
    } else if recorded_rpc == GrpcRpc::LockForceUnlock.wire_name() {
        lore_proto::lock::ForceUnlockRequest::decode(canonical_request)
            .map_err(invalid)?
            .resources
    } else {
        return Err(ProtocolError::internal(format!(
            "{recorded_rpc} is not a recoverable lock request"
        )));
    };
    resources
        .into_iter()
        .map(|resource| {
            let token = crate::attempt_store::OwnershipToken::from_wire(
                resource.expected_ownership_token.as_ref(),
            )?;
            Ok(crate::attempt_store::FencedLockResource::with_token(
                resource.into(),
                token,
            ))
        })
        .collect()
}

/// Whether a recorded child is a fragment Put from a build that still journaled them.
///
/// Fragment Puts write no child since 2026-10-22. Old journals may still hold unresolved ones,
/// and no receipt can settle them. A Put is content-addressed and the server ignores its attempt
/// id, so recovery settles such a child as not applied without a read: nothing is owed, and the
/// next push uploads whatever the remote lacks.
pub fn is_legacy_fragment_put(recorded_rpc: &str) -> bool {
    recorded_rpc == GrpcRpc::StoragePut.wire_name()
}

/// Read the exact repository credential selection without declaring or dispatching a mutation.
/// The signature remains verified by the peer; this snapshot binds subsequent dispatches.
pub async fn selected_caller_namespace(
    connection: &Arc<crate::connection::Connection>,
    repository: RepositoryId,
) -> Result<CallerRecoveryContext, ProtocolError> {
    if !matches!(connection.remote_url.scheme(), "grpc" | "grpcs") {
        return Err(ProtocolError::internal(
            "managed namespace binding requires gRPC",
        ));
    }
    let grpc = crate::grpc::connect(
        Arc::downgrade(connection),
        connection.remote_url.as_str(),
        true,
    )
    .await?;
    let auth = grpc
        .repository_authz(
            &connection.auth_url,
            &connection.identity,
            repository,
            connection.credentials(),
        )
        .await;
    let authorization = crate::grpc::authorization_snapshot(&auth);
    let claims = lore_credential::insecure_decode_token(&authorization)
        .map_err(|_err| ProtocolError::internal("selected credential namespace is unavailable"))?
        .claims;
    if claims.issuer.is_empty() || claims.user_id.is_empty() {
        return Err(ProtocolError::internal(
            "selected credential namespace is incomplete",
        ));
    }
    Ok(CallerRecoveryContext {
        repository,
        endpoint: canonical_endpoint(grpc.selected_endpoint())?,
        verified_issuer: claims.issuer,
        authenticated_subject: claims.user_id,
        caller_capabilities: OUTCOME_UNKNOWN_CAPABILITY_V1.to_owned(),
    })
}

pub fn with_caller_recovery<F: Future>(
    context: CallerRecoveryContext,
    future: F,
) -> impl Future<Output = F::Output> {
    CALLER_RECOVERY.scope(context, future)
}

pub(crate) fn current_caller_recovery() -> Option<CallerRecoveryContext> {
    CALLER_RECOVERY.try_with(Clone::clone).ok()
}

#[lore_macro::test_pub]
pub(crate) fn canonical_endpoint(endpoint: &str) -> Result<String, ProtocolError> {
    let mut url = url::Url::parse(endpoint)
        .map_err(|_err| ProtocolError::internal("invalid managed endpoint"))?;
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string())
}

/// Versioned, nonsecret canonical request binding persisted atomically with the child record.
/// Canonical protobuf bytes exclude authentication, but retain protected ownership preconditions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManagedAttemptIntent {
    pub version: u32,
    pub parent_id: Uuid,
    pub repository: RepositoryId,
    pub rpc: String,
    pub canonical_request: Vec<u8>,
    pub endpoint: String,
    /// Issuer claimed by the exact credential sent; the server verifies the signature.
    pub verified_issuer: String,
    pub authenticated_subject: String,
    pub caller_capabilities: String,
}

/// Construct only at a managed product boundary whose journal belongs to this parent.
/// A store by itself never declares adoption. No connection or session owns this context.
#[derive(Clone)]
pub struct CallerOperationContext {
    parent_id: Uuid,
    repository: RepositoryId,
    attempts: Arc<dyn AttemptStore>,
    binding: Arc<parking_lot::Mutex<Option<CallerRecoveryContext>>>,
    latest_attempt: Arc<parking_lot::Mutex<Option<AttemptId>>>,
}

impl CallerOperationContext {
    pub fn new(parent_id: Uuid, repository: RepositoryId, attempts: Arc<dyn AttemptStore>) -> Self {
        Self {
            parent_id,
            repository,
            attempts,
            binding: Arc::new(parking_lot::Mutex::new(None)),
            latest_attempt: Arc::new(parking_lot::Mutex::new(None)),
        }
    }

    pub fn parent_id(&self) -> Uuid {
        self.parent_id
    }
    pub fn repository(&self) -> RepositoryId {
        self.repository
    }
    pub fn attempts(&self) -> &Arc<dyn AttemptStore> {
        &self.attempts
    }
    pub fn capabilities(&self) -> &'static str {
        OUTCOME_UNKNOWN_CAPABILITY_V1
    }
    pub fn latest_attempt(&self) -> Option<AttemptId> {
        *self.latest_attempt.lock()
    }
}

tokio::task_local! {
    static CALLER_OPERATION: Option<CallerOperationContext>;
    static MANAGED_CALLER: (Uuid, Arc<dyn AttemptStore>);
    static TRANSPORT_ENDPOINT: String;
    static DISPATCH_AUTHORIZATION: String;
    static CALLER_RECOVERY: CallerRecoveryContext;
}

#[lore_macro::test_pub]
pub(crate) fn with_transport_endpoint<F: Future>(
    endpoint: String,
    future: F,
) -> impl Future<Output = F::Output> {
    TRANSPORT_ENDPOINT.scope(endpoint, future)
}

pub(crate) fn current_transport_endpoint() -> String {
    TRANSPORT_ENDPOINT
        .try_with(Clone::clone)
        .unwrap_or_default()
}

pub(crate) fn current_dispatch_authorization() -> Option<String> {
    DISPATCH_AUTHORIZATION.try_with(Clone::clone).ok()
}

/// Explicit adoption boundary for callers that have not opened the repository yet.
/// Lore binds the actual repository id before invoking its command.
pub fn with_managed_caller<F: Future>(
    parent_id: Uuid,
    attempts: Arc<dyn AttemptStore>,
    future: F,
) -> impl Future<Output = F::Output> {
    MANAGED_CALLER.scope((parent_id, attempts), future)
}

pub fn caller_operation_for_repository(repository: RepositoryId) -> Option<CallerOperationContext> {
    current_caller_operation().or_else(|| {
        MANAGED_CALLER
            .try_with(|(parent_id, attempts)| {
                CallerOperationContext::new(*parent_id, repository, attempts.clone())
            })
            .ok()
    })
}

pub fn current_caller_operation() -> Option<CallerOperationContext> {
    CALLER_OPERATION.try_with(Clone::clone).ok().flatten()
}

/// A managed promise exists even before Lore has opened the repository.
pub fn has_managed_caller() -> bool {
    current_caller_operation().is_some() || MANAGED_CALLER.try_with(|_| ()).is_ok()
}

pub fn with_caller_operation<F: Future>(
    context: CallerOperationContext,
    future: F,
) -> impl Future<Output = F::Output> {
    Box::pin(CALLER_OPERATION.scope(Some(context), future))
}

/// Capture before spawning, then enter inside the spawned task. `None` clears an outer scope.
pub fn with_optional_caller_operation<F: Future>(
    context: Option<CallerOperationContext>,
    future: F,
) -> impl Future<Output = F::Output> {
    Box::pin(CALLER_OPERATION.scope(context, future))
}

pub(crate) async fn record(
    context: &CallerOperationContext,
    attempt: AttemptId,
    rpc: GrpcRpc,
    canonical_request: Vec<u8>,
    endpoint: String,
    authorization: &str,
) -> Result<(), ProtocolError> {
    let claims = lore_credential::insecure_decode_token(authorization)
        .map_err(|_err| {
            ProtocolError::internal("managed dispatch cannot bind credential namespace")
        })?
        .claims;
    if endpoint.is_empty() || claims.issuer.is_empty() || claims.user_id.is_empty() {
        return Err(ProtocolError::internal(
            "managed dispatch namespace is incomplete",
        ));
    }
    let endpoint = canonical_endpoint(&endpoint)?;
    let binding = CallerRecoveryContext {
        repository: context.repository,
        endpoint: endpoint.clone(),
        verified_issuer: claims.issuer.clone(),
        authenticated_subject: claims.user_id.clone(),
        caller_capabilities: context.capabilities().to_owned(),
    };
    {
        let mut existing = context.binding.lock();
        if existing
            .as_ref()
            .is_some_and(|existing| existing != &binding)
        {
            return Err(ProtocolError::internal(
                "managed parent credential namespace changed",
            ));
        }
        *existing = Some(binding);
    }
    let recorded_at_unix_millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_millis()).unwrap_or(i64::MAX)
        });
    context
        .attempts
        .record_managed(
            &AttemptRecord {
                attempt_id: attempt,
                state: AttemptState::Unresolved,
                operation: rpc.wire_name().to_owned(),
                repository: context.repository,
                recorded_at_unix_millis,
                receipt: None,
            },
            &ManagedAttemptIntent {
                version: 1,
                parent_id: context.parent_id,
                repository: context.repository,
                rpc: rpc.wire_name().to_owned(),
                canonical_request,
                endpoint,
                verified_issuer: claims.issuer,
                authenticated_subject: claims.user_id,
                caller_capabilities: context.capabilities().to_owned(),
            },
        )
        .await?;
    *context.latest_attempt.lock() = Some(attempt);
    Ok(())
}

pub(crate) async fn settle<T>(
    context: &CallerOperationContext,
    attempt: AttemptId,
    result: &Result<T, ProtocolError>,
) -> Result<(), ProtocolError> {
    let resolution = match result {
        Ok(_) => AttemptResolution::Applied,
        Err(error) if error.is_outcome_unknown() => return Ok(()),
        Err(_) => AttemptResolution::NotApplied,
    };
    context
        .attempts
        .resolve(&attempt, resolution)
        .await
        .map_err(|_err| crate::outcome::outcome_unknown("journal settlement", &attempt))
}

/// The request producer supplies canonical nonsecret intent; no interceptor manufactures it.
pub(crate) async fn dispatch<T, F: Future<Output = Result<T, ProtocolError>>>(
    repository: RepositoryId,
    rpc: GrpcRpc,
    canonical_request: Vec<u8>,
    endpoint: String,
    authorization: String,
    future: F,
) -> Result<T, ProtocolError> {
    if current_caller_operation().is_none() {
        return future.await;
    }
    dispatch_recorded_result(
        repository,
        rpc,
        canonical_request,
        endpoint,
        authorization,
        future,
    )
    .await?
}

/// Keep local admission/journal failures separate from the RPC's semantic result.
/// A decisive inner result is returned only after its original attempt has been settled;
/// an unknown inner result retains the original unresolved attempt.
pub(crate) async fn dispatch_recorded_result<T, F: Future<Output = Result<T, ProtocolError>>>(
    repository: RepositoryId,
    rpc: GrpcRpc,
    canonical_request: Vec<u8>,
    endpoint: String,
    authorization: String,
    future: F,
) -> Result<Result<T, ProtocolError>, ProtocolError> {
    let context = current_caller_operation()
        .ok_or_else(|| ProtocolError::internal("recorded dispatch requires a managed caller"))?;
    if repository != context.repository {
        return Err(ProtocolError::internal(
            "managed operation repository mismatch",
        ));
    }
    let attempt = match rpc {
        GrpcRpc::StoragePut
        | GrpcRpc::StoragePutResolved
        | GrpcRpc::StorageCopy
        | GrpcRpc::StorageVerify
        | GrpcRpc::StorageMutableStore
        | GrpcRpc::StorageMutableCompareAndSwap => AttemptId::new(),
        _ => crate::outcome::current_dispatch_attempt().unwrap_or_else(AttemptId::new),
    };
    record(
        &context,
        attempt,
        rpc,
        canonical_request,
        endpoint,
        &authorization,
    )
    .await?;
    let result = DISPATCH_AUTHORIZATION
        .scope(
            authorization,
            crate::outcome::with_dispatch_attempt(attempt, future),
        )
        .await;
    // Positive proof the message never left settles the attempt not applied. The caller sees
    // `Disconnected`, which the reconnect layer may resend under a fresh attempt.
    if let Err(error) = &result
        && crate::error::is_request_not_sent(error)
    {
        settle(&context, attempt, &result).await?;
        let mut disconnected = ProtocolError::from(lore_base::error::Disconnected);
        lore_error_set::ErrorSet::push_trace(
            &mut disconnected,
            lore_error_set::Location::with_context(
                file!(),
                line!(),
                column!(),
                Arc::from(format!("{}: {error}", rpc.wire_name())),
            ),
        );
        return Ok(Err(disconnected));
    }
    let result = match result {
        Err(error)
            if error.is_outcome_unknown()
                || error.is_disconnected()
                || crate::error::answer_lost_code(&error).is_some()
                // Same rule `with_reconnect_classified` applies, and it must hold here too: this
                // journal settles before that outer check runs.
                || !crate::grpc::not_prepared_proof_holds(&error, &attempt) =>
        {
            Err(crate::outcome::outcome_unknown(rpc.wire_name(), &attempt))
        }
        result => result,
    };
    settle(&context, attempt, &result).await?;
    Ok(result)
}

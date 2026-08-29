// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use futures::FutureExt;
pub mod admin_service;
pub mod domain_operation_metadata;
pub mod environment;
pub mod environment_service;
pub mod forwarded_repository;
pub mod forwarded_requests;
pub mod forwarded_revision;
pub mod handlers;
pub mod lock_service;
pub mod notification_service;
pub mod repository;
pub mod repository_service;
pub mod revision;
pub mod revision_service;
pub mod server;
pub mod storage;
pub mod storage_service;
pub mod thinclient;

use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

mod grpc_internal_server;
mod replication_service;
pub mod tower;

pub use admin_service::LoreAdminService;
pub use grpc_internal_server::GrpcInternalServerBuilder;
use lore_base::types::Context;
use lore_revision::link::LinkError;
use lore_revision::lore::RepositoryId;
use lore_revision::metadata::MetadataError;
use lore_revision::repository::RepositoryWriteToken;
use lore_revision::repository::ServerContext;
use lore_revision::state::StateError;
use lore_transport::grpc::CORRELATION_ID_HEADER;
use lore_transport::grpc::PARTITION_ID_KEY;
use lore_transport::grpc::REPOSITORY_ID_KEY;
pub use repository::LoreRepositoryV1Service;
pub use revision::LoreRevisionV1Service;
pub use revision_service::LoreRevisionService;
pub use server::GrpcServerBuilder;
pub use storage_service::LoreStorageService;
pub use thinclient::LoreThinClientV1Service;
use tokio::sync::mpsc::Sender;
use tokio::time::timeout;
use tonic::Code;
use tonic::Extensions;
use tonic::Status;
use tonic::metadata::MetadataMap;
use tracing::debug;
use tracing::info;
use tracing::warn;

use crate::auth::jwt::AuthorizationToken;
use crate::auth::jwt::ResourcePermission;
use crate::auth::jwt::verify_authorization;
use crate::hooks::traits::HookError;
use crate::hooks::traits::StatusCode;
use crate::protocol::attribute_map::AttributeMap;
use crate::protocol::storage::messages::MessageHandleError;
use crate::util::get_user_id_from_token_ref;
use crate::util::resources_from_token;

/// Matches the Infrastructure alerting rule regex
/// for what counts as an internal status code error
pub fn is_code_considered_server_error(code: &Code) -> bool {
    matches!(code, Code::Internal | Code::Unavailable | Code::Cancelled)
}

pub(crate) fn simple_map_message_handle_error(error: MessageHandleError) -> Status {
    map_message_handle_error_to_status(&error, None, None)
}

pub fn map_message_handle_error_to_status(
    error: &MessageHandleError,
    message: Option<String>,
    details: Option<Bytes>,
) -> Status {
    let (code, message) = match error {
        MessageHandleError::AuthorizationFailure(err) => (
            Code::PermissionDenied,
            message.unwrap_or_else(|| format!("Authorization failed {err}")),
        ),
        MessageHandleError::MissingToken => (
            Code::Unauthenticated,
            message.unwrap_or_else(|| "Missing auth token".into()),
        ),
        MessageHandleError::AlreadyConnected => (
            Code::FailedPrecondition,
            message.unwrap_or_else(|| "Already connected".into()),
        ),
        MessageHandleError::BranchExists => (
            Code::AlreadyExists,
            message.unwrap_or_else(|| "Branch already exists".into()),
        ),
        MessageHandleError::BranchMismatch => (
            Code::InvalidArgument,
            message.unwrap_or_else(|| "Branch mismatch".into()),
        ),
        MessageHandleError::BranchProtected => (
            Code::PermissionDenied,
            message.unwrap_or_else(|| "Branch protected".into()),
        ),
        MessageHandleError::FragmentNotFound => (
            Code::NotFound,
            message.unwrap_or_else(|| "Fragment not found".into()),
        ),
        MessageHandleError::HashMismatch => (
            Code::InvalidArgument,
            message.unwrap_or_else(|| "Hash mismatch".into()),
        ),
        MessageHandleError::InvalidParentBranch => (
            Code::InvalidArgument,
            message.unwrap_or_else(|| "Invalid parent branch".into()),
        ),
        MessageHandleError::InternalError => (
            Code::Internal,
            message.unwrap_or_else(|| "Internal error".into()),
        ),
        MessageHandleError::MutableDataNotFound(hash) => (
            Code::NotFound,
            message.unwrap_or_else(|| format!("No data found for hash: {hash}")),
        ),
        MessageHandleError::NoSuchBranch => (
            Code::NotFound,
            message.unwrap_or_else(|| "No such branch".into()),
        ),
        MessageHandleError::NotConnected => (
            Code::FailedPrecondition,
            message.unwrap_or_else(|| "Not connected".into()),
        ),
        MessageHandleError::NotImplemented => (
            Code::Internal,
            message.unwrap_or_else(|| "Operation not implemented".into()),
        ),
        MessageHandleError::QueryResultSizeMismatch => (
            Code::Internal,
            message.unwrap_or_else(|| "Query result size mismatch".into()),
        ),
        MessageHandleError::StoreFailure => (
            Code::Internal,
            message.unwrap_or_else(|| "Store failure".into()),
        ),
        MessageHandleError::SlowDown => (
            Code::ResourceExhausted,
            message.unwrap_or_else(|| "slowdown".into()),
        ),
        MessageHandleError::Oversized => (
            Code::OutOfRange,
            message.unwrap_or_else(|| "Oversized fragment or blob".into()),
        ),
        MessageHandleError::Metadata => (
            Code::Internal,
            message.unwrap_or_else(|| "Metadata failure".into()),
        ),
        MessageHandleError::HashFailed => (
            Code::InvalidArgument,
            message.unwrap_or_else(|| "Hash failed".into()),
        ),
        MessageHandleError::InvalidFragment => (
            Code::InvalidArgument,
            message.unwrap_or_else(|| "Invalid fragment".into()),
        ),
        MessageHandleError::HandlerTimeout => (
            Code::Cancelled,
            message.unwrap_or_else(|| "Request Handler Timeout".into()),
        ),
        MessageHandleError::SessionLimitReached => (
            Code::Unavailable,
            message.unwrap_or_else(|| "Session limit reached".into()),
        ),
    };

    Status::with_details(code, message, details.unwrap_or_default())
}

/// Stable client-facing meaning of an indeterminate domain commit.
///
/// Kept as a constant because it is the only thing distinguishing an
/// outcome-unknown `ABORTED` from a contention `ABORTED` on the wire, and
/// clients match on it.
pub const DOMAIN_OUTCOME_UNKNOWN_DETAIL: &str =
    "mutation outcome unknown; refetch authoritative state before retry";

/// Fixed detail for every denied or race-lost repository result, so active,
/// unknown, tombstoned, catalog-removed, and race-lost cases stay
/// indistinguishable (CR-029 repository delete).
pub const DOMAIN_REPOSITORY_NOT_FOUND_DETAIL: &str = "Repository not found";

/// Translate a CR-029 domain-coordinator error into a gRPC status, in exactly
/// one place.
///
/// # `OutcomeUnknown` is `ABORTED`, never `UNKNOWN` (R-BLOCK-1)
///
/// CR-029 originally mandated `UNKNOWN` for an indeterminate commit, to avoid
/// the replay that generic retry policy applies to `UNAVAILABLE`. That is
/// inverted in this fork: [`lore_transport::error::ProtocolError`]'s
/// `From<tonic::Status>` folds `Unavailable` **and** `Unknown` into the same
/// `Disconnected` variant, and `lore-transport/src/grpc/mod.rs` reissues the
/// operation on exactly that variant, bounded by `MAX_RECONNECTS_PER_OP`. So
/// `UNKNOWN` is one of the two codes that *cause* a replay of a mutation whose
/// outcome is unknown, which is the specific thing that must never happen.
///
/// `ABORTED` is selected instead: it falls to the `_ => internal` arm, so it is
/// never replayed, and CR-029 already uses it for the generation/witness loser
/// with the meaning "rerun preflight and refetch authoritative state" — exactly
/// the outcome-unknown instruction. The justification of record is that
/// `From<tonic::Status>` mapping, not generic gRPC retry policy. This is not
/// fixed by changing `lore-transport`: that is a `[CLIENT]`-path crate whose
/// replay policy WP-120 owns, and WP-116 precedes it.
pub fn map_domain_error_to_status(error: &lore_postgres::domain::DomainError) -> Status {
    use lore_postgres::domain::DomainError;

    let status = match error {
        DomainError::InvalidInput(detail) => Status::invalid_argument(detail.clone()),
        DomainError::NotReady(detail) => Status::failed_precondition(detail.clone()),
        DomainError::DomainKeyBypass(detail) => Status::failed_precondition(detail.clone()),
        DomainError::PreconditionRejected { reason, .. } => {
            map_domain_rejection_to_status(reason.as_str())
        }
        // Bounded retry already ran and did not resolve it. Postgres proved the
        // transaction rolled back, so the client may re-drive after refetching.
        DomainError::Contention(detail) => Status::aborted(detail.clone()),
        DomainError::Transient(detail) => Status::resource_exhausted(detail.clone()),
        DomainError::OutcomeUnknown(detail) => {
            warn!(detail = %detail, "Domain commit outcome unknown");
            Status::aborted(DOMAIN_OUTCOME_UNKNOWN_DETAIL)
        }
        DomainError::Internal(detail) => {
            warn!(detail = %detail, "Domain store internal error");
            Status::internal("Internal error")
        }
    };
    debug!(code = ?status.code(), error = %error, "Mapped domain error");
    status
}

/// Map one frozen rejection reason to its public result.
///
/// Every denial-shaped reason collapses to the same `NOT_FOUND` and the same
/// fixed detail, so a caller cannot distinguish an unauthorized live
/// repository, an unknown one, a tombstoned one, and a race it lost.
fn map_domain_rejection_to_status(reason: &str) -> Status {
    use lore_postgres::domain::coordinator;

    match reason {
        coordinator::GENERATION_MISMATCH_V1 | coordinator::CAS_MISMATCH_V1 => {
            Status::aborted(reason.to_owned())
        }
        coordinator::TOMBSTONED_V1 | coordinator::NOT_FOUND_V1 => {
            Status::not_found(DOMAIN_REPOSITORY_NOT_FOUND_DETAIL)
        }
        coordinator::NAME_TAKEN_V1 | coordinator::FINGERPRINT_MISMATCH_V1 => {
            Status::already_exists(reason.to_owned())
        }
        coordinator::ADMISSION_REJECTED_V1 => Status::failed_precondition(reason.to_owned()),
        // Vocabulary drift between the coordinator and this mapper. Refusing to
        // guess is deliberate: an unrecognised reason must not become a code
        // that instructs the client to retry a decisive rejection.
        other => {
            warn!(reason = %other, "Unrecognised domain rejection reason");
            Status::internal("Internal error")
        }
    }
}

pub fn get_repository(metadata: &MetadataMap) -> Result<RepositoryId, Status> {
    let repo_id = metadata
        .get_bin(PARTITION_ID_KEY)
        .or_else(|| metadata.get_bin(REPOSITORY_ID_KEY))
        .ok_or_else(|| Status::invalid_argument("Missing repository ID"))?;

    let context: Context = repo_id
        .to_bytes()
        .map_err(|e| Status::invalid_argument(format!("Error converting repo ID: {e}")))?
        .into();

    Ok(context.into())
}

/// The verified token when one is present, without treating its absence as an
/// error.
///
/// [`get_authorization`] is the right call when a missing token must fail the
/// request. This one exists for callers that have to distinguish "no verified
/// principal" from "verified principal X" and decide for themselves — the
/// CR-029 domain admission gate, which refuses carriage from an unauthenticated
/// caller but leaves an ordinary auth-off request alone.
pub fn get_authorization_optional(extensions: &Extensions) -> Option<AuthorizationToken> {
    extensions.get::<AuthorizationToken>().cloned()
}

pub fn get_authorization(extensions: &Extensions) -> Result<AuthorizationToken, Status> {
    match extensions.get::<AuthorizationToken>() {
        Some(auth) => Ok(auth.clone()),
        None => Err(Status::unauthenticated("Missing authorization")),
    }
}

pub fn link_read_authorizer(
    authorization: Option<AuthorizationToken>,
) -> lore_revision::state::CanReadRepository {
    match authorization {
        Some(token) => {
            Arc::new(move |repository_id| verify_authorization(&token, repository_id).is_ok())
        }
        None => lore_revision::state::allow_all_repositories(),
    }
}

pub fn get_user_id(extensions: &Extensions) -> String {
    let auth = extensions.get::<AuthorizationToken>();
    get_user_id_from_token_ref(auth)
}

/// Marker that opts the gRPC server crate into [`RepositoryWriteToken::server`].
///
/// Defined here (private) so the only path to mint a server token in this
/// crate is via [`get_write_token`] below.
struct LoreServer;
impl ServerContext for LoreServer {}
const LORE_SERVER: LoreServer = LoreServer;

/// Mint a fresh server-side write token. Server contexts are always writable
/// (the storage layer's per-bucket `RwLock`s are the actual concurrency
/// boundary), so handlers can call this directly at the start of a handler
/// without consulting the `RepositoryContext`.
pub fn get_write_token() -> RepositoryWriteToken {
    RepositoryWriteToken::server(&LORE_SERVER)
}

pub(crate) fn metadata_to_attribute(
    metadata: &MetadataMap,
    extensions: &Extensions,
) -> Result<AttributeMap, Status> {
    let repository = get_repository(metadata)?;
    let attr_map = AttributeMap::default();
    attr_map.insert(repository);

    if let Ok(token) = get_authorization(extensions) {
        attr_map.insert(token);
    }

    Ok(attr_map)
}

pub fn interpret_streaming_error(err: Status) -> Status {
    // Surfaced from tonic crate src/codec/decode.rs
    // An abrupt client error has occurred where they were streaming data then suddenly
    // they have dropped.
    if err.code() == Code::Internal && err.message() == "Unexpected EOF decoding stream." {
        return Status::invalid_argument(format!("Probable client disconnect: {}", err.message()));
    }

    err
}

pub(crate) async fn send_err<T>(status: Status, tx: Sender<Result<T, Status>>) {
    let rpc_status_code = rpc_code_to_str(&status.code());

    if is_code_considered_server_error(&status.code()) {
        warn!(response = ?status, rpc_status_code, "GRPC service send_err - server error");
    } else {
        info!(response = ?status, rpc_status_code, "GRPC service send_err - user error");
    }
    if let Err(e) = tx.send(Err(status)).await {
        debug!(send_error = ?e, "GRPC service error performing send_err");
    }
}

/// Warns if the status code is a server error — call at unified response points so internal failures are observable even when the error path didn't go through `warn_error_to_status`.
pub(crate) fn log_server_error(status: &Status) {
    if is_code_considered_server_error(&status.code()) {
        warn!(
            response = ?status,
            rpc_status_code = rpc_code_to_str(&status.code()),
            "GRPC handler server error response",
        );
    }
}

pub fn is_owner_or_admin(extensions: &Extensions, repository: RepositoryId) -> bool {
    let user_permissions = user_permissions(extensions, repository);
    user_permissions.contains(&"owner".to_string())
        || user_permissions.contains(&"admin".to_string())
}

pub fn can_obliterate(extensions: &Extensions, repository: RepositoryId) -> bool {
    user_permissions(extensions, repository).contains(&"obliterate".to_string())
}

pub fn can_admin_lock(extensions: &Extensions, repository: RepositoryId) -> bool {
    has_required_permission(extensions, repository, "migrate")
}

pub fn get_matching_permissions(
    extensions: &Extensions,
    repository: RepositoryId,
) -> Vec<ResourcePermission> {
    let user_resources = resources_from_token(get_authorization(extensions).ok());
    let repository_to_match = format!("urc-{repository}");

    user_resources
        .into_iter()
        .filter(|resource| resource.matches_repository(&repository_to_match))
        .collect()
}

pub fn has_required_permission(
    extensions: &Extensions,
    repository_to_check: RepositoryId,
    permission_to_check: &str,
) -> bool {
    get_matching_permissions(extensions, repository_to_check)
        .into_iter()
        .any(|resource_permission| {
            resource_permission
                .permission
                .contains(&permission_to_check.to_string())
        })
}

/// Enforce a write-path permission. No-op when auth is OFF (no token in
/// extensions — keeps the auth-disabled dev/CI stack green) or when `enforce`
/// is false; otherwise the token must carry `permission` for this repository,
/// else permission_denied. Lorehub's mint stacks role→scopes, so admin/owner
/// tokens already carry `write`; loreserver stays policy-dumb.
pub fn require_permission(
    extensions: &Extensions,
    repository: RepositoryId,
    permission: &str,
    enforce: bool,
) -> Result<(), Status> {
    if get_authorization(extensions).is_err() {
        return Ok(()); // auth OFF (no token) ⇒ no enforcement
    }
    if enforce && !has_required_permission(extensions, repository, permission) {
        return Err(Status::permission_denied("Permission denied"));
    }
    Ok(())
}

pub fn user_permissions(extensions: &Extensions, repository: RepositoryId) -> Vec<String> {
    let user_resources = resources_from_token(get_authorization(extensions).ok());
    for resource in user_resources {
        let resource_repository = resource
            .resource_id
            .strip_prefix("urc-")
            .unwrap_or_default();
        let resource_repository: RepositoryId = Context::from_str(resource_repository)
            .unwrap_or_default()
            .into();
        if resource_repository == repository {
            return resource.permission;
        }
    }

    Vec::new()
}

pub fn extract_correlation_id<B>(request: &tonic::Request<B>) -> Option<String> {
    match request.metadata().get(CORRELATION_ID_HEADER) {
        Some(val) => val.to_str().map(|s| s.to_string()).ok(),
        None => None,
    }
}

pub fn extract_authorization_header<B>(request: &tonic::Request<B>) -> Option<String> {
    request
        .metadata()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_string())
}

pub fn rpc_code_to_str(code: &Code) -> &'static str {
    match code {
        Code::Ok => "Ok",
        Code::Cancelled => "Cancelled",
        Code::Unknown => "Unknown",
        Code::InvalidArgument => "InvalidArgument",
        Code::DeadlineExceeded => "DeadlineExceeded",
        Code::NotFound => "NotFound",
        Code::AlreadyExists => "AlreadyExists",
        Code::PermissionDenied => "PermissionDenied",
        Code::ResourceExhausted => "ResourceExhausted",
        Code::FailedPrecondition => "FailedPrecondition",
        Code::Aborted => "Aborted",
        Code::OutOfRange => "OutOfRange",
        Code::Unimplemented => "Unimplemented",
        Code::Internal => "Internal",
        Code::Unavailable => "Unavailable",
        Code::DataLoss => "DataLoss",
        Code::Unauthenticated => "Unauthenticated",
    }
}

pub trait ServerResultExt<T, E> {
    fn warn_map_err<Callback>(self, map: Callback) -> Result<T, Status>
    where
        Callback: FnOnce(&E) -> Status;
}

impl<T, E> ServerResultExt<T, E> for Result<T, E>
where
    E: std::error::Error,
{
    fn warn_map_err<Callback>(self, map: Callback) -> Result<T, Status>
    where
        Callback: FnOnce(&E) -> Status,
    {
        match self {
            Ok(t) => Ok(t),
            Err(error) => {
                let response = warn_error_to_status(&error, map);
                Err(response)
            }
        }
    }
}

pub fn warn_error_to_status<E, Callback>(error: &E, map: Callback) -> Status
where
    E: std::error::Error,
    Callback: FnOnce(&E) -> Status,
{
    let response = map(error);
    warn_mapped_error_status(error, &response);
    response
}

pub fn warn_mapped_error_status<E>(error: &E, response: &Status)
where
    E: std::error::Error,
{
    if !is_code_considered_server_error(&response.code()) {
        return;
    }
    let rpc_status_code = rpc_code_to_str(&response.code());
    warn!(?error, ?response, rpc_status_code, "error status");
}

/// Converts a [`HookError`] into a [`tonic::Status`].
///
/// Maps [`StatusCode`] variants to their corresponding gRPC status codes.
/// Non-rejection errors (timeout, panic, execution failure) map to `INTERNAL`.
pub fn hook_error_to_status(error: HookError) -> Status {
    match &error {
        HookError::Rejected {
            message, status, ..
        } => match status {
            StatusCode::PermissionDenied => Status::permission_denied(message),
            StatusCode::FailedPrecondition => Status::failed_precondition(message),
            StatusCode::ResourceExhausted => Status::resource_exhausted(message),
            StatusCode::InvalidArgument => Status::invalid_argument(message),
            StatusCode::Aborted => Status::aborted(message),
            StatusCode::Internal => Status::internal(message),
        },
        _ => Status::internal(error.to_string()),
    }
}

pub fn no_repository_access_status() -> Status {
    Status::permission_denied("Unauthorized")
}

pub fn timeout_grpc<T>(
    duration: Duration,
    fut: impl Future<Output = Result<T, Status>>,
) -> impl Future<Output = Result<T, Status>> {
    timeout(duration, fut).map(|result| {
        result.unwrap_or_else(|_| Err(Status::cancelled("Request handler timeout exceeded")))
    })
}

pub trait FilterSlowDownExt<T, E> {
    fn filter_slow_down(self) -> Result<Result<T, E>, Status>;
}

impl<T> FilterSlowDownExt<T, StateError> for Result<T, StateError> {
    fn filter_slow_down(self) -> Result<Result<T, StateError>, Status> {
        if let Err(err) = &self
            && err.is_slow_down()
        {
            return Err(Status::resource_exhausted(err.to_string()));
        }
        Ok(self)
    }
}

impl<T> FilterSlowDownExt<T, LinkError> for Result<T, LinkError> {
    fn filter_slow_down(self) -> Result<Result<T, LinkError>, Status> {
        if let Err(err) = &self
            && err.is_slow_down()
        {
            return Err(Status::resource_exhausted(err.to_string()));
        }
        Ok(self)
    }
}

impl<T> FilterSlowDownExt<T, MetadataError> for Result<T, MetadataError> {
    fn filter_slow_down(self) -> Result<Result<T, MetadataError>, Status> {
        if let Err(err) = &self
            && err.is_slow_down()
        {
            return Err(Status::resource_exhausted(err.to_string()));
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_authorization_extracts_auth() {
        let mut extensions = Extensions::new();
        let test_authz_token = AuthorizationToken::default();
        extensions.insert(test_authz_token.clone());

        let authz_data = get_authorization(&extensions).ok().unwrap();
        assert_eq!(authz_data, test_authz_token);
    }

    #[test]
    fn get_matching_permissions_includes_matched_repo_permissions() {
        let mut extensions = Extensions::new();
        let test_repository_id = "urc-0194b726b34e72b0b45550b88a967076".to_string();
        let unrelated_repository_id = "urc-0192ae48ccf17060bc1ba9d04f6acb2f".to_string();
        let mut test_authz_token = AuthorizationToken::default();

        let test_resource_permission = ResourcePermission {
            resource_id: test_repository_id.clone(),
            permission: vec!["test_permission".to_string()],
        };

        test_authz_token.resources = Some(vec![test_resource_permission.clone()]);
        extensions.insert(test_authz_token.clone());

        let test_repository_context: RepositoryId =
            Context::from_str(test_repository_id.strip_prefix("urc-").unwrap())
                .unwrap()
                .into();
        let test_unrelated_repository_context: RepositoryId =
            Context::from_str(unrelated_repository_id.strip_prefix("urc-").unwrap())
                .unwrap()
                .into();
        let matched_resources = get_matching_permissions(&extensions, test_repository_context);
        let no_matched_resources =
            get_matching_permissions(&extensions, test_unrelated_repository_context);
        assert_eq!(matched_resources, vec![test_resource_permission]);
        assert_eq!(no_matched_resources, vec![]);
    }

    #[test]
    fn get_matching_permissions_includes_wildcard_resource() {
        let mut extensions = Extensions::new();
        let test_repository_id = "urc-0194b726b34e72b0b45550b88a967076".to_string();
        let unrelated_repository_id = "urc-0192ae48ccf17060bc1ba9d04f6acb2f".to_string();
        let mut test_authz_token = AuthorizationToken::default();

        let test_resource_permission = ResourcePermission {
            resource_id: test_repository_id.clone(),
            permission: vec!["test_permission".to_string()],
        };
        let test_wildcard_resource_permission = ResourcePermission {
            resource_id: "urc-*".to_string().clone(),
            permission: vec!["test_wildcard_permission".to_string()],
        };

        test_authz_token.resources = Some(vec![
            test_resource_permission.clone(),
            test_wildcard_resource_permission.clone(),
        ]);
        extensions.insert(test_authz_token.clone());

        let test_repository_context: RepositoryId =
            Context::from_str(test_repository_id.strip_prefix("urc-").unwrap())
                .unwrap()
                .into();
        let test_unrelated_repository_context: RepositoryId =
            Context::from_str(unrelated_repository_id.strip_prefix("urc-").unwrap())
                .unwrap()
                .into();
        let matched_resources = get_matching_permissions(&extensions, test_repository_context);
        let no_matched_resources =
            get_matching_permissions(&extensions, test_unrelated_repository_context);
        assert_eq!(
            matched_resources,
            vec![
                test_resource_permission,
                test_wildcard_resource_permission.clone()
            ]
        );
        assert_eq!(
            no_matched_resources,
            vec![test_wildcard_resource_permission]
        );
    }

    #[test]
    fn finds_existing_matching_permission_with_regular_repo() {
        let mut extensions = Extensions::new();
        let test_repository_id = "urc-0194b726b34e72b0b45550b88a967076".to_string();
        let unrelated_repository_id = "urc-0192ae48ccf17060bc1ba9d04f6acb2f".to_string();
        let mut test_authz_token = AuthorizationToken::default();

        let test_resource_permission = ResourcePermission {
            resource_id: test_repository_id.clone(),
            permission: vec![
                "test_permission".to_string(),
                "other_permission".to_string(),
            ],
        };

        test_authz_token.resources = Some(vec![test_resource_permission.clone()]);
        extensions.insert(test_authz_token.clone());

        let test_repository_context: RepositoryId =
            Context::from_str(test_repository_id.strip_prefix("urc-").unwrap())
                .unwrap()
                .into();
        let test_unrelated_repository_context: RepositoryId =
            Context::from_str(unrelated_repository_id.strip_prefix("urc-").unwrap())
                .unwrap()
                .into();

        // user has test_permission for a given repo in their token
        assert!(has_required_permission(
            &extensions,
            test_repository_context,
            "test_permission"
        ));
        // user has other_permission for a given repo in their token
        assert!(has_required_permission(
            &extensions,
            test_repository_context,
            "other_permission"
        ));
        // user doesn't have test_permission2 for a given repo in their token
        assert!(!has_required_permission(
            &extensions,
            test_repository_context,
            "test_permission2"
        ),);
        // user doesn't have test_permission for an unrelated repository
        assert!(!has_required_permission(
            &extensions,
            test_unrelated_repository_context,
            "test_permission"
        ),);
        // user doesn't have other_permission for an unrelated repository
        assert!(!has_required_permission(
            &extensions,
            test_unrelated_repository_context,
            "other_permission"
        ));
    }

    #[test]
    fn finds_existing_matching_permission_with_wildcard_repo() {
        let mut extensions = Extensions::new();
        let test_repository_id = "urc-0194b726b34e72b0b45550b88a967076".to_string();
        let unrelated_repository_id = "urc-0192ae48ccf17060bc1ba9d04f6acb2f".to_string();
        let mut test_authz_token = AuthorizationToken::default();

        let test_resource_permission = ResourcePermission {
            resource_id: test_repository_id.clone(),
            permission: vec![
                "test_permission".to_string(),
                "unique_permission".to_string(),
            ],
        };
        let test_wildcard_resource_permission = ResourcePermission {
            resource_id: "urc-*".to_string().clone(),
            permission: vec![
                "test_permission".to_string(),
                "test_wildcard_permission".to_string(),
                "another_wildcard_permission".to_string(),
            ],
        };

        test_authz_token.resources = Some(vec![
            test_resource_permission.clone(),
            test_wildcard_resource_permission.clone(),
        ]);
        extensions.insert(test_authz_token.clone());

        let test_repository_context: RepositoryId =
            Context::from_str(test_repository_id.strip_prefix("urc-").unwrap())
                .unwrap()
                .into();
        let test_unrelated_repository_context: RepositoryId =
            Context::from_str(unrelated_repository_id.strip_prefix("urc-").unwrap())
                .unwrap()
                .into();

        // user has test_permission for a given repo in their token
        assert!(has_required_permission(
            &extensions,
            test_repository_context,
            "test_permission"
        ));
        // user has unique_permission for a given repo in their token
        assert!(has_required_permission(
            &extensions,
            test_repository_context,
            "unique_permission"
        ));
        // user has test_wildcard_permission for a given repo — through the wildcard resource
        assert!(has_required_permission(
            &extensions,
            test_repository_context,
            "test_wildcard_permission"
        ));
        // user also has test_permission for an unrelated repository — through the wildcard resource
        assert!(has_required_permission(
            &extensions,
            test_unrelated_repository_context,
            "test_permission"
        ));

        // user doesn't have unique_permission for an unrelated repository
        assert!(!has_required_permission(
            &extensions,
            test_unrelated_repository_context,
            "unique_permission"
        ));
    }

    #[test]
    fn can_admin_lock_with_direct_permission_claim() {
        let mut extensions = Extensions::new();
        let test_repository_id = "urc-0194b726b34e72b0b45550b88a967076".to_string();
        let unrelated_repository_id = "urc-0192ae48ccf17060bc1ba9d04f6acb2f".to_string();
        let mut test_authz_token = AuthorizationToken::default();

        let test_resource_permission = ResourcePermission {
            resource_id: test_repository_id.clone(),
            permission: vec!["test_permission".to_string(), "migrate".to_string()],
        };

        test_authz_token.resources = Some(vec![test_resource_permission.clone()]);
        extensions.insert(test_authz_token.clone());

        let test_repository_context: RepositoryId =
            Context::from_str(test_repository_id.strip_prefix("urc-").unwrap())
                .unwrap()
                .into();
        let test_unrelated_repository_context: RepositoryId =
            Context::from_str(unrelated_repository_id.strip_prefix("urc-").unwrap())
                .unwrap()
                .into();

        // as user has "migrate" permission for a given repo, they CAN admin lock that repo
        assert!(can_admin_lock(&extensions, test_repository_context));

        // as user doesn't have "migrate" permission for an unrelated repo, they CAN'T admin lock that repo
        assert!(!can_admin_lock(
            &extensions,
            test_unrelated_repository_context
        ));
    }

    #[test]
    fn can_admin_lock_with_wildcard_permission_claim() {
        let mut extensions = Extensions::new();
        let test_repository_id = "urc-0194b726b34e72b0b45550b88a967076".to_string();
        let unrelated_repository_id = "urc-0192ae48ccf17060bc1ba9d04f6acb2f".to_string();
        let mut test_authz_token = AuthorizationToken::default();

        let test_resource_permission = ResourcePermission {
            resource_id: test_repository_id.clone(),
            permission: vec!["test_permission".to_string(), "migrate".to_string()],
        };

        let test_wildcard_resource_permission = ResourcePermission {
            resource_id: "urc-*".to_string().clone(),
            permission: vec![
                "migrate".to_string(),
                "test_wildcard_permission".to_string(),
            ],
        };

        test_authz_token.resources = Some(vec![
            test_resource_permission.clone(),
            test_wildcard_resource_permission.clone(),
        ]);
        extensions.insert(test_authz_token.clone());

        let test_repository_context: RepositoryId =
            Context::from_str(test_repository_id.strip_prefix("urc-").unwrap())
                .unwrap()
                .into();
        let test_unrelated_repository_context: RepositoryId =
            Context::from_str(unrelated_repository_id.strip_prefix("urc-").unwrap())
                .unwrap()
                .into();

        // as user has "migrate" permission for a given repo, they CAN admin lock that repo
        assert!(can_admin_lock(&extensions, test_repository_context));

        // user doesn't have direct "migrate" permission for an unrelated repo
        // but they have a wildcard token with "migrate", so they should be able to admin lock arbitrary repo
        assert!(can_admin_lock(
            &extensions,
            test_unrelated_repository_context
        ));
    }

    mod timeout_grpc_tests {
        use std::time::Duration;

        use super::*;

        #[tokio::test]
        async fn returns_ok_when_future_succeeds_within_timeout() {
            let fut = async { Ok::<_, Status>(42) };
            let result = timeout_grpc(Duration::from_secs(1), fut).await;
            assert_eq!(result.unwrap(), 42);
        }

        #[tokio::test]
        async fn preserves_original_error_when_future_fails_within_timeout() {
            let fut = async { Err::<i32, _>(Status::not_found("missing")) };
            let result = timeout_grpc(Duration::from_secs(1), fut).await;
            let status = result.unwrap_err();
            assert_eq!(status.code(), Code::NotFound);
            assert_eq!(status.message(), "missing");
        }

        #[tokio::test]
        async fn returns_cancelled_when_future_exceeds_timeout() {
            let fut = async {
                tokio::time::sleep(Duration::from_secs(10)).await;
                Ok::<_, Status>(42)
            };
            let result = timeout_grpc(Duration::from_millis(10), fut).await;
            let status = result.unwrap_err();
            assert_eq!(status.code(), Code::Cancelled);
            assert!(status.message().contains("timeout"));
        }
    }

    mod filter_slow_down_tests {
        use lore_base::error::SlowDown;

        use super::*;

        #[test]
        fn state_ok_passes_through() {
            let result: Result<i32, StateError> = Ok(42);
            let filtered = result.filter_slow_down().unwrap();
            assert_eq!(filtered.unwrap(), 42);
        }

        #[test]
        fn state_slow_down_returns_resource_exhausted() {
            let result: Result<i32, StateError> = Err(StateError::from(SlowDown));
            let status = result.filter_slow_down().unwrap_err();
            assert_eq!(status.code(), Code::ResourceExhausted);
        }

        #[test]
        fn state_error_passes_through() {
            let result: Result<i32, StateError> = Err(StateError::internal("other error"));
            let filtered = result.filter_slow_down().unwrap();
            let underlying_error = filtered.expect_err("Should be err");
            assert!(!underlying_error.is_slow_down());
        }

        #[test]
        fn metadata_ok_passes_through() {
            let result: Result<i32, MetadataError> = Ok(42);
            let filtered = result.filter_slow_down().unwrap();
            assert_eq!(filtered.unwrap(), 42);
        }

        #[test]
        fn metadata_slow_down_returns_resource_exhausted() {
            let result: Result<i32, MetadataError> = Err(MetadataError::from(SlowDown));
            let status = result.filter_slow_down().unwrap_err();
            assert_eq!(status.code(), Code::ResourceExhausted);
        }

        #[test]
        fn metadata_error_passes_through() {
            let result: Result<i32, MetadataError> = Err(MetadataError::internal("other error"));
            let filtered = result.filter_slow_down().unwrap();
            let underlying_error = filtered.expect_err("Should be err");
            assert!(!underlying_error.is_slow_down());
        }
    }

    mod domain_error_mapping_tests {
        use lore_postgres::domain::DomainError;
        use lore_postgres::domain::coordinator;
        use lore_transport::error::ProtocolError;

        use super::*;

        #[test]
        fn invalid_input_maps_to_invalid_argument() {
            let status = map_domain_error_to_status(&DomainError::InvalidInput("bad".into()));
            assert_eq!(status.code(), Code::InvalidArgument);
        }

        #[test]
        fn not_ready_maps_to_failed_precondition() {
            let status = map_domain_error_to_status(&DomainError::NotReady("not ready".into()));
            assert_eq!(status.code(), Code::FailedPrecondition);
        }

        #[test]
        fn domain_key_bypass_maps_to_failed_precondition() {
            let status = map_domain_error_to_status(&DomainError::DomainKeyBypass("bypass".into()));
            assert_eq!(status.code(), Code::FailedPrecondition);
        }

        #[test]
        fn contention_maps_to_aborted() {
            let status = map_domain_error_to_status(&DomainError::Contention("contention".into()));
            assert_eq!(status.code(), Code::Aborted);
        }

        #[test]
        fn transient_maps_to_resource_exhausted() {
            let status = map_domain_error_to_status(&DomainError::Transient("transient".into()));
            assert_eq!(status.code(), Code::ResourceExhausted);
        }

        #[test]
        fn outcome_unknown_maps_to_aborted_with_the_fixed_detail() {
            let status =
                map_domain_error_to_status(&DomainError::OutcomeUnknown("lost ack".into()));
            assert_eq!(status.code(), Code::Aborted);
            assert_eq!(status.message(), DOMAIN_OUTCOME_UNKNOWN_DETAIL);
        }

        #[test]
        fn internal_maps_to_internal_without_leaking_the_inner_detail() {
            let secret_detail = "connection string password=hunter2";
            let status = map_domain_error_to_status(&DomainError::Internal(secret_detail.into()));
            assert_eq!(status.code(), Code::Internal);
            assert!(!status.message().contains(secret_detail));
        }

        #[test]
        fn generation_and_cas_mismatch_reasons_map_to_aborted() {
            for reason in [
                coordinator::GENERATION_MISMATCH_V1,
                coordinator::CAS_MISMATCH_V1,
            ] {
                let status = map_domain_rejection_to_status(reason);
                assert_eq!(status.code(), Code::Aborted);
            }
        }

        // Indistinguishability is the security property under test: a
        // tombstoned repository and one that never existed must be
        // byte-identical NOT_FOUND responses, or a caller could use the
        // difference to probe for a repository's prior existence.
        #[test]
        fn tombstoned_and_never_existed_are_byte_identical_not_found_responses() {
            let tombstoned = map_domain_rejection_to_status(coordinator::TOMBSTONED_V1);
            let not_found = map_domain_rejection_to_status(coordinator::NOT_FOUND_V1);

            assert_eq!(tombstoned.code(), Code::NotFound);
            assert_eq!(tombstoned.message(), DOMAIN_REPOSITORY_NOT_FOUND_DETAIL);
            assert_eq!(tombstoned.code(), not_found.code());
            assert_eq!(tombstoned.message(), not_found.message());
        }

        #[test]
        fn name_taken_and_fingerprint_mismatch_reasons_map_to_already_exists() {
            for reason in [
                coordinator::NAME_TAKEN_V1,
                coordinator::FINGERPRINT_MISMATCH_V1,
            ] {
                let status = map_domain_rejection_to_status(reason);
                assert_eq!(status.code(), Code::AlreadyExists);
            }
        }

        #[test]
        fn admission_rejected_maps_to_failed_precondition() {
            let status = map_domain_rejection_to_status(coordinator::ADMISSION_REJECTED_V1);
            assert_eq!(status.code(), Code::FailedPrecondition);
        }

        #[test]
        fn unrecognised_reason_maps_to_internal() {
            let status = map_domain_rejection_to_status("SOME_UNKNOWN_REASON_V99");
            assert_eq!(status.code(), Code::Internal);
        }

        // R-BLOCK-1, CR-029: an indeterminate database commit must map to a
        // gRPC code whose `From<tonic::Status>` arm in `lore-transport` is not
        // `Disconnected`. `lore-transport/src/error.rs` folds `Unavailable`
        // AND `Unknown` into `ProtocolError::Disconnected`, and
        // `lore-transport/src/grpc/mod.rs` reissues the operation on exactly
        // that variant (bounded by `MAX_RECONNECTS_PER_OP`) — i.e. it would
        // replay a mutation whose outcome is unknown. This is the most
        // important test in this batch: it is the regression pin for that
        // rule, not merely a mapping check.
        #[test]
        fn outcome_unknown_never_maps_into_the_transport_replay_arm() {
            let status =
                map_domain_error_to_status(&DomainError::OutcomeUnknown("lost ack".into()));

            let protocol_error = ProtocolError::from(status);

            assert!(!matches!(protocol_error, ProtocolError::Disconnected(_)));

            // The guard that gives the assertion above its teeth: without these
            // two positive checks, the negative assertion would still pass if
            // someone silently changed the transport's own mapping too.
            assert!(matches!(
                ProtocolError::from(Status::new(Code::Unknown, "")),
                ProtocolError::Disconnected(_)
            ));
            assert!(matches!(
                ProtocolError::from(Status::new(Code::Unavailable, "")),
                ProtocolError::Disconnected(_)
            ));
        }
    }
}

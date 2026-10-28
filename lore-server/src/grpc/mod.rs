// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use futures::FutureExt;
pub mod admin_service;
pub mod caller_capabilities;
pub mod domain;
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

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

mod grpc_internal_server;
mod replication_service;
pub mod tower;

pub use admin_service::LoreAdminService;
pub use grpc_internal_server::GrpcInternalServerBuilder;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_postgres::domain::locks::VerifiedLockOwner;
use lore_revision::branch::BranchError;
use lore_revision::diff::DiffError;
use lore_revision::find::FindError;
use lore_revision::immutable::ImmutableError;
use lore_revision::link::LinkError;
use lore_revision::lore::RepositoryId;
use lore_revision::metadata::MetadataError;
use lore_revision::metadata::branch::BranchMetadataError;
use lore_revision::metadata::repository::RepositoryMetadataError;
use lore_revision::repository::RepositoryError;
use lore_revision::repository::RepositoryWriteToken;
use lore_revision::repository::ServerContext;
use lore_revision::state::StateError;
use lore_storage::StoreError;
use lore_transport::grpc::CORRELATION_ID_HEADER;
use lore_transport::grpc::PARTITION_ID_KEY;
use lore_transport::grpc::REPOSITORY_ID_KEY;
pub use repository::LoreRepositoryV1Service;
pub use revision::LoreRevisionV1Service;
pub use revision_service::LoreRevisionService;
pub use server::GrpcServerBuilder;
pub use server::GrpcServiceSettings;
pub use server::GrpcTimeouts;
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
use crate::auth::jwt::ResourceMatcher;
use crate::authnz::repository_authorizer::RawToken;
use crate::authnz::repository_authorizer::RepositoryAuthorizer;
use crate::authnz::repository_authorizer::VerifiedToken;
use crate::authnz::repository_authorizer::VerifiedTokenOwned;
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
        MessageHandleError::OutcomeUnknown => (
            Code::Aborted,
            message.unwrap_or_else(|| "Store operation outcome is unknown".into()),
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
        MessageHandleError::LocalStoreUnavailable(_) => (
            Code::Unimplemented,
            message.unwrap_or_else(|| error.to_string()),
        ),
        MessageHandleError::UnsupportedClient => (
            Code::FailedPrecondition,
            message.unwrap_or_else(|| "unsupported client capability".into()),
        ),
        MessageHandleError::DomainKeyRefused(_) => (
            Code::PermissionDenied,
            message.unwrap_or_else(|| error.to_string()),
        ),
        // FORK-LOCAL (Tideshift, WP-124): raised only by the QUIC storage service; gRPC checks
        // the token per call in its interceptor and never reaches this arm.
        MessageHandleError::SessionExpired => (
            Code::Unauthenticated,
            message.unwrap_or_else(|| error.to_string()),
        ),
    };

    let mut status = Status::with_details(code, message, details.unwrap_or_default());
    if matches!(error, MessageHandleError::UnsupportedClient) {
        status.metadata_mut().insert(
            caller_capabilities::ADMISSION_HEADER,
            tonic::metadata::MetadataValue::from_static("unsupported-client"),
        );
    }
    if matches!(error, MessageHandleError::OutcomeUnknown) {
        status.metadata_mut().insert(
            lore_transport::outcome::OUTCOME_UNKNOWN_METADATA_KEY,
            tonic::metadata::MetadataValue::from_static(
                lore_transport::outcome::OUTCOME_UNKNOWN_METADATA_VALUE,
            ),
        );
    }
    status
}

/// Stable client-facing meaning of an indeterminate domain commit.
///
/// CR-029's triage selects `ABORTED` for both an outcome-unknown commit and a
/// contention loss, so the message is what separates "may have committed" from
/// "provably rolled back". That makes it a wire contract, not a log line: it is
/// emitted verbatim with nothing interpolated, so a client compares it for
/// equality rather than parsing it, and [`DOMAIN_CONTENTION_DETAIL`] is
/// likewise fixed so the two can never collide.
///
/// A typed status detail would carry this better than a message does. That is a
/// wire-contract decision CR-029's triage did not make - it chose the code and
/// said nothing about details - so it is left to the CR rather than invented
/// here.
pub const DOMAIN_OUTCOME_UNKNOWN_DETAIL: &str =
    "mutation outcome unknown; refetch authoritative state before retry";

/// Stable client-facing meaning of a contention loss.
///
/// Fixed rather than pass-through for two reasons: it must never coincide with
/// [`DOMAIN_OUTCOME_UNKNOWN_DETAIL`], and the underlying value is a SQLSTATE
/// context string that no client should see.
pub const DOMAIN_CONTENTION_DETAIL: &str =
    "domain transaction contention; the transaction rolled back, refetch and retry";

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
        DomainError::NotReady(detail) | DomainError::DomainKeyBypass(detail) => {
            Status::failed_precondition(detail.clone())
        }
        DomainError::PreconditionRejected { reason, .. } => {
            map_domain_rejection_to_status(reason.as_str())
        }
        // Bounded retry already ran and did not resolve it. Postgres proved the
        // transaction rolled back, so the client may re-drive after refetching.
        // Distinct from the outcome-unknown arm below, which shares this code
        // but explicitly may have committed.
        DomainError::Contention(detail) => {
            debug!(detail = %detail, "Domain transaction contention");
            Status::aborted(DOMAIN_CONTENTION_DETAIL)
        }
        DomainError::Transient(detail) => {
            debug!(detail = %detail, "Domain store transient failure");
            Status::resource_exhausted("Domain store temporarily unavailable")
        }
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
#[lore_macro::test_pub]
pub(crate) fn map_domain_rejection_to_status(reason: &str) -> Status {
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

/// Rebuild the interceptor-verified token from request extensions. `None`
/// when no interceptor ran (no verifier configured) or when either half is
/// missing.
pub fn get_verified_token(extensions: &Extensions) -> Option<VerifiedToken<'_>> {
    let claims = extensions.get::<AuthorizationToken>()?;
    let raw = extensions.get::<RawToken>()?;
    Some(VerifiedToken {
        raw: &raw.0,
        claims,
    })
}

/// The cross-partition link-read check for a revision-graph traversal: may
/// the caller behind `extensions` reach a partition a link points into?
///
/// Asked synchronously, potentially many times per request, so it consults
/// [`RepositoryAuthorizer::check_repository_access_sync`] with the verified
/// token and denies when the authorizer cannot answer without I/O. The
/// partition-access layer's `PartitionGrants` extension does not apply: it
/// answers for the request's own partition, and a link points elsewhere.
pub fn link_read_authorizer(
    authorizer: &Arc<dyn RepositoryAuthorizer>,
    extensions: &Extensions,
) -> lore_revision::state::CanReadRepository {
    let authorizer = authorizer.clone();
    let token = get_verified_token(extensions).map(|token| token.owned());
    Arc::new(move |repository_id| {
        let token = token.as_ref().map(VerifiedTokenOwned::as_token);
        authorizer
            .check_repository_access_sync(token.as_ref(), repository_id, None)
            .is_some_and(|verdict| verdict.is_ok())
    })
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

    // Both halves of the verified token, so a handler working from the
    // attribute map (copy's source check) can rebuild a `VerifiedToken`.
    if let Ok(token) = get_authorization(extensions) {
        attr_map.insert(token);
    }
    if let Some(raw) = extensions.get::<RawToken>() {
        attr_map.insert(raw.clone());
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

/// FORK-LOCAL (Tideshift): the permission list of the FIRST token resource
/// whose `urc-<hex>` id names `repository`, and nothing else.
///
/// This is the pre-v0.10.0 `user_permissions` reader, kept verbatim for the
/// fork-owned sites that were built on it. Upstream 657e05e9 changed
/// [`user_permissions`] to merge every matching entry and honour `urc-*`; this
/// helper does neither. A `urc-*` entry never matches here (its id does not
/// parse as a repository), and an exact entry after the first is ignored.
pub fn first_exact_repository_permissions(
    extensions: &Extensions,
    repository: RepositoryId,
) -> Vec<String> {
    let user_resources = resources_from_token(get_authorization(extensions).ok());
    for resource in user_resources {
        let resource_repository = resource
            .resource_id
            .strip_prefix("urc-")
            .unwrap_or_default();
        let resource_repository: RepositoryId = resource_repository
            .parse::<Context>()
            .unwrap_or_default()
            .into();
        if resource_repository == repository {
            return resource.permission;
        }
    }

    Vec::new()
}

/// FORK-LOCAL (Tideshift): whether a `BranchCreate` caller may name a
/// `creator` other than its own verified identity.
///
/// Requires `owner` or `admin` on the FIRST exact `urc-<repository>` entry
/// (see [`first_exact_repository_permissions`]). A `urc-*` grant does not
/// qualify. This keeps the fork's pre-v0.10.0 creator-attribution rule; it does
/// not follow upstream's wildcard-honouring [`is_owner_or_admin`].
pub fn can_set_branch_creator(extensions: &Extensions, repository: RepositoryId) -> bool {
    let permissions = first_exact_repository_permissions(extensions, repository);
    permissions
        .iter()
        .any(|permission| permission == "owner" || permission == "admin")
}

pub fn can_obliterate(extensions: &Extensions, repository: RepositoryId) -> bool {
    user_permissions(extensions, repository).contains(&"obliterate".to_string())
}

pub fn can_admin_lock(extensions: &Extensions, repository: RepositoryId) -> bool {
    user_permissions(extensions, repository).contains(&"migrate".to_string())
}

/// The `ForceUnlock` bar: the `owner` permission, and deliberately not
/// [`can_admin_lock`]'s `migrate`.
///
/// **The platform table no longer says the same thing, and that is deliberate.**
/// Owner ruling D8 (2026-09-15) lowered `lock.force_release` in the platform's
/// direct-authorization table to `write`/`developer`, because that rail's
/// request carries no target-owner field and so cannot tell a self force-release
/// from an administrative one. This gate CAN tell them apart — that is what
/// [`is_self_force_unlock`] is — so it keeps `owner` for the administrative half
/// and does not follow the table down. Do NOT "re-align" this to the table on
/// the strength of the paragraph below: the alignment argument it makes is
/// historical, and acting on it now would hand every `developer` the authority
/// to break another user's lock. See
/// `lorehub/docs/lore-change-requests/cr-030-same-principal-force-unlock-amendment.md`.
///
/// CR-030 P-030-2, and the history that produced it. The two halves of this
/// authority used to disagree by name:
/// the wire gate here required `migrate`, while the platform's
/// direct-authorization table gives `lock.force_release` the permission `owner`
/// and `lock.admin_acquire` the permission `migrate`. Only the `owner` role
/// carries both today, so the two agreed in effect and would have diverged the
/// moment a role carried one but not the other. The ruling names the platform
/// table as the contract, so `ForceUnlock` gets its own gate and `AdminLock`
/// keeps [`can_admin_lock`].
///
/// `owner` is a first-class scope in the JWT vocabulary this server reads, not a
/// new name introduced here: [`is_owner_or_admin`] already matches the same
/// string, and Lorehub's mint emits it for the `owner` role alongside `migrate`.
///
/// It reads the string through [`has_required_permission`], which merges ALL
/// resources matching the repository and honours the `urc-*` wildcard. That
/// was its semantics before v0.10.0 and it is unchanged. Since upstream
/// 657e05e9 (merged at v0.10.0) [`is_owner_or_admin`], [`can_admin_lock`] and
/// [`can_obliterate`] resolve the same way through [`user_permissions`]. The
/// fork's branch-creator rule does NOT: it keeps the pre-v0.10.0 first-exact,
/// no-wildcard reader ([`can_set_branch_creator`]). This gate still behaves
/// exactly like [`can_admin_lock`], the sibling it was split away from, so the
/// two administrative RPCs differ in which scope they demand and in nothing
/// else.
pub fn can_force_unlock(extensions: &Extensions, repository: RepositoryId) -> bool {
    has_required_permission(extensions, repository, "owner")
}

/// The second, role-independent half of the `ForceUnlock` bar: the caller IS
/// the principal the force-release names.
///
/// Owner ruling D8 (2026-09-15). WP-117 fences a lock's ownership token to the
/// client session that acquired it, not to the user, so a user holding their own
/// lock on one client (the desktop agent, or Unreal through it) has no token for
/// it on another (the web portal). Force-release is the only authorized way out
/// of that state, and gating it on the `owner` permission alone left a
/// `developer` or `maintainer` with no release path for a lock that is already
/// theirs. Ownership of the lock is authority enough to break one's own.
///
/// This is a self-check, never a widening. It authorizes exactly the caller
/// naming their own verified principal, and nothing about any other caller
/// changes: [`can_force_unlock`] is untouched, and a caller without it who names
/// somebody else is refused exactly as before.
///
/// **No second round trip, and no trust in the named string.** The wire value is
/// client-supplied, but it is not believed here — it is only compared. What
/// makes that sufficient is what the domain does with the same string
/// afterwards: `fenced_force_release` always builds `ForceReleaseInput`'s
/// `target_owner` with the CALLER's own `verified_issuer`, and `release_inner`
/// matches `row.owner.ct_matches(target)` on every resource unconditionally,
/// rejecting the batch otherwise. So a caller admitted by this check can only
/// ever reach rows recorded to their own verified `(issuer, subject)` pair; a
/// caller who names their own subject to reach a row held by a same-named
/// subject under a different issuer clears this gate and is still refused by
/// that match. The gate therefore never has to read the lock rows to decide.
///
/// **Still repository-scoped.** Naming oneself is authority over one's own lock,
/// not a reason to be answered about a repository at all. Without the `read`
/// conjunct below, any authenticated principal could name itself against an
/// arbitrary repository id, clear this gate, and read cell state back out of
/// what follows — `fenced_call` discloses whether fenced routing is active and
/// whether the cell is wired for it, and the outcome then separates `NotFound`
/// from `AuthorityMismatch`. That is precisely the disclosure the bar is
/// ordered to prevent, and it does not stop being a disclosure because the
/// release itself would have failed.
///
/// Fails closed on every ambiguity about who is calling, who is named, and
/// whether the caller may be answered about this repository: no verified token
/// (auth OFF), an anonymous token carrying no subject, an unnamed target, or no
/// `read` scope here all answer `false` rather than self-authorize.
///
/// The comparison itself is [`VerifiedLockOwner::ct_matches`], the same
/// comparator the domain uses to decide the identical question, rather than a
/// short-circuiting `==`. Both sides are built from the caller's own issuer, so
/// it reduces to a constant-time compare of the subject; the issuer half is
/// carried anyway because it is the pair, not the subject, that the domain
/// matches, and a future caller-supplied issuer must not quietly become a
/// subject-only check.
pub fn is_self_force_unlock(
    extensions: &Extensions,
    repository: RepositoryId,
    target_owner: &str,
) -> bool {
    if target_owner.is_empty() {
        return false;
    }
    if !has_required_permission(extensions, repository, "read") {
        return false;
    }
    let Some(token) = extensions.get::<AuthorizationToken>() else {
        return false; // auth OFF, or an unauthenticated call: never self-authorize
    };
    if token.user_id.is_empty() {
        return false;
    }
    let caller = VerifiedLockOwner {
        verified_issuer: token.issuer.clone(),
        authenticated_subject: token.user_id.clone(),
    };
    // The issuer is the caller's own on both sides because that is precisely how
    // `fenced_force_release` composes the target the domain will match against.
    let named = VerifiedLockOwner {
        verified_issuer: token.issuer.clone(),
        authenticated_subject: target_owner.to_owned(),
    };
    caller.ct_matches(&named)
}

/// FORK-LOCAL (Tideshift, CR-018 / CR-030): whether the verified token grants
/// `permission_to_check` on `repository_to_check`.
///
/// Reads the token's `resources` claim through [`user_permissions`], which
/// since upstream 657e05e9 merges every matching entry and honours the `urc-*`
/// wildcard — the semantics the fork's earlier filter-all-matching reader had.
/// It deliberately reads the claim, not the configured `RepositoryAuthorizer`,
/// for parity with the pre-v0.10.0 write gate (merge decision D2). A follow-up
/// is open: an identity token (no `resources` claim) that reaches a service
/// through the online authorizer is still refused every write here.
pub fn has_required_permission(
    extensions: &Extensions,
    repository_to_check: RepositoryId,
    permission_to_check: &str,
) -> bool {
    user_permissions(extensions, repository_to_check)
        .iter()
        .any(|permission| permission == permission_to_check)
}

/// Enforce a write-path permission. No-op when auth is OFF (no token in
/// extensions — keeps the auth-disabled dev/CI stack green) or when `enforce`
/// is false; otherwise the token must carry `permission` for this repository,
/// else `permission_denied`. Lorehub's mint stacks role→scopes, so admin/owner
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
    ResourceMatcher::default().merged_permissions(&user_resources, repository)
}

pub fn extract_correlation_id<B>(request: &tonic::Request<B>) -> Option<String> {
    match request.metadata().get(CORRELATION_ID_HEADER) {
        Some(val) => val.to_str().map(|s| s.to_string()).ok(),
        None => None,
    }
}

/// The call's correlation id, read from metadata alone.
///
/// For a seam that is handed a `MetadataMap` rather than the whole `Request` and
/// still has to name the call it is refusing. Falls back to the same sentinel the
/// per-RPC spans use, so a log line never renders an empty field and "absent" is
/// distinguishable from "blank".
pub fn correlation_id_of(metadata: &tonic::metadata::MetadataMap) -> String {
    metadata
        .get(CORRELATION_ID_HEADER)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty())
        .unwrap_or(crate::quic::NO_CORRELATION_ID)
        .to_owned()
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

/// What an authorization check answers with when its own bound elapses,
/// wherever that check is made. A server condition rather than a denial, and
/// worded apart from a handler timeout so that which of the two elapsed stays
/// legible in logs and metrics.
pub fn authorization_timeout_status() -> Status {
    Status::cancelled("Authorization timeout exceeded")
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

/// Implements [`FilterSlowDownExt`] for error sets that declare a `SlowDown`
/// variant: the backpressure signal becomes `RESOURCE_EXHAUSTED`, and every
/// other outcome passes through for the caller to match on.
macro_rules! impl_filter_slow_down {
    ($($error:ty),+ $(,)?) => {
        $(
            impl<T> FilterSlowDownExt<T, $error> for Result<T, $error> {
                fn filter_slow_down(self) -> Result<Result<T, $error>, Status> {
                    if let Err(err) = &self
                        && err.is_slow_down()
                    {
                        return Err(Status::resource_exhausted(err.to_string()));
                    }
                    Ok(self)
                }
            }
        )+
    };
}

impl_filter_slow_down!(
    BranchError,
    BranchMetadataError,
    DiffError,
    FindError,
    ImmutableError,
    LinkError,
    MetadataError,
    RepositoryError,
    RepositoryMetadataError,
    StateError,
    StoreError,
);

/// Converts a failed result into `Ok(None)` when `discard` accepts the error,
/// and into a [`Status`] otherwise.
///
/// The failing path routes through [`FilterSlowDownExt::filter_slow_down`]
/// first, so an error that carries its own status keeps it and only the
/// remainder is reported as internal. A caller that can act on `None` keeps
/// that path without also discarding the errors it cannot act on.
pub fn none_or_status<T, E>(
    result: Result<T, E>,
    discard: impl FnOnce(&E) -> bool,
) -> Result<Option<T>, Status>
where
    Result<T, E>: FilterSlowDownExt<T, E>,
    E: std::error::Error,
{
    match result.filter_slow_down()? {
        Ok(value) => Ok(Some(value)),
        Err(err) if discard(&err) => Ok(None),
        Err(err) => Err(warn_error_to_status(&err, |err| {
            Status::internal(err.to_string())
        })),
    }
}

/// Reads a revision hash out of a request's `signature` field, refusing a
/// signature that is not a whole one.
///
/// A partial hash signature is a request the server cannot act on rather than a
/// revision it looked for and did not find, so it is refused as
/// `FAILED_PRECONDITION`: retrying it unchanged fails the same way.
///
/// An empty field is not a partial signature but an unset one, and is left to
/// the zero hash its callers already handle.
pub fn revision_signature(signature: Bytes) -> Result<Hash, Status> {
    if !signature.is_empty() && signature.len() != size_of::<Hash>() {
        return Err(Status::failed_precondition(format!(
            "partial revision hash signature of {} byte(s) - give the whole {} byte signature, or a branch and revision number",
            signature.len(),
            size_of::<Hash>(),
        )));
    }

    Ok(Hash::from(signature))
}

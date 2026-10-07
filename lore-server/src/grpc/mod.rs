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
use crate::auth::jwt::verify_authorization;
use crate::authnz::repository_authorizer::RawToken;
use crate::authnz::repository_authorizer::VerifiedToken;
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
    };

    let mut status = Status::with_details(code, message, details.unwrap_or_default());
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::auth::jwt::ResourcePermission;

    #[test]
    fn revision_signature_reads_a_whole_signature() {
        let hash = Hash::hash_buffer(&[1, 2, 3]);
        let read = revision_signature(Bytes::from(hash)).expect("a whole signature is read");
        assert_eq!(read, hash);
    }

    // Not a partial signature but an unset one, which the callers already answer
    // for as a revision that does not exist.
    #[test]
    fn revision_signature_reads_an_absent_signature_as_zero() {
        let read = revision_signature(Bytes::new()).expect("an unset signature is read");
        assert!(read.is_zero());
    }

    // Both directions of wrong: a prefix of a hash, and a hash with anything
    // trailing it.
    #[test]
    fn revision_signature_refuses_a_signature_that_is_not_whole() {
        let hash = Hash::hash_buffer(&[1, 2, 3]);
        for length in [1, 8, size_of::<Hash>() - 1, size_of::<Hash>() + 1] {
            let mut signature = Vec::from(Bytes::from(hash));
            signature.resize(length, 0);

            let status = revision_signature(Bytes::from(signature))
                .expect_err("a signature that is not whole is refused");
            assert_eq!(
                status.code(),
                tonic::Code::FailedPrecondition,
                "a {length} byte signature was not refused as a failed precondition",
            );
            assert!(
                status.message().contains("partial revision hash signature"),
                "the refusal does not say what was wrong: {}",
                status.message(),
            );
        }
    }

    #[test]
    fn get_authorization_extracts_auth() {
        let mut extensions = Extensions::new();
        let test_authz_token = AuthorizationToken::default();
        extensions.insert(test_authz_token.clone());

        let authz_data = get_authorization(&extensions).ok().unwrap();
        assert_eq!(authz_data, test_authz_token);
    }

    #[test]
    fn user_permissions_includes_matched_repo_permissions() {
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
        let matched_permissions = user_permissions(&extensions, test_repository_context);
        let no_matched_permissions =
            user_permissions(&extensions, test_unrelated_repository_context);
        assert_eq!(matched_permissions, vec!["test_permission".to_string()]);
        assert_eq!(no_matched_permissions, Vec::<String>::new());
    }

    #[test]
    fn user_permissions_includes_wildcard_resource() {
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
        let matched_permissions = user_permissions(&extensions, test_repository_context);
        let no_matched_permissions =
            user_permissions(&extensions, test_unrelated_repository_context);
        assert_eq!(
            matched_permissions,
            vec![
                "test_permission".to_string(),
                "test_wildcard_permission".to_string()
            ]
        );
        assert_eq!(
            no_matched_permissions,
            vec!["test_wildcard_permission".to_string()]
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
        assert!(
            user_permissions(&extensions, test_repository_context)
                .contains(&"test_permission".to_string())
        );
        // user has other_permission for a given repo in their token
        assert!(
            user_permissions(&extensions, test_repository_context)
                .contains(&"other_permission".to_string())
        );
        // user doesn't have test_permission2 for a given repo in their token
        assert!(
            !user_permissions(&extensions, test_repository_context)
                .contains(&"test_permission2".to_string())
        );
        // user doesn't have test_permission for an unrelated repository
        assert!(
            !user_permissions(&extensions, test_unrelated_repository_context)
                .contains(&"test_permission".to_string())
        );
        // user doesn't have other_permission for an unrelated repository
        assert!(
            !user_permissions(&extensions, test_unrelated_repository_context)
                .contains(&"other_permission".to_string())
        );
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
        assert!(
            user_permissions(&extensions, test_repository_context)
                .contains(&"test_permission".to_string())
        );
        // user has unique_permission for a given repo in their token
        assert!(
            user_permissions(&extensions, test_repository_context)
                .contains(&"unique_permission".to_string())
        );
        // user has test_wildcard_permission for a given repo — through the wildcard resource
        assert!(
            user_permissions(&extensions, test_repository_context)
                .contains(&"test_wildcard_permission".to_string())
        );
        // user also has test_permission for an unrelated repository — through the wildcard resource
        assert!(
            user_permissions(&extensions, test_unrelated_repository_context)
                .contains(&"test_permission".to_string())
        );

        // user doesn't have unique_permission for an unrelated repository
        assert!(
            !user_permissions(&extensions, test_unrelated_repository_context)
                .contains(&"unique_permission".to_string())
        );
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

    /// Regression: two entries matching the same partition merge
    /// their permission lists. The old reader stopped at the first matching
    /// entry, so whichever permission sat in a later entry was lost.
    #[test]
    fn user_permissions_merge_across_matching_entries() {
        let mut extensions = Extensions::new();
        let test_repository_id = "urc-0194b726b34e72b0b45550b88a967076".to_string();
        let mut test_authz_token = AuthorizationToken::default();

        let test_resource_permissions = vec![
            ResourcePermission {
                resource_id: test_repository_id.clone(),
                permission: vec!["push".to_string()],
            },
            ResourcePermission {
                resource_id: "urc-*".to_string(),
                permission: vec!["migrate".to_string()],
            },
            ResourcePermission {
                resource_id: test_repository_id.clone(),
                permission: vec!["obliterate".to_string()],
            },
        ];

        test_authz_token.resources = Some(test_resource_permissions);
        extensions.insert(test_authz_token.clone());

        let test_repository_context: RepositoryId =
            Context::from_str(test_repository_id.strip_prefix("urc-").unwrap())
                .unwrap()
                .into();

        assert_eq!(
            user_permissions(&extensions, test_repository_context),
            vec![
                "push".to_string(),
                "migrate".to_string(),
                "obliterate".to_string()
            ]
        );
    }

    /// Regression: a `urc-*` grant now satisfies `can_obliterate`
    /// and `is_owner_or_admin`, not just `can_admin_lock`. The old
    /// `user_permissions` reader never looked at the wildcard entry, so the
    /// three checks disagreed about one token.
    #[test]
    fn wildcard_grant_satisfies_every_action_check() {
        let mut extensions = Extensions::new();
        let test_repository_id = "urc-0194b726b34e72b0b45550b88a967076".to_string();
        let unrelated_repository_id = "urc-0192ae48ccf17060bc1ba9d04f6acb2f".to_string();
        let mut test_authz_token = AuthorizationToken::default();

        let test_wildcard_resource_permission = ResourcePermission {
            resource_id: "urc-*".to_string(),
            permission: vec![
                "obliterate".to_string(),
                "admin".to_string(),
                "migrate".to_string(),
            ],
        };

        test_authz_token.resources = Some(vec![test_wildcard_resource_permission]);
        extensions.insert(test_authz_token.clone());

        for repository_id in [test_repository_id, unrelated_repository_id] {
            let repository_context: RepositoryId =
                Context::from_str(repository_id.strip_prefix("urc-").unwrap())
                    .unwrap()
                    .into();
            assert!(can_obliterate(&extensions, repository_context));
            assert!(is_owner_or_admin(&extensions, repository_context));
            assert!(can_admin_lock(&extensions, repository_context));
        }
    }

    #[test]
    fn no_grant_denies_every_action_check() {
        let mut extensions = Extensions::new();
        let mut test_authz_token = AuthorizationToken::default();
        let test_resource_permissions = Vec::new();
        test_authz_token.resources = Some(test_resource_permissions);
        extensions.insert(test_authz_token.clone());

        let test_repository_context: RepositoryId =
            Context::from_str("0194b726b34e72b0b45550b88a967076")
                .unwrap()
                .into();

        assert!(!is_owner_or_admin(&extensions, test_repository_context));
        assert!(!can_obliterate(&extensions, test_repository_context));
        assert!(!can_admin_lock(&extensions, test_repository_context));
    }

    /// Fork extensions carrying one verified token with `resources`.
    fn fork_extensions_with(subject: &str, resources: Vec<(&str, &[&str])>) -> Extensions {
        let mut extensions = Extensions::new();
        extensions.insert(AuthorizationToken {
            user_id: subject.to_string(),
            issuer: "issuer".to_string(),
            resources: Some(
                resources
                    .into_iter()
                    .map(|(resource_id, permissions)| ResourcePermission {
                        resource_id: resource_id.to_string(),
                        permission: permissions.iter().map(|p| p.to_string()).collect(),
                    })
                    .collect(),
            ),
            ..Default::default()
        });
        extensions
    }

    const FORK_REPO: &str = "0194b726b34e72b0b45550b88a967076";

    fn fork_repo() -> RepositoryId {
        Context::from_str(FORK_REPO).unwrap().into()
    }

    /// FORK-LOCAL: the branch-creator rule keeps the pre-v0.10.0 reader. Only
    /// the FIRST exact `urc-<repo>` entry counts. `urc-*` and later exact
    /// entries do not, although upstream's `is_owner_or_admin` now honours both.
    #[test]
    fn branch_creator_rule_reads_only_the_first_exact_entry() {
        let exact = format!("urc-{FORK_REPO}");
        let other = "urc-0192ae48ccf17060bc1ba9d04f6acb2f";

        let wildcard_owner = fork_extensions_with("s", vec![("urc-*", &["owner"])]);
        assert!(!can_set_branch_creator(&wildcard_owner, fork_repo()));
        assert!(is_owner_or_admin(&wildcard_owner, fork_repo()));

        let later_exact_admin =
            fork_extensions_with("s", vec![(&exact, &["read"]), (&exact, &["admin"])]);
        assert!(!can_set_branch_creator(&later_exact_admin, fork_repo()));
        assert!(is_owner_or_admin(&later_exact_admin, fork_repo()));

        let exact_owner_after_others = fork_extensions_with(
            "s",
            vec![
                ("urc-*", &["read"]),
                (other, &["owner"]),
                (&exact, &["owner"]),
            ],
        );
        assert!(can_set_branch_creator(
            &exact_owner_after_others,
            fork_repo()
        ));

        let exact_admin = fork_extensions_with("s", vec![(&exact, &["admin"])]);
        assert!(can_set_branch_creator(&exact_admin, fork_repo()));

        assert!(!can_set_branch_creator(&Extensions::new(), fork_repo()));
    }

    /// FORK-LOCAL: the write gate and both force-unlock gates keep their
    /// pre-v0.10.0 semantics, which already merged every matching entry and
    /// honoured `urc-*`.
    #[test]
    fn fork_write_and_force_unlock_gates_honour_wildcard_and_merge_entries() {
        let exact = format!("urc-{FORK_REPO}");

        let wildcard = fork_extensions_with("me", vec![("urc-*", &["read", "write", "owner"])]);
        assert!(require_permission(&wildcard, fork_repo(), "write", true).is_ok());
        assert!(can_force_unlock(&wildcard, fork_repo()));
        assert!(is_self_force_unlock(&wildcard, fork_repo(), "me"));

        let split = fork_extensions_with("me", vec![(&exact, &["read"]), (&exact, &["write"])]);
        assert!(require_permission(&split, fork_repo(), "write", true).is_ok());
        assert!(is_self_force_unlock(&split, fork_repo(), "me"));
        assert!(!can_force_unlock(&split, fork_repo()));

        let read_only = fork_extensions_with("me", vec![(&exact, &["read"])]);
        assert_eq!(
            require_permission(&read_only, fork_repo(), "write", true)
                .unwrap_err()
                .code(),
            Code::PermissionDenied
        );
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

        #[test]
        fn store_ok_passes_through() {
            let result: Result<i32, StoreError> = Ok(42);
            let filtered = result.filter_slow_down().unwrap();
            assert_eq!(filtered.unwrap(), 42);
        }

        #[test]
        fn store_slow_down_returns_resource_exhausted() {
            let result: Result<i32, StoreError> = Err(StoreError::from(SlowDown));
            let status = result.filter_slow_down().unwrap_err();
            assert_eq!(status.code(), Code::ResourceExhausted);
        }

        #[test]
        fn store_error_passes_through() {
            let result: Result<i32, StoreError> = Err(StoreError::internal("other error"));
            let filtered = result.filter_slow_down().unwrap();
            let underlying_error = filtered.expect_err("Should be err");
            assert!(!underlying_error.is_slow_down());
        }

        #[test]
        fn branch_slow_down_returns_resource_exhausted() {
            let result: Result<i32, BranchError> = Err(BranchError::from(SlowDown));
            let status = result.filter_slow_down().unwrap_err();
            assert_eq!(status.code(), Code::ResourceExhausted);
        }

        #[test]
        fn branch_error_passes_through() {
            let result: Result<i32, BranchError> = Err(BranchError::internal("other error"));
            let filtered = result.filter_slow_down().unwrap();
            let underlying_error = filtered.expect_err("Should be err");
            assert!(!underlying_error.is_slow_down());
        }

        #[test]
        fn repository_slow_down_returns_resource_exhausted() {
            let result: Result<i32, RepositoryError> = Err(RepositoryError::from(SlowDown));
            let status = result.filter_slow_down().unwrap_err();
            assert_eq!(status.code(), Code::ResourceExhausted);
        }

        #[test]
        fn immutable_slow_down_returns_resource_exhausted() {
            let result: Result<i32, ImmutableError> = Err(ImmutableError::from(SlowDown));
            let status = result.filter_slow_down().unwrap_err();
            assert_eq!(status.code(), Code::ResourceExhausted);
        }

        #[test]
        fn branch_metadata_slow_down_returns_resource_exhausted() {
            let result: Result<i32, BranchMetadataError> = Err(BranchMetadataError::from(SlowDown));
            let status = result.filter_slow_down().unwrap_err();
            assert_eq!(status.code(), Code::ResourceExhausted);
        }

        /// `filter_slow_down`'s mapping must survive: flattening every
        /// undiscarded error into the internal arm loses it silently, because
        /// both arms still produce a `Status`.
        #[test]
        fn discarded_error_is_none_and_others_keep_their_status() {
            let absent: Result<i32, StoreError> = Err(StoreError::from(
                lore_base::error::AddressNotFound::from(lore_base::types::Address::default()),
            ));
            assert_eq!(
                none_or_status(absent, StoreError::is_address_not_found).unwrap(),
                None
            );

            let throttled: Result<i32, StoreError> = Err(StoreError::from(SlowDown));
            let status = none_or_status(throttled, StoreError::is_address_not_found)
                .expect_err("an undiscarded error must not become None");
            assert_eq!(status.code(), Code::ResourceExhausted);

            let failed: Result<i32, StoreError> = Err(StoreError::internal("store unusable"));
            let status = none_or_status(failed, StoreError::is_address_not_found)
                .expect_err("an undiscarded error must not become None");
            assert_eq!(status.code(), Code::Internal);
        }

        #[test]
        fn find_slow_down_returns_resource_exhausted() {
            let result: Result<i32, FindError> = Err(FindError::from(SlowDown));
            let status = result.filter_slow_down().unwrap_err();
            assert_eq!(status.code(), Code::ResourceExhausted);
        }

        #[test]
        fn find_error_passes_through() {
            let result: Result<i32, FindError> = Err(FindError::internal("no revision found"));
            let filtered = result.filter_slow_down().unwrap();
            let underlying_error = filtered.expect_err("Should be err");
            assert!(!underlying_error.is_slow_down());
        }

        #[test]
        fn diff_slow_down_returns_resource_exhausted() {
            let result: Result<i32, DiffError> = Err(DiffError::from(SlowDown));
            let status = result.filter_slow_down().unwrap_err();
            assert_eq!(status.code(), Code::ResourceExhausted);
        }

        #[test]
        fn repository_metadata_slow_down_returns_resource_exhausted() {
            let result: Result<i32, RepositoryMetadataError> =
                Err(RepositoryMetadataError::from(SlowDown));
            let status = result.filter_slow_down().unwrap_err();
            assert_eq!(status.code(), Code::ResourceExhausted);
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

        // Contention and outcome-unknown share `ABORTED` by CR-029's explicit
        // choice, so the message is the only discriminator a client has — it
        // must be exact-comparable, never the raw SQLSTATE context string the
        // error was constructed with (a client should never have to parse
        // prose to tell "provably rolled back" from "may have committed").
        #[test]
        fn contention_maps_to_aborted_with_the_fixed_detail_not_the_sqlstate_context() {
            let sqlstate_context = "SQLSTATE 40001: could not serialize access";
            let status =
                map_domain_error_to_status(&DomainError::Contention(sqlstate_context.into()));

            assert_eq!(status.code(), Code::Aborted);
            assert_eq!(status.message(), DOMAIN_CONTENTION_DETAIL);
            assert!(!status.message().contains(sqlstate_context));
        }

        #[test]
        fn transient_maps_to_resource_exhausted_without_leaking_the_inner_detail() {
            let sqlstate_context = "SQLSTATE 08006: connection failure";
            let status =
                map_domain_error_to_status(&DomainError::Transient(sqlstate_context.into()));

            assert_eq!(status.code(), Code::ResourceExhausted);
            assert!(!status.message().contains(sqlstate_context));
        }

        #[test]
        fn outcome_unknown_maps_to_aborted_with_the_fixed_detail() {
            let status =
                map_domain_error_to_status(&DomainError::OutcomeUnknown("lost ack".into()));
            assert_eq!(status.code(), Code::Aborted);
            assert_eq!(status.message(), DOMAIN_OUTCOME_UNKNOWN_DETAIL);
        }

        // The two `ABORTED` details must never collide, or a client can no
        // longer tell contention (provably rolled back, safe to retry) from
        // outcome-unknown (may have committed, must refetch first) apart.
        #[test]
        fn domain_contention_detail_and_outcome_unknown_detail_are_distinct() {
            assert_ne!(DOMAIN_CONTENTION_DETAIL, DOMAIN_OUTCOME_UNKNOWN_DETAIL);
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

    /// Owner ruling D8: `ForceUnlock`'s second authorization arm. Follows the
    /// `user_permissions_*` fixture style above (build `Extensions`,
    /// insert an `AuthorizationToken` directly rather than a real JWT).
    ///
    /// `is_self_force_unlock` takes a `repository: RepositoryId` conjunct too
    /// (fail-closed: the caller must hold `read` on THIS repository, or naming
    /// oneself against an arbitrary repository id would leak whether fenced
    /// routing is armed there via `fenced_call`'s later disclosures). Every
    /// case below is explicit about which repository the token's permission
    /// grant covers, rather than relying on a wildcard everywhere, so the
    /// repository conjunct is actually exercised and not accidentally always
    /// satisfied.
    mod is_self_force_unlock_tests {
        use super::*;

        fn repository(hex: &str) -> RepositoryId {
            Context::from_str(hex).unwrap().into()
        }

        // The repository the token's grants below are scoped to, unless a case
        // says otherwise.
        fn granted_repository() -> RepositoryId {
            repository("0194b726b34e72b0b45550b88a967076")
        }

        // A different repository the token carries no grant for at all.
        fn ungranted_repository() -> RepositoryId {
            repository("0192ae48ccf17060bc1ba9d04f6acb2f")
        }

        fn extensions_with_token(
            issuer: &str,
            user_id: &str,
            permissions_for_granted_repo: &[&str],
        ) -> Extensions {
            let mut extensions = Extensions::new();
            let mut token = AuthorizationToken {
                issuer: issuer.to_owned(),
                user_id: user_id.to_owned(),
                ..Default::default()
            };
            if !permissions_for_granted_repo.is_empty() {
                token.resources = Some(vec![ResourcePermission {
                    resource_id: format!("urc-{}", granted_repository()),
                    permission: permissions_for_granted_repo
                        .iter()
                        .map(|p| p.to_string())
                        .collect(),
                }]);
            }
            extensions.insert(token);
            extensions
        }

        #[test]
        fn read_permission_alone_is_enough_without_owner_or_migrate() {
            // The positive half of the repository conjunct: `read` alone --
            // no `owner`, no `migrate` -- is sufficient, because this arm is
            // about owning the lock, not about administrative rank.
            let extensions = extensions_with_token("https://issuer.example", "user-1", &["read"]);
            assert!(is_self_force_unlock(
                &extensions,
                granted_repository(),
                "user-1"
            ));
        }

        #[test]
        fn subject_mismatch_does_not_self_authorize() {
            let extensions = extensions_with_token("https://issuer.example", "user-1", &["read"]);
            assert!(!is_self_force_unlock(
                &extensions,
                granted_repository(),
                "someone-else"
            ));
        }

        #[test]
        fn empty_target_owner_does_not_self_authorize() {
            // The caller carries a real, non-empty subject and read permission
            // on this exact repository -- everything else about the call would
            // otherwise clear the gate -- so an empty `target_owner` is the
            // ONLY reason this must return false. Naming nobody must not be
            // read as naming oneself.
            let extensions = extensions_with_token("https://issuer.example", "user-1", &["read"]);
            assert!(!is_self_force_unlock(&extensions, granted_repository(), ""));
        }

        #[test]
        fn empty_token_user_id_does_not_self_authorize() {
            // Defense in depth over the subject-mismatch case above: a token
            // that carries no subject at all must never self-authorize a named
            // target, whatever that target string is. Read permission is
            // granted here specifically so this test exercises the user_id
            // check itself rather than failing earlier on the permission gate.
            let extensions = extensions_with_token("https://issuer.example", "", &["read"]);
            assert!(!is_self_force_unlock(
                &extensions,
                granted_repository(),
                "someone"
            ));
        }

        #[test]
        fn no_read_permission_on_the_named_repository_does_not_self_authorize() {
            // Regression case for the repository conjunct: the caller names
            // themselves correctly, but the repository passed in is one their
            // token carries NO grant for at all (their `read` grant covers a
            // different repository). Without the `has_required_permission(
            // .., "read")` check, a same-subject match alone would clear this
            // gate for ANY repository id the caller can name, disclosing
            // fenced-routing/cell state for repositories the caller has no
            // standing to be answered about.
            let extensions = extensions_with_token("https://issuer.example", "user-1", &["read"]);
            assert!(!is_self_force_unlock(
                &extensions,
                ungranted_repository(),
                "user-1"
            ));
        }

        #[test]
        fn auth_off_does_not_self_authorize() {
            // No `AuthorizationToken` in extensions at all -- the auth-disabled
            // dev/CI shape. Absence of a verified principal must never be read
            // as "the caller is whoever they name".
            let extensions = Extensions::new();
            assert!(!is_self_force_unlock(
                &extensions,
                granted_repository(),
                "user-1"
            ));
        }
    }
}

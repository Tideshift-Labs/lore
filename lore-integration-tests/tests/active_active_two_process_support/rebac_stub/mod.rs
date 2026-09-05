// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! A rebac/auth-grpc stand-in this harness runs so two real loreserver
//! processes can reach the WP-120 direct-authorization rail.
//!
//! # Why this exists
//!
//! A real loreserver builds its repository-operation verifier only when
//! `settings.environment.endpoint.auth_url` names a live service
//! (`lore-server/src/domain.rs`'s `configure_domain_context`). With no
//! verifier, `DomainContext::internal_admission_reason` returns `Ok(None)` at
//! its second condition and every carriage-free mutation by a human is refused
//! before any handler logic — under enforcement, with `FailedPrecondition:
//! "Internal domain prepare requires a configured repository-operation
//! verifier"`. That refusal is not specific to locking: it blocks EVERY
//! cross-process governed mutation a released client could make.
//!
//! `lore-server/tests/p12_lock_service_fenced_routing.rs` escapes it with an
//! in-process `DirectEchoVerifier` double, which cannot be reached across two
//! subprocesses. This is that double moved onto a real gRPC wire.
//!
//! # What it is, and what it is not
//!
//! PIN(WP-120, 2026-09-05): **a test double, not a second implementation.** The
//! authority for direct-human authorization is the platform's own code —
//! `lorehub/packages/control-plane/src/mutation-authorization.ts` and
//! `lorehub/apps/auth-grpc/src/service-human-authorization.ts` — together with
//! its own test suite. This stub mirrors that behaviour closely enough that a
//! harness case exercises the real wire contract, and no more. If the two ever
//! disagree, the platform is right and this is the bug.
//!
//! What it mirrors, in the platform handler's own order: authenticate the
//! forwarded bearer independently; refuse a service account; validate the
//! request shape; equality-check the echoed issuer and subject against the
//! principal it verified; require the subject to be able to key an initiating
//! principal namespace, which admits only a canonical UUID subject; refuse
//! `repository.create` by name and any unknown family; require the scope to
//! carry the repository id and its domain to match the family; check the role
//! floor; and only then mint, answering a replay from the stored row rather
//! than from a fresh nonce.
//!
//! What it deliberately DIVERGES on, because a harness has neither a control
//! plane nor an ACL store:
//!
//! * **`CreateResource` is a rubber stamp.** Setting `auth_url` routes every
//!   repository create through it, and loreserver requires an exact
//!   acknowledgement of an attached governed claim before it opens the mutation
//!   transaction. The real platform answers that from its own committed claim
//!   row; this stub echoes what it was sent. No case here is evidence about
//!   claim acknowledgement. See [`StubState::create_resource`].
//!
//! * **No repository catalog and no org.** The platform resolves a repository
//!   row by partition and derives the org from it. A case grants a role to this
//!   stub explicitly with [`RebacStub::grant`], and an ungranted repository is
//!   denied. The `org_uuid` it echoes is a fixed per-run value; loreserver
//!   treats that field as audit-only and it is not an input to the direct
//!   receipt namespace.
//! * **No durable authorization row, no TTL, no retention sweep.** Minted
//!   authorizations live in memory for the life of the case. Replay within a
//!   case is answered from that map, which is the property loreserver's fence
//!   depends on; expiry is not exercised, because loreserver mints a fresh
//!   UUIDv7 per attempt and calls prepare immediately.
//! * **`CheckUserPermission` is deliberately permissive.** Setting `auth_url`
//!   also switches loreserver's repository-query authorizer from
//!   `AllowAllRepositoryAuthorizer` to the auth-grpc one, so the read cases
//!   would otherwise stop working. This stub authenticates the bearer and then
//!   allows any `urc-*` resource. No case in this harness claims read-path
//!   authorization coverage, and none may: that policy lives on the platform.
//!
//! # Wire plumbing
//!
//! `lore-proto` compiles `auth_api.proto` and `rebac_api.proto` with
//! `.build_server(false)` — loreserver is only ever a *client* of both — so
//! there is no generated server to bind an implementation to. The two service
//! impls in [`service`] are hand-rolled in the shape `tonic-prost-build` emits
//! for a unary RPC, exactly as `lore-server`'s own
//! `repository_query::authz_test_support` already does for `UrcAuthApi`. They
//! reuse `lore_proto`'s message types, so the messages on the wire are the ones
//! loreserver encodes and decodes, not a second copy that could drift.

pub mod policy;
mod service;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use lore_base::lore_spawn;
use rand::RngCore;
use tonic::Status;

use self::policy::DIRECT_AUTHORIZATION_REVISION;
use self::policy::DirectAuthorizationBinding;
use self::policy::MEDIATED_ONLY_METHOD;
use self::policy::Role;
use self::policy::bound_fields_digest;
use self::policy::contains_bytes;
use self::policy::method_permits_role;
use self::policy::required_role;
use self::policy::scope_matches_mutation_family;
use super::Env;

/// The one service identity refused by name, as the platform refuses it.
const CONTROL_PLANE_SERVICE_SUBJECT: &str = "lorehub-control-plane";

/// Widths the platform pins, restated so a wrong one is refused here rather
/// than travelling into a witness.
const UUID_BYTES: usize = 16;
const DIGEST_BYTES: usize = 32;
const MAX_METHOD_BYTES: usize = 128;
const MAX_SCOPE_BYTES: usize = 4096;
const MAX_IDENTITY_BYTES: usize = 512;
/// The platform's initiating-principal namespace, and the exact width it must
/// come to. `"principal-v1\0"` is 13 bytes and a canonical lowercase UUID is 36,
/// so 49 admits a UUID subject and nothing else.
const PRINCIPAL_NAMESPACE_PREFIX: &str = "principal-v1\0";
const PRINCIPAL_NAMESPACE_LEN: usize = 49;

/// One authorization this stub issued, for a case to assert against.
#[derive(Debug, Clone)]
pub struct AuthorizedOperation {
    pub subject: String,
    pub method: String,
    pub repository_id: Vec<u8>,
    pub branch_id: Vec<u8>,
    pub operation_id: [u8; UUID_BYTES],
}

/// The witness minted for one operation id, kept so a replay is answered from
/// the row rather than from a second nonce.
#[derive(Clone)]
struct MintedAuthorization {
    verified_issuer: String,
    authenticated_subject: String,
    method: String,
    scope: Vec<u8>,
    fingerprint_version: u32,
    fingerprint: Vec<u8>,
    canonical_intent_digest: Vec<u8>,
    repository_id: Vec<u8>,
    branch_id: Vec<u8>,
    verification_nonce: [u8; DIGEST_BYTES],
    bound_fields_digest: [u8; DIGEST_BYTES],
}

/// Everything both services read, behind one handle.
pub(crate) struct StubState {
    /// The issuer this stub accepts, which is also the value loreserver must
    /// echo. A different echo means loreserver validated the JWT against a
    /// different trust root than the one minting these tokens.
    issuer: String,
    audience: String,
    /// The public half of the harness's TEST signing key, read from the same
    /// JWKS document both loreserver processes fetch.
    decoding_key: jsonwebtoken::DecodingKey,
    /// Audit-only org identity. Fixed per run; see this module's divergence
    /// list.
    org_uuid: [u8; UUID_BYTES],
    /// repository id -> subject -> role. The stand-in for the platform's
    /// repository catalog and ACL resolver; an absent repository denies, which
    /// is the same fail-closed shape a null repository row produces there.
    grants: Mutex<HashMap<Vec<u8>, HashMap<String, Role>>>,
    minted: Mutex<HashMap<[u8; UUID_BYTES], MintedAuthorization>>,
    authorized: Mutex<Vec<AuthorizedOperation>>,
    /// Why this stub refused, in order, for EVERY refusal it made. The wire
    /// answer to a policy denial is one opaque sentence, exactly as the
    /// platform's is, so probing that RPC cannot enumerate repositories, roles,
    /// or in-flight operations. These reasons are for the harness's own failure
    /// messages and never leave the process.
    refusals: Mutex<Vec<String>>,
    authorize_calls: AtomicU64,
    permission_checks: AtomicU64,
    resource_creates: AtomicU64,
    resource_deletes: AtomicU64,
}

/// The claims this stub reads out of a forwarded bearer.
#[derive(serde::Deserialize)]
struct StubClaims {
    sub: String,
    iss: String,
    #[serde(default)]
    is_service_account: bool,
}

/// A verified human principal.
struct Principal {
    subject: String,
    issuer: String,
}

impl StubState {
    /// Record why this stub refused, whatever shape the refusal takes.
    ///
    /// EVERY refusal goes through here, not just the policy denials. A harness
    /// that recorded only `PERMISSION_DENIED` would report an empty refusal
    /// list after an `UNAUTHENTICATED` or an `INVALID_ARGUMENT`, and a case
    /// asserting "the authorizer refused nothing" would then be satisfied by a
    /// stub that refused everything.
    fn refuse(&self, reason: String, status: Status) -> Status {
        if let Ok(mut refusals) = self.refusals.lock() {
            refusals.push(reason);
        }
        status
    }

    /// One message for every denial. A caller learns that it may not have an
    /// authorization, never why.
    fn denied(&self, reason: impl Into<String>) -> Status {
        self.refuse(
            reason.into(),
            Status::permission_denied("repository operation authorization denied"),
        )
    }

    /// A shape refusal, which names its own cause exactly as the platform's
    /// does: a malformed request is the caller's to correct, unlike a denial.
    fn invalid(&self, reason: &str) -> Status {
        self.refuse(reason.to_owned(), Status::invalid_argument(reason))
    }

    /// An authentication refusal.
    fn unauthenticated(&self, reason: String) -> Status {
        let status = Status::unauthenticated(reason.clone());
        self.refuse(reason, status)
    }

    /// Authenticate the forwarded bearer ourselves.
    ///
    /// This is the whole security argument of the direct rail: loreserver
    /// cannot assert who the human is, it can only relay a credential the
    /// authorizer verifies. The echoed identity fields are checked against what
    /// this returns and never used to select authority.
    fn authenticate(&self, metadata: &tonic::metadata::MetadataMap) -> Result<Principal, Status> {
        let header = metadata
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| self.unauthenticated("no bearer token was forwarded".to_owned()))?;
        // loreserver forwards the header VERBATIM, so it arrives as
        // `Bearer <jwt>`. A bare token is tolerated so a future caller that
        // forwards only the credential is not a mystery failure.
        let token = header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("bearer "))
            .unwrap_or(header)
            .trim();

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.set_issuer(&[self.issuer.as_str()]);
        validation.set_audience(&[self.audience.as_str()]);
        let decoded = jsonwebtoken::decode::<StubClaims>(token, &self.decoding_key, &validation)
            .map_err(|error| self.unauthenticated(format!("bearer rejected: {error}")))?;

        // Humans only. A service account here would be the control plane taking
        // a second, ticket-free route to an authorization, which is exactly what
        // the mediated rail's committed preclaim ticket exists to prevent. The
        // named refusal is belt and braces for a token that simply omits the
        // claim.
        if decoded.claims.is_service_account {
            return Err(self.denied("the bearer is a service account"));
        }
        if decoded.claims.sub == CONTROL_PLANE_SERVICE_SUBJECT {
            return Err(self.denied("the bearer is the control-plane service subject"));
        }
        Ok(Principal {
            subject: decoded.claims.sub,
            issuer: decoded.claims.iss,
        })
    }

    /// The role `subject` holds on `repository_id`, or `None`.
    fn role_of(&self, repository_id: &[u8], subject: &str) -> Option<Role> {
        let grants = self.grants.lock().ok()?;
        grants.get(repository_id)?.get(subject).copied()
    }

    /// Authorize ONE direct human mutation and mint its witness.
    ///
    /// Ordering mirrors the platform handler and is the fail-closed shape:
    /// authenticate, reject a non-human, validate the SHAPE, bind the echoed
    /// identity to the verified principal, resolve the repository, check the
    /// permission, and only then mint. Nothing is recorded as authorized until
    /// every one of those has passed, so a denial leaves no row.
    fn authorize_direct(
        &self,
        metadata: &tonic::metadata::MetadataMap,
        request: lore_proto::rebac::AuthorizeDirectRepositoryOperationRequest,
    ) -> Result<lore_proto::rebac::AuthorizeDirectRepositoryOperationResponse, Status> {
        self.authorize_calls.fetch_add(1, Ordering::SeqCst);
        let principal = self.authenticate(metadata)?;

        // -- shape, before anything is looked up ---------------------------
        if request.verified_issuer.is_empty()
            || request.verified_issuer.len() > MAX_IDENTITY_BYTES
            || request.authenticated_subject.is_empty()
            || request.authenticated_subject.len() > MAX_IDENTITY_BYTES
        {
            return Err(self.invalid("issuer or subject is out of bounds"));
        }
        if request.operation_id.len() != UUID_BYTES {
            return Err(self.invalid("operation_id must be 16 bytes"));
        }
        // Version AND variant. The version alone would admit a value whose
        // variant bits make it not an RFC 9562 UUID at all.
        if request.operation_id[6] >> 4 != 7 || request.operation_id[8] & 0xc0 != 0x80 {
            return Err(self.invalid("operation_id must be UUIDv7"));
        }
        if request.method.is_empty() || request.method.len() > MAX_METHOD_BYTES {
            return Err(self.invalid("method is out of bounds"));
        }
        if request.scope.is_empty() || request.scope.len() > MAX_SCOPE_BYTES {
            return Err(self.invalid("scope is out of bounds"));
        }
        if request.fingerprint_version == 0 {
            return Err(self.invalid("fingerprint_version is out of bounds"));
        }
        if request.fingerprint.len() != DIGEST_BYTES {
            return Err(self.invalid("fingerprint must be 32 bytes"));
        }
        if request.canonical_intent_digest.len() != DIGEST_BYTES {
            return Err(self.invalid("canonical_intent_digest must be 32 bytes"));
        }
        if request.repository_id.len() != UUID_BYTES {
            return Err(self.invalid("repository_id must be 16 bytes"));
        }
        // Empty is legal and does NOT mean "this family has no branch": the
        // five mutation families send it empty by deliberate deferral. A
        // non-empty value must still be a whole id, or the witness would bind a
        // branch nobody named.
        if !request.branch_id.is_empty() && request.branch_id.len() != UUID_BYTES {
            return Err(self.invalid("branch_id must be empty or 16 bytes"));
        }

        // -- bind the echoes to the principal we actually verified ---------
        if request.verified_issuer != self.issuer {
            return Err(self.denied(format!(
                "echoed verified_issuer {:?} is not this authorizer's issuer",
                request.verified_issuer
            )));
        }
        if request.verified_issuer != principal.issuer {
            return Err(self.denied("echoed verified_issuer disagrees with the bearer's issuer"));
        }
        if request.authenticated_subject != principal.subject {
            return Err(self.denied(format!(
                "echoed subject {:?} is not the verified principal {:?}",
                request.authenticated_subject, principal.subject
            )));
        }
        // The subject must be able to KEY a row on the platform.
        //
        // auth-grpc derives the initiating principal namespace as
        // `"principal-v1\0" || Principal.userId` and denies unless the result is
        // exactly 49 bytes, which admits only a canonical lowercase UUID
        // subject. Nothing in Lore enforces that, so without this check a case
        // could pass here on a subject the real platform would refuse — the
        // most likely way for this harness to prove something the product does
        // not do.
        if PRINCIPAL_NAMESPACE_PREFIX.len() + principal.subject.len() != PRINCIPAL_NAMESPACE_LEN {
            return Err(self.denied(format!(
                "subject {:?} cannot key a principal namespace; auth-grpc requires a canonical \
                 lowercase UUID subject, so a case must mint its token for one",
                principal.subject
            )));
        }

        // -- family --------------------------------------------------------
        if request.method == MEDIATED_ONLY_METHOD {
            return Err(self.denied("repository.create stays on the mediated claim rail"));
        }
        if required_role(&request.method).is_none() {
            return Err(self.denied(format!("{:?} is not a direct family", request.method)));
        }

        // -- the repository, and the tenant boundary -----------------------
        let repository_id = request.repository_id.to_vec();
        let Some(role) = self.role_of(&repository_id, &principal.subject) else {
            return Err(self.denied(format!(
                "no grant for subject {:?} on repository {}; a case must call \
                 RebacStub::grant before the mutation",
                principal.subject,
                hex(&repository_id)
            )));
        };
        // Lore's scope key is computed over the target repository, so it must
        // carry those same 16 bytes. This is the one check available on a field
        // otherwise taken on trust, and it stops a caller naming one repository
        // while filing the receipt under another's namespace.
        if !contains_bytes(&request.scope, &repository_id) {
            return Err(self.denied("scope does not carry the named repository id"));
        }
        if !scope_matches_mutation_family(&request.method, &request.scope) {
            return Err(self.denied(format!(
                "scope domain does not match the {:?} family",
                request.method
            )));
        }

        // -- the permission ------------------------------------------------
        if !method_permits_role(&request.method, Some(role)) {
            let required = required_role(&request.method).map_or("none", Role::name);
            return Err(self.denied(format!(
                "subject {:?} holds {} on this repository; {:?} requires {}",
                principal.subject,
                role.name(),
                request.method,
                required
            )));
        }

        // -- mint ----------------------------------------------------------
        let mut operation_id = [0u8; UUID_BYTES];
        operation_id.copy_from_slice(&request.operation_id);

        let minted = self.mint_or_replay(&operation_id, &request)?;
        if let Ok(mut authorized) = self.authorized.lock() {
            authorized.push(AuthorizedOperation {
                subject: principal.subject,
                method: minted.method.clone(),
                repository_id: minted.repository_id.clone(),
                branch_id: minted.branch_id.clone(),
                operation_id,
            });
        }

        Ok(
            lore_proto::rebac::AuthorizeDirectRepositoryOperationResponse {
                verified_issuer: minted.verified_issuer.clone(),
                authenticated_subject: minted.authenticated_subject.clone(),
                // CR-029 freezes the authorization id to the operation UUID.
                operation_id: bytes::Bytes::copy_from_slice(&operation_id),
                method: minted.method.clone(),
                scope: bytes::Bytes::copy_from_slice(&minted.scope),
                fingerprint_version: minted.fingerprint_version,
                fingerprint: bytes::Bytes::copy_from_slice(&minted.fingerprint),
                canonical_intent_digest: bytes::Bytes::copy_from_slice(
                    &minted.canonical_intent_digest,
                ),
                authorization_id: bytes::Bytes::copy_from_slice(&operation_id),
                authorization_revision: DIRECT_AUTHORIZATION_REVISION,
                verification_nonce: bytes::Bytes::copy_from_slice(&minted.verification_nonce),
                bound_fields_digest: bytes::Bytes::copy_from_slice(&minted.bound_fields_digest),
                org_uuid: bytes::Bytes::copy_from_slice(&self.org_uuid),
            },
        )
    }

    /// Return the stored witness for this operation id, or mint one.
    ///
    /// A known operation id presented with a DIFFERENT binding is denied, not
    /// re-minted: loreserver's fence needs one witness per operation, and a
    /// second, different one for the same id is exactly what it cannot survive.
    fn mint_or_replay(
        &self,
        operation_id: &[u8; UUID_BYTES],
        request: &lore_proto::rebac::AuthorizeDirectRepositoryOperationRequest,
    ) -> Result<MintedAuthorization, Status> {
        let mut minted = self
            .minted
            .lock()
            .map_err(|_| Status::internal("the stub's authorization map is poisoned"))?;
        if let Some(existing) = minted.get(operation_id) {
            let same = existing.verified_issuer == request.verified_issuer
                && existing.authenticated_subject == request.authenticated_subject
                && existing.method == request.method
                && existing.scope == request.scope.as_ref()
                && existing.fingerprint_version == request.fingerprint_version
                && existing.fingerprint == request.fingerprint.as_ref()
                && existing.canonical_intent_digest == request.canonical_intent_digest.as_ref()
                && existing.repository_id == request.repository_id.as_ref()
                && existing.branch_id == request.branch_id.as_ref();
            if !same {
                drop(minted);
                return Err(self.denied("a known operation id was presented with a new binding"));
            }
            return Ok(existing.clone());
        }

        let mut verification_nonce = [0u8; DIGEST_BYTES];
        rand::rng().fill_bytes(&mut verification_nonce);
        let bound_fields_digest = bound_fields_digest(&DirectAuthorizationBinding {
            verified_issuer: &request.verified_issuer,
            authenticated_subject: &request.authenticated_subject,
            operation_id,
            method: &request.method,
            scope: &request.scope,
            fingerprint_version: request.fingerprint_version,
            fingerprint: &request.fingerprint,
            canonical_intent_digest: &request.canonical_intent_digest,
            repository_id: &request.repository_id,
            branch_id: &request.branch_id,
            authorization_id: operation_id,
            authorization_revision: DIRECT_AUTHORIZATION_REVISION,
            verification_nonce: &verification_nonce,
        });

        let record = MintedAuthorization {
            verified_issuer: request.verified_issuer.clone(),
            authenticated_subject: request.authenticated_subject.clone(),
            method: request.method.clone(),
            scope: request.scope.to_vec(),
            fingerprint_version: request.fingerprint_version,
            fingerprint: request.fingerprint.to_vec(),
            canonical_intent_digest: request.canonical_intent_digest.to_vec(),
            repository_id: request.repository_id.to_vec(),
            branch_id: request.branch_id.to_vec(),
            verification_nonce,
            bound_fields_digest,
        };
        minted.insert(*operation_id, record.clone());
        Ok(record)
    }

    /// Register a repository's auth resource, as `RepositoryCreate` does.
    ///
    /// Setting `auth_url` makes EVERY repository create call this, governed or
    /// not (`lore-server/src/grpc/handlers/repository_create.rs`'s
    /// `repository_create_auth_resource`), so a harness that did not serve it
    /// would fail case A on the very first call with an `Unimplemented` that
    /// reads like a broken create.
    ///
    /// PIN(WP-120, 2026-09-05) — a RUBBER STAMP, and the one divergence here
    /// worth stating twice. When the request carries a governed create claim,
    /// loreserver requires an exact acknowledgement of `claim_id`,
    /// `claim_revision` and `claim_verification_witness` before it opens the
    /// mutation transaction (`verify_create_acknowledgement`). The real platform
    /// answers those from its own committed claim row; this stub ECHOES what it
    /// was sent, which is precisely what a real verifier must never do. So no
    /// case in this harness is evidence about claim acknowledgement, and none
    /// may be read as such. Nothing is lost against the previous state of this
    /// harness, which called no authorizer on this path at all.
    fn create_resource(
        &self,
        metadata: &tonic::metadata::MetadataMap,
        request: lore_proto::rebac::CreateResourceRequest,
    ) -> Result<lore_proto::rebac::CreateResourceResponse, Status> {
        self.resource_creates.fetch_add(1, Ordering::SeqCst);
        self.authenticate(metadata)?;
        if !request.resource_id.starts_with("urc-") {
            return Err(self.invalid("resource_id must be a urc- resource"));
        }
        Ok(lore_proto::rebac::CreateResourceResponse {
            claim_id: request.claim_id,
            claim_revision: request.claim_revision,
            claim_verification_witness: request.claim_verification_witness,
        })
    }

    /// Retire a repository's auth resource, as `RepositoryDelete` does.
    ///
    /// Served for the same reason `create_resource` is: `auth_url` makes the
    /// delete handler call it. No case here exercises a repository delete, so
    /// this exists to keep an unserved path from failing as `Unimplemented`
    /// rather than as whatever it would really fail as.
    fn delete_resource(
        &self,
        metadata: &tonic::metadata::MetadataMap,
        request: lore_proto::rebac::DeleteResourceRequest,
    ) -> Result<lore_proto::rebac::DeleteResourceResponse, Status> {
        self.resource_deletes.fetch_add(1, Ordering::SeqCst);
        self.authenticate(metadata)?;
        if !request.resource_id.starts_with("urc-") {
            return Err(self.invalid("resource_id must be a urc- resource"));
        }
        Ok(lore_proto::rebac::DeleteResourceResponse {})
    }

    /// The read-path authorizer loreserver switches on together with the
    /// direct rail. Deliberately permissive; see this module's divergence list.
    fn check_user_permission(
        &self,
        metadata: &tonic::metadata::MetadataMap,
        request: lore_proto::auth::CheckUserPermissionRequest,
    ) -> Result<lore_proto::auth::CheckUserPermissionResponse, Status> {
        self.permission_checks.fetch_add(1, Ordering::SeqCst);
        // Authenticated, because that is what this RPC is for. Not authorized
        // against any policy, because this harness has no repository catalog
        // and no case here claims read-path authorization coverage.
        self.authenticate(metadata)?;
        let mut allowed = Vec::new();
        let mut denied = Vec::new();
        for resource_id in request.resource_id {
            if resource_id.starts_with("urc-") {
                allowed.push(lore_proto::auth::ResourcePermission {
                    resource_id,
                    permission: vec![
                        "read".to_owned(),
                        "write".to_owned(),
                        "obliterate".to_owned(),
                        "migrate".to_owned(),
                    ],
                });
            } else {
                denied.push(lore_proto::auth::ResourcePermission {
                    resource_id,
                    permission: Vec::new(),
                });
            }
        }
        Ok(lore_proto::auth::CheckUserPermissionResponse {
            allowed_resource_permission: allowed,
            denied_resource_permission: denied,
        })
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A running stub. Dropping it shuts the server down.
pub struct RebacStub {
    state: Arc<StubState>,
    url: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl RebacStub {
    /// Bind and serve on `port`, then wait until the listener answers.
    ///
    /// Started before either loreserver process, though nothing forces that:
    /// loreserver dials this lazily, per call. It is done anyway so a stub that
    /// failed to bind is reported here rather than as an unexplained
    /// `UNAVAILABLE` deep inside a mutation.
    pub async fn start(env: &Env, port: u16) -> Self {
        let document = std::fs::read_to_string(&env.jwks_json).unwrap_or_else(|error| {
            panic!(
                "read the JWKS document {}: {error}",
                env.jwks_json.display()
            )
        });
        let decoding_key = decoding_key_from_jwks(&document);

        let mut org_uuid = [0u8; UUID_BYTES];
        rand::rng().fill_bytes(&mut org_uuid);

        let state = Arc::new(StubState {
            issuer: env.jwt_issuer.clone(),
            audience: env.jwt_audience.clone(),
            decoding_key,
            org_uuid,
            grants: Mutex::new(HashMap::new()),
            minted: Mutex::new(HashMap::new()),
            authorized: Mutex::new(Vec::new()),
            refusals: Mutex::new(Vec::new()),
            authorize_calls: AtomicU64::new(0),
            permission_checks: AtomicU64::new(0),
            resource_creates: AtomicU64::new(0),
            resource_deletes: AtomicU64::new(0),
        });

        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let (shutdown, stop) = tokio::sync::oneshot::channel();
        let rebac = service::RebacApiStub::new(state.clone());
        let auth = service::UrcAuthApiStub::new(state.clone());
        lore_spawn!(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(rebac)
                .add_service(auth)
                .serve_with_shutdown(addr, async move {
                    let _ = stop.await;
                })
                .await;
        });

        // Wait for the listener rather than assuming it. The failure this
        // avoids is not a slow start: a port collision inside the case's own
        // ten-port band would otherwise surface much later as an `UNAVAILABLE`
        // from inside a mutation, which reads as a verifier fault rather than
        // as a harness one.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the harness rebac stub never accepted a connection on {addr}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }

        Self {
            state,
            // Plaintext h2c. `RebacClientHelper` and `LoreAuthClientHelper`
            // both add TLS only when the URL starts with `https://`.
            url: format!("http://127.0.0.1:{port}"),
            shutdown: Some(shutdown),
        }
    }

    /// The value both processes' `[environment.endpoint] auth_url` is set to.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Grant `subject` a role on `repository_id`.
    ///
    /// The stand-in for the platform's repository catalog plus its ACL
    /// resolver. A repository nothing has granted is denied, so a case that
    /// forgets this gets a refusal naming the omission rather than a silent
    /// pass.
    pub fn grant(&self, repository_id: &[u8], subject: &str, role: Role) {
        let mut grants = self
            .state
            .grants
            .lock()
            .expect("the stub's grant map must not be poisoned");
        grants
            .entry(repository_id.to_vec())
            .or_default()
            .insert(subject.to_owned(), role);
    }

    /// Every authorization this stub issued, in order.
    pub fn authorized(&self) -> Vec<AuthorizedOperation> {
        self.state
            .authorized
            .lock()
            .map(|authorized| authorized.clone())
            .unwrap_or_default()
    }

    /// How many authorizations this stub issued for one principal, family and
    /// repository.
    ///
    /// Scoped by repository as well as by subject, because a case that created
    /// two repositories would otherwise let an authorization for one satisfy an
    /// assertion about the other.
    pub fn authorized_count(&self, subject: &str, method: &str, repository_id: &[u8]) -> usize {
        self.authorized()
            .into_iter()
            .filter(|entry| {
                entry.subject == subject
                    && entry.method == method
                    && entry.repository_id == repository_id
            })
            .count()
    }

    /// Every reason this stub refused anything, for a failure message. Covers
    /// policy denials, shape refusals and authentication refusals alike, so an
    /// empty list really does mean it refused nothing. Never sent on the wire.
    pub fn refusals(&self) -> Vec<String> {
        self.state
            .refusals
            .lock()
            .map(|refusals| refusals.clone())
            .unwrap_or_default()
    }

    /// How many times `AuthorizeDirectRepositoryOperation` was called at all.
    ///
    /// The discriminating counter for "did this case actually reach the direct
    /// rail". A case whose mutation succeeded with this at zero proved
    /// something other than what it says.
    pub fn authorize_calls(&self) -> u64 {
        self.state.authorize_calls.load(Ordering::SeqCst)
    }

    /// How many times the read-path `CheckUserPermission` was called.
    pub fn permission_checks(&self) -> u64 {
        self.state.permission_checks.load(Ordering::SeqCst)
    }
}

impl Drop for RebacStub {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

/// Build the verification key from the JWKS document both processes fetch.
///
/// Read from the same file rather than from the private key's public half, so
/// this stub can only accept what loreserver's own verifier accepts: one
/// document, one key, no chance of the two drifting.
fn decoding_key_from_jwks(document: &str) -> jsonwebtoken::DecodingKey {
    let parsed: serde_json::Value =
        serde_json::from_str(document).expect("the JWKS document must be JSON");
    let key = parsed
        .get("keys")
        .and_then(serde_json::Value::as_array)
        .and_then(|keys| keys.first())
        .expect("the JWKS document must carry at least one key");
    let modulus = key
        .get("n")
        .and_then(serde_json::Value::as_str)
        .expect("the JWKS key must carry an RSA modulus");
    let exponent = key
        .get("e")
        .and_then(serde_json::Value::as_str)
        .expect("the JWKS key must carry an RSA exponent");
    jsonwebtoken::DecodingKey::from_rsa_components(modulus, exponent)
        .expect("the JWKS key must be a usable RSA public key")
}

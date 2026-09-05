// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-029 domain-Postgres construction, readiness, and the handler admission
//! gate.
//!
//! `lore-postgres` owns the domain transactions themselves. This module owns
//! the server-side seam around them:
//!
//! - **Construction** — build the coordinator from the same
//!   `[plugins.postgres.*]` configuration the three CR-007 stores use, and
//!   prove positively that all four conventional pools address one database
//!   (R-SHOULD-1). When the fragment provider is enabled, this attested identity
//!   is also the expectation for the separately credentialed fifth, dispatch
//!   pool. No URL comparison stands in for either proof.
//! - **Readiness** — a Postgres-mode cell with enforcement requested must refuse
//!   to come up on an incomplete backfill. The schema `CHECK` is the backstop,
//!   not the gate.
//! - **Admission** — [`DomainContext::admit`] is the one place a governed
//!   handler turns validated request metadata plus a target identity into a
//!   [`GovernedOperation`]. It fails closed under enforcement, before any
//!   authorization side effect.
//!
//! # Why the coordinator is not a plugin-registry store
//!
//! The registry brokers `ImmutableStore`/`MutableStore`/`LockStore`. The
//! coordinator implements none of those; it implements
//! `DomainTransactionStore`, has exactly one implementation, and is selected by
//! the mutable store already being in `postgres` mode. Giving it a fourth
//! registry trait would add a selection axis with one possible value.

use std::sync::Arc;
use std::sync::OnceLock;

use anyhow::Result;
use anyhow::anyhow;
use lore_base::types::Context;
use lore_base::types::Hash;
use lore_base::types::KeyType;
use lore_base::types::RepositoryId;
use lore_postgres::domain::DatabaseIdentity;
use lore_postgres::domain::DomainSchemaState;
use lore_postgres::domain::bypass::DomainEnforcement;
use lore_postgres::domain::coordinator::BranchDeleteInput;
use lore_postgres::domain::coordinator::BranchSnapshot;
use lore_postgres::domain::coordinator::CAS_MISMATCH_V1;
use lore_postgres::domain::coordinator::DEFAULT_BRANCH_V1;
use lore_postgres::domain::coordinator::DomainTransactionStore;
use lore_postgres::domain::coordinator::GovernedOperation;
use lore_postgres::domain::coordinator::MetadataCasInput;
use lore_postgres::domain::coordinator::PendingEvent;
use lore_postgres::domain::coordinator::ProjectionWrite;
use lore_postgres::domain::coordinator::RepositoryCreateInput;
use lore_postgres::domain::coordinator::RepositoryDeleteInput;
use lore_postgres::domain::errors::DomainOutcome;
use lore_postgres::domain::fragments::PostgresFragmentCoordinator;
use lore_postgres::domain::locks::LockFencingReadiness;
use lore_postgres::domain::locks::PostgresLockCoordinator;
use lore_postgres::domain::outbox::builders as outbox_builders;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptKey;
use lore_revision::branch;
use lore_revision::repository;
use lore_storage::hash;
use tonic::Status;
use tonic::metadata::MetadataMap;
use tracing::debug;
use tracing::info;
use tracing::warn;
use uuid::Uuid;

use crate::auth::jwt::AuthorizationToken;
use crate::authnz::common::create_request_with_authorization;
use crate::authnz::rebac::RepositoryOperationAuthorizationVerifier;
use crate::event_relay::admission::OutboxAdmission;
use crate::grpc::domain_operation_metadata;
use crate::plugins::postgres::assert_domain_store_colocated;
use crate::plugins::postgres::connect_domain_store;
use crate::settings::Settings;
use crate::store::configuration::resolve_plugin_config_with_fallback;

/// The `mode` string that selects the Postgres backend.
const POSTGRES_MODE: &str = "postgres";
const CONTROL_PLANE_SERVICE_SUBJECT: &str = "lorehub-control-plane";

// PIN(WP-120, 2026-09-04): the loreserver-internal prepare's wire contract with
// auth-grpc, agreed with the platform lane and frozen here so a later reader can
// check both halves against one statement.
//
// * RPC path: `/ucs.auth.RebacApi/AuthorizeDirectRepositoryOperation`.
// * Request:  verified_issuer=1, authenticated_subject=2, operation_id=3 (16B
//             UUIDv7), method=4, scope=5, fingerprint_version=6, fingerprint=7
//             (32B), canonical_intent_digest=8 (32B), repository_id=9 (16B).
// * Response: the same eight echoed, then authorization_id=9 (16B),
//             authorization_revision=10, verification_nonce=11 (32B),
//             bound_fields_digest=12 (32B), org_uuid=13 (audit only).
// * `method` is a closed set: the six governed families named by the
//   `PLATFORM_METHOD_*` constants below, plus the five lock families
//   `lore-postgres` freezes (`lock.acquire`, `lock.renew`, `lock.admin_acquire`,
//   `lock.release`, `lock.force_release`).
// * `repository_id` means two different things by family and the verifier must
//   branch on `method`: on `repository.create` it is the caller-chosen NEW
//   identity and the decision is org-level, because there is no resource to look
//   up; on every other family it names an existing repository.
// * No `consumed_ticket_sha256` and no `expected_claim_identity_digest`. A
//   direct human operation has no preclaim ticket and no platform claim, and
//   sending either would file it as a mediated operation.
// * The caller's own bearer token is forwarded on the call's `authorization`
//   metadata. The verifier authenticates the human itself; the echoed issuer and
//   subject are for agreement-checking, never for authentication.

/// Domain separator for the fingerprint a loreserver-internal prepare mints.
///
/// PIN(WP-120, 2026-09-04). A mediated operation's fingerprint is computed by
/// the control plane over the caller-controlled fields it holds. A released
/// client holds nothing, so this server mints the fingerprint itself — and it
/// must be **derived**, not random, so that the value in the `PREPARED` row is
/// reproducible from the operation's own binding rather than being a second
/// secret nothing can check. Every component is length-prefixed, including the
/// method, so no two distinct bindings can frame to the same preimage.
const INTERNAL_FINGERPRINT_DOMAIN_V1: &[u8] = b"lore-internal-prepare-fingerprint-v1\0";

/// Width of the two 32-byte witness fields the direct verifier must return.
const DIRECT_WITNESS_FIELD_LEN: usize = 32;

/// Which tenant scope a governed operation belongs to.
///
/// Every variant derives the scope from the **target** resource identity, never
/// from the token's resource list — R-BLOCK-5. `urc-*` is refused by the
/// builders in [`domain_operation_metadata`].
#[derive(Debug, Clone)]
pub enum GovernedScope<'a> {
    /// Repository create: the repository does not exist yet, so the scope is a
    /// fixed method constant plus the caller-chosen repository UUID.
    RepositoryCreate {
        /// Caller-chosen 16-byte repository identity.
        repository_id: &'a [u8],
    },
    /// Every other direct governed operation: the target repository identity.
    TargetRepository {
        /// 16-byte repository identity being mutated.
        repository_id: &'a [u8],
    },
    /// A control-plane-mediated operation, scoped by the auth-grpc-verified
    /// `(org UUID, principal-v1\0 || Principal.userId)` tuple.
    Mediated {
        /// 16-byte organisation identity from the preclaim-authorization
        /// witness.
        org_uuid: &'a [u8],
        /// Initiating principal's user identity from that same witness.
        principal_user_id: &'a [u8],
    },
}

impl GovernedScope<'_> {
    fn tenant_scope_key(&self) -> Result<Vec<u8>, Status> {
        let built = match self {
            Self::RepositoryCreate { repository_id } => {
                domain_operation_metadata::scope_key_repository_create(repository_id)
            }
            Self::TargetRepository { repository_id } => {
                domain_operation_metadata::scope_key_target_repository(repository_id)
            }
            Self::Mediated {
                org_uuid,
                principal_user_id,
            } => domain_operation_metadata::scope_key_mediated(org_uuid, principal_user_id),
        };
        built.map_err(|e| {
            // A client fault, not a server one. The gate deliberately runs
            // before handler logic, so the target identity here is raw request
            // input that nothing has validated yet: a caller can send a
            // repository id that is not 16 bytes, or one whose first bytes
            // spell `urc-`, and both are its mistake to correct. Reporting
            // `INTERNAL` would blame the server for a bad request and would
            // also be the one code an operator would page on.
            debug!(error = %e, "Rejected a domain tenant scope key component");
            Status::invalid_argument(e.to_string())
        })
    }
}

/// The server-side handle on CR-029's domain coordinator.
///
/// Held as `Option<Arc<DomainContext>>` everywhere: a cell that is not in
/// Postgres mode has no coordinator at all, and that absence is the legacy
/// path, not an error.
pub struct DomainContext {
    store: Arc<dyn DomainTransactionStore>,
    enforcement: bool,
    lock_coordinator: Option<Arc<PostgresLockCoordinator>>,
    cell_id: Option<String>,
    /// CR-032's required-event admission gate, present only on a cell whose
    /// relay was built and passed every startup precondition.
    ///
    /// A `OnceLock` rather than a constructor argument because of an ordering
    /// fact, not a preference: the relay is checked against the database
    /// identity this context's construction attests, so `prepare_event_relay`
    /// necessarily runs after this type exists. The relay's own wiring sets it,
    /// once, and only when `[outbox_relay] enabled = true` — an absent handle
    /// is a cell with no relay, and it admits exactly as it did before WP-119.
    admission: OnceLock<Arc<OutboxAdmission>>,
    /// WP-120's direct-authorization verifier, present only on a cell that has
    /// the private auth-grpc endpoint configured.
    ///
    /// Its presence is the enablement switch for the loreserver-internal
    /// prepare. A cell without it keeps refusing a carriage-less mutation under
    /// enforcement exactly as it did before WP-120, rather than admitting one
    /// it cannot get an authorization for.
    operation_verifier: Option<Arc<dyn RepositoryOperationAuthorizationVerifier>>,
}

impl DomainContext {
    /// Wrap an already-connected coordinator with its enforcement state.
    pub fn new(store: Arc<dyn DomainTransactionStore>, enforcement: bool) -> Self {
        Self {
            store,
            enforcement,
            lock_coordinator: None,
            cell_id: None,
            admission: OnceLock::new(),
            operation_verifier: None,
        }
    }

    /// Wrap a coordinator and the active fenced-lock authority. The latter is
    /// present only after SCHEMA-117 cutover and all fail-closed readiness
    /// checks have succeeded.
    pub fn new_with_lock_coordinator(
        store: Arc<dyn DomainTransactionStore>,
        enforcement: bool,
        lock_coordinator: Arc<PostgresLockCoordinator>,
    ) -> Self {
        Self {
            store,
            enforcement,
            lock_coordinator: Some(lock_coordinator),
            cell_id: None,
            admission: OnceLock::new(),
            operation_verifier: None,
        }
    }

    /// Attach the private direct-authorization verifier.
    ///
    /// Separate from the constructors because the verifier is built from the
    /// same `auth_url` the private receipt rail uses, and a cell can be in
    /// Postgres mode with that endpoint unconfigured. `None` is a real state,
    /// not a defaulting mistake: it means no released client can be admitted on
    /// this cell, and every such caller keeps today's refusal.
    #[must_use]
    pub fn with_operation_verifier(
        mut self,
        verifier: Option<Arc<dyn RepositoryOperationAuthorizationVerifier>>,
    ) -> Self {
        self.operation_verifier = verifier;
        self
    }

    /// The attached direct-authorization verifier, or `None`.
    pub fn operation_verifier(&self) -> Option<&Arc<dyn RepositoryOperationAuthorizationVerifier>> {
        self.operation_verifier.as_ref()
    }

    /// Attach the configured cell identity, so producers can build CR-032
    /// outbox events.
    ///
    /// Separate from the constructors on purpose: the cell identity is
    /// **optional** at this layer. A cell that has not configured one is the
    /// pre-CR-032 cell, and it keeps working with no outbox rows rather than
    /// refusing every mutation. Closing that gap fail-closed is WP-119's
    /// required-event admission gate, which knows whether the cell is supposed
    /// to be producing events; this constructor cannot tell the difference
    /// between "not configured yet" and "misconfigured".
    #[must_use]
    pub fn with_cell_id(mut self, cell_id: Option<String>) -> Self {
        self.cell_id = cell_id;
        self
    }

    /// The configured cell identity, or `None` on a cell that has none.
    ///
    /// A producer with `None` here emits no event. It must not substitute a
    /// hostname, a database name, or any other plausible-looking string: the
    /// `cell_id` is field one of CR-032's frozen `idempotency_key` preimage and
    /// becomes a broker subject token, so an invented value silently re-keys
    /// every event this cell will ever emit and can restructure the subject.
    pub fn cell_id(&self) -> Option<&str> {
        self.cell_id.as_deref()
    }

    /// The coordinator itself.
    pub fn store(&self) -> &Arc<dyn DomainTransactionStore> {
        &self.store
    }

    /// Whether this cell enforces domain transactions. False until backfill,
    /// residue classification, and cutover have all completed.
    pub fn enforcement_enabled(&self) -> bool {
        self.enforcement
    }

    /// Active fenced-lock coordinator, absent until SCHEMA-117 cutover.
    pub fn lock_coordinator(&self) -> Option<&Arc<PostgresLockCoordinator>> {
        self.lock_coordinator.as_ref()
    }

    /// Attach CR-032's required-event admission gate.
    ///
    /// Called once, from `event_relay::wiring::spawn_event_relay`, after
    /// every relay startup precondition has passed. `Err` carries the handle
    /// back when one is already attached; the caller treats that as a wiring
    /// fault rather than replacing a live gate, because two gates over one
    /// cell would mean two caches and a coin flip over which one a mutation
    /// reads.
    pub fn attach_admission(
        &self,
        admission: Arc<OutboxAdmission>,
    ) -> Result<(), Arc<OutboxAdmission>> {
        self.admission.set(admission)
    }

    /// The attached admission gate, or `None` on a cell with no relay.
    pub fn admission(&self) -> Option<&Arc<OutboxAdmission>> {
        self.admission.get()
    }

    /// Turn request metadata plus a target identity into a governed operation.
    ///
    /// This is the **only** place a handler is allowed to read the
    /// domain-operation headers, and it runs once, at handler entry, before any
    /// authorization side effect (CR-029 R-BLOCK-2). A second reading of the
    /// same identity at a different layer is what CR-010 and
    /// `loreserver-body-repo-authz-recheck.md` record the cost of.
    ///
    /// - `Ok(None)` — enforcement is off, the caller carried no operation
    ///   identity, and no internal admission was possible: the legacy carve-out,
    ///   and the only path that reaches today's unsynchronised writes.
    /// - `Ok(Some(_))` — a validated governed operation, either from presented
    ///   carriage or from WP-120's loreserver-internal admission.
    /// - `Err(_)` — decisive pre-admission rejection. Under enforcement this
    ///   covers absence that no internal admission could cover; in every mode it
    ///   covers malformed, wrong-length, wrong-version, non-UUIDv7, and
    ///   divergent-duplicate carriage.
    pub fn admit(
        &self,
        metadata: &MetadataMap,
        authorization: Option<&AuthorizationToken>,
        scope: GovernedScope<'_>,
    ) -> Result<Option<AdmittedOperation>, Status> {
        // Always `extract`, never `require`. Partial carriage is still an error
        // — `extract` returns `Ok(None)` only when *none* of the three headers
        // is present — so a caller that supplies two of three cannot fall
        // through into the internal path and have this server invent the third.
        let Some(carried) = domain_operation_metadata::extract(metadata)? else {
            return self.admit_internal(metadata, authorization, &scope);
        };

        // A governed mutation needs a verified principal: the receipt namespace
        // is keyed by `(verified issuer, authenticated subject, ...)`, so an
        // unauthenticated caller has no namespace to be admitted into. Refuse
        // rather than invent a shared one — and refuse regardless of
        // enforcement, because the caller carried operation identity and
        // silently continuing on the legacy path would hand it today's
        // unsynchronised writes while it believed it had been receipted.
        let Some(token) = authorization else {
            return Err(Status::unauthenticated(
                "Domain operation identity was supplied without a verified principal",
            ));
        };

        let is_control_plane = token.user_id == CONTROL_PLANE_SERVICE_SUBJECT
            && token.is_service_account == Some(true);
        let tenant_scope_key = match (is_control_plane, carried.mediated_scope.as_ref()) {
            (true, Some(mediated)) => domain_operation_metadata::scope_key_mediated_namespace(
                &mediated.org_uuid,
                &mediated.initiating_principal_namespace,
            )
            .map_err(|error| Status::invalid_argument(error.to_string()))?,
            (true, None) => {
                return Err(Status::invalid_argument(
                    "control-plane governed mutation is missing mediated-scope carriage",
                ));
            }
            (false, Some(_)) => {
                return Err(Status::invalid_argument(
                    "mediated-scope carriage is reserved for the control-plane service principal",
                ));
            }
            (false, None) => scope.tenant_scope_key()?,
        };

        // The attached claim is control-plane-only for the same reason the
        // mediated scope is: it names a platform claim row that only a mediated
        // operation has. Accepting it on a direct operation would put fields on
        // the ReBAC callback that flip auth-grpc's `hasGovernedCreateWitness`
        // for a create that has no claim to acknowledge, turning today's
        // working catalog path into a denial.
        if carried.claim_witness.is_some() && carried.mediated_scope.is_none() {
            return Err(Status::invalid_argument(
                "claim-witness carriage requires mediated-scope carriage",
            ));
        }

        // CR-032 "Lag, readiness, and backpressure". Every path that reaches
        // here is about to return a governed operation, and a governed
        // operation is exactly what appends an outbox row — so this is the
        // choke point, and it is the last thing checked. Everything above is a
        // client fault (malformed carriage, a missing principal, an unusable
        // scope) and stays classified as one: a backlog is a cell condition and
        // must not relabel a bad request.
        //
        // The gate is deliberately not conditioned on `self.enforcement`. What
        // decides whether a mutation produces a durable event is having been
        // admitted, not the enforcement flag, and a cell running a relay with
        // enforcement off would otherwise append rows into a backlog nothing
        // is allowed to refuse. The handle's own presence is the enablement
        // switch: it exists only on a cell with `[outbox_relay] enabled`.
        //
        // The read is cache-only. See `event_relay::admission`'s module
        // documentation for why a database probe may not run here.
        if let Some(admission) = self.admission.get() {
            admission.refuse_if_closed()?;
        }

        Ok(Some(AdmittedOperation {
            key: ReceiptKey {
                verified_issuer: token.issuer.clone(),
                authenticated_subject: token.user_id.clone(),
                tenant_scope_key,
                operation_id: carried.operation_id,
            },
            source: AdmissionSource::Carried(Box::new(carried)),
        }))
    }

    /// WP-120: admit a released client that presented a verified human JWT and
    /// no carriage at all.
    ///
    /// Owner decision of 2026-09-04 (option A): a released desktop obtains
    /// governed carriage through a **loreserver-internal** prepare rather than
    /// by minting carriage of its own. This function is the entry half of that
    /// decision — it decides whether an internal admission is possible and mints
    /// the operation identity. The prepare itself runs later, in
    /// [`DomainContext::complete_governed`], because the receipt binding needs
    /// the canonical intent digest and that is only assembled at the coordinator
    /// call site (see [`AdmittedOperation`]'s own note).
    ///
    /// # Every refusal below leaves the caller exactly where it was
    ///
    /// This is the property that makes the change safe to land: each `Ok(None)`
    /// here falls through to the *pre-WP-120* outcome for that caller — today's
    /// absent-carriage refusal under enforcement, or the legacy carve-out
    /// without it. Nothing here can turn a previously-working call into a
    /// failure, and nothing here admits a caller the old code would have
    /// admitted differently.
    ///
    /// The claim is about the `Ok(None)` paths and nothing wider. A caller that
    /// IS admitted here and then reaches a site with no coordinator call site —
    /// either of the branch-delete or repository-delete guards, or a branch push
    /// on a cell whose fenced lock routing is not armed — is refused
    /// `UNIMPLEMENTED` by `reject_unwired_governed_operation` where it used to be
    /// refused for absent carriage. Still a refusal, and still before any
    /// mutation, but a different code. Worth knowing before reading a changed
    /// status in a log as a regression.
    ///
    /// The operational consequence of that last case is real and easy to miss:
    /// a released client can push on an enforcing cell only if fenced lock
    /// routing is armed as well. Enforcement alone is not enough.
    fn admit_internal(
        &self,
        metadata: &MetadataMap,
        authorization: Option<&AuthorizationToken>,
        scope: &GovernedScope<'_>,
    ) -> Result<Option<AdmittedOperation>, Status> {
        let admissible = self.internal_admission_reason(metadata, authorization, scope)?;
        let Some((token, bearer, repository_id, tenant_scope_key)) = admissible else {
            if self.enforcement {
                // Unchanged pre-WP-120 refusal. Produced by `require` itself,
                // so the status this caller sees is byte-identical to the one it
                // saw before internal admission existed; `extract` already
                // returned `None`, so `require` cannot succeed here.
                domain_operation_metadata::require(metadata)?;
                return Err(Status::internal(
                    "domain carriage was absent yet accepted by require",
                ));
            }
            return Ok(None);
        };

        // Same choke point, same reasoning, same position as the carried path:
        // an internally admitted operation appends an outbox row too, and a
        // backlog is a cell condition that must not relabel anything above it.
        if let Some(admission) = self.admission.get() {
            admission.refuse_if_closed()?;
        }

        Ok(Some(AdmittedOperation {
            key: ReceiptKey {
                verified_issuer: token.issuer.clone(),
                authenticated_subject: token.user_id.clone(),
                tenant_scope_key,
                // Minted at handler entry rather than at the seam, so the
                // receipt's temporal class is the moment the request arrived.
                //
                // A released client carries no operation identity of its own, so
                // it gets a fresh id per attempt and there is **no cross-attempt
                // idempotency**: a client retry is a new operation, not a
                // replay. That is a property of the caller having nothing to
                // replay with, not a gap in the rail — the rail still gives this
                // operation atomicity, a single-use prepare token, and its
                // classified outbox row.
                operation_id: Uuid::now_v7(),
            },
            source: AdmissionSource::Internal(InternalAdmission {
                repository_id,
                bearer,
                // Read here rather than at the seam because this is the last point that holds the
                // request's metadata. A malformed value refuses the mutation; see
                // `extract_attempt_id` for why that is the safer direction.
                client_attempt_id: domain_operation_metadata::extract_attempt_id(metadata)?,
            }),
        }))
    }

    /// The closed list of conditions an internal admission needs.
    ///
    /// Returns the pieces the caller needs on success, and `Ok(None)` when this
    /// cell or this caller cannot use the internal path at all.
    #[allow(clippy::type_complexity)]
    fn internal_admission_reason<'t>(
        &self,
        metadata: &MetadataMap,
        authorization: Option<&'t AuthorizationToken>,
        scope: &GovernedScope<'_>,
    ) -> Result<Option<(&'t AuthorizationToken, String, Vec<u8>, Vec<u8>)>, Status> {
        // 1. Enforcement. An unenforcing cell still writes the generic mutable
        //    path unfenced, so admitting a governed mutation there would put two
        //    writers on the same rows under two lock disciplines — the same
        //    reasoning the delete and branch-delete seams already refuse on.
        if !self.enforcement {
            return Ok(None);
        }
        // 2. A verifier. Without one there is no way to obtain an authorization
        //    for this principal, and minting a receipt on the strength of the
        //    JWT alone would make loreserver its own authorizer.
        if self.operation_verifier.is_none() {
            return Ok(None);
        }
        // 3. A verified principal, and its raw bearer token. The token is
        //    forwarded to auth-grpc so the verifier re-verifies the JWT itself
        //    rather than trusting this server's report of who the caller is.
        let Some(token) = authorization else {
            return Ok(None);
        };
        let Some(bearer) = metadata
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
        else {
            return Ok(None);
        };
        // 4. A human. The control-plane service principal always carries its own
        //    carriage; minting identity for it would drop a mediated operation
        //    into a direct receipt namespace, and every service account is
        //    likewise excluded rather than silently granted a new admission
        //    route it was never designed for.
        if token.user_id == CONTROL_PLANE_SERVICE_SUBJECT || token.is_service_account == Some(true)
        {
            return Ok(None);
        }
        // 5. A direct scope. `Mediated` names an org and an initiating principal
        //    that only carriage carries, so a mediated scope with no carriage is
        //    a contradiction and is refused rather than downgraded.
        //
        //    No handler constructs `GovernedScope::Mediated` today — `admit`
        //    derives the mediated scope key from the carriage itself, not from
        //    this argument — so this arm is unreachable from the wire. It is a
        //    fail-closed guard on a variant that exists, not a live path, and it
        //    is written as a refusal so that a future handler which does pass
        //    one gets a decisive answer rather than a scope key built from the
        //    wrong provenance.
        let repository_id = match scope {
            // PIN(WP-120, 2026-09-04): `repository.create` is REFUSED on the
            // direct rail and stays on the mediated claim rail. The platform's
            // `AuthorizeDirectRepositoryOperation` accepts ten families and this
            // is the one it excludes, because a create reserves a platform
            // catalog row before Lore is called at all — there is no repository
            // to check a role against, and no direct-human create exists.
            //
            // `Ok(None)` rather than an error, so a released client attempting a
            // create lands on exactly the pre-WP-120 outcome: today's
            // absent-carriage refusal under enforcement, or the legacy path
            // without it. Erroring here would invent a new failure for a caller
            // whose request was already going to be refused, and would report it
            // as a client fault when it is a capability this rail does not have.
            GovernedScope::RepositoryCreate { .. } => return Ok(None),
            GovernedScope::TargetRepository { repository_id } => (*repository_id).to_vec(),
            GovernedScope::Mediated { .. } => {
                return Err(Status::invalid_argument(
                    "mediated-scope governed operations require control-plane carriage",
                ));
            }
        };
        let tenant_scope_key = scope.tenant_scope_key()?;
        Ok(Some((token, bearer, repository_id, tenant_scope_key)))
    }

    /// Turn an admitted operation into a governed one.
    ///
    /// The one completion point. Carriage the caller presented is a pure
    /// projection, exactly as before WP-120. An internal admission runs its
    /// prepare here, at the one layer that knows the canonical intent.
    pub async fn complete_governed(
        &self,
        admitted: AdmittedOperation,
        method: &str,
        canonical_intent_digest: Vec<u8>,
    ) -> Result<GovernedOperation, Status> {
        match &admitted.source {
            AdmissionSource::Carried(_) => {
                Ok(admitted.into_governed(method, canonical_intent_digest))
            }
            AdmissionSource::Internal(_) => {
                self.internal_prepare(admitted, method, canonical_intent_digest)
                    .await
            }
        }
    }

    /// Run the same prepare contract the private `DomainOperationPrepare` runs,
    /// on this server's own behalf, for a released client.
    ///
    /// The sequence, and why it is in this order:
    ///
    /// 1. Build the receipt binding. The fingerprint is **derived** from the
    ///    binding (see [`INTERNAL_FINGERPRINT_DOMAIN_V1`]), never random.
    /// 2. Call the auth-grpc verifier, forwarding the caller's own bearer token
    ///    so the verifier authenticates the human independently.
    /// 3. Exact-echo every identity and binding field it returns. A divergent
    ///    echo is `PERMISSION_DENIED` and **no receipt row is written**, which is
    ///    why the echo check precedes the prepare rather than following it.
    /// 4. Persist the `PREPARED` receipt through the existing rail.
    ///
    /// Every failure lands before the mutation and is a typed refusal with no
    /// side effect.
    async fn internal_prepare(
        &self,
        admitted: AdmittedOperation,
        method: &str,
        canonical_intent_digest: Vec<u8>,
    ) -> Result<GovernedOperation, Status> {
        let AdmissionSource::Internal(internal) = &admitted.source else {
            // Unreachable: `complete_governed` selects this arm. Refusing rather
            // than asserting keeps it an enforced property.
            return Err(Status::internal(
                "internal prepare called for presented carriage",
            ));
        };
        // A handler-supplied digest that is not the frozen width would travel
        // into the receipt binding and the verifier request, so it is refused
        // here rather than carried. `INTERNAL` rather than `INVALID_ARGUMENT`:
        // every digest reaching this point came from `canonical_intent_digest`,
        // so a wrong width is this server's fault, not the caller's.
        if canonical_intent_digest.len() != domain_operation_metadata::DIGEST_LEN {
            return Err(Status::internal(
                "canonical intent digest must be 32 bytes for an internal prepare",
            ));
        }

        let binding = OperationBinding {
            method: method.to_owned(),
            scope: admitted.key.tenant_scope_key.clone(),
            fingerprint_version: i32::from(domain_operation_metadata::FINGERPRINT_VERSION_V1),
            fingerprint: internal_prepare_fingerprint(
                method,
                &admitted.key.tenant_scope_key,
                &canonical_intent_digest,
            )?,
            canonical_intent_digest,
        };

        // PIN(WP-120, 2026-09-04): `branch_id` is sent EMPTY for the governed
        // families, and the platform's contract admits that ("16 bytes when the
        // family names a branch and empty otherwise"). Two of these families do
        // name a branch — `branch.push` and `branch.metadata-set` — so this is a
        // deliberate narrowing, not an absence.
        //
        // The reason is structural: the entry gate is handed a `GovernedScope`,
        // which carries a repository and never a branch, and the branch only
        // becomes known at the coordinator call site inside the canonical
        // intent. Threading it here means widening every seam signature, which
        // the owner's happy-path-first ruling puts out of scope for this change.
        //
        // What it costs: the platform's role check for those two families is
        // repository-scoped anyway, so no authorization decision changes. What
        // it defers: the witness does not name the branch for them, so the
        // cross-branch binding the platform gets for the lock families is
        // absent here. The lock families, which are branch-scoped by nature, DO
        // send it — see `prepare_direct_lock_operation`.
        self.prepare_direct(
            admitted.key.clone(),
            binding,
            &internal.repository_id,
            &[],
            &internal.bearer,
            internal.client_attempt_id,
        )
        .await
    }

    /// Run the internal prepare for a **fenced lock** mutation.
    ///
    /// Locks reach the same rail by a different road. The lock coordinator
    /// builds its own complete [`OperationBinding`] — method, `lock-tenant-
    /// scope-v1` scope, fingerprint and canonical-intent digest all come from
    /// `lore-postgres`'s typed lock intent, and it re-checks every one of them
    /// under `validate_operation_binding` — so this path takes the finished
    /// binding rather than a method plus a digest, and mints only the receipt
    /// key around it.
    ///
    /// Everything after that is the same verifier callback, the same exact echo,
    /// and the same prepare as every other governed family.
    #[allow(clippy::too_many_arguments)]
    pub async fn prepare_direct_lock_operation(
        &self,
        token: &AuthorizationToken,
        bearer: &str,
        repository_id: &[u8],
        branch_id: &[u8],
        binding: OperationBinding,
        client_attempt_id: Option<Uuid>,
    ) -> Result<GovernedOperation, Status> {
        if token.user_id == CONTROL_PLANE_SERVICE_SUBJECT || token.is_service_account == Some(true)
        {
            // Same exclusion the entry gate applies. The control plane reaches a
            // governed lock through the mediated rail with its own carriage; a
            // service account minting a direct lock receipt would take fenced
            // ownership under a namespace that was never designed for it.
            return Err(Status::permission_denied(
                "Direct fenced lock mutations are for human principals",
            ));
        }
        let key = ReceiptKey {
            verified_issuer: token.issuer.clone(),
            authenticated_subject: token.user_id.clone(),
            // The lock coordinator derives the same value and refuses the
            // operation if the two disagree, so this is a shared derivation
            // rather than a value one side gets to choose.
            tenant_scope_key: binding.scope.clone(),
            operation_id: Uuid::now_v7(),
        };
        if let Some(admission) = self.admission.get() {
            admission.refuse_if_closed()?;
        }
        // Every lock family is branch-scoped by nature, so the branch is always
        // known here and always sent. This is the half of the platform's
        // repository-and-branch binding that Lore can supply today.
        self.prepare_direct(
            key,
            binding,
            repository_id,
            branch_id,
            bearer,
            client_attempt_id,
        )
        .await
    }

    /// The shared half of every internal prepare: verify, echo-check, persist.
    #[allow(clippy::too_many_arguments)]
    async fn prepare_direct(
        &self,
        key: ReceiptKey,
        binding: OperationBinding,
        repository_id: &[u8],
        branch_id: &[u8],
        bearer: &str,
        client_attempt_id: Option<Uuid>,
    ) -> Result<GovernedOperation, Status> {
        let verifier = self.operation_verifier.as_ref().ok_or_else(|| {
            Status::failed_precondition(
                "Internal domain prepare requires a configured repository-operation verifier",
            )
        })?;
        let fingerprint_version = u32::try_from(binding.fingerprint_version)
            .map_err(|_| Status::internal("fingerprint version is not representable"))?;
        let request = create_request_with_authorization(
            lore_proto::rebac::AuthorizeDirectRepositoryOperationRequest {
                verified_issuer: key.verified_issuer.clone(),
                authenticated_subject: key.authenticated_subject.clone(),
                operation_id: bytes::Bytes::copy_from_slice(key.operation_id.as_bytes()),
                method: binding.method.clone(),
                scope: bytes::Bytes::copy_from_slice(&binding.scope),
                fingerprint_version,
                fingerprint: bytes::Bytes::copy_from_slice(&binding.fingerprint),
                canonical_intent_digest: bytes::Bytes::copy_from_slice(
                    &binding.canonical_intent_digest,
                ),
                repository_id: bytes::Bytes::copy_from_slice(repository_id),
                branch_id: bytes::Bytes::copy_from_slice(branch_id),
            },
            Some(bearer.to_owned()),
        )?;
        let response = verifier
            .authorize_direct_repository_operation(request)
            .await?;
        verify_direct_echo(&key, &binding, &response)?;

        // The witness is deliberately `None`. A present witness makes the
        // receipt rail also write the **mediated** dispatch-possibility fence,
        // which requires a 32-byte `expected_claim_identity_digest` minted by
        // the platform's claim CAS. A direct human operation has no claim, so
        // there is nothing to fence and nothing honest to put in that column.
        //
        // BLOCKED(WP-120): direct-authorization evidence is verified but not
        // persisted beside the receipt. Recording it needs a receipt-schema
        // column of its own and a CR-029/CR-030 amendment naming its contract;
        // inventing values for the mediated columns would file a direct
        // operation as a mediated one.
        let prepared = self
            .store
            .domain_operation_prepare(&key, &binding, None, client_attempt_id)
            .await
            .map_err(|error| crate::grpc::map_domain_error_to_status(&error))?;
        match prepared {
            PrepareResult::Prepared { token, .. } => Ok(GovernedOperation {
                key,
                binding,
                prepare_token: token,
            }),
            // The operation id was minted moments ago by this server, so every
            // arm below is a cell fault or an id collision rather than a client
            // one — but each is still decisive and leaves nothing mutated.
            PrepareResult::Committed(outcome) => {
                warn!(
                    operation_id = %key.operation_id,
                    ?outcome,
                    "Internal prepare found a freshly minted operation id already decided"
                );
                Err(Status::aborted(
                    "Internally prepared operation was already decided",
                ))
            }
            PrepareResult::Mismatch => Err(Status::aborted(
                "Internally prepared operation collided with a different binding",
            )),
            PrepareResult::ExpiredOrUnknown => Err(Status::aborted(
                "Internally prepared operation was not admissible",
            )),
            PrepareResult::CapacityExhausted => Err(Status::resource_exhausted(
                "Domain operation admission capacity is exhausted",
            )),
        }
    }
}

/// The fingerprint a loreserver-internal prepare mints for one binding.
///
/// Deterministic from the binding's own caller-known fields, so the value in
/// the `PREPARED` row can be recomputed and checked rather than being a second
/// unverifiable secret. Every component is length-prefixed, including the
/// method string, so two distinct bindings cannot frame to one preimage.
fn internal_prepare_fingerprint(
    method: &str,
    scope: &[u8],
    canonical_intent_digest: &[u8],
) -> Result<Vec<u8>, Status> {
    let mut preimage = Vec::with_capacity(
        INTERNAL_FINGERPRINT_DOMAIN_V1.len()
            + 12
            + method.len()
            + scope.len()
            + canonical_intent_digest.len(),
    );
    preimage.extend_from_slice(INTERNAL_FINGERPRINT_DOMAIN_V1);
    for component in [method.as_bytes(), scope, canonical_intent_digest] {
        // A refusal, not a saturating conversion. Every component here is
        // bounded far below `u32::MAX` today, but a saturating length is the one
        // way this framing could stop being injective — two over-long
        // components would frame identically — and a fingerprint that is not
        // injective is a receipt key collision. Refusing costs nothing on a
        // path that can never take it.
        let len = u32::try_from(component.len()).map_err(|_| {
            Status::internal("internal prepare fingerprint component exceeds the frame width")
        })?;
        preimage.extend_from_slice(&len.to_be_bytes());
        preimage.extend_from_slice(component);
    }
    Ok(blake3::hash(&preimage).as_bytes().to_vec())
}

/// Refuse anything but an exact echo from the direct-authorization verifier.
///
/// Every identity and binding field is compared, and both witness widths are
/// checked, before a receipt row can exist. A verifier that answers about a
/// different principal, a different method, or a different intent is a
/// conclusive denial rather than a widened path.
fn verify_direct_echo(
    key: &ReceiptKey,
    binding: &OperationBinding,
    response: &lore_proto::rebac::AuthorizeDirectRepositoryOperationResponse,
) -> Result<(), Status> {
    let exact = response.verified_issuer == key.verified_issuer
        && response.authenticated_subject == key.authenticated_subject
        && response.operation_id.as_ref() == key.operation_id.as_bytes()
        && response.method == binding.method
        && response.scope.as_ref() == binding.scope
        // Compared against the binding rather than against the v1 constant.
        // The lock families build their own binding in `lore-postgres`, so a
        // future family that versions its fingerprint differently must still be
        // echo-checked against what was actually sent, not against a constant
        // that happens to agree today.
        && i64::from(response.fingerprint_version) == i64::from(binding.fingerprint_version)
        && response.fingerprint.as_ref() == binding.fingerprint
        && response.canonical_intent_digest.as_ref() == binding.canonical_intent_digest;
    if !exact {
        return Err(Status::permission_denied(
            "Direct repository operation authorization binding mismatch",
        ));
    }
    for (field, bytes) in [
        ("verification_nonce", response.verification_nonce.as_ref()),
        ("bound_fields_digest", response.bound_fields_digest.as_ref()),
    ] {
        if bytes.len() != DIRECT_WITNESS_FIELD_LEN {
            return Err(Status::permission_denied(format!(
                "Direct repository operation verifier returned invalid {field}"
            )));
        }
    }
    if response.authorization_id.len() != domain_operation_metadata::OPERATION_ID_LEN {
        return Err(Status::permission_denied(
            "Direct repository operation verifier returned invalid authorization_id",
        ));
    }
    Ok(())
}

/// A governed operation that passed the entry gate.
///
/// Deliberately stops short of a [`GovernedOperation`]: the binding's
/// `canonical_intent_digest` is a *contract* between this server and the
/// control plane's fingerprint computation, and it is only knowable at the
/// coordinator call site where the full canonical intent has been assembled.
/// Building it here would freeze that contract at the one layer that does not
/// know it.
#[derive(Debug, Clone)]
pub struct AdmittedOperation {
    /// Receipt namespace this operation was admitted into.
    pub key: ReceiptKey,
    /// Where this operation's identity came from.
    pub source: AdmissionSource,
}

/// Where an admitted operation's identity came from.
///
/// An enum rather than an optional carriage field on purpose: the two arms
/// complete through genuinely different code, and a missed arm has to be a
/// compile error. Filling a synthesised `DomainOperationMetadata` with zeroed
/// stand-ins for the prepare token and fingerprint would make a skipped
/// internal prepare present an all-zero bearer secret instead.
/// `Debug` is hand-written for the same reason [`InternalAdmission`]'s is, and
/// for symmetry with it. The carried arm holds a `prepare_token`, which is a
/// single-use bearer secret, and `DomainOperationMetadata` derives `Debug` over
/// it. Redacting only the internal arm's bearer would have left the sibling arm
/// printing a credential from the same one-word edit.
#[derive(Clone)]
pub enum AdmissionSource {
    /// Carriage the caller presented and this gate validated. Today's
    /// control-plane-mediated path, and any client that prepared through the
    /// private receipt rail itself.
    ///
    /// Boxed because the validated carriage is roughly six times the size of an
    /// internal admission, and every `AdmittedOperation` — including the far
    /// more common internal one, once released clients are the norm — would
    /// otherwise carry that width.
    Carried(Box<domain_operation_metadata::DomainOperationMetadata>),
    /// WP-120: no carriage, a verified human principal on a released client.
    /// This server mints the operation identity and runs the prepare itself.
    Internal(InternalAdmission),
}

/// What an internal admission carries from the entry gate to the seam.
///
/// `Debug` is implemented by hand rather than derived: this type holds the
/// caller's raw bearer token, and a derived `Debug` would print it in full the
/// first time anyone writes `warn!(?admitted, ..)` at a governed site. That is a
/// credential in a log file, reachable by a one-word edit at any of a dozen call
/// sites, so the redaction lives in the type rather than in a convention every
/// future call site has to remember.
#[derive(Clone)]
pub struct InternalAdmission {
    /// 16-byte target repository identity, handed to the verifier so its
    /// authorization decision names the resource actually being mutated.
    pub repository_id: Vec<u8>,
    /// The caller's own `authorization` header value, forwarded to auth-grpc so
    /// the verifier authenticates the human independently rather than trusting
    /// this server's report of who is calling.
    ///
    /// Never logged, never persisted, and never placed in a receipt row.
    pub bearer: String,
    /// The client's own attempt identity, when it sent one. PIN(WP-120, 2026-09-05).
    ///
    /// Persisted beside the receipt so a client whose response was lost can find the receipt
    /// again. It has to be the client's value rather than this server's, because the operation id
    /// minted here is only ever learned from the response, and the response is the thing that
    /// went missing.
    ///
    /// It lives on this arm alone. A carried admission belongs to the control plane, which minted
    /// the operation id itself and already knows it, so it has nothing to join and needs no second
    /// identifier. That asymmetry is the shape of the problem, not an oversight.
    ///
    /// An identifier, never an authority: the receipt namespace still comes from the verified
    /// token, so a caller quoting someone else's attempt id finds nothing.
    pub client_attempt_id: Option<Uuid>,
}

impl std::fmt::Debug for AdmissionSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Carried(carried) => f
                .debug_struct("Carried")
                .field("operation_id", &carried.operation_id)
                .field("fingerprint_version", &carried.fingerprint_version)
                .field("fingerprint", &carried.fingerprint)
                .field("prepare_token", &"<redacted>")
                .field("mediated_scope", &carried.mediated_scope)
                .field("claim_witness", &carried.claim_witness)
                .finish(),
            Self::Internal(internal) => f.debug_tuple("Internal").field(internal).finish(),
        }
    }
}

impl std::fmt::Debug for InternalAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InternalAdmission")
            .field("repository_id", &self.repository_id)
            .field("bearer", &"<redacted>")
            .field("client_attempt_id", &self.client_attempt_id)
            .finish()
    }
}

impl AdmittedOperation {
    /// The carriage the caller presented, or `None` when this server minted the
    /// operation identity itself.
    #[must_use]
    pub fn carried(&self) -> Option<&domain_operation_metadata::DomainOperationMetadata> {
        match &self.source {
            AdmissionSource::Carried(carried) => Some(carried),
            AdmissionSource::Internal(_) => None,
        }
    }

    /// Whether this server minted the operation identity itself.
    #[must_use]
    pub fn is_internally_prepared(&self) -> bool {
        matches!(self.source, AdmissionSource::Internal(_))
    }

    /// Complete a **presented-carriage** operation at the coordinator call site.
    ///
    /// Unchanged from before WP-120 and still infallible: the caller already
    /// holds a prepare token, so nothing here can fail. An internally admitted
    /// operation has no token yet and cannot use this path — it goes through
    /// [`DomainContext::complete_governed`], which is the entry point every seam
    /// now calls.
    pub fn into_governed(
        self,
        method: impl Into<String>,
        canonical_intent_digest: Vec<u8>,
    ) -> GovernedOperation {
        let (fingerprint_version, fingerprint, prepare_token) = match self.source {
            AdmissionSource::Carried(carried) => (
                carried.fingerprint_version,
                carried.fingerprint,
                carried.prepare_token,
            ),
            // Unreachable through `complete_governed`, which routes this arm to
            // the internal prepare. A zero token is refused by `receipts::
            // consume`'s constant-time comparison, so a future caller that
            // reached here by mistake gets a decisive admission rejection rather
            // than a silently unadmitted mutation.
            AdmissionSource::Internal(_) => (
                i32::from(domain_operation_metadata::FINGERPRINT_VERSION_V1),
                Vec::new(),
                [0u8; domain_operation_metadata::PREPARE_TOKEN_LEN],
            ),
        };
        GovernedOperation {
            binding: OperationBinding {
                method: method.into(),
                // For a direct operation the binding's canonical scope and the
                // receipt's tenant scope are the same bytes: the operation
                // targets exactly the resource whose namespace admits it.
                scope: self.key.tenant_scope_key.clone(),
                fingerprint_version,
                fingerprint,
                canonical_intent_digest,
            },
            prepare_token,
            key: self.key,
        }
    }
}

/// The single call every governed repository/branch handler makes at entry.
///
/// This is the whole of R-BLOCK-2's handler-entry rule in one place: read the
/// carriage once, validate it, and decide before any handler logic runs.
///
/// Three outcomes:
///
/// - **Legacy path** (`Ok(None)`) — no coordinator, or a coordinator with
///   enforcement off and no carriage. The handler proceeds exactly as it does
///   today.
/// - **Rejected** (`Err`) — carriage that is absent under enforcement,
///   malformed, wrong-length, wrong-version, non-UUIDv7, or duplicated with
///   divergent values. Decisive, before any authorization side effect.
/// - **Admitted** (`Ok(Some(_))`) — a validated governed operation for the
///   coordinator.
///
/// A caller that carries operation identity against a cell with **no**
/// coordinator is rejected rather than silently downgraded: it asked for
/// governed semantics and would otherwise get today's unsynchronised writes
/// while believing its operation was admitted.
pub fn admit_at_entry(
    domain: Option<&Arc<DomainContext>>,
    metadata: &MetadataMap,
    authorization: Option<&AuthorizationToken>,
    scope: GovernedScope<'_>,
) -> Result<Option<AdmittedOperation>, Status> {
    let Some(domain) = domain else {
        if domain_operation_metadata::extract(metadata)?.is_some() {
            return Err(Status::failed_precondition(
                "Domain operation identity was supplied but this cell has no domain coordinator",
            ));
        }
        return Ok(None);
    };
    domain.admit(metadata, authorization, scope)
}

/// The governed metadata compare-and-swap seam, shared by all four CAS sites.
///
/// Repository and branch metadata CAS each exist twice, on v0 and v1, and the
/// four handlers differ only in their response shape. Everything between
/// admission and the coordinator is identical, so it lives here once: four
/// copies of a governed mutation path is how two of them drift, and CR-029's
/// whole point is that v0 and v1 stop disagreeing about what a write means.
///
/// This is deliberately not a handler helper. It is the same seam
/// [`admit_at_entry`] belongs to: it turns an [`AdmittedOperation`] into a
/// committed domain transaction and nothing else. It performs no
/// authorization, no validation, and no I/O of its own.
pub struct GovernedMetadataCas {
    domain: Arc<DomainContext>,
    operation: GovernedOperation,
}

/// What a governed metadata CAS committed.
///
/// A CAS loss is **not** an error here, matching the ungoverned path and
/// CR-029 Phase 5: it is a successful RPC whose response carries the pointer
/// that was actually there.
pub enum MetadataCasOutcome {
    /// The swap applied. The pointer is now the requested one.
    Applied,
    /// The swap lost. This is the pointer the transaction observed under its
    /// row lock, which is what the caller must retry against.
    Lost(Vec<u8>),
}

impl GovernedMetadataCas {
    /// Prepare the governed call, or `Ok(None)` for the ungoverned path.
    ///
    /// `digest` must already have been computed from validated wire values
    /// through the one shared canonical-intent definition. Lore never accepts a
    /// body- or handler-supplied digest (CR-029's canonical-intent contract),
    /// which is why this takes the bytes rather than the request. It is the
    /// 32 bytes `canonical_intent_digest` returns.
    ///
    /// # A family, never a method string
    ///
    /// This seam serves two families across four handlers, so unlike the create
    /// and delete seams it cannot simply drop the argument. It takes a
    /// [`MetadataCasFamily`] instead, which buys the same guarantee: v0 and v1
    /// of one family resolve to one constant by construction, and no handler can
    /// spell a method of its own. Before this, each of the four bound its own
    /// gRPC path, so one operation id was consumable only by whichever wire
    /// version the caller happened to reach.
    pub async fn prepare(
        domain: Option<&Arc<DomainContext>>,
        admitted: Option<AdmittedOperation>,
        family: MetadataCasFamily,
        digest: Vec<u8>,
    ) -> Result<Option<Self>, Status> {
        let Some(admitted) = admitted else {
            return Ok(None);
        };
        let Some(domain) = domain else {
            // Unreachable in practice: `admit_at_entry` returns `None` when
            // there is no coordinator. Refusing rather than asserting keeps
            // that an enforced property instead of an assumed one.
            return Err(Status::failed_precondition(
                "Domain coordinator is unavailable",
            ));
        };
        let operation = domain
            .complete_governed(admitted, family.platform_method(), digest)
            .await?;
        Ok(Some(Self {
            domain: domain.clone(),
            operation,
        }))
    }

    /// This cell's configured identity, or `None` when it has none.
    ///
    /// Handlers need it to decide whether to build an event at all; see
    /// [`DomainContext::cell_id`].
    pub fn cell_id(&self) -> Option<&str> {
        self.domain.cell_id()
    }

    /// Read a branch's committed identity for the event's bounded payload.
    ///
    /// A branch event names the branch and its tip, and neither is in the CAS
    /// request. This is a read **before** the transaction, so the values are a
    /// preflight observation rather than a committed one, which is why they go
    /// in the payload and never in the aggregate version: the version's ordinal
    /// and identity are resolved by the coordinator from what it actually
    /// commits.
    pub async fn branch_snapshot(
        &self,
        repository_id: &[u8],
        branch_id: &[u8],
    ) -> Result<Option<BranchSnapshot>, Status> {
        self.domain
            .store()
            .branch_snapshot(repository_id, branch_id)
            .await
            .map_err(|error| crate::grpc::map_domain_error_to_status(&error))
    }

    /// Commit the swap, its projection row, and its classified event in one
    /// transaction.
    ///
    /// `branch_id` selects the aggregate: `None` swaps the repository's own
    /// metadata pointer, `Some` swaps a branch's.
    pub async fn commit(
        &self,
        repository_id: &[u8],
        branch_id: Option<&[u8]>,
        expected_hash: &[u8],
        new_hash: &[u8],
        projection: ProjectionWrite,
        event: Option<PendingEvent>,
    ) -> Result<MetadataCasOutcome, Status> {
        let input = MetadataCasInput {
            repository_id: repository_id.to_vec(),
            branch_id: branch_id.map(<[u8]>::to_vec),
            expected_hash: expected_hash.to_vec(),
            new_hash: new_hash.to_vec(),
            projection: vec![projection],
            event,
        };
        let result = self
            .domain
            .store()
            .metadata_compare_and_swap(&self.operation, &input)
            .await
            .map_err(|error| crate::grpc::map_domain_error_to_status(&error))?;
        match result.outcome {
            DomainOutcome::Applied => Ok(MetadataCasOutcome::Applied),
            DomainOutcome::NotApplied { reason, .. } => match reason.as_str() {
                CAS_MISMATCH_V1 => {
                    // The coordinator promises the observed pointer on exactly
                    // this reason. Its absence is a coordinator defect, not a
                    // caller error, so it must not be reported as a CAS loss
                    // with a fabricated or empty pointer: a client would then
                    // retry against a value nothing ever held.
                    let observed = result.observed_pointer.ok_or_else(|| {
                        Status::internal(
                            "governed metadata CAS lost without reporting the observed pointer",
                        )
                    })?;
                    Ok(MetadataCasOutcome::Lost(observed))
                }
                // A tombstoned or absent target is indistinguishable by
                // contract, and the coordinator's own rejection reasons already
                // carry that mapping.
                other => Err(crate::grpc::map_domain_rejection_to_status(other)),
            },
        }
    }
}

/// Everything one repository create publishes, as the handler validated it.
///
/// Both blobs this names are already in the immutable store by the time a
/// [`GovernedRepositoryCreate::commit`] call is made. That ordering is the
/// whole point of taking hashes here rather than metadata: the transaction
/// commits pointers to content that already exists, so it can never publish a
/// pointer to a blob a later failure prevented from being written. The reverse
/// failure — a blob written, then the transaction refused — leaves an orphan
/// blob in a content-addressed store, which is unreferenced, harmless, and the
/// side of the trade CR-029's side-effect boundary deliberately chooses.
pub struct RepositoryCreatePublication<'a> {
    /// Repository-format salt, from the target `RepositoryContext`.
    ///
    /// Taken from the context rather than hardcoded to `SALT_LORE`, so the
    /// governed projection rows are byte-identical to the keys the legacy
    /// writers derive on the same repository.
    pub salt: &'a [u8],
    /// 16-byte repository identity.
    pub repository_id: &'a [u8],
    /// Exact repository name. Repository names do not fold case.
    pub name: &'a str,
    /// 32-byte repository metadata pointer, already published.
    pub metadata_hash: &'a [u8],
    /// 16-byte default-branch identity.
    pub default_branch_id: &'a [u8],
    /// Default branch name, as authored. The live-name key folds case.
    pub default_branch_name: &'a str,
    /// 32-byte default-branch metadata pointer, already published.
    pub default_branch_metadata_hash: &'a [u8],
    /// 32-byte default-branch tip. The zero hash on a fresh create.
    pub default_branch_latest_hash: &'a [u8],
}

impl RepositoryCreatePublication<'_> {
    /// The five `lore_mutable` rows a create writes today, rebuilt exactly.
    ///
    /// The legacy path writes these through four separate unsynchronised store
    /// calls (`repository::metadata_store_hash`, `repository::store_name_to_id`,
    /// and two inside `branch::create`), which is WP-119 inventory rows R1/R2
    /// and disagreement D3: the repository metadata pointer is published with a
    /// blind store rather than a compare-and-swap, so two concurrent creates
    /// race and the loser's pointer can survive. Handing the same rows to the
    /// coordinator is what removes that second unfenced writer — the rows now
    /// commit with the domain rows or not at all.
    ///
    /// The two name keys normalize **differently** and that is not an
    /// oversight: `repository::mutable_name_key` hashes the exact name while
    /// `branch::mutable_name_key` hashes its lowercase form. Two
    /// identically-shaped private helpers with different normalization is a
    /// recorded fork hazard; both are reproduced here from their own module's
    /// rule rather than from the other's.
    ///
    /// The two legacy primitives disagree about a zero value, so this cannot
    /// use one rule for all five rows. `MutableStore::store` treats the null
    /// hash as a delete, while `compare_and_swap` **retains a zero-valued
    /// row** — the Postgres store says so at its own INSERT, and the local
    /// store matches it — because a later zero-expected CAS uses that row as
    /// its predecessor. Four of these rows are written by `store` and the
    /// branch tip is written by `compare_and_swap`, which is the one that is
    /// actually zero on a fresh create. So the tip row is an explicit
    /// zero-valued row, not a delete.
    fn projection(&self) -> Vec<ProjectionWrite> {
        let repository_hex = hex::encode(self.repository_id);
        let branch_hex = hex::encode(self.default_branch_id);
        // The four `store`-backed rows. A zero value here would be a delete,
        // matching `store`'s null-hash contract; none of them is reachable with
        // a zero value on a real create, since a metadata pointer is a content
        // hash and both identities are non-zero.
        let stored =
            |key: Hash, key_type: KeyType, value: &[u8], partition: Vec<u8>| ProjectionWrite {
                partition,
                key_type: key_type as i16,
                key: key.as_ref().to_vec(),
                value: if value.iter().all(|byte| *byte == 0) {
                    None
                } else {
                    Some(value.to_vec())
                },
            };
        let repository_partition = self.repository_id.to_vec();
        // The repository name index is global, not per-repository: the legacy
        // writer stores it under the zero partition so a name can be resolved
        // to an ID without already knowing the ID.
        let global_partition = RepositoryId::default().data().to_vec();
        vec![
            stored(
                hash::hash_function_arg(self.salt, repository::METADATA, &repository_hex),
                KeyType::RepositoryMetadata,
                self.metadata_hash,
                repository_partition.clone(),
            ),
            stored(
                hash::hash_function_arg(self.salt, repository::ID, self.name),
                KeyType::RepositoryId,
                Hash::from_context(Context::from(self.repository_id)).as_ref(),
                global_partition,
            ),
            stored(
                hash::hash_function_args(self.salt, branch::METADATA, &repository_hex, &branch_hex),
                KeyType::BranchMetadata,
                self.default_branch_metadata_hash,
                repository_partition.clone(),
            ),
            stored(
                hash::hash_function_arg(
                    self.salt,
                    branch::ID,
                    &self.default_branch_name.to_lowercase(),
                ),
                KeyType::BranchId,
                Hash::from_context(Context::from(self.default_branch_id)).as_ref(),
                repository_partition.clone(),
            ),
            // The compare-and-swap-backed row. `branch::store_latest` reaches
            // `compare_and_swap`, which writes the value verbatim even when it
            // is the null hash, so a fresh create leaves a zero-valued row
            // rather than no row. `load` reads the two identically and a
            // zero-expected CAS accepts either, but writing a delete here would
            // still leave the governed and legacy paths with different table
            // contents for the same create.
            ProjectionWrite {
                partition: repository_partition,
                key_type: KeyType::BranchLatestPointer as i16,
                key: hash::hash_function_args(
                    self.salt,
                    branch::LATEST,
                    &repository_hex,
                    &branch_hex,
                )
                .as_ref()
                .to_vec(),
                value: Some(self.default_branch_latest_hash.to_vec()),
            },
        ]
    }
}

/// What a governed repository create committed.
pub struct RepositoryCreateOutcome {
    /// Repository generation this transaction committed, or the existing one an
    /// exact retry found. `None` only when the coordinator reported an already
    /// committed receipt whose generation it does not retain.
    pub repository_generation: Option<i64>,
    /// The committed metadata pointer, read back from the domain row rather
    /// than assumed to be the one this call published.
    ///
    /// On a fresh create the two are the same. On an exact retry they can
    /// differ, because a metadata compare-and-swap may have moved the pointer
    /// between the original create and this retry — and the caller is owed the
    /// repository that exists, not a pointer that was current once.
    pub metadata_hash: Hash,
}

/// The one method name a governed repository create is known by.
///
/// It is the receipt binding's method **and** the ReBAC callback's `method`,
/// because the platform has exactly one value for both and cannot satisfy two.
/// `acknowledgeCreateClaim` compares the callback's method against the
/// authorization row; the prepare verifier compares the prepare request's method
/// against that same row; and `ReceiptRow::matches`
/// (`lore-postgres/src/domain/receipts.rs:306`) compares the stored method
/// against whatever binding a handler later presents. One row, three
/// comparisons, so one string.
///
/// # Why this is a constant and not a handler argument
///
/// The first cut of this passed the gRPC path into the binding
/// (`lore.RepositoryService/RepositoryCreate` on v0,
/// `lore.repository.v1.RepositoryService/RepositoryCreate` on v1) and this
/// constant only to the callback. Those two are independent values that had to
/// agree, and they did not: the platform's single stored method made the
/// callback pass and the receipt match fail, so a live governed create died at
/// the coordinator with `ADMISSION_REJECTED_V1` after the callback had already
/// succeeded. Worse, the two paths disagreed with **each other** — one operation
/// id could only ever be consumed by whichever wire version the caller happened
/// to reach, which is precisely the v0/v1 divergence CR-029 exists to end.
///
/// [`GovernedRepositoryCreate::prepare`] therefore takes no `method` argument at
/// all. Divergence is unrepresentable rather than merely corrected.
pub const PLATFORM_METHOD_REPOSITORY_CREATE: &str = "repository.create";

/// The one method name a governed repository delete is known by.
///
/// [`PLATFORM_METHOD_REPOSITORY_CREATE`]'s reasoning applies unchanged; only the
/// family differs. Bound here **before** delete is wired, rather than after the
/// same defect is found a second time: the platform named this value
/// (`REPOSITORY_DELETE_METHOD` in
/// `packages/control-plane/src/repository-operation-dispatch.ts`), so there is
/// nothing left to discover and no reason to leave a `method` argument for a
/// future handler to fill in wrongly.
pub const PLATFORM_METHOD_REPOSITORY_DELETE: &str = "repository.delete";

// PIN(WP-116, 2026-09-04): reserved name, no platform producer yet; CR-029
// amendment owed.
//
// The four families below have no authorization producer on the platform:
// `issueRepositoryOperationAuthorization` has one production caller and only the
// create family reaches it, so no row has ever held any of these strings. They
// are the control-plane lane's proposed dotted, family-scoped names, frozen here
// by owner ruling on 2026-09-04 so the binding shape is settled before each
// family's wiring lands rather than after the create defect repeats.
//
// Reserved is not observed. The first real producer for a family is what turns
// its name into a fact, and the CR-029 amendment naming all six is owed. If a
// producer lands writing something else, that is a conflict to resolve
// deliberately, not a Lore-side value to quietly follow.
/// Reserved method name for a governed repository metadata compare-and-swap.
pub const PLATFORM_METHOD_REPOSITORY_METADATA_SET: &str = "repository.metadata-set";
/// Reserved method name for a governed branch metadata compare-and-swap.
pub const PLATFORM_METHOD_BRANCH_METADATA_SET: &str = "branch.metadata-set";
/// Reserved method name for a governed branch push.
pub const PLATFORM_METHOD_BRANCH_PUSH: &str = "branch.push";
/// Reserved method name for a governed obliterate.
pub const PLATFORM_METHOD_REPOSITORY_OBLITERATE: &str = "repository.obliterate";

/// Which metadata compare-and-swap family a governed CAS belongs to.
///
/// [`GovernedMetadataCas`] serves two genuinely different families across four
/// handlers, so it cannot drop its method argument the way the single-family
/// create and delete seams did. This is the next best thing and gets the same
/// guarantee: a handler picks a **family**, never a string, so v0 and v1 of one
/// family map to one constant by construction and no handler can invent a method
/// or drift from its sibling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataCasFamily {
    /// Repository metadata pointer CAS, on either wire version.
    Repository,
    /// Branch metadata pointer CAS, on either wire version.
    Branch,
}

impl MetadataCasFamily {
    /// The reserved platform method name for this family.
    #[must_use]
    pub fn platform_method(self) -> &'static str {
        match self {
            Self::Repository => PLATFORM_METHOD_REPOSITORY_METADATA_SET,
            Self::Branch => PLATFORM_METHOD_BRANCH_METADATA_SET,
        }
    }
}

/// The complete attached platform claim a governed create hands the ReBAC
/// `CreateResource` callback.
///
/// Assembled once, at [`GovernedRepositoryCreate::prepare`], from three
/// separate provenances that must not be confused:
///
/// - **The verified JWT** supplies `verified_issuer` and
///   `authenticated_subject`. Never a header, never the request body.
/// - **Lore's own validated state** supplies `operation_id`, `scope`,
///   `fingerprint_version`, `fingerprint`, `canonical_intent_digest`, and
///   `prepare_token` — everything the receipt namespace is already keyed by.
/// - **The claim-witness header** supplies the seven values Lore records at
///   prepare time but cannot read back at the create call site, because
///   `domain_operation_receipt_get` deliberately returns bounded timing
///   metadata and never the witness.
///
/// Nothing here is an authority input to this server. auth-grpc exact-matches
/// every field against its own claim and authorization rows, so a caller that
/// supplies values it was not issued gets a conclusive denial rather than a
/// widened path.
#[derive(Debug, Clone)]
pub struct GovernedCreateWitness {
    /// Verified token issuer.
    pub verified_issuer: String,
    /// Authenticated subject; the control-plane service principal.
    pub authenticated_subject: String,
    /// 16-byte organisation identity, from the mediated scope.
    pub org_uuid: [u8; 16],
    /// Canonical 49-byte initiating principal namespace, from the mediated
    /// scope.
    pub initiating_principal_namespace:
        [u8; domain_operation_metadata::MEDIATED_PRINCIPAL_NAMESPACE_V1_LEN],
    /// 16-byte operation identity.
    ///
    /// CR-029 freezes `authorization_id` to this same value until a separate
    /// authorization-id column exists, and the verifier requires the equality,
    /// so there is one field here rather than two.
    pub operation_id: [u8; 16],
    /// Canonical mediated tenant scope key.
    pub scope: Vec<u8>,
    /// Fingerprint schema version.
    pub fingerprint_version: u32,
    /// Fingerprint bytes.
    pub fingerprint: Vec<u8>,
    /// The canonical-intent digest this handler computed.
    pub canonical_intent_digest: Vec<u8>,
    /// The single-use prepare token.
    pub prepare_token: [u8; domain_operation_metadata::PREPARE_TOKEN_LEN],
    /// The carried claim and authorization witness.
    pub claim: domain_operation_metadata::ClaimWitness,
}

/// Assemble the attached claim for a mediated governed create.
///
/// Three outcomes, and the middle one is the whole reason this is a function
/// rather than an `Option` map:
///
/// - No mediated scope — a direct governed create. `Ok(None)`, and the ReBAC
///   callback keeps resolving through the catalog.
/// - A mediated scope with no claim witness — refused. The control plane is the
///   only caller that reaches this arm, the callback it is about to trigger
///   exact-matches a claim, and a partially-attached claim is a denial from
///   auth-grpc rather than a fallback. Refusing here makes it a decisive
///   `INVALID_ARGUMENT` **before** the callback and before any receipt is
///   consumed, which is the same ordering rule the rest of the entry gate keeps.
/// - Both present — the assembled witness.
fn build_create_witness(
    admitted: &AdmittedOperation,
    digest: &[u8],
) -> Result<Option<GovernedCreateWitness>, Status> {
    // An internally prepared create has no carriage at all, so it has no
    // mediated scope and no claim — the same answer a direct carried create
    // gives, reached one step earlier.
    let Some(carried) = admitted.carried() else {
        return Ok(None);
    };
    let Some(mediated) = carried.mediated_scope.as_ref() else {
        return Ok(None);
    };
    let Some(claim) = carried.claim_witness.as_ref() else {
        return Err(Status::invalid_argument(
            "mediated governed repository create is missing claim-witness carriage",
        ));
    };
    let fingerprint_version = u32::try_from(carried.fingerprint_version).map_err(|_| {
        // Unreachable through `validated`, which only ever produces version
        // 1. Refusing rather than casting keeps the wire type conversion an
        // enforced property instead of a silent truncation.
        Status::invalid_argument("domain-operation fingerprint version is not representable")
    })?;
    Ok(Some(GovernedCreateWitness {
        verified_issuer: admitted.key.verified_issuer.clone(),
        authenticated_subject: admitted.key.authenticated_subject.clone(),
        org_uuid: mediated.org_uuid,
        initiating_principal_namespace: mediated.initiating_principal_namespace,
        operation_id: *admitted.key.operation_id.as_bytes(),
        scope: admitted.key.tenant_scope_key.clone(),
        fingerprint_version,
        fingerprint: carried.fingerprint.clone(),
        canonical_intent_digest: digest.to_vec(),
        prepare_token: carried.prepare_token,
        claim: claim.clone(),
    }))
}

/// The governed repository-create seam, shared by the v0 and v1 create sites.
///
/// Repository create exists twice on the wire and the two handlers differ only
/// in their request and response shapes: v0 takes a caller-supplied `created`
/// timestamp and a plain `creator` string, v1 assigns the timestamp and treats
/// `creator` as optional. Everything between admission and the coordinator —
/// the projection rows, both classified events, the input, and the outcome
/// mapping — is identical, so it lives here once, for the same reason
/// [`GovernedMetadataCas`] does: two copies of a governed mutation path is how
/// the two come to mean different things.
pub struct GovernedRepositoryCreate {
    domain: Arc<DomainContext>,
    operation: GovernedOperation,
    create_witness: Option<GovernedCreateWitness>,
}

impl GovernedRepositoryCreate {
    /// Prepare the governed call, or `Ok(None)` for the ungoverned path.
    ///
    /// `digest` is the 32 bytes `canonical_intent_digest` returns for
    /// `CanonicalIntent::RepositoryCreate`, computed by the handler from its
    /// own validated wire values. Lore never accepts a body- or
    /// handler-supplied digest.
    ///
    /// # Carriage with enforcement off is refused
    ///
    /// A cell whose coordinator exists but is not enforcing still writes the
    /// generic mutable path unfenced (`reject_domain_key` only refuses a
    /// domain-owned key while enforcement is on). Admitting a governed create
    /// there would put two writers on the same five keys under two different
    /// lock disciplines — the coordinator's row locks and the mutable store's
    /// per-key advisory lock — and `lore_mutable` could keep the loser's value.
    /// The owner's 2026-09-03 ruling closes that at the gate rather than by
    /// adding a lock: a cell that is not enforcing does not admit a governed
    /// create at all. `FAILED_PRECONDITION` rather than a silent downgrade to
    /// the legacy path, because the caller asked for governed semantics and
    /// would otherwise get today's unsynchronised writes while believing its
    /// operation had been receipted.
    /// # No `method` argument
    ///
    /// Both wire versions of repository create are the same operation family to
    /// the platform, so the method is [`PLATFORM_METHOD_REPOSITORY_CREATE`] and
    /// a handler has no say in it. See that constant for what passing it per
    /// handler cost.
    pub async fn prepare(
        domain: Option<&Arc<DomainContext>>,
        admitted: Option<AdmittedOperation>,
        digest: Vec<u8>,
    ) -> Result<Option<Self>, Status> {
        let Some(admitted) = admitted else {
            return Ok(None);
        };
        let Some(domain) = domain else {
            // Unreachable in practice: `admit_at_entry` returns `None` when
            // there is no coordinator. Refusing rather than asserting keeps
            // that an enforced property instead of an assumed one.
            return Err(Status::failed_precondition(
                "Domain coordinator is unavailable",
            ));
        };
        if !domain.enforcement_enabled() {
            warn!(
                method = PLATFORM_METHOD_REPOSITORY_CREATE,
                operation_id = %admitted.key.operation_id,
                "Refusing a governed repository create on a cell that is not enforcing"
            );
            return Err(Status::failed_precondition(
                "Governed repository create requires domain enforcement on this cell",
            ));
        }
        let create_witness = build_create_witness(&admitted, &digest)?;
        let operation = domain
            .complete_governed(admitted, PLATFORM_METHOD_REPOSITORY_CREATE, digest)
            .await?;
        Ok(Some(Self {
            domain: domain.clone(),
            operation,
            create_witness,
        }))
    }

    /// The attached platform claim, or `None` for a direct governed create.
    ///
    /// `None` is not a degraded governed create: it is a governed create by a
    /// principal that is not the control plane, which has no platform claim and
    /// whose ReBAC callback must keep resolving through the catalog exactly as
    /// it does today.
    #[must_use]
    pub fn create_witness(&self) -> Option<&GovernedCreateWitness> {
        self.create_witness.as_ref()
    }

    /// Commit the domain rows, every projection row, and both classified
    /// events in one transaction.
    ///
    /// The immutable-store blob writes and the ReBAC `CreateResource` callback
    /// have already happened by the time this is called, and neither is
    /// reachable from inside the transaction: the coordinator's methods take
    /// plain data and a transaction, with no store handle, auth client, or
    /// network client (CR-029 R-SHOULD-4).
    pub async fn commit(
        &self,
        publication: &RepositoryCreatePublication<'_>,
    ) -> Result<RepositoryCreateOutcome, Status> {
        // CR-032 classifies a repository create as two committed transitions,
        // not one: "Repository live publication" and "Branch create". The
        // reservation and verification work that precedes it — the private
        // claim, the authorization ticket, the active-only catalog row — emits
        // no Lore outbox row at all, so nothing here represents it.
        //
        // `None` when this cell has no configured identity; see
        // `DomainContext::cell_id`. A cell with no `cell_id` still mutates and
        // simply produces no outbox rows.
        let events = match self.domain.cell_id() {
            Some(cell_id) => vec![
                outbox_builders::repository_published(
                    cell_id,
                    publication.repository_id,
                    publication.name,
                    publication.default_branch_id,
                    publication.default_branch_name,
                )
                .map_err(|error| crate::grpc::map_domain_error_to_status(&error))?,
                outbox_builders::branch_created(
                    cell_id,
                    publication.repository_id,
                    publication.default_branch_id,
                    publication.default_branch_name,
                    publication.default_branch_latest_hash,
                )
                .map_err(|error| crate::grpc::map_domain_error_to_status(&error))?,
            ],
            None => Vec::new(),
        };
        let input = RepositoryCreateInput {
            repository_id: publication.repository_id.to_vec(),
            name: publication.name.to_owned(),
            metadata_hash: publication.metadata_hash.to_vec(),
            default_branch_id: publication.default_branch_id.to_vec(),
            default_branch_name: publication.default_branch_name.to_owned(),
            default_branch_metadata_hash: publication.default_branch_metadata_hash.to_vec(),
            default_branch_latest_hash: publication.default_branch_latest_hash.to_vec(),
            // The canonical intent digest *is* the creation fingerprint. It is
            // exactly the 32 bytes the domain row's CHECK requires, and it is
            // already the one frozen definition of "the caller-known create
            // intent" shared with the control plane — so an exact retry matches
            // by construction and a same-ID create with different intent cannot
            // match by accident. Minting a second fingerprint here would be a
            // second definition of the same thing.
            creation_fingerprint: self.operation.binding.canonical_intent_digest.clone(),
            creation_fingerprint_version: CREATION_FINGERPRINT_VERSION_V1,
            projection: publication.projection(),
            events,
        };
        let result = self
            .domain
            .store()
            .repository_create(&self.operation, &input)
            .await
            .map_err(|error| crate::grpc::map_domain_error_to_status(&error))?;
        match result.outcome {
            DomainOutcome::Applied => {}
            DomainOutcome::NotApplied { reason, .. } => {
                return Err(map_repository_create_rejection(reason.as_str()));
            }
        }

        // Read the committed pointer back rather than reporting the one this
        // call published. They are the same on a fresh create; on an exact
        // retry of a create whose metadata has since moved, the domain row is
        // the repository that exists and the published hash is stale.
        //
        // Deliberately best-effort. The transaction has already committed, so a
        // failure here says nothing about the mutation, and turning it into an
        // error would report a durable success as a failure — the one thing
        // CR-029's outcome rules never permit. A read failure or a missing row
        // falls back to the pointer this call published, which is exactly right
        // on the fresh-create path and at worst stale on a retry.
        let metadata_hash = match self
            .domain
            .store()
            .repository_snapshot(publication.repository_id)
            .await
        {
            Ok(Some(snapshot)) => Hash::from(snapshot.metadata_hash.as_slice()),
            Ok(None) => Hash::from(publication.metadata_hash),
            Err(error) => {
                warn!(
                    %error,
                    "Governed repository create committed, but reading its metadata pointer back \
                     failed; reporting the published pointer"
                );
                Hash::from(publication.metadata_hash)
            }
        };
        Ok(RepositoryCreateOutcome {
            repository_generation: result.repository_generation,
            metadata_hash,
        })
    }
}

/// Fingerprint schema version for a create fingerprint that is the v1
/// canonical-intent digest.
const CREATION_FINGERPRINT_VERSION_V1: i32 = 1;

/// The 32-byte attempt-compatible delete proof CR-029 records on a tombstone.
///
/// BLOCKED(WP-116): delete_proof derivation unfrozen in CR-029.
///
/// A typed placeholder rather than a `Vec<u8>` with a comment, because the
/// difference between "the bytes are missing" and "the bytes are wrong" has to
/// survive review. `lore_domain_repositories` carries a `NOT NULL` `CHECK` of
/// exactly 32 bytes on any tombstoned row, CR-029 names the field three times
/// only as an "attempt-compatible immutable delete proof", and it freezes no
/// preimage, no field order, no framing, and no domain separator. Nothing in
/// either repository computes one.
///
/// Minting 32 bytes here would be CR-029's own MISSING-2 failure verbatim: one
/// side invents a value, the other cannot reproduce it, and the divergence is
/// silent. Worse than silent here, because the proof is committed into the
/// principal-scoped receipt and returned by receipt lookup, so a wrong shape
/// becomes permanent evidence.
///
/// Missing artefact: a frozen `delete_proof` derivation in CR-029 on the same
/// terms as its canonical-intent digest contract — one canonical preimage, its
/// exact field order and framing, and independently computed golden vectors on
/// both sides. Adding the variant that carries real bytes is the whole of the
/// remaining work; every other input this seam needs is built below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepositoryDeleteProof {
    /// No derivation exists. [`GovernedRepositoryDelete::commit`] refuses.
    Unfrozen,
}

impl RepositoryDeleteProof {
    /// The 32 proof bytes the tombstone row requires, or `None` while CR-029
    /// freezes no derivation.
    ///
    /// The `match` is exhaustive on purpose and has no `_` arm: adding the
    /// variant that carries real bytes must be a compile error here until it is
    /// handled, rather than silently falling through to a refusal that now
    /// looks like a bug.
    fn bytes(self) -> Option<Vec<u8>> {
        match self {
            Self::Unfrozen => None,
        }
    }
}

/// One branch a repository delete tombstones, as the handler enumerated it.
///
/// The name is what the projection needs: the branch name-to-id row is keyed on
/// the **lowercase** name, unlike the repository name row, which is keyed on the
/// exact name. Both rules are reproduced from their own module rather than from
/// each other; see [`RepositoryCreatePublication::projection`].
#[derive(Debug, Clone)]
pub struct RepositoryDeleteBranch {
    /// 16-byte branch identity.
    pub branch_id: Vec<u8>,
    /// Branch name as authored. Empty where the legacy path found none, in
    /// which case no name row is retired, exactly as `delete_name_to_id` is
    /// skipped there.
    pub name: String,
}

/// Everything one repository delete retires, as the handler observed it.
pub struct RepositoryDeletePublication<'a> {
    /// Repository-format salt, from the target `RepositoryContext`.
    pub salt: &'a [u8],
    /// 16-byte repository identity.
    pub repository_id: &'a [u8],
    /// Exact repository name. Repository names do not fold case.
    pub name: &'a str,
    /// Generation the caller expects to be tombstoning, when it read one.
    pub expected_generation: Option<i64>,
    /// Every live branch, as `branch::list` enumerated it.
    pub branches: &'a [RepositoryDeleteBranch],
    /// BLOCKED(WP-116): delete_proof derivation unfrozen in CR-029.
    pub delete_proof: RepositoryDeleteProof,
}

impl RepositoryDeletePublication<'_> {
    /// The `lore_mutable` rows a delete removes today, rebuilt exactly.
    ///
    /// The mirror image of [`RepositoryCreatePublication::projection`], and
    /// derived from the same two legacy primitives. Every row here is a
    /// **delete**, expressed as `value: None`, because that is what the legacy
    /// path's own calls amount to: `store_name_to_id(name, RepositoryId::default())`
    /// and `metadata_store_hash(Hash::default())` both reach `MutableStore::store`
    /// with a null hash, which that primitive treats as a delete, and both
    /// per-branch pointers go through `branch::mutable_delete` outright.
    ///
    /// The branch **latest** pointer is a delete here even though create writes
    /// it as an explicit zero-valued row. That asymmetry is in the legacy path,
    /// not introduced here: create reaches `compare_and_swap`, which retains a
    /// zero-valued row so a later zero-expected CAS has a predecessor, while
    /// delete reaches `mutable_delete`, which removes the row. Writing a
    /// zero-valued row here instead would leave the governed and legacy deletes
    /// with different table contents for the same operation.
    ///
    /// Unlike create's five fixed rows, this count is 2 + 3N. That is fine for
    /// the projection, which has never been bounded, and is exactly why the
    /// event carriage is **not** allowed to grow the same way: see
    /// `RepositoryDeleteInput::events`.
    fn projection(&self) -> Vec<ProjectionWrite> {
        let repository_hex = hex::encode(self.repository_id);
        let repository_partition = self.repository_id.to_vec();
        // The repository name index is global, not per-repository, matching the
        // partition the legacy writer stores it under.
        let global_partition = RepositoryId::default().data().to_vec();
        let removed = |key: Hash, key_type: KeyType, partition: Vec<u8>| ProjectionWrite {
            partition,
            key_type: key_type as i16,
            key: key.as_ref().to_vec(),
            value: None,
        };
        let mut rows = vec![
            removed(
                hash::hash_function_arg(self.salt, repository::METADATA, &repository_hex),
                KeyType::RepositoryMetadata,
                repository_partition.clone(),
            ),
            removed(
                hash::hash_function_arg(self.salt, repository::ID, self.name),
                KeyType::RepositoryId,
                global_partition,
            ),
        ];
        for branch_entry in self.branches {
            let branch_hex = hex::encode(&branch_entry.branch_id);
            rows.push(removed(
                hash::hash_function_args(self.salt, branch::METADATA, &repository_hex, &branch_hex),
                KeyType::BranchMetadata,
                repository_partition.clone(),
            ));
            rows.push(removed(
                hash::hash_function_args(self.salt, branch::LATEST, &repository_hex, &branch_hex),
                KeyType::BranchLatestPointer,
                repository_partition.clone(),
            ));
            // The legacy path skips `delete_name_to_id` outright on an empty
            // name, so an empty name retires no row here either. Retiring the
            // hash of the empty string would delete a key the create path never
            // wrote.
            if !branch_entry.name.is_empty() {
                rows.push(removed(
                    hash::hash_function_arg(
                        self.salt,
                        branch::ID,
                        &branch_entry.name.to_lowercase(),
                    ),
                    KeyType::BranchId,
                    repository_partition.clone(),
                ));
            }
        }
        rows
    }
}

/// Refuse an identity that is not the 16 bytes every domain id is.
fn checked_id_16(id: &[u8], field: &'static str) -> Result<(), Status> {
    if id.len() != 16 {
        return Err(Status::invalid_argument(format!(
            "{field} must be 16 bytes, got {}",
            id.len()
        )));
    }
    Ok(())
}

/// What a governed repository delete committed.
pub struct RepositoryDeleteOutcome {
    /// Repository generation this transaction committed, or the existing one an
    /// exact retry found.
    pub repository_generation: Option<i64>,
}

/// The governed repository-delete seam, shared by the v0 and v1 delete sites.
///
/// Built for the same reason [`GovernedRepositoryCreate`] is: repository delete
/// exists twice on the wire, the two handlers differ only in their request and
/// response shapes, and everything between admission and the coordinator is
/// identical. Two copies of a governed mutation path is how the two come to
/// mean different things, which is the divergence CR-029 exists to end.
///
/// # Fenced by one missing value, not by missing plumbing
///
/// The projection rows, the classified event, the coordinator input, and the
/// outcome mapping are all here and complete. [`RepositoryDeleteProof`] is the
/// only input with no derivation, and [`Self::commit`] refuses on it before it
/// touches the coordinator.
///
/// **[`Self::prepare`] has no caller today.** Both delete handlers still refuse
/// at entry through `reject_unwired_governed_operation`, so the entry check is
/// the only fence that actually runs and this seam's refusal is the one that
/// will run once the handlers are wired — not a second fence standing behind
/// the first right now. The entry refusal is what keeps a delete that will
/// certainly refuse from first performing the ReBAC `DeleteResource` callback,
/// and it stays there for that reason when the wiring lands.
/// `lore-server/tests/p12_governed_wiring.rs` pins both facts: that the sites
/// stay fenced, and that this seam is otherwise complete.
pub struct GovernedRepositoryDelete {
    domain: Arc<DomainContext>,
    operation: GovernedOperation,
}

impl GovernedRepositoryDelete {
    /// Prepare the governed call, or `Ok(None)` for the ungoverned path.
    ///
    /// Identical admission rules to [`GovernedRepositoryCreate::prepare`],
    /// including the refusal on a cell that is not enforcing: an unenforcing
    /// cell still writes the generic mutable path unfenced, so admitting a
    /// governed delete there would put two writers on the same rows under two
    /// lock disciplines.
    ///
    /// # No `method` argument
    ///
    /// Same reason as the create seam, applied before rather than after the
    /// defect: the method is [`PLATFORM_METHOD_REPOSITORY_DELETE`] and the two
    /// wire versions have no say in it.
    pub async fn prepare(
        domain: Option<&Arc<DomainContext>>,
        admitted: Option<AdmittedOperation>,
        digest: Vec<u8>,
    ) -> Result<Option<Self>, Status> {
        let Some(admitted) = admitted else {
            return Ok(None);
        };
        let Some(domain) = domain else {
            return Err(Status::failed_precondition(
                "Domain coordinator is unavailable",
            ));
        };
        if !domain.enforcement_enabled() {
            warn!(
                method = PLATFORM_METHOD_REPOSITORY_DELETE,
                operation_id = %admitted.key.operation_id,
                "Refusing a governed repository delete on a cell that is not enforcing"
            );
            return Err(Status::failed_precondition(
                "Governed repository delete requires domain enforcement on this cell",
            ));
        }
        let operation = domain
            .complete_governed(admitted, PLATFORM_METHOD_REPOSITORY_DELETE, digest)
            .await?;
        Ok(Some(Self {
            domain: domain.clone(),
            operation,
        }))
    }

    /// Commit the tombstone, every projection row, and the classified event in
    /// one transaction.
    pub async fn commit(
        &self,
        publication: &RepositoryDeletePublication<'_>,
    ) -> Result<RepositoryDeleteOutcome, Status> {
        // BLOCKED(WP-116): delete_proof derivation unfrozen in CR-029.
        //
        // Fails closed, first, before the projection is built and before the
        // coordinator is reached. Everything past this line is the rest of the
        // wiring and runs unchanged the moment the proof has a derivation.
        let Some(delete_proof) = publication.delete_proof.bytes() else {
            warn!(
                operation_id = %self.operation.key.operation_id,
                "Refusing a governed repository delete: CR-029 freezes no delete_proof \
                 derivation, and a minted proof would become permanent receipt evidence"
            );
            return Err(Status::unimplemented(
                "Governed repository delete requires a frozen CR-029 delete_proof derivation",
            ));
        };
        // Every id that becomes a `lore_mutable` key is checked for width here,
        // before the first key is derived. `hash_function_arg` hashes whatever
        // it is handed, so a short or long id produces a plausible key for a row
        // that does not exist and the delete silently retires nothing. The
        // event's own repository id is checked again by the pinned builder;
        // branch ids never reach the event, so this is the only place they can
        // be checked at all.
        checked_id_16(publication.repository_id, "repository_id")?;
        for branch_entry in publication.branches {
            checked_id_16(&branch_entry.branch_id, "branch_id")?;
        }
        let input = self.input(publication, delete_proof)?;
        self.publish(&input).await
    }

    /// The classified event this transition owes, and the coordinator input it
    /// commits with.
    ///
    /// Split out of [`Self::commit`] so the carriage is real, reviewable code
    /// rather than a promise inside a branch nothing reaches. `commit` calls it
    /// today; what nothing reaches today is `commit` itself, because
    /// [`RepositoryDeleteProof`] has no derivable variant.
    fn input(
        &self,
        publication: &RepositoryDeletePublication<'_>,
        delete_proof: Vec<u8>,
    ) -> Result<RepositoryDeleteInput, Status> {
        // CR-032 classifies a repository tombstone as ONE bounded generation
        // event covering everything it hides, not one row per branch and not
        // one row per association. `None` when this cell has no configured
        // identity, exactly as the create seam does.
        let events = match self.domain.cell_id() {
            Some(cell_id) => {
                vec![
                    outbox_builders::repository_tombstoned(cell_id, publication.repository_id)
                        .map_err(|error| crate::grpc::map_domain_error_to_status(&error))?,
                ]
            }
            None => Vec::new(),
        };
        Ok(RepositoryDeleteInput {
            repository_id: publication.repository_id.to_vec(),
            expected_generation: publication.expected_generation,
            delete_proof,
            projection: publication.projection(),
            events,
        })
    }

    /// Hand the built input to the coordinator and map its outcome.
    ///
    /// Separated from [`Self::input`] for the same reason: the coordinator call
    /// and its outcome mapping are the rest of the wiring, and they are written
    /// once here rather than twice in the two handlers.
    async fn publish(
        &self,
        input: &RepositoryDeleteInput,
    ) -> Result<RepositoryDeleteOutcome, Status> {
        let result = self
            .domain
            .store()
            .repository_delete(&self.operation, input)
            .await
            .map_err(|error| crate::grpc::map_domain_error_to_status(&error))?;
        match result.outcome {
            DomainOutcome::Applied => Ok(RepositoryDeleteOutcome {
                repository_generation: result.repository_generation,
            }),
            DomainOutcome::NotApplied { reason, .. } => {
                Err(crate::grpc::map_domain_rejection_to_status(reason.as_str()))
            }
        }
    }
}

/// The 32 proof bytes a branch tombstone requires, or the fence while CR-029
/// derives none.
///
/// The exact shape of [`RepositoryDeleteProof`], and blocked on the exact same
/// missing artefact, so the two are deliberately separate types rather than one
/// shared enum: freezing a repository delete proof must not silently open the
/// branch path, and vice versa. `lore_domain_branches_tombstone_evidence`
/// requires 32 bytes on a tombstoned branch row, so this is not a value the
/// coordinator can be called without.
///
/// Missing artefact: a frozen `delete_proof` derivation in CR-029 on the same
/// terms as its canonical-intent digest contract — one canonical preimage, its
/// exact field order and framing, and independently computed golden vectors on
/// both sides.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BranchDeleteProof {
    /// No derivation exists. [`GovernedBranchDelete::commit`] refuses.
    Unfrozen,
}

impl BranchDeleteProof {
    /// The 32 proof bytes the tombstone row requires, or `None` while CR-029
    /// freezes no derivation.
    ///
    /// Exhaustive with no `_` arm, for the reason
    /// [`RepositoryDeleteProof::bytes`] is: the variant that carries real bytes
    /// must be a compile error here until it is handled.
    fn bytes(self) -> Option<Vec<u8>> {
        match self {
            Self::Unfrozen => None,
        }
    }
}

/// Everything one branch delete retires, as the handler observed it.
pub struct BranchDeletePublication<'a> {
    /// Repository-format salt, from the target `RepositoryContext`.
    ///
    /// Taken from the context rather than hardcoded, so the retired key is
    /// byte-identical to the one `delete_name_to_id` derives on the same
    /// repository.
    pub salt: &'a [u8],
    /// 16-byte owning repository identity.
    pub repository_id: &'a [u8],
    /// 16-byte branch identity.
    pub branch_id: &'a [u8],
    /// Branch name as authored. The live-name key folds case.
    pub name: &'a str,
    /// Generation the caller expects to be tombstoning, when it read one.
    pub expected_generation: Option<i64>,
    /// 32-byte tip the branch is being tombstoned at. The `branch.deleted`
    /// event's aggregate identity, per CR-032's branch row.
    pub final_latest_hash: &'a [u8],
    /// BLOCKED(WP-116): delete_proof derivation unfrozen in CR-029.
    pub delete_proof: BranchDeleteProof,
}

impl BranchDeletePublication<'_> {
    /// The `lore_mutable` row a branch delete removes today, rebuilt exactly.
    ///
    /// **One row, not three.** This is the whole of what the legacy writer
    /// touches: `lore_revision::branch::delete` performs its protection,
    /// default-branch and current-branch checks and then calls
    /// `delete_name_to_id` and nothing else, which reaches `MutableStore::store`
    /// with a null hash — a delete, expressed here as `value: None`.
    ///
    /// The branch **metadata** and **latest** rows deliberately survive, and
    /// that asymmetry with [`RepositoryDeletePublication::projection`] is in the
    /// legacy path rather than introduced here: a repository delete removes them
    /// through `branch::mutable_delete` on its way out, while a branch delete
    /// leaves them. The v1 handler depends on that. It re-reads the branch's
    /// metadata pointer through `branch::metadata_hash` **after** the delete and
    /// builds its `Branch` record from it plus the metadata it loaded before,
    /// and a repeat call on an already-deleted branch reaches both reads with
    /// nothing else having run. Retiring either row here would make the governed
    /// delete answer differently from the legacy one.
    ///
    /// The key folds case because `branch::mutable_name_key` hashes
    /// `name.to_lowercase()`; the repository name key does not fold. Both rules
    /// are reproduced from their own module rather than from each other.
    fn projection(&self) -> Vec<ProjectionWrite> {
        vec![ProjectionWrite {
            partition: self.repository_id.to_vec(),
            key_type: KeyType::BranchId as i16,
            key: hash::hash_function_arg(self.salt, branch::ID, &self.name.to_lowercase())
                .as_ref()
                .to_vec(),
            value: None,
        }]
    }
}

/// What a governed branch delete committed.
pub struct BranchDeleteOutcome {
    /// Branch generation this transaction committed, or the existing one an
    /// exact retry found.
    pub branch_generation: Option<i64>,
}

/// The governed branch-delete seam, shared by the v0 and v1 delete sites.
///
/// Built for the reason every seam in this module is: branch delete exists twice
/// on the wire, the two handlers differ only in their response shapes, and
/// everything between admission and the coordinator is identical. Two copies of
/// a governed mutation path is how the two come to mean different things.
///
/// This is the only seam that can emit `branch.deleted`, the last unemitted row
/// in CR-032's classification table. The ungoverned writers it replaces
/// (WP-119 writer inventory B4 and B5) each perform one unsynchronised
/// `MutableStore::store` with no domain row, no generation, and no event.
///
/// # Fenced by two missing values, not by missing plumbing
///
/// The projection row, the classified event, the coordinator input, the
/// coordinator call and the outcome mapping are all here and complete. Two
/// inputs have no derivation, and they fence at different layers:
///
/// - [`BranchDeleteProof`] has no frozen preimage, and [`Self::commit`] refuses
///   on it before it touches the coordinator. Same artefact as
///   [`RepositoryDeleteProof`].
/// - **There is no `CanonicalIntent::BranchDelete` family.** CR-029's
///   canonical-intent contract freezes six, `lore-server/src/domain_intent.rs`
///   defines those six, and `packages/control-plane/src/repository-operation-intent.ts`
///   defines the same six on the platform side. `AdmittedOperation::into_governed`
///   requires a digest and `receipts::consume` compares the resulting binding
///   against the `PREPARED` row the platform wrote, so a Lore-side seventh family
///   with no platform counterpart would fail every admission it was offered.
///   Freezing it is a CR-029 amendment with cross-language golden vectors, not a
///   Lore-side edit.
///
/// The second is why **both handlers still refuse at entry** through
/// `reject_unwired_governed_operation` rather than calling [`Self::prepare`]:
/// they have no digest to hand it. That entry refusal is also what stops a
/// delete that will certainly refuse from first running its pre-hook and
/// notification side effects. `lore-server/tests/p12_governed_wiring.rs` pins
/// both facts: that the two sites stay guarded, and that this seam is otherwise
/// complete.
pub struct GovernedBranchDelete {
    domain: Arc<DomainContext>,
    operation: GovernedOperation,
}

impl GovernedBranchDelete {
    /// Prepare the governed call, or `Ok(None)` for the ungoverned path.
    ///
    /// Identical admission rules to [`GovernedRepositoryDelete::prepare`],
    /// including the refusal on a cell that is not enforcing: an unenforcing
    /// cell still writes the generic mutable path unfenced, so admitting a
    /// governed delete there would put two writers on the same name row under
    /// two lock disciplines.
    ///
    /// That refusal is also this seam's answer to INV-DX's R-SHOULD-8, which
    /// found `require_permission`'s `enforce` flag to be a third state CR-029's
    /// two-state branch-delete contract does not model. A governed branch delete
    /// is admitted only on an enforcing cell, so the unmodelled state cannot
    /// reach this path at all; it remains open for the ungoverned one.
    pub async fn prepare(
        domain: Option<&Arc<DomainContext>>,
        admitted: Option<AdmittedOperation>,
        method: &'static str,
        digest: Vec<u8>,
    ) -> Result<Option<Self>, Status> {
        let Some(admitted) = admitted else {
            return Ok(None);
        };
        let Some(domain) = domain else {
            return Err(Status::failed_precondition(
                "Domain coordinator is unavailable",
            ));
        };
        if !domain.enforcement_enabled() {
            warn!(
                method,
                operation_id = %admitted.key.operation_id,
                "Refusing a governed branch delete on a cell that is not enforcing"
            );
            return Err(Status::failed_precondition(
                "Governed branch delete requires domain enforcement on this cell",
            ));
        }
        let operation = domain.complete_governed(admitted, method, digest).await?;
        Ok(Some(Self {
            domain: domain.clone(),
            operation,
        }))
    }

    /// Commit the tombstone, its projection row, and its classified event in one
    /// transaction.
    pub async fn commit(
        &self,
        publication: &BranchDeletePublication<'_>,
    ) -> Result<BranchDeleteOutcome, Status> {
        // BLOCKED(WP-116): branch delete_proof derivation unfrozen in CR-029.
        //
        // Fails closed, first, before the projection is built and before the
        // coordinator is reached. Everything past this line is the rest of the
        // wiring and runs unchanged the moment the proof has a derivation.
        //
        // Named "branch delete_proof" rather than reusing the repository seam's
        // marker text so the two are individually greppable and individually
        // pinnable: freezing the repository derivation must not read as having
        // freed this one.
        let Some(delete_proof) = publication.delete_proof.bytes() else {
            warn!(
                operation_id = %self.operation.key.operation_id,
                "Refusing a governed branch delete: CR-029 freezes no branch delete_proof \
                 derivation, and a minted proof would become permanent receipt evidence"
            );
            return Err(Status::unimplemented(
                "Governed branch delete requires a frozen CR-029 delete_proof derivation",
            ));
        };
        // Both ids become part of a `lore_mutable` key or an event identity, so
        // both are width-checked before the first key is derived.
        // `hash_function_arg` hashes whatever it is handed, so a short or long id
        // produces a plausible key for a row that does not exist and the delete
        // silently retires nothing.
        checked_id_16(publication.repository_id, "repository_id")?;
        checked_id_16(publication.branch_id, "branch_id")?;
        // An empty name is not a row this may skip. The legacy path treats a
        // branch with no readable name as absent and returns `BranchNotFound`
        // before it writes anything, so an empty name here means the handler
        // published something the legacy path would have refused. Retiring the
        // hash of the empty string would delete a key nothing ever wrote.
        if publication.name.is_empty() {
            return Err(Status::invalid_argument(
                "branch name must be known to release its live-name row",
            ));
        }
        let input = self.input(publication, delete_proof)?;
        self.publish(&input).await
    }

    /// The classified event this transition owes, and the coordinator input it
    /// commits with.
    ///
    /// Split out of [`Self::commit`] so the carriage is real, reviewable code
    /// rather than a promise inside a branch nothing reaches.
    fn input(
        &self,
        publication: &BranchDeletePublication<'_>,
        delete_proof: Vec<u8>,
    ) -> Result<BranchDeleteInput, Status> {
        // CR-032 classifies a branch tombstone as ONE `branch.deleted` row on
        // the branch aggregate, keyed on the committed branch generation with
        // the branch's final tip as its identity. `None` when this cell has no
        // configured identity, exactly as the create and delete seams do.
        let events = match self.domain.cell_id() {
            Some(cell_id) => {
                vec![
                    outbox_builders::branch_deleted(
                        cell_id,
                        publication.repository_id,
                        publication.branch_id,
                        publication.name,
                        publication.final_latest_hash,
                    )
                    .map_err(|error| crate::grpc::map_domain_error_to_status(&error))?,
                ]
            }
            None => Vec::new(),
        };
        Ok(BranchDeleteInput {
            repository_id: publication.repository_id.to_vec(),
            branch_id: publication.branch_id.to_vec(),
            expected_generation: publication.expected_generation,
            delete_proof,
            projection: publication.projection(),
            events,
        })
    }

    /// Hand the built input to the coordinator and map its outcome.
    async fn publish(&self, input: &BranchDeleteInput) -> Result<BranchDeleteOutcome, Status> {
        let result = self
            .domain
            .store()
            .branch_delete(&self.operation, input)
            .await
            .map_err(|error| crate::grpc::map_domain_error_to_status(&error))?;
        match result.outcome {
            DomainOutcome::Applied => Ok(BranchDeleteOutcome {
                branch_generation: result.branch_generation,
            }),
            DomainOutcome::NotApplied { reason, .. } => {
                Err(map_branch_delete_rejection(reason.as_str()))
            }
        }
    }
}

/// Map a branch-delete-specific rejection, deferring to the shared mapper
/// elsewhere.
///
/// Exactly one reason is answered here rather than by
/// [`crate::grpc::map_domain_rejection_to_status`], on the same terms
/// [`map_repository_create_rejection`] answers exactly one: the shared mapper's
/// vocabulary is what every family agrees on, and `DEFAULT_BRANCH_V1` is a
/// reason only this family can produce. Adding it to the shared mapper would
/// oblige every other family to have an opinion about it.
///
/// `FAILED_PRECONDITION` matches what the ungoverned handlers already return for
/// the same refusal, so the governed and legacy paths answer a default-branch
/// delete identically. It is deliberately not the shared mapper's `NOT_FOUND`:
/// the caller can already see the repository and its default branch, so nothing
/// is disclosed by naming the rule it broke, and reporting `NOT_FOUND` for a
/// branch the caller just read would be an answer to a question nobody asked.
fn map_branch_delete_rejection(reason: &str) -> Status {
    match reason {
        DEFAULT_BRANCH_V1 => Status::failed_precondition(reason.to_owned()),
        other => crate::grpc::map_domain_rejection_to_status(other),
    }
}

/// Map a create-specific rejection, deferring to the shared mapper elsewhere.
///
/// Exactly one reason is answered here rather than by
/// [`crate::grpc::map_domain_rejection_to_status`], because create is the one
/// operation whose contract for it differs. Everything else — `NAME_TAKEN_V1`
/// and `FINGERPRINT_MISMATCH_V1` to `ALREADY_EXISTS`, `ADMISSION_REJECTED_V1`
/// to `FAILED_PRECONDITION`, and an unrecognised reason to `INTERNAL` rather
/// than a guess — already matches CR-029's create outcomes, and duplicating it
/// here is how the two mappers would come to disagree.
///
/// `TOMBSTONED_V1` is `ALREADY_EXISTS`, not the shared `NOT_FOUND`. CR-029's
/// repository-create outcome list is explicit — "same ID after tombstone:
/// `ALREADY_EXISTS`; IDs are permanent" — and the non-disclosure rule the
/// shared mapper implements is about an operation on a repository the caller
/// may not know exists. Here the caller chose the identity itself, so the
/// answer discloses only that its own 128-bit identity is already spent, and
/// reporting `NOT_FOUND` for a create would be an answer to a question nobody
/// asked.
///
fn map_repository_create_rejection(reason: &str) -> Status {
    use lore_postgres::domain::coordinator;

    match reason {
        coordinator::TOMBSTONED_V1 => Status::already_exists(reason.to_owned()),
        other => crate::grpc::map_domain_rejection_to_status(other),
    }
}

/// Refuse an admitted operation that has no coordinator call site yet.
///
/// WP-116 Phase 4 lands the entry gate before the coordinator call sites, which
/// are blocked on the private prepare/receipt rail
/// (`CONTROL-PLANE-DOMAIN-RECEIPT-READY`). Until those land, a caller that
/// carried operation identity is refused **explicitly**. Silently continuing on
/// the legacy path would be strictly worse than refusing: the caller asked for
/// governed semantics and would instead get today's unsynchronised writes while
/// believing its operation had been admitted and receipted.
pub fn reject_unwired_governed_operation(admitted: &AdmittedOperation, method: &str) -> Status {
    warn!(
        method,
        operation_id = %admitted.key.operation_id,
        "Governed domain operation admitted but no coordinator call site is wired yet"
    );
    Status::unimplemented(
        "Governed domain repository operations are not yet available on this cell",
    )
}

#[cfg(test)]
mod p12_tests;

/// Build the domain coordinator for this cell, when one applies.
///
/// Returns `Ok(None)` for every non-Postgres cell. For a Postgres cell it
/// connects, proves co-location with each other configured Postgres store, and
/// gates enforcement on the recorded backfill/cutover state.
///
/// # Why a failure here aborts startup
///
/// Failing open — logging and continuing with no coordinator — would be worse
/// than it looks: enforcement state is read *from* this store, so a cell that
/// could not connect cannot tell whether enforcement was requested, and would
/// silently serve ungoverned traffic on a cell where an operator had turned
/// enforcement on. Aborting adds no new availability failure mode either: the
/// coordinator and three CR-007 store pools connect to the same database at
/// boot and already fail hard, while enabled provider composition separately
/// attests the fifth, dispatch pool. A cell that cannot reach this database
/// cannot serve anyway.
pub struct ConfiguredDomainContext {
    /// Coordinator exposed to governed handlers and the private receipt rail.
    pub context: Option<Arc<DomainContext>>,
    /// Handle that must be installed into the concrete Postgres mutable store
    /// before the store is published behind its trait object.
    pub mutable_enforcement: Option<DomainEnforcement>,
    /// Fragment lifecycle handle on the same CR-029 pool and database.
    ///
    /// Server composition passes this only to the Postgres immutable store;
    /// other immutable-store modes never receive or construct a provider route.
    pub fragment_coordinator: Option<PostgresFragmentCoordinator>,
    /// Physical identity positively shared by the domain, immutable, mutable,
    /// and lock pools: PostgreSQL system identifier plus database OID.
    ///
    /// The diagnostic database name travels with the value but is not an
    /// identity component for dispatch attestation.
    pub database_identity: Option<DatabaseIdentity>,
}

pub async fn configure_domain_context(settings: &Settings) -> Result<ConfiguredDomainContext> {
    if settings.mutable_store.mode != POSTGRES_MODE {
        return Ok(ConfiguredDomainContext {
            context: None,
            mutable_enforcement: None,
            fragment_coordinator: None,
            database_identity: None,
        });
    }

    let Some(domain_config) =
        resolve_plugin_config_with_fallback(&settings.plugins, POSTGRES_MODE, "mutable_store")
    else {
        return Err(anyhow!(
            "Postgres mutable store is configured but no [plugins.postgres] section was found"
        ));
    };

    info!("Creating CR-029 domain coordinator via the Postgres plugin configuration");
    let store = connect_domain_store(&domain_config)
        .await
        .map_err(|e| anyhow!("Failed to create the Postgres domain coordinator: {e}"))?;

    // R-SHOULD-1: positively prove same-database identity for every other
    // Postgres-mode store this cell runs, not only the mutable one.
    for (label, store_type, mode) in [
        (
            "mutable store",
            "mutable_store",
            settings.mutable_store.mode.as_str(),
        ),
        (
            "immutable store",
            "immutable_store",
            settings.immutable_store.mode.as_str(),
        ),
        (
            "lock store",
            "lock_store",
            settings
                .lock_store
                .as_ref()
                .map(|s| s.mode.as_str())
                .unwrap_or_default(),
        ),
    ] {
        // A store on some other backend is genuinely out of scope for a
        // same-database proof, so skipping it is correct.
        if mode != POSTGRES_MODE {
            continue;
        }
        // A store that IS in postgres mode but resolves no configuration is
        // not. Skipping it here would silently drop one leg of the very check
        // whose entire purpose is to be positive, leaving the cell believing it
        // proved co-location it never tested.
        let other =
            resolve_plugin_config_with_fallback(&settings.plugins, POSTGRES_MODE, store_type)
                .ok_or_else(|| {
                    anyhow!(
                        "The {label} is in postgres mode but no [plugins.postgres] configuration \
                 resolves for it, so its co-location with the domain coordinator cannot be \
                 proven"
                    )
                })?;
        assert_domain_store_colocated(&store, label, &other)
            .await
            .map_err(|e| anyhow!("{e}"))?;
    }

    let state = store
        .schema_state()
        .await
        .map_err(|e| anyhow!("Failed to read the domain schema state: {e}"))?;
    let enforcement = resolve_enforcement(&state)?;
    let lock_coordinator = store.lock_coordinator();
    let lock_readiness = lock_coordinator
        .readiness()
        .await
        .map_err(|e| anyhow!("Failed to read SCHEMA-117 lock-fencing readiness: {e}"))?;
    let lock_fencing = resolve_lock_fencing(&lock_readiness, settings)?;
    let mutable_enforcement = DomainEnforcement::disabled();
    if enforcement {
        mutable_enforcement.enable();
    }

    let database_identity = store.identity().clone();
    let cell_id = resolve_cell_id(settings)?;
    // The fragment coordinator stamps the same cell identity on its bounded
    // CR-032 summaries that the governed repository seam stamps on its rows, so
    // it is resolved once, here, and handed to both.
    let fragment_coordinator = store
        .fragment_coordinator()
        .with_outbox_cell_id(cell_id.clone());
    // WP-120: the same private auth-grpc endpoint the receipt rail is mounted
    // on. Resolved from one place so the internal prepare and the private rail
    // can never end up pointed at different verifiers.
    //
    // The rail additionally requires JWT authentication to be on
    // (`grpc::server::domain_operation_service_available`). That condition is
    // not re-tested here because it is already load-bearing at the point of
    // use: an internal admission requires an `AuthorizationToken`, and one only
    // exists on a cell whose JWT verifier ran.
    let operation_verifier: Option<Arc<dyn RepositoryOperationAuthorizationVerifier>> = settings
        .environment
        .as_ref()
        .and_then(|environment| environment.endpoint.as_ref())
        .and_then(|endpoint| endpoint.auth_url.clone())
        .map(|auth_url| {
            Arc::new(
                crate::authnz::rebac::GrpcRepositoryOperationAuthorizationVerifier::new(auth_url),
            ) as Arc<dyn RepositoryOperationAuthorizationVerifier>
        });
    let context = if lock_fencing {
        DomainContext::new_with_lock_coordinator(
            Arc::new(store),
            enforcement,
            Arc::new(lock_coordinator),
        )
    } else {
        DomainContext::new(Arc::new(store), enforcement)
    }
    .with_cell_id(cell_id)
    .with_operation_verifier(operation_verifier);
    Ok(ConfiguredDomainContext {
        context: Some(Arc::new(context)),
        mutable_enforcement: Some(mutable_enforcement),
        fragment_coordinator: Some(fragment_coordinator),
        database_identity: Some(database_identity),
    })
}

/// Resolve the cell identity CR-032 producers stamp on every outbox event.
///
/// The value lives in `[plugins.remote] cell_id`, which is where the
/// notification plane already reads it from, so a cell cannot end up publishing
/// events under one identity and relaying them under another.
///
/// Three outcomes, and the asymmetry is deliberate:
///
/// * **No plugin table at all** is `Ok(None)`. A cell with no notification
///   plugin configured is the pre-CR-032 cell; it keeps mutating and simply
///   produces no outbox rows. Refusing to boot here would take down every
///   existing Postgres-mode cell for a feature none of them has turned on.
/// * **A plugin table with no `cell_id`** is also `Ok(None)`, and deliberately
///   not a boot failure here. The table is the notification plugin's, not the
///   outbox's; when `[notification] mode = "remote"` is actually set, that
///   plugin's own factory validation refuses the missing key at boot, and
///   duplicating the refusal in this function would make an unrelated,
///   unenabled stanza fatal to a cell that never asked for either feature.
/// * **Present but malformed** is a boot failure. `cell_id` is field one of the
///   frozen `idempotency_key` preimage and becomes a broker subject token, so a
///   typo is not a value to fall back from: accepting it would key every event
///   this cell emits under a name no consumer subscribes to, and treating it as
///   absent would silently disable the outbox on a cell an operator believed
///   was configured.
///
/// Known gap, deliberately not closed here: a well-formed `cell_id` in a stale
/// `[plugins.remote]` table on a cell whose `[notification] mode` is not
/// `remote` yields a producing outbox with no relay configured. That is the
/// correct failure shape — rows accumulate durably and the relay's own startup
/// gate is what reports it — but it is worth knowing that this function does
/// not couple the two.
// PIN(WP-116): cell identity source is [plugins.remote_notification].cell_id
// until a top-level cell setting exists. The table is named `remote` on the
// wire (`PLUGIN_NAME`); it is the notification plugin's, and the outbox
// borrows it so producer and relay cannot disagree about which cell this is.
fn resolve_cell_id(settings: &Settings) -> Result<Option<String>> {
    let Some(table) = settings
        .plugins
        .get(crate::plugins::remote_notification::PLUGIN_NAME)
    else {
        return Ok(None);
    };
    let Some(value) = table.get("cell_id") else {
        return Ok(None);
    };
    let cell_id = value.as_str().ok_or_else(|| {
        anyhow!(
            "[plugins.{}] cell_id must be a string",
            crate::plugins::remote_notification::PLUGIN_NAME
        )
    })?;
    // Validated against the outbox's own grammar, not the notification
    // plugin's identical copy: this value is going into `lore_outbox_events`,
    // and the append API is the thing that will reject it. Both come from the
    // same contract clause, so they agree today; keying the check to the
    // consumer means they cannot silently stop agreeing.
    if !lore_postgres::domain::outbox::schema::is_valid_cell_id(cell_id) {
        return Err(anyhow!(
            "[plugins.{}] cell_id is not a valid cell identity: it must match the contract grammar and fit {} bytes",
            crate::plugins::remote_notification::PLUGIN_NAME,
            lore_postgres::domain::outbox::schema::MAX_CELL_ID_BYTES,
        ));
    }
    Ok(Some(cell_id.to_owned()))
}

fn resolve_lock_fencing(readiness: &LockFencingReadiness, settings: &Settings) -> Result<bool> {
    if !readiness.fencing_enabled {
        info!(
            provisioned = readiness.provisioned,
            schema_version = readiness.schema_version,
            backfill_state = readiness.backfill_state,
            "Fenced lock routing is off; the public lock service remains on its legacy store"
        );
        return Ok(false);
    }

    let auth = settings.server.auth.as_ref().ok_or_else(|| {
        anyhow!("Lock fencing is enabled but JWT authentication is not configured")
    })?;
    if auth.jwk.is_none() {
        return Err(anyhow!(
            "Lock fencing is enabled but no JWK verifier is configured"
        ));
    }
    if auth.jwt_issuer.as_deref().is_none_or(str::is_empty) {
        return Err(anyhow!(
            "Lock fencing is enabled but no non-empty JWT issuer policy is configured"
        ));
    }
    if !auth.enforce_write_permission {
        return Err(anyhow!(
            "Lock fencing is enabled but enforce_write_permission is false"
        ));
    }
    if settings
        .lock_store
        .as_ref()
        .is_none_or(|lock_store| lock_store.mode != POSTGRES_MODE)
    {
        return Err(anyhow!(
            "Lock fencing is enabled but the configured lock store is not Postgres"
        ));
    }
    if readiness.schema_version != lore_postgres::domain::locks::schema::LOCK_SCHEMA_VERSION
        || readiness.backfill_state != lore_postgres::domain::locks::schema::BACKFILL_COMPLETE
        || !readiness.same_database
        || !readiness.sequence_headroom
        || readiness.quarantined_rows != 0
        || readiness.unfenced_rows != 0
    {
        return Err(anyhow!(
            "Lock fencing is enabled without complete SCHEMA-117 evidence \
             (schema_version={}, backfill_state={}, same_database={}, sequence_headroom={}, \
              quarantined_rows={}, unfenced_rows={})",
            readiness.schema_version,
            readiness.backfill_state,
            readiness.same_database,
            readiness.sequence_headroom,
            readiness.quarantined_rows,
            readiness.unfenced_rows
        ));
    }
    // WP-120 makes public clients token-capable, which was the original reason
    // this refusal existed. It stays because the *other* half never landed:
    // nothing on the wire renews a lease, so a finite expiry would silently drop
    // a lock a working client still believes it holds, and the row it leaves
    // behind is a takeover target for anyone else. Leases stay off until a
    // renewal cadence is specified.
    if readiness.lease_enabled {
        return Err(anyhow!(
            "Finite lock leases are enabled, but no public client renews a lease, so a lock \
             would expire under a caller that still holds it"
        ));
    }
    info!("Fenced lock coordinator is active");
    Ok(true)
}

/// Decide whether this cell may enforce, refusing readiness rather than
/// enforcing over an incomplete backfill.
///
/// CR-029's rollout rule is explicit: a Postgres-mode server with enforcement
/// enabled must refuse readiness on an incomplete backfill. Downgrading to
/// "enforcement off" instead would silently return the cell to the
/// unsynchronised writes the operator just turned off.
fn resolve_enforcement(state: &DomainSchemaState) -> Result<bool> {
    if !state.enforcement_enabled {
        info!(
            backfill_state = %state.backfill_state,
            "Domain enforcement is off; repository and branch mutations use the legacy path"
        );
        return Ok(false);
    }
    if !state.ready_for_enforcement() {
        return Err(anyhow!(
            "Domain enforcement is enabled but this cell is not ready for it \
             (backfill_state={}, residue_classified={}, cutover_at={:?}); \
             refusing readiness rather than enforcing over an incomplete backfill",
            state.backfill_state,
            state.residue_classified,
            state.cutover_at
        ));
    }
    info!("Domain enforcement is on; repository and branch mutations are governed");
    Ok(true)
}

/// Test-only fixtures shared across this crate's domain-admission tests: a
/// coordinator whose methods are never reached, and a helper to wrap it in a
/// [`DomainContext`]. `pub(crate)` and `#[cfg(test)]`-gated so a gated
/// handler's own `mod tests` elsewhere in the crate can build a real
/// `Some(&Arc<DomainContext>)` without duplicating the trait impl or leaking
/// test-only code into a non-test build.
#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Arc;

    use async_trait::async_trait;
    use lore_postgres::domain::DomainError;
    use lore_postgres::domain::PostgresDomainStore;
    use lore_postgres::domain::backfill::BranchFacts;
    use lore_postgres::domain::backfill::DomainBackfill;
    use lore_postgres::domain::backfill::DomainBackfillSource;
    use lore_postgres::domain::backfill::OrphanKey;
    use lore_postgres::domain::backfill::RepositoryFacts;
    use lore_postgres::domain::coordinator::BranchDeleteInput;
    use lore_postgres::domain::coordinator::BranchPushCommitInput;
    use lore_postgres::domain::coordinator::BranchSnapshot;
    use lore_postgres::domain::coordinator::MetadataCasInput;
    use lore_postgres::domain::coordinator::MutationResult;
    use lore_postgres::domain::coordinator::PendingEvent;
    use lore_postgres::domain::coordinator::RepositoryCreateInput;
    use lore_postgres::domain::coordinator::RepositoryDeleteInput;
    use lore_postgres::domain::coordinator::RepositorySnapshot;
    use lore_postgres::domain::maintenance::ProofNamespaceMaterializeInput;
    use lore_postgres::domain::maintenance::ProofNamespaceMaterializeReceipt;
    use lore_postgres::domain::maintenance::ProofNamespaceRetireAck;
    use lore_postgres::domain::maintenance::ProofNamespaceRetireInput;
    use lore_postgres::domain::maintenance::TerminalStatusAttachInput;
    use lore_postgres::domain::maintenance::TerminalStatusAttachmentAck;
    use lore_postgres::domain::maintenance::VerifiedStaleFinalizeInput;
    use lore_postgres::domain::maintenance::VerifiedStaleFinalizeResult;
    use lore_postgres::domain::receipts::AuthorizationWitness;
    use lore_postgres::domain::receipts::OperationBinding;
    use lore_postgres::domain::receipts::PrepareResult;
    use lore_postgres::domain::receipts::ReceiptKey;
    use lore_postgres::domain::receipts::ReceiptLookup;
    use lore_postgres::pool::TlsConfig;
    use lore_postgres::store::mutable_store::PostgresMutableStore;

    use super::DomainContext;
    use super::DomainTransactionStore;
    use super::GovernedOperation;
    use crate::settings::Settings;

    struct EmptyBackfillSource;

    #[async_trait]
    impl DomainBackfillSource for EmptyBackfillSource {
        async fn list_repositories(&self) -> Result<Vec<RepositoryFacts>, DomainError> {
            Ok(Vec::new())
        }

        async fn list_branches(
            &self,
            _repository_id: &[u8],
        ) -> Result<Vec<BranchFacts>, DomainError> {
            Ok(Vec::new())
        }

        async fn snapshot_token(&self, _repository_id: &[u8]) -> Result<Vec<u8>, DomainError> {
            Ok(Vec::new())
        }

        async fn orphan_projection_keys(&self) -> Result<Vec<OrphanKey>, DomainError> {
            Ok(Vec::new())
        }
    }

    /// Construct an enforcing context through the real Postgres readiness and
    /// settings path. Callers must remain `#[ignore]` live-Postgres tests.
    pub(crate) async fn configured_enforcing_context() -> Option<Arc<DomainContext>> {
        let Ok(url) = std::env::var("LORE_TEST_PG_URL") else {
            eprintln!("LORE_TEST_PG_URL unset; live construction-path test cannot run");
            return None;
        };
        let store = PostgresDomainStore::connect(&url, 2, &TlsConfig::default())
            .await
            .expect("bootstrap disposable domain schema");
        let lock_coordinator = store.lock_coordinator();
        lock_coordinator
            .bootstrap()
            .await
            .expect("install SCHEMA-117 in the disposable fixture");
        lock_coordinator
            .backfill(&Default::default())
            .await
            .expect("complete the empty disposable lock backfill");
        let _mutable_store = PostgresMutableStore::connect(&url, 2, &TlsConfig::default())
            .await
            .expect("bootstrap disposable mutable projection schema");
        let state = store
            .schema_state()
            .await
            .expect("read domain schema state");
        if !state.ready_for_enforcement() {
            let source = EmptyBackfillSource;
            let backfill = DomainBackfill::for_store(&store, &source);
            backfill
                .run()
                .await
                .expect("run empty disposable-cell domain backfill");
            let report = backfill
                .verify()
                .await
                .expect("verify empty disposable-cell domain backfill");
            backfill
                .complete(&report)
                .await
                .expect("complete empty disposable-cell domain cutover");
        }
        if !store
            .schema_state()
            .await
            .expect("re-read domain schema state")
            .enforcement_enabled
        {
            store
                .enable_enforcement()
                .await
                .expect("enable through the production schema-state API");
        }

        let mut settings: Settings = toml::from_str(include_str!("../config/default.toml"))
            .expect("built-in settings fixture must deserialize");
        settings.mutable_store.mode = "postgres".to_string();
        settings.plugins.insert(
            "postgres".to_string(),
            toml::from_str(&format!("url = {url:?}\npool_max = 2\ndomain_pool_max = 2"))
                .expect("Postgres plugin fixture config"),
        );
        super::configure_domain_context(&settings)
            .await
            .expect("real domain-context construction path")
            .context
    }

    /// A coordinator whose methods are never reached: `DomainContext::admit`
    /// only runs the entry gate, never a coordinator call. Every method is
    /// implemented explicitly (never a trait default — `DomainTransactionStore`
    /// has none) so a signature drift fails to compile rather than silently
    /// inheriting a body.
    pub(crate) struct UnreachableDomainStore;

    #[async_trait]
    impl DomainTransactionStore for UnreachableDomainStore {
        // WP-120's public attempt lookup. Stated rather than defaulted: a store that answers
        // "no receipt" when it simply cannot look one up would report a real attempt as absent,
        // and absence is what tells a client to stop waiting.
        async fn domain_operation_attempt_receipt_get(
            &self,
            _verified_issuer: &str,
            _authenticated_subject: &str,
            _client_attempt_id: &uuid::Uuid,
        ) -> Result<lore_postgres::domain::receipts::AttemptReceipt, DomainError> {
            unreachable!("UnreachableDomainStore does not serve attempt receipt lookups")
        }

        async fn domain_operation_clock_get(&self) -> Result<std::time::SystemTime, DomainError> {
            unreachable!("DomainContext::admit tests never call the coordinator")
        }

        async fn domain_operation_prepare(
            &self,
            _key: &ReceiptKey,
            _binding: &OperationBinding,
            _witness: Option<&AuthorizationWitness>,
            _client_attempt_id: Option<uuid::Uuid>,
        ) -> Result<PrepareResult, DomainError> {
            unreachable!("DomainContext::admit tests never call the coordinator")
        }

        async fn domain_operation_receipt_get(
            &self,
            _key: &ReceiptKey,
            _binding: &OperationBinding,
        ) -> Result<ReceiptLookup, DomainError> {
            unreachable!("DomainContext::admit tests never call the coordinator")
        }

        async fn domain_operation_verified_stale_finalize(
            &self,
            _input: &VerifiedStaleFinalizeInput,
        ) -> Result<VerifiedStaleFinalizeResult, DomainError> {
            unreachable!("DomainContext::admit tests never call the coordinator")
        }

        async fn domain_operation_terminal_status_attach(
            &self,
            _input: &TerminalStatusAttachInput,
        ) -> Result<TerminalStatusAttachmentAck, DomainError> {
            unreachable!("DomainContext::admit tests never call the coordinator")
        }

        async fn domain_operation_proof_namespace_materialize(
            &self,
            _input: &ProofNamespaceMaterializeInput,
        ) -> Result<ProofNamespaceMaterializeReceipt, DomainError> {
            unreachable!("DomainContext::admit tests never call the coordinator")
        }

        async fn domain_operation_proof_namespace_retire(
            &self,
            _input: &ProofNamespaceRetireInput,
        ) -> Result<ProofNamespaceRetireAck, DomainError> {
            unreachable!("DomainContext::admit tests never call the coordinator")
        }

        async fn repository_snapshot(
            &self,
            _repository_id: &[u8],
        ) -> Result<Option<RepositorySnapshot>, DomainError> {
            unreachable!("DomainContext::admit tests never call the coordinator")
        }

        async fn branch_snapshot(
            &self,
            _repository_id: &[u8],
            _branch_id: &[u8],
        ) -> Result<Option<BranchSnapshot>, DomainError> {
            unreachable!("DomainContext::admit tests never call the coordinator")
        }

        async fn repository_create(
            &self,
            _operation: &GovernedOperation,
            _input: &RepositoryCreateInput,
        ) -> Result<MutationResult, DomainError> {
            unreachable!("DomainContext::admit tests never call the coordinator")
        }

        async fn repository_delete(
            &self,
            _operation: &GovernedOperation,
            _input: &RepositoryDeleteInput,
        ) -> Result<MutationResult, DomainError> {
            unreachable!("DomainContext::admit tests never call the coordinator")
        }

        async fn branch_delete(
            &self,
            _operation: &GovernedOperation,
            _input: &BranchDeleteInput,
        ) -> Result<MutationResult, DomainError> {
            unreachable!("DomainContext::admit tests never call the coordinator")
        }

        async fn metadata_compare_and_swap(
            &self,
            _operation: &GovernedOperation,
            _input: &MetadataCasInput,
        ) -> Result<MutationResult, DomainError> {
            unreachable!("DomainContext::admit tests never call the coordinator")
        }

        async fn branch_push_commit(
            &self,
            _operation: &GovernedOperation,
            _input: &BranchPushCommitInput,
        ) -> Result<MutationResult, DomainError> {
            unreachable!("DomainContext::admit tests never call the coordinator")
        }

        async fn begin_obliterate(
            &self,
            _operation: &GovernedOperation,
            _repository_id: &[u8],
            _event: Option<&PendingEvent>,
        ) -> Result<MutationResult, DomainError> {
            unreachable!("DomainContext::admit tests never call the coordinator")
        }
    }

    /// Wrap [`UnreachableDomainStore`] in a [`DomainContext`] with the given
    /// enforcement setting. Safe for any admission test: the entry gate
    /// decides before ever reaching the coordinator.
    pub(crate) fn context(enforcement: bool) -> DomainContext {
        DomainContext::new(Arc::new(UnreachableDomainStore), enforcement)
    }

    /// [`UnreachableDomainStore`] with one method made reachable:
    /// `domain_operation_prepare` returns a fixed `Prepared`.
    ///
    /// The internal-prepare tests that reach the coordinator are the ones whose
    /// verifier ACCEPTS. Every refusal case fails at the echo check, before the
    /// prepare, which is the ordering the design depends on — so those keep
    /// using [`UnreachableDomainStore`] and its panic is the proof that no
    /// receipt row could have been written. This double exists only for the
    /// happy path, and everything except prepare still panics, so a test that
    /// wanders past it fails loudly rather than silently exercising a stub.
    pub(crate) struct PreparingDomainStore;

    /// The token this double hands back, so a test can assert the governed
    /// operation carries the coordinator's token rather than anything the
    /// caller supplied.
    pub(crate) const PREPARED_TEST_TOKEN: [u8; 32] = [0x5Au8; 32];

    #[async_trait]
    impl DomainTransactionStore for PreparingDomainStore {
        // WP-120's public attempt lookup. Stated rather than defaulted: a store that answers
        // "no receipt" when it simply cannot look one up would report a real attempt as absent,
        // and absence is what tells a client to stop waiting.
        async fn domain_operation_attempt_receipt_get(
            &self,
            _verified_issuer: &str,
            _authenticated_subject: &str,
            _client_attempt_id: &uuid::Uuid,
        ) -> Result<lore_postgres::domain::receipts::AttemptReceipt, DomainError> {
            unreachable!("PreparingDomainStore does not serve attempt receipt lookups")
        }

        async fn domain_operation_prepare(
            &self,
            _key: &ReceiptKey,
            _binding: &OperationBinding,
            witness: Option<&AuthorizationWitness>,
            _client_attempt_id: Option<uuid::Uuid>,
        ) -> Result<PrepareResult, DomainError> {
            // The direct rail must never write a mediated dispatch fence, and a
            // present witness is what makes the real rail write one. Asserted
            // here rather than documented, so a change that starts passing one
            // fails this test instead of quietly filing a direct operation as a
            // mediated one.
            assert!(
                witness.is_none(),
                "a direct internal prepare must pass no authorization witness"
            );
            Ok(PrepareResult::Prepared {
                token: PREPARED_TEST_TOKEN,
                hard_expires_at: std::time::SystemTime::UNIX_EPOCH
                    + std::time::Duration::from_secs(1),
            })
        }

        async fn domain_operation_clock_get(&self) -> Result<std::time::SystemTime, DomainError> {
            unreachable!("PreparingDomainStore only serves domain_operation_prepare")
        }

        async fn domain_operation_receipt_get(
            &self,
            _key: &ReceiptKey,
            _binding: &OperationBinding,
        ) -> Result<ReceiptLookup, DomainError> {
            unreachable!("PreparingDomainStore only serves domain_operation_prepare")
        }

        async fn domain_operation_verified_stale_finalize(
            &self,
            _input: &lore_postgres::domain::maintenance::VerifiedStaleFinalizeInput,
        ) -> Result<lore_postgres::domain::maintenance::VerifiedStaleFinalizeResult, DomainError>
        {
            unreachable!("PreparingDomainStore only serves domain_operation_prepare")
        }

        async fn domain_operation_terminal_status_attach(
            &self,
            _input: &lore_postgres::domain::maintenance::TerminalStatusAttachInput,
        ) -> Result<lore_postgres::domain::maintenance::TerminalStatusAttachmentAck, DomainError>
        {
            unreachable!("PreparingDomainStore only serves domain_operation_prepare")
        }

        async fn domain_operation_proof_namespace_materialize(
            &self,
            _input: &lore_postgres::domain::maintenance::ProofNamespaceMaterializeInput,
        ) -> Result<lore_postgres::domain::maintenance::ProofNamespaceMaterializeReceipt, DomainError>
        {
            unreachable!("PreparingDomainStore only serves domain_operation_prepare")
        }

        async fn domain_operation_proof_namespace_retire(
            &self,
            _input: &lore_postgres::domain::maintenance::ProofNamespaceRetireInput,
        ) -> Result<lore_postgres::domain::maintenance::ProofNamespaceRetireAck, DomainError>
        {
            unreachable!("PreparingDomainStore only serves domain_operation_prepare")
        }

        async fn repository_snapshot(
            &self,
            _repository_id: &[u8],
        ) -> Result<Option<lore_postgres::domain::coordinator::RepositorySnapshot>, DomainError>
        {
            unreachable!("PreparingDomainStore only serves domain_operation_prepare")
        }

        async fn branch_snapshot(
            &self,
            _repository_id: &[u8],
            _branch_id: &[u8],
        ) -> Result<Option<BranchSnapshot>, DomainError> {
            unreachable!("PreparingDomainStore only serves domain_operation_prepare")
        }

        async fn repository_create(
            &self,
            _operation: &GovernedOperation,
            _input: &RepositoryCreateInput,
        ) -> Result<MutationResult, DomainError> {
            unreachable!("PreparingDomainStore only serves domain_operation_prepare")
        }

        async fn repository_delete(
            &self,
            _operation: &GovernedOperation,
            _input: &RepositoryDeleteInput,
        ) -> Result<MutationResult, DomainError> {
            unreachable!("PreparingDomainStore only serves domain_operation_prepare")
        }

        async fn branch_delete(
            &self,
            _operation: &GovernedOperation,
            _input: &BranchDeleteInput,
        ) -> Result<MutationResult, DomainError> {
            unreachable!("PreparingDomainStore only serves domain_operation_prepare")
        }

        async fn metadata_compare_and_swap(
            &self,
            _operation: &GovernedOperation,
            _input: &MetadataCasInput,
        ) -> Result<MutationResult, DomainError> {
            unreachable!("PreparingDomainStore only serves domain_operation_prepare")
        }

        async fn branch_push_commit(
            &self,
            _operation: &GovernedOperation,
            _input: &lore_postgres::domain::coordinator::BranchPushCommitInput,
        ) -> Result<MutationResult, DomainError> {
            unreachable!("PreparingDomainStore only serves domain_operation_prepare")
        }

        async fn begin_obliterate(
            &self,
            _operation: &GovernedOperation,
            _repository_id: &[u8],
            _event: Option<&PendingEvent>,
        ) -> Result<MutationResult, DomainError> {
            unreachable!("PreparingDomainStore only serves domain_operation_prepare")
        }
    }

    /// A context whose coordinator will serve one `domain_operation_prepare`.
    pub(crate) fn preparing_context() -> DomainContext {
        DomainContext::new(Arc::new(PreparingDomainStore), true)
    }

    /// A scriptable coordinator for `branch_push.rs`'s `GovernedPushCommit::publish`
    /// tests (INV-EE P1-5): records every `branch_push_commit` call's input and
    /// returns a caller-supplied scripted [`MutationResult`] for it. Every other
    /// method is `unreachable!()`, mirroring [`UnreachableDomainStore`] so a
    /// signature drift fails to compile rather than silently inheriting a body.
    pub(crate) struct ScriptedDomainStore {
        result: MutationResult,
        calls: std::sync::Mutex<Vec<BranchPushCommitInput>>,
    }

    impl ScriptedDomainStore {
        /// Every scripted `branch_push_commit` call returns a clone of `result`.
        pub(crate) fn new(result: MutationResult) -> Self {
            Self {
                result,
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }

        /// Every `branch_push_commit` input recorded so far, in call order.
        pub(crate) fn recorded_branch_push_commit_calls(&self) -> Vec<BranchPushCommitInput> {
            self.calls
                .lock()
                .expect("scripted store mutex poisoned")
                .clone()
        }
    }

    #[async_trait]
    impl DomainTransactionStore for ScriptedDomainStore {
        // WP-120's public attempt lookup. Stated rather than defaulted: a store that answers
        // "no receipt" when it simply cannot look one up would report a real attempt as absent,
        // and absence is what tells a client to stop waiting.
        async fn domain_operation_attempt_receipt_get(
            &self,
            _verified_issuer: &str,
            _authenticated_subject: &str,
            _client_attempt_id: &uuid::Uuid,
        ) -> Result<lore_postgres::domain::receipts::AttemptReceipt, DomainError> {
            unreachable!("ScriptedDomainStore does not serve attempt receipt lookups")
        }

        async fn domain_operation_clock_get(&self) -> Result<std::time::SystemTime, DomainError> {
            unreachable!("ScriptedDomainStore only scripts branch_push_commit")
        }

        async fn domain_operation_prepare(
            &self,
            _key: &ReceiptKey,
            _binding: &OperationBinding,
            _witness: Option<&AuthorizationWitness>,
            _client_attempt_id: Option<uuid::Uuid>,
        ) -> Result<PrepareResult, DomainError> {
            unreachable!("ScriptedDomainStore only scripts branch_push_commit")
        }

        async fn domain_operation_receipt_get(
            &self,
            _key: &ReceiptKey,
            _binding: &OperationBinding,
        ) -> Result<ReceiptLookup, DomainError> {
            unreachable!("ScriptedDomainStore only scripts branch_push_commit")
        }

        async fn domain_operation_verified_stale_finalize(
            &self,
            _input: &VerifiedStaleFinalizeInput,
        ) -> Result<VerifiedStaleFinalizeResult, DomainError> {
            unreachable!("ScriptedDomainStore only scripts branch_push_commit")
        }

        async fn domain_operation_terminal_status_attach(
            &self,
            _input: &TerminalStatusAttachInput,
        ) -> Result<TerminalStatusAttachmentAck, DomainError> {
            unreachable!("ScriptedDomainStore only scripts branch_push_commit")
        }

        async fn domain_operation_proof_namespace_materialize(
            &self,
            _input: &ProofNamespaceMaterializeInput,
        ) -> Result<ProofNamespaceMaterializeReceipt, DomainError> {
            unreachable!("ScriptedDomainStore only scripts branch_push_commit")
        }

        async fn domain_operation_proof_namespace_retire(
            &self,
            _input: &ProofNamespaceRetireInput,
        ) -> Result<ProofNamespaceRetireAck, DomainError> {
            unreachable!("ScriptedDomainStore only scripts branch_push_commit")
        }

        async fn repository_snapshot(
            &self,
            _repository_id: &[u8],
        ) -> Result<Option<RepositorySnapshot>, DomainError> {
            unreachable!("ScriptedDomainStore only scripts branch_push_commit")
        }

        async fn branch_snapshot(
            &self,
            _repository_id: &[u8],
            _branch_id: &[u8],
        ) -> Result<Option<BranchSnapshot>, DomainError> {
            unreachable!("ScriptedDomainStore only scripts branch_push_commit")
        }

        async fn repository_create(
            &self,
            _operation: &GovernedOperation,
            _input: &RepositoryCreateInput,
        ) -> Result<MutationResult, DomainError> {
            unreachable!("ScriptedDomainStore only scripts branch_push_commit")
        }

        async fn repository_delete(
            &self,
            _operation: &GovernedOperation,
            _input: &RepositoryDeleteInput,
        ) -> Result<MutationResult, DomainError> {
            unreachable!("ScriptedDomainStore only scripts branch_push_commit")
        }

        async fn branch_delete(
            &self,
            _operation: &GovernedOperation,
            _input: &BranchDeleteInput,
        ) -> Result<MutationResult, DomainError> {
            unreachable!("ScriptedDomainStore only scripts branch_push_commit")
        }

        async fn metadata_compare_and_swap(
            &self,
            _operation: &GovernedOperation,
            _input: &MetadataCasInput,
        ) -> Result<MutationResult, DomainError> {
            unreachable!("ScriptedDomainStore only scripts branch_push_commit")
        }

        async fn branch_push_commit(
            &self,
            _operation: &GovernedOperation,
            input: &BranchPushCommitInput,
        ) -> Result<MutationResult, DomainError> {
            self.calls
                .lock()
                .expect("scripted store mutex poisoned")
                .push(input.clone());
            Ok(self.result.clone())
        }

        async fn begin_obliterate(
            &self,
            _operation: &GovernedOperation,
            _repository_id: &[u8],
            _event: Option<&PendingEvent>,
        ) -> Result<MutationResult, DomainError> {
            unreachable!("ScriptedDomainStore only scripts branch_push_commit")
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use lore_postgres::domain::schema::BACKFILL_CUTOVER;
    use lore_postgres::domain::schema::BACKFILL_NOT_STARTED;
    use tonic::Code;
    use tonic::metadata::BinaryMetadataValue;
    use uuid::Uuid;

    use super::test_support::PREPARED_TEST_TOKEN;
    use super::test_support::context;
    use super::test_support::preparing_context;
    use super::*;
    use crate::auth::jwk::JWKServiceSettings;
    use crate::grpc::domain_operation_metadata::FINGERPRINT_KEY;
    use crate::grpc::domain_operation_metadata::FINGERPRINT_V1_LEN;
    use crate::grpc::domain_operation_metadata::FINGERPRINT_VERSION_V1;
    use crate::grpc::domain_operation_metadata::OPERATION_ID_KEY;
    use crate::grpc::domain_operation_metadata::PREPARE_TOKEN_KEY;
    use crate::grpc::domain_operation_metadata::PREPARE_TOKEN_LEN;
    use crate::grpc::domain_operation_metadata::SCOPE_PRINCIPAL_NAMESPACE_V1;
    use crate::settings::AuthSettings;

    // --- shared helpers ------------------------------------------------

    fn valid_metadata(operation_id: Uuid) -> MetadataMap {
        let mut metadata = MetadataMap::new();
        metadata.insert_bin(
            OPERATION_ID_KEY,
            BinaryMetadataValue::from_bytes(operation_id.as_bytes()),
        );
        let mut fingerprint = vec![FINGERPRINT_VERSION_V1];
        fingerprint.extend(std::iter::repeat_n(0xAB, FINGERPRINT_V1_LEN));
        metadata.insert_bin(
            FINGERPRINT_KEY,
            BinaryMetadataValue::from_bytes(&fingerprint),
        );
        metadata.insert_bin(
            PREPARE_TOKEN_KEY,
            BinaryMetadataValue::from_bytes(&[0xCDu8; PREPARE_TOKEN_LEN]),
        );
        metadata
    }

    fn test_token(issuer: &str, subject: &str) -> AuthorizationToken {
        AuthorizationToken {
            issuer: issuer.to_string(),
            user_id: subject.to_string(),
            ..Default::default()
        }
    }

    fn test_repository_id() -> [u8; 16] {
        *Uuid::new_v4().as_bytes()
    }

    // --- 1. GovernedScope::tenant_scope_key -------------------------------

    #[test]
    fn repository_create_and_target_repository_scopes_differ_over_the_same_id() {
        let repository_id = test_repository_id();

        let create = GovernedScope::RepositoryCreate {
            repository_id: &repository_id,
        }
        .tenant_scope_key()
        .expect("valid repository id");
        let target = GovernedScope::TargetRepository {
            repository_id: &repository_id,
        }
        .tenant_scope_key()
        .expect("valid repository id");

        assert_ne!(create, target);
    }

    #[test]
    fn mediated_scope_contains_the_principal_namespace_tag() {
        let org_uuid = test_repository_id();

        let key = GovernedScope::Mediated {
            org_uuid: &org_uuid,
            principal_user_id: b"user-1",
        }
        .tenant_scope_key()
        .expect("valid mediated components");

        assert!(
            key.windows(SCOPE_PRINCIPAL_NAMESPACE_V1.len())
                .any(|window| window == SCOPE_PRINCIPAL_NAMESPACE_V1)
        );
    }

    // A bad target identity is the caller's mistake, not the server's: the
    // gate runs before handler logic, so nothing has validated `repository_id`
    // yet. `Code::Internal` would misattribute the fault and is the one code
    // an operator pages on. Both cases need carriage present and a token, or
    // `admit` short-circuits before the scope key is ever built.
    #[test]
    fn wrong_length_repository_id_reaches_admit_as_invalid_argument_not_internal() {
        let ctx = context(false);
        let metadata = valid_metadata(Uuid::now_v7());
        let token = test_token("https://issuer.example", "subject-123");
        let repository_id = [0xAAu8; 15];

        let err = ctx
            .admit(
                &metadata,
                Some(&token),
                GovernedScope::TargetRepository {
                    repository_id: &repository_id,
                },
            )
            .expect_err("a wrong-length repository id must be rejected");

        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[test]
    fn urc_prefixed_repository_id_reaches_admit_as_invalid_argument_not_internal() {
        let ctx = context(false);
        let metadata = valid_metadata(Uuid::now_v7());
        let token = test_token("https://issuer.example", "subject-123");
        let mut repository_id = [0u8; 16];
        repository_id[..4].copy_from_slice(b"urc-");

        let err = ctx
            .admit(
                &metadata,
                Some(&token),
                GovernedScope::TargetRepository {
                    repository_id: &repository_id,
                },
            )
            .expect_err("a urc--prefixed repository id must be rejected");

        assert_eq!(err.code(), Code::InvalidArgument);
    }

    // --- 2/3. admit_at_entry against a cell with no coordinator -----------

    #[test]
    fn admit_at_entry_with_no_coordinator_and_no_carriage_is_the_legacy_path() {
        let metadata = MetadataMap::new();
        let repository_id = test_repository_id();

        let result = admit_at_entry(
            None,
            &metadata,
            None,
            GovernedScope::TargetRepository {
                repository_id: &repository_id,
            },
        );

        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn admit_at_entry_with_no_coordinator_and_valid_carriage_is_refused() {
        let metadata = valid_metadata(Uuid::now_v7());
        let repository_id = test_repository_id();

        let err = admit_at_entry(
            None,
            &metadata,
            None,
            GovernedScope::TargetRepository {
                repository_id: &repository_id,
            },
        )
        .expect_err(
            "carriage against a cell with no coordinator must be refused, never downgraded",
        );

        assert_eq!(err.code(), Code::FailedPrecondition);
    }

    // --- 4. DomainContext::admit, enforcement off --------------------------

    #[test]
    fn enforcement_off_with_no_carriage_is_the_legacy_path() {
        let ctx = context(false);
        let metadata = MetadataMap::new();
        let repository_id = test_repository_id();

        let result = ctx.admit(
            &metadata,
            None,
            GovernedScope::TargetRepository {
                repository_id: &repository_id,
            },
        );

        assert!(matches!(result, Ok(None)));
    }

    #[test]
    fn enforcement_off_with_carriage_and_a_token_admits_keyed_by_the_token_not_the_body() {
        let ctx = context(false);
        let operation_id = Uuid::now_v7();
        let metadata = valid_metadata(operation_id);
        let token = test_token("https://issuer.example", "subject-123");
        let repository_id = test_repository_id();

        let admitted = ctx
            .admit(
                &metadata,
                Some(&token),
                GovernedScope::TargetRepository {
                    repository_id: &repository_id,
                },
            )
            .expect("valid carriage plus a verified principal must admit")
            .expect("must be Some, not the legacy path");

        assert_eq!(admitted.key.operation_id, operation_id);
        assert_eq!(admitted.key.verified_issuer, token.issuer);
        assert_eq!(admitted.key.authenticated_subject, token.user_id);
    }

    // --- 5. DomainContext::admit, absence and unauthenticated carriage ----

    #[test]
    fn enforcement_on_with_no_carriage_is_refused_as_invalid_argument() {
        let ctx = context(true);
        let metadata = MetadataMap::new();
        let repository_id = test_repository_id();

        let err = ctx
            .admit(
                &metadata,
                None,
                GovernedScope::TargetRepository {
                    repository_id: &repository_id,
                },
            )
            .expect_err("enforcement on requires carriage");

        assert_eq!(err.code(), Code::InvalidArgument);
    }

    #[test]
    fn carriage_without_a_verified_principal_is_refused_with_enforcement_on() {
        let ctx = context(true);
        let metadata = valid_metadata(Uuid::now_v7());
        let repository_id = test_repository_id();

        let err = ctx
            .admit(
                &metadata,
                None,
                GovernedScope::TargetRepository {
                    repository_id: &repository_id,
                },
            )
            .expect_err("carriage without a verified principal must be refused");

        assert_eq!(err.code(), Code::Unauthenticated);
    }

    // Absence of enforcement is not a licence to ignore carriage: a caller
    // that asked for governed semantics by supplying operation identity must
    // not be silently handed today's unsynchronised writes just because this
    // cell has not turned enforcement on yet.
    #[test]
    fn carriage_without_a_verified_principal_is_refused_even_with_enforcement_off() {
        let ctx = context(false);
        let metadata = valid_metadata(Uuid::now_v7());
        let repository_id = test_repository_id();

        let err = ctx
            .admit(
                &metadata,
                None,
                GovernedScope::TargetRepository {
                    repository_id: &repository_id,
                },
            )
            .expect_err(
                "carriage without a verified principal must be refused regardless of enforcement",
            );

        assert_eq!(err.code(), Code::Unauthenticated);
    }

    // --- 6. AdmittedOperation::into_governed -------------------------------

    #[test]
    fn into_governed_carries_prepare_token_and_fingerprint_unchanged_and_binds_scope_to_the_key() {
        let ctx = context(false);
        let operation_id = Uuid::now_v7();
        let metadata = valid_metadata(operation_id);
        let token = test_token("https://issuer.example", "subject-123");
        let repository_id = test_repository_id();

        let admitted = ctx
            .admit(
                &metadata,
                Some(&token),
                GovernedScope::TargetRepository {
                    repository_id: &repository_id,
                },
            )
            .expect("valid carriage plus a verified principal must admit")
            .expect("must be Some");

        let carried = admitted.carried().expect("presented carriage").clone();
        let expected_prepare_token = carried.prepare_token;
        let expected_fingerprint = carried.fingerprint.clone();
        let expected_scope = admitted.key.tenant_scope_key.clone();

        let governed =
            admitted.into_governed("lore.RepositoryService/RepositoryDelete", vec![0xAAu8; 8]);

        assert_eq!(governed.prepare_token, expected_prepare_token);
        assert_eq!(governed.binding.fingerprint, expected_fingerprint);
        assert_eq!(governed.binding.scope, expected_scope);
        assert_eq!(governed.binding.scope, governed.key.tenant_scope_key);
    }

    // --- 6a. WP-120 internal admission --------------------------------------

    /// A verifier double for the direct-authorization rail. Every method but
    /// `authorize_direct_repository_operation` is unreachable, matching this
    /// file's other doubles (`UnreachableDomainStore`) -- a signature drift on
    /// an unused method must fail to compile, not silently inherit a body.
    struct DirectVerifierDouble {
        calls: std::sync::atomic::AtomicUsize,
        forwarded_bearer: std::sync::Mutex<Option<String>>,
        diverge: Option<EchoDivergence>,
        error: Option<Status>,
    }

    /// Which single field of an otherwise-exact echo this double flips.
    #[derive(Clone, Copy)]
    enum EchoDivergence {
        VerifiedIssuer,
        AuthenticatedSubject,
        OperationId,
        Method,
        Scope,
        FingerprintVersion,
        Fingerprint,
        CanonicalIntentDigest,
    }

    impl DirectVerifierDouble {
        fn echo() -> Self {
            Self {
                calls: std::sync::atomic::AtomicUsize::new(0),
                forwarded_bearer: std::sync::Mutex::new(None),
                diverge: None,
                error: None,
            }
        }

        fn diverging(divergence: EchoDivergence) -> Self {
            Self {
                diverge: Some(divergence),
                ..Self::echo()
            }
        }

        fn erroring(status: Status) -> Self {
            Self {
                error: Some(status),
                ..Self::echo()
            }
        }

        fn call_count(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn forwarded_bearer(&self) -> Option<String> {
            self.forwarded_bearer
                .lock()
                .expect("forwarded-bearer mutex poisoned")
                .clone()
        }
    }

    #[async_trait::async_trait]
    impl RepositoryOperationAuthorizationVerifier for DirectVerifierDouble {
        async fn verify_repository_operation_authorization(
            &self,
            _request: tonic::Request<
                lore_proto::rebac::VerifyRepositoryOperationAuthorizationRequest,
            >,
        ) -> Result<lore_proto::rebac::VerifyRepositoryOperationAuthorizationResponse, Status>
        {
            unreachable!("WP-120 internal-admission tests exercise only the direct rail")
        }

        async fn claim_repository_operation_stale_finalize_permit(
            &self,
            _request: tonic::Request<
                lore_proto::rebac::DomainOperationMaintenanceVerificationRequest,
            >,
        ) -> Result<lore_proto::rebac::DomainOperationMaintenanceVerificationResponse, Status>
        {
            unreachable!("WP-120 internal-admission tests exercise only the direct rail")
        }

        async fn verify_repository_operation_terminal_status_attach(
            &self,
            _request: tonic::Request<
                lore_proto::rebac::DomainOperationMaintenanceVerificationRequest,
            >,
        ) -> Result<lore_proto::rebac::DomainOperationMaintenanceVerificationResponse, Status>
        {
            unreachable!("WP-120 internal-admission tests exercise only the direct rail")
        }

        async fn verify_repository_operation_proof_namespace_materialize(
            &self,
            _request: tonic::Request<
                lore_proto::rebac::DomainOperationMaintenanceVerificationRequest,
            >,
        ) -> Result<lore_proto::rebac::DomainOperationMaintenanceVerificationResponse, Status>
        {
            unreachable!("WP-120 internal-admission tests exercise only the direct rail")
        }

        async fn verify_repository_operation_proof_namespace_retire(
            &self,
            _request: tonic::Request<
                lore_proto::rebac::DomainOperationMaintenanceVerificationRequest,
            >,
        ) -> Result<lore_proto::rebac::DomainOperationMaintenanceVerificationResponse, Status>
        {
            unreachable!("WP-120 internal-admission tests exercise only the direct rail")
        }

        async fn authorize_direct_repository_operation(
            &self,
            request: tonic::Request<lore_proto::rebac::AuthorizeDirectRepositoryOperationRequest>,
        ) -> Result<lore_proto::rebac::AuthorizeDirectRepositoryOperationResponse, Status> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            *self
                .forwarded_bearer
                .lock()
                .expect("forwarded-bearer mutex poisoned") = request
                .metadata()
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            if let Some(status) = &self.error {
                return Err(status.clone());
            }
            let request = request.into_inner();
            let mut response = lore_proto::rebac::AuthorizeDirectRepositoryOperationResponse {
                verified_issuer: request.verified_issuer,
                authenticated_subject: request.authenticated_subject,
                operation_id: request.operation_id,
                method: request.method,
                scope: request.scope,
                fingerprint_version: request.fingerprint_version,
                fingerprint: request.fingerprint,
                canonical_intent_digest: request.canonical_intent_digest,
                authorization_id: bytes::Bytes::from_static(&[0x77u8; 16]),
                authorization_revision: 1,
                verification_nonce: bytes::Bytes::from_static(&[0x11u8; 32]),
                bound_fields_digest: bytes::Bytes::from_static(&[0x22u8; 32]),
                org_uuid: bytes::Bytes::new(),
            };
            match self.diverge {
                Some(EchoDivergence::VerifiedIssuer) => {
                    response.verified_issuer = "wrong-issuer".to_owned();
                }
                Some(EchoDivergence::AuthenticatedSubject) => {
                    response.authenticated_subject = "wrong-subject".to_owned();
                }
                Some(EchoDivergence::OperationId) => {
                    response.operation_id = bytes::Bytes::from_static(&[0xFFu8; 16]);
                }
                Some(EchoDivergence::Method) => {
                    response.method = "wrong-method".to_owned();
                }
                Some(EchoDivergence::Scope) => {
                    response.scope = bytes::Bytes::from_static(b"wrong-scope");
                }
                Some(EchoDivergence::FingerprintVersion) => {
                    response.fingerprint_version = response.fingerprint_version.wrapping_add(1);
                }
                Some(EchoDivergence::Fingerprint) => {
                    response.fingerprint = bytes::Bytes::from_static(&[0xEEu8; 32]);
                }
                Some(EchoDivergence::CanonicalIntentDigest) => {
                    response.canonical_intent_digest = bytes::Bytes::from_static(&[0xDDu8; 32]);
                }
                None => {}
            }
            Ok(response)
        }
    }

    fn human_token() -> AuthorizationToken {
        test_token("https://issuer.example", "released-desktop-user")
    }

    fn direct_scope_ctx(repository_id: &[u8; 16]) -> GovernedScope<'_> {
        GovernedScope::TargetRepository { repository_id }
    }

    /// The bearer this cell's JWT interceptor would have verified.
    pub(crate) const TEST_BEARER: &str = "Bearer released-desktop-jwt";

    /// Request metadata carrying the caller's own `authorization` header and
    /// nothing else.
    ///
    /// An empty `MetadataMap` beside a verified `AuthorizationToken` is a shape
    /// the real server never emits: the interceptor derives that token FROM this
    /// header, so one cannot exist without the other. The internal path forwards
    /// this exact value to auth-grpc as the human's bearer, so a fixture without
    /// it exercises the no-bearer refusal rather than the case it names.
    fn human_metadata() -> MetadataMap {
        let mut metadata = MetadataMap::new();
        metadata.insert(
            "authorization",
            TEST_BEARER.parse().expect("a static header value parses"),
        );
        metadata
    }

    // Gate 1: enforcement off leaves the caller on the legacy path even with
    // a verifier configured -- a verifier's presence is not itself a licence
    // to admit a governed mutation on a cell that still writes the generic
    // mutable path unfenced.
    #[test]
    fn internal_admission_is_unavailable_when_enforcement_is_off_even_with_a_verifier_configured() {
        let ctx = context(false)
            .with_operation_verifier(Some(std::sync::Arc::new(DirectVerifierDouble::echo())));
        let repository_id = test_repository_id();
        let token = human_token();

        let result = ctx.admit_internal(
            &human_metadata(),
            Some(&token),
            &direct_scope_ctx(&repository_id),
        );

        assert!(matches!(result, Ok(None)));
    }

    // Gate 2: no verifier configured, enforcement on, no carriage -- falls
    // through to the exact pre-WP-120 absent-carriage refusal. This is the
    // same status `enforcement_on_with_no_carriage_is_refused_as_invalid_argument`
    // already pins through the public `admit` entry point; this one exercises
    // `admit_internal` directly so the gate itself, not just its caller, is
    // proven byte-identical.
    #[test]
    fn internal_admission_is_unavailable_with_no_verifier_configured_and_falls_through_to_the_pre_wp120_refusal()
     {
        let ctx = context(true);
        let repository_id = test_repository_id();
        let token = human_token();

        let err = ctx
            .admit(
                &human_metadata(),
                Some(&token),
                direct_scope_ctx(&repository_id),
            )
            .expect_err("no verifier configured must fall through to the pre-WP-120 refusal");

        assert_eq!(err.code(), Code::InvalidArgument);
    }

    // Gate 3: no verified principal at all -- absent carriage still refuses
    // through `require`, not through a WP-120-specific status, even with a
    // verifier configured.
    #[test]
    fn internal_admission_is_unavailable_with_no_authorization_token() {
        let ctx = context(true)
            .with_operation_verifier(Some(std::sync::Arc::new(DirectVerifierDouble::echo())));
        let repository_id = test_repository_id();

        let err = ctx
            .admit(&human_metadata(), None, direct_scope_ctx(&repository_id))
            .expect_err("no authorization token must fall through to the pre-WP-120 refusal");

        assert_eq!(err.code(), Code::InvalidArgument);
    }

    // Gate 4 (security-critical): the control-plane service principal never
    // takes the internal-admission path, even with a verifier configured and
    // every other gate open. It always carries its own mediated carriage; a
    // silent internal admission would drop a mediated operation into a
    // direct human's receipt namespace.
    #[test]
    fn internal_admission_excludes_the_control_plane_service_principal() {
        let ctx = context(true)
            .with_operation_verifier(Some(std::sync::Arc::new(DirectVerifierDouble::echo())));
        let repository_id = test_repository_id();
        let control_plane = AuthorizationToken {
            issuer: "https://issuer.example".to_owned(),
            user_id: CONTROL_PLANE_SERVICE_SUBJECT.to_owned(),
            is_service_account: Some(true),
            ..Default::default()
        };

        let err = ctx
            .admit(
                &human_metadata(),
                Some(&control_plane),
                direct_scope_ctx(&repository_id),
            )
            .expect_err("the control-plane principal must never take the internal path");

        assert_eq!(err.code(), Code::InvalidArgument);
    }

    // Gate 4 (security-critical), the other half: ANY service account is
    // excluded, not only the named control-plane subject.
    #[test]
    fn internal_admission_excludes_every_service_account_not_only_the_control_plane_subject() {
        let ctx = context(true)
            .with_operation_verifier(Some(std::sync::Arc::new(DirectVerifierDouble::echo())));
        let repository_id = test_repository_id();
        let service_account = AuthorizationToken {
            issuer: "https://issuer.example".to_owned(),
            user_id: "some-other-service-account".to_owned(),
            is_service_account: Some(true),
            ..Default::default()
        };

        let err = ctx
            .admit(
                &human_metadata(),
                Some(&service_account),
                direct_scope_ctx(&repository_id),
            )
            .expect_err("no service account, named or not, may take the internal path");

        assert_eq!(err.code(), Code::InvalidArgument);
    }

    // Gate 5: a mediated scope with no carriage is a contradiction -- refused
    // directly, not silently downgraded to the legacy path or the generic
    // absent-carriage refusal.
    #[test]
    fn internal_admission_refuses_a_mediated_scope_with_no_carriage() {
        let ctx = context(true)
            .with_operation_verifier(Some(std::sync::Arc::new(DirectVerifierDouble::echo())));
        let org_uuid = test_repository_id();
        let token = human_token();

        let err = ctx
            .admit(
                &human_metadata(),
                Some(&token),
                GovernedScope::Mediated {
                    org_uuid: &org_uuid,
                    principal_user_id: b"user-1",
                },
            )
            .expect_err("a mediated scope with no carriage must be refused, not downgraded");

        assert_eq!(err.code(), Code::InvalidArgument);
    }

    // The positive case: every gate open admits, keyed by the token and a
    // freshly minted operation id, and is reported as internally prepared.
    #[test]
    fn internal_admission_admits_a_released_client_when_every_gate_is_open() {
        let ctx = context(true)
            .with_operation_verifier(Some(std::sync::Arc::new(DirectVerifierDouble::echo())));
        let repository_id = test_repository_id();
        let token = human_token();

        let admitted = ctx
            .admit(
                &human_metadata(),
                Some(&token),
                direct_scope_ctx(&repository_id),
            )
            .expect("every gate open must admit")
            .expect("must be Some, not the legacy path");

        assert!(admitted.is_internally_prepared());
        assert!(admitted.carried().is_none());
        assert_eq!(admitted.key.verified_issuer, token.issuer);
        assert_eq!(admitted.key.authenticated_subject, token.user_id);
    }

    // Two internal admissions for the same repository mint two different
    // operation ids: a released client carries no operation identity of its
    // own, so there is no cross-attempt idempotency by construction.
    #[test]
    fn internal_admission_mints_a_fresh_operation_id_per_attempt() {
        let ctx = context(true)
            .with_operation_verifier(Some(std::sync::Arc::new(DirectVerifierDouble::echo())));
        let repository_id = test_repository_id();
        let token = human_token();

        let first = ctx
            .admit(
                &human_metadata(),
                Some(&token),
                direct_scope_ctx(&repository_id),
            )
            .expect("admit")
            .expect("Some");
        let second = ctx
            .admit(
                &human_metadata(),
                Some(&token),
                direct_scope_ctx(&repository_id),
            )
            .expect("admit")
            .expect("Some");

        assert_ne!(first.key.operation_id, second.key.operation_id);
    }

    // --- 6b. WP-120 complete_governed / internal_prepare --------------------

    // Carriage still wins: `complete_governed` on a `Carried` admission never
    // calls the verifier, even when one is configured, and produces the exact
    // same `GovernedOperation` `into_governed` builds directly.
    #[tokio::test]
    async fn complete_governed_on_carried_admission_never_calls_the_verifier_and_matches_into_governed()
     {
        let verifier = std::sync::Arc::new(DirectVerifierDouble::echo());
        let ctx = context(false).with_operation_verifier(Some(verifier.clone()));
        let operation_id = Uuid::now_v7();
        let metadata = valid_metadata(operation_id);
        let token = test_token("https://issuer.example", "subject-123");
        let repository_id = test_repository_id();

        let admitted = ctx
            .admit(
                &metadata,
                Some(&token),
                GovernedScope::TargetRepository {
                    repository_id: &repository_id,
                },
            )
            .expect("valid carriage plus a verified principal must admit")
            .expect("must be Some");
        let digest = vec![0x99u8; 32];
        let expected = admitted
            .clone()
            .into_governed("lore.RepositoryService/RepositoryDelete", digest.clone());

        let governed = ctx
            .complete_governed(admitted, "lore.RepositoryService/RepositoryDelete", digest)
            .await
            .expect("carried admission must complete without touching the verifier");

        assert_eq!(governed.prepare_token, expected.prepare_token);
        assert_eq!(governed.binding.fingerprint, expected.binding.fingerprint);
        assert_eq!(governed.binding.scope, expected.binding.scope);
        assert_eq!(governed.key.operation_id, expected.key.operation_id);
        assert_eq!(verifier.call_count(), 0);
    }

    // Echo divergence: a verifier that flips any single field of its
    // otherwise-exact echo must be refused `PERMISSION_DENIED`, and the
    // refusal happens before `domain_operation_prepare` is ever called --
    // `UnreachableDomainStore` backs this context, so a regression that
    // reordered the echo check after the store call would panic this test
    // instead of merely failing an assertion.
    async fn assert_echo_divergence_is_refused(divergence: EchoDivergence) {
        let ctx = context(true).with_operation_verifier(Some(std::sync::Arc::new(
            DirectVerifierDouble::diverging(divergence),
        )));
        let repository_id = test_repository_id();
        let token = human_token();

        let admitted = ctx
            .admit(
                &human_metadata(),
                Some(&token),
                direct_scope_ctx(&repository_id),
            )
            .expect("every gate open must admit")
            .expect("must be Some");

        let error = ctx
            .complete_governed(
                admitted,
                PLATFORM_METHOD_REPOSITORY_METADATA_SET,
                vec![0x11u8; 32],
            )
            .await
            .expect_err("a divergent echo must be refused, not admitted");

        assert_eq!(error.code(), Code::PermissionDenied);
    }

    #[tokio::test]
    async fn internal_prepare_refuses_a_verified_issuer_echo_divergence() {
        assert_echo_divergence_is_refused(EchoDivergence::VerifiedIssuer).await;
    }

    #[tokio::test]
    async fn internal_prepare_refuses_an_authenticated_subject_echo_divergence() {
        assert_echo_divergence_is_refused(EchoDivergence::AuthenticatedSubject).await;
    }

    #[tokio::test]
    async fn internal_prepare_refuses_an_operation_id_echo_divergence() {
        assert_echo_divergence_is_refused(EchoDivergence::OperationId).await;
    }

    #[tokio::test]
    async fn internal_prepare_refuses_a_method_echo_divergence() {
        assert_echo_divergence_is_refused(EchoDivergence::Method).await;
    }

    #[tokio::test]
    async fn internal_prepare_refuses_a_scope_echo_divergence() {
        assert_echo_divergence_is_refused(EchoDivergence::Scope).await;
    }

    #[tokio::test]
    async fn internal_prepare_refuses_a_fingerprint_version_echo_divergence() {
        assert_echo_divergence_is_refused(EchoDivergence::FingerprintVersion).await;
    }

    #[tokio::test]
    async fn internal_prepare_refuses_a_fingerprint_echo_divergence() {
        assert_echo_divergence_is_refused(EchoDivergence::Fingerprint).await;
    }

    #[tokio::test]
    async fn internal_prepare_refuses_a_canonical_intent_digest_echo_divergence() {
        assert_echo_divergence_is_refused(EchoDivergence::CanonicalIntentDigest).await;
    }

    // The internal prepare forwards the caller's own bearer token to the
    // verifier, unaltered, so the verifier re-verifies the JWT itself rather
    // than trusting this server's report of who is calling.
    #[tokio::test]
    async fn internal_prepare_forwards_the_callers_own_bearer_token_to_the_verifier() {
        let verifier = std::sync::Arc::new(DirectVerifierDouble::echo());
        // `preparing_context` rather than `context(true)`: an ACCEPTING verifier
        // means execution continues past the echo check into the coordinator's
        // prepare, which `UnreachableDomainStore` panics on by design. Every
        // refusal case still uses that store, and its panic is what proves those
        // paths write no receipt row.
        let ctx = preparing_context().with_operation_verifier(Some(verifier.clone()));
        let repository_id = test_repository_id();
        let token = human_token();
        let mut metadata = MetadataMap::new();
        metadata.insert(
            "authorization",
            "Bearer released-client-jwt".parse().expect("ascii header"),
        );

        let admitted = ctx
            .admit_internal(&metadata, Some(&token), &direct_scope_ctx(&repository_id))
            .expect("every gate open must admit")
            .expect("must be Some");

        let governed = ctx
            .complete_governed(
                admitted,
                PLATFORM_METHOD_REPOSITORY_METADATA_SET,
                vec![0x22u8; 32],
            )
            .await
            .expect("echoing verifier must admit");

        assert_eq!(
            verifier.forwarded_bearer(),
            Some("Bearer released-client-jwt".to_owned()),
            "the verifier must receive the caller's own bearer, unaltered"
        );
        assert_eq!(
            governed.prepare_token, PREPARED_TEST_TOKEN,
            "the governed operation must carry the token the coordinator minted"
        );
        assert_eq!(
            governed.binding.method,
            PLATFORM_METHOD_REPOSITORY_METADATA_SET
        );
    }

    // A verifier that errors is a refusal, never a silent downgrade to the
    // legacy path -- the caller already committed to the internal path by
    // reaching `complete_governed`'s `Internal` arm.
    #[tokio::test]
    async fn internal_prepare_refuses_when_the_configured_verifier_errors() {
        let ctx = context(true).with_operation_verifier(Some(std::sync::Arc::new(
            DirectVerifierDouble::erroring(Status::unavailable("verifier unreachable")),
        )));
        let repository_id = test_repository_id();
        let token = human_token();

        let admitted = ctx
            .admit(
                &human_metadata(),
                Some(&token),
                direct_scope_ctx(&repository_id),
            )
            .expect("every gate open must admit")
            .expect("must be Some");

        let error = ctx
            .complete_governed(
                admitted,
                PLATFORM_METHOD_REPOSITORY_METADATA_SET,
                vec![0x33u8; 32],
            )
            .await
            .expect_err("a verifier error must be refused, not downgraded");

        assert_eq!(error.code(), Code::Unavailable);
    }

    // A fenced-lock direct prepare against a cell with no verifier configured
    // is refused the same way -- `prepare_direct_lock_operation` does not
    // gate on verifier presence itself the way `admit_internal` does, so this
    // is its own independent proof rather than a restatement of the
    // repository-mutation gate table above.
    #[tokio::test]
    async fn prepare_direct_lock_operation_refuses_with_no_verifier_configured() {
        let ctx = context(true);
        let token = human_token();
        let repository_id = test_repository_id();
        let branch_id = test_repository_id();
        let binding = OperationBinding {
            method: "lock.acquire".to_owned(),
            scope: vec![0x44u8; 16],
            fingerprint_version: 1,
            fingerprint: vec![0x55u8; 32],
            canonical_intent_digest: vec![0x66u8; 32],
        };

        let error = ctx
            .prepare_direct_lock_operation(
                &token,
                "Bearer x",
                &repository_id,
                &branch_id,
                binding,
                None,
            )
            .await
            .expect_err("no verifier configured must refuse, not panic or silently admit");

        assert_eq!(error.code(), Code::FailedPrecondition);
    }

    // A fenced-lock direct prepare excludes the control-plane and service
    // accounts the same way the repository-mutation gate does -- a direct
    // fenced lock is for human principals.
    #[tokio::test]
    async fn prepare_direct_lock_operation_excludes_service_accounts() {
        let ctx = context(true)
            .with_operation_verifier(Some(std::sync::Arc::new(DirectVerifierDouble::echo())));
        let repository_id = test_repository_id();
        let branch_id = test_repository_id();
        let service_account = AuthorizationToken {
            issuer: "https://issuer.example".to_owned(),
            user_id: "some-service-account".to_owned(),
            is_service_account: Some(true),
            ..Default::default()
        };
        let binding = OperationBinding {
            method: "lock.acquire".to_owned(),
            scope: vec![0x44u8; 16],
            fingerprint_version: 1,
            fingerprint: vec![0x55u8; 32],
            canonical_intent_digest: vec![0x66u8; 32],
        };

        let error = ctx
            .prepare_direct_lock_operation(
                &service_account,
                "Bearer x",
                &repository_id,
                &branch_id,
                binding,
                None,
            )
            .await
            .expect_err("a service account must be refused a direct fenced lock");

        assert_eq!(error.code(), Code::PermissionDenied);
    }

    // --- 6c. internal_prepare_fingerprint determinism -----------------------
    //
    // Every vector below is computed independently (Python's `blake3`
    // package, not this function's own output) over
    // `b"lore-internal-prepare-fingerprint-v1\0"` followed by each of
    // method/scope/canonical_intent_digest, u32-big-endian length-prefixed.
    // Per the testing guide's "never hash two blocks of output to rule out a
    // difference" rule, these are golden values, not a change detector.

    fn fingerprint_digest_fixture() -> [u8; 32] {
        let mut digest = [0u8; 32];
        for (index, byte) in digest.iter_mut().enumerate() {
            *byte = index as u8;
        }
        digest
    }

    #[test]
    fn internal_prepare_fingerprint_matches_an_independently_computed_golden_vector() {
        let fingerprint = internal_prepare_fingerprint(
            "branch.push",
            b"test-scope-bytes",
            &fingerprint_digest_fixture(),
        )
        .expect("bounded inputs must not overflow the frame width");

        assert_eq!(
            hex::encode(&fingerprint),
            "8b51c6c83b92f3c6f2f40e85d611ead84ff1bde91c64b82babe004a7baef90d8"
        );
    }

    #[test]
    fn internal_prepare_fingerprint_changes_when_the_method_changes() {
        let fingerprint = internal_prepare_fingerprint(
            "repository.metadata-set",
            b"test-scope-bytes",
            &fingerprint_digest_fixture(),
        )
        .expect("bounded inputs must not overflow the frame width");

        assert_eq!(
            hex::encode(&fingerprint),
            "220c20b16ec8c3bd3a0a61400255fb492a1d598832abd66b3a70978cbb5c6616"
        );
    }

    #[test]
    fn internal_prepare_fingerprint_changes_when_the_scope_changes() {
        let fingerprint = internal_prepare_fingerprint(
            "branch.push",
            b"different-scope",
            &fingerprint_digest_fixture(),
        )
        .expect("bounded inputs must not overflow the frame width");

        assert_eq!(
            hex::encode(&fingerprint),
            "8e356e78514930907e37109a15e141a2d15983f1ed752829589be3cdfe7c8b48"
        );
    }

    #[test]
    fn internal_prepare_fingerprint_changes_when_the_digest_changes() {
        let mut digest = fingerprint_digest_fixture();
        digest[0] = 0xff;

        let fingerprint = internal_prepare_fingerprint("branch.push", b"test-scope-bytes", &digest)
            .expect("bounded inputs must not overflow the frame width");

        assert_eq!(
            hex::encode(&fingerprint),
            "89d96fa375318e4a0e156584292745ba017b99d40c6c2dc5de0dd866fdc8fe35"
        );
    }

    #[test]
    fn internal_prepare_fingerprint_changes_with_an_empty_scope() {
        let fingerprint =
            internal_prepare_fingerprint("branch.push", b"", &fingerprint_digest_fixture())
                .expect("bounded inputs must not overflow the frame width");

        assert_eq!(
            hex::encode(&fingerprint),
            "94bfef7a8a2c81b22e1d5217d45bffd6dfa5e00ff0eba7e91e2b3c04afe729fc"
        );
    }

    // --- 7. resolve_enforcement ---------------------------------------------

    fn schema_state(
        enforcement_enabled: bool,
        backfill_state: i16,
        residue_classified: bool,
        cutover_at: Option<SystemTime>,
    ) -> DomainSchemaState {
        DomainSchemaState {
            schema_version: 1,
            backfill_version: 1,
            backfill_state,
            backfill_cursor: None,
            residue_classified,
            cutover_at,
            enforcement_enabled,
            database_identity: "test-database".to_string(),
        }
    }

    #[test]
    fn resolve_enforcement_off_is_ok_false_regardless_of_backfill_state() {
        let state = schema_state(false, BACKFILL_NOT_STARTED, false, None);

        let enforcement = resolve_enforcement(&state).expect("enforcement off never fails");

        assert!(!enforcement);
    }

    // The readiness rule: an incomplete backfill must refuse the cell's
    // readiness, never silently downgrade to the unsynchronised path.
    #[test]
    fn resolve_enforcement_on_but_not_ready_refuses_readiness_rather_than_downgrading() {
        let state = schema_state(true, BACKFILL_NOT_STARTED, false, None);

        let err = resolve_enforcement(&state)
            .expect_err("an unready cell with enforcement requested must refuse readiness");

        assert!(err.to_string().contains("refusing readiness"));
    }

    #[test]
    fn resolve_enforcement_on_and_ready_is_ok_true() {
        let state = schema_state(true, BACKFILL_CUTOVER, true, Some(SystemTime::now()));

        let enforcement = resolve_enforcement(&state).expect("a ready cell must enforce");

        assert!(enforcement);
    }

    fn lock_ready() -> LockFencingReadiness {
        LockFencingReadiness {
            provisioned: true,
            schema_version: lore_postgres::domain::locks::schema::LOCK_SCHEMA_VERSION,
            backfill_state: lore_postgres::domain::locks::schema::BACKFILL_COMPLETE,
            fencing_enabled: true,
            lease_enabled: false,
            same_database: true,
            sequence_headroom: true,
            quarantined_rows: 0,
            unfenced_rows: 0,
        }
    }

    fn fenced_settings() -> Settings {
        let mut settings: Settings = toml::from_str(include_str!("../config/default.toml"))
            .expect("built-in settings fixture must deserialize");
        settings
            .lock_store
            .as_mut()
            .expect("default lock store")
            .mode = POSTGRES_MODE.to_owned();
        settings.server.auth = Some(AuthSettings {
            jwk: Some(JWKServiceSettings {
                endpoint: "https://issuer.example/.well-known/jwks.json".to_owned(),
            }),
            jwt_audience: None,
            jwt_issuer: Some("https://issuer.example".to_owned()),
            enforce_write_permission: true,
        });
        settings
    }

    #[test]
    fn lock_fencing_off_keeps_the_legacy_route_without_auth_requirements() {
        let mut readiness = lock_ready();
        readiness.fencing_enabled = false;
        let settings: Settings = toml::from_str(include_str!("../config/default.toml"))
            .expect("built-in settings fixture must deserialize");
        assert!(!resolve_lock_fencing(&readiness, &settings).expect("disabled route"));
    }

    #[test]
    fn lock_fencing_requires_auth_issuer_write_permission_and_postgres_routing() {
        let readiness = lock_ready();

        let mut no_auth = fenced_settings();
        no_auth.server.auth = None;
        assert!(resolve_lock_fencing(&readiness, &no_auth).is_err());

        let mut no_jwk = fenced_settings();
        no_jwk.server.auth.as_mut().expect("auth").jwk = None;
        assert!(resolve_lock_fencing(&readiness, &no_jwk).is_err());

        let mut no_issuer = fenced_settings();
        no_issuer.server.auth.as_mut().expect("auth").jwt_issuer = None;
        assert!(resolve_lock_fencing(&readiness, &no_issuer).is_err());

        let mut no_write_enforcement = fenced_settings();
        no_write_enforcement
            .server
            .auth
            .as_mut()
            .expect("auth")
            .enforce_write_permission = false;
        assert!(resolve_lock_fencing(&readiness, &no_write_enforcement).is_err());

        let mut wrong_store = fenced_settings();
        wrong_store.lock_store.as_mut().expect("lock store").mode = "local".to_owned();
        assert!(resolve_lock_fencing(&readiness, &wrong_store).is_err());
    }

    #[test]
    fn lock_fencing_requires_every_database_backfill_and_cutover_witness() {
        let settings = fenced_settings();
        assert!(resolve_lock_fencing(&lock_ready(), &settings).expect("complete evidence"));

        let mut cases = Vec::new();
        let mut schema = lock_ready();
        schema.schema_version += 1;
        cases.push(schema);
        let mut backfill = lock_ready();
        backfill.backfill_state = lore_postgres::domain::locks::schema::BACKFILL_RUNNING;
        cases.push(backfill);
        let mut database = lock_ready();
        database.same_database = false;
        cases.push(database);
        let mut sequence = lock_ready();
        sequence.sequence_headroom = false;
        cases.push(sequence);
        let mut quarantine = lock_ready();
        quarantine.quarantined_rows = 1;
        cases.push(quarantine);
        let mut lease = lock_ready();
        lease.lease_enabled = true;
        cases.push(lease);

        for readiness in cases {
            assert!(resolve_lock_fencing(&readiness, &settings).is_err());
        }
    }

    // --- 8. Boot against a cell the SCHEMA-117 migration never touched ------

    /// A Postgres-mode cell that has never had the SCHEMA-117 migration
    /// applied must still boot, on the legacy lock route.
    ///
    /// `configure_domain_context` runs before `configure_lock_store_via_plugin`
    /// (`server.rs`), so when it reads lock readiness neither the fenced tables
    /// nor `lore_locks` itself exists yet. Nothing in the runtime creates them:
    /// CR-030 N-7 keeps `LOCK_SCHEMA` migration-owned, and `bootstrap()` is a
    /// fixture-only method production never calls. Every other test reaching
    /// this path calls `bootstrap()` first — a state the production rail never
    /// produces — so this case boots the way an unmigrated cell actually boots.
    #[tokio::test]
    #[ignore = "needs live Postgres env (LORE_TEST_PG_URL); run with -- --ignored"]
    async fn a_never_migrated_postgres_cell_boots_on_the_legacy_lock_route() {
        let url = std::env::var("LORE_TEST_PG_URL")
            .expect("LORE_TEST_PG_URL must be set; a skipped live case is NOT RUN, never a pass");

        let mut settings: Settings = toml::from_str(include_str!("../config/default.toml"))
            .expect("built-in settings fixture must deserialize");
        settings.mutable_store.mode = POSTGRES_MODE.to_owned();
        settings.plugins.insert(
            "postgres".to_owned(),
            toml::from_str(&format!("url = {url:?}\npool_max = 2\ndomain_pool_max = 2"))
                .expect("Postgres plugin fixture config"),
        );

        let configured = configure_domain_context(&settings)
            .await
            .expect("an unmigrated cell must boot rather than abort on SQLSTATE 42P01");

        let context = configured
            .context
            .expect("a Postgres-mode cell always gets a domain context");
        assert!(
            context.lock_coordinator().is_none(),
            "a cell without the SCHEMA-117 migration must stay on the legacy lock route"
        );
    }

    // --- 9. WP-116 guarded-stop contract gap: real construction paths ------

    // PERMANENT cross-namespace isolation guarantee (WP-116 guarded stop),
    // corrected 2026-08-30 after a reviewer round. This test deliberately
    // consumes under the WRONG scope key (a direct handler's
    // `GovernedScope::TargetRepository`/`RepositoryCreate` key) against a row
    // `domain_operation_prepare` created under the CORRECT mediated key. That
    // must ALWAYS fail closed -- cross-namespace consumption is a permanent
    // invariant of the receipt state machine, not an artifact of today's gap,
    // and this test's assertions (`ADMISSION_REJECTED_V1`, no domain
    // mutation, the source row still `PREPARED`) must stay green forever. Do
    // NOT replace them with a positive `Applied` proof when the WP-116
    // carriage gap closes: add a positive proof ALONGSIDE these assertions
    // instead, exercising a call site that correctly threads the mediated key
    // end-to-end once carriage exists.
    //
    // What today's gap actually is: a governed handler has no way to obtain
    // the `org_uuid`/principal identity a correct mediated key would need.
    // One of the two carriage sites is pinned at compile time
    // (`grpc::domain_operation_metadata::tests::
    // domain_operation_metadata_carries_no_org_or_principal_identity`, over
    // this module's own request-metadata carriage struct); the other,
    // `AuthorizationToken` (`auth/jwt.rs:60`), is deliberately not pinned by
    // an exhaustive destructure there and must be checked by hand when
    // closing MISSING-1 -- see that test's own comment for why. This test is
    // the live, decisive companion to
    // `grpc::domain_operation_metadata::tests::
    // direct_and_mediated_scope_key_families_never_collide`, driven through
    // the REAL production construction path against a live Postgres domain
    // store rather than by comparing key bytes in isolation: a
    // `domain_operation_prepare` call built exactly the way the private
    // `DomainOperationPrepare` RPC builds it, followed by a coordinator
    // mutation call built exactly the way a governed handler builds it.
    #[tokio::test]
    #[ignore = "needs disposable live Postgres via LORE_TEST_PG_URL; run with -- --ignored --test-threads=1"]
    async fn a_mediated_prepare_key_cannot_be_consumed_by_a_repository_scoped_governed_mutation() {
        use lore_postgres::domain::DomainOutcome;
        use lore_postgres::domain::coordinator::ADMISSION_REJECTED_V1;
        use lore_postgres::domain::coordinator::GovernedOperation;
        use lore_postgres::domain::coordinator::RepositoryCreateInput;
        use lore_postgres::domain::receipts::OperationBinding;
        use lore_postgres::domain::receipts::PrepareResult;
        use lore_postgres::domain::receipts::ReceiptKey;
        use lore_postgres::domain::receipts::ReceiptLookup;

        use crate::grpc::domain_operation_metadata::ScopeKeyError;
        use crate::grpc::domain_operation_metadata::scope_key_mediated_namespace;
        use crate::grpc::domain_operation_metadata::scope_key_repository_create;
        use crate::grpc::domain_operation_metadata::scope_key_target_repository;

        // Required explicitly, matching this module's other live case: a
        // silent `return` here would let an unconfigured run report a pass it
        // never earned. A skipped live case is NOT RUN, never a pass.
        std::env::var("LORE_TEST_PG_URL")
            .expect("LORE_TEST_PG_URL must be set; a skipped live case is NOT RUN, never a pass");
        let context = super::test_support::configured_enforcing_context()
            .await
            .expect("real domain-context construction path must yield an enforcing context");
        let store = context.store().clone();

        type ScopeBuilder = fn(&[u8]) -> Result<Vec<u8>, ScopeKeyError>;
        let handler_builders: [(&str, ScopeBuilder); 2] = [
            (
                "GovernedScope::TargetRepository",
                scope_key_target_repository,
            ),
            (
                "GovernedScope::RepositoryCreate",
                scope_key_repository_create,
            ),
        ];

        for (label, build_handler_scope) in handler_builders {
            let repository_id = *Uuid::new_v4().as_bytes();
            let org_uuid = *Uuid::new_v4().as_bytes();
            let principal_namespace = format!("principal-v1\0{}", Uuid::new_v4());
            let verified_issuer = format!(
                "https://issuer.example/wp116-gap/{:016x}",
                rand::random::<u64>()
            );
            let authenticated_subject = "svc:wp116-gap-test".to_string();
            let operation_id = Uuid::now_v7();

            let mediated_scope =
                scope_key_mediated_namespace(&org_uuid, principal_namespace.as_bytes())
                    .expect("valid mediated namespace components");
            let mediated_key = ReceiptKey {
                verified_issuer: verified_issuer.clone(),
                authenticated_subject: authenticated_subject.clone(),
                tenant_scope_key: mediated_scope,
                operation_id,
            };
            let binding = OperationBinding {
                method: PLATFORM_METHOD_REPOSITORY_CREATE.to_string(),
                scope: mediated_key.tenant_scope_key.clone(),
                fingerprint_version: 1,
                fingerprint: rand::random::<[u8; 32]>().to_vec(),
                canonical_intent_digest: rand::random::<[u8; 32]>().to_vec(),
            };

            // Prepare exactly the way DomainOperationPrepare does: the
            // mediated key.
            let prepared = store
                .domain_operation_prepare(&mediated_key, &binding, None, None)
                .await
                .expect("prepare through the real production construction path must succeed");
            let PrepareResult::Prepared { token, .. } = prepared else {
                panic!("{label}: expected Prepared, got {prepared:?}");
            };

            // Now build the operation the way a governed handler would: same
            // prepare token and identity fields, but a repository-scoped key.
            let handler_scope = build_handler_scope(&repository_id).expect("valid repository id");
            let handler_key = ReceiptKey {
                verified_issuer,
                authenticated_subject,
                tenant_scope_key: handler_scope,
                operation_id,
            };
            let governed = GovernedOperation {
                key: handler_key,
                binding: binding.clone(),
                prepare_token: token,
            };
            let input = RepositoryCreateInput {
                repository_id: repository_id.to_vec(),
                name: format!("wp116-gap-{operation_id}"),
                metadata_hash: rand::random::<[u8; 32]>().to_vec(),
                default_branch_id: Uuid::new_v4().as_bytes().to_vec(),
                default_branch_name: "main".to_string(),
                default_branch_metadata_hash: rand::random::<[u8; 32]>().to_vec(),
                default_branch_latest_hash: vec![0u8; 32],
                creation_fingerprint: binding.fingerprint.clone(),
                creation_fingerprint_version: binding.fingerprint_version,
                projection: Vec::new(),
                events: Vec::new(),
            };

            let result = store.repository_create(&governed, &input).await.expect(
                "a wrong-scope consume must fail closed with a decisive result, not a \
                     transport/database error",
            );

            assert_eq!(
                result.repository_generation, None,
                "{label}: no domain mutation may happen on a scope-key mismatch"
            );
            assert_eq!(
                result.branch_generation, None,
                "{label}: no domain mutation may happen on a scope-key mismatch"
            );
            match result.outcome {
                DomainOutcome::NotApplied { reason, .. } => {
                    assert_eq!(
                        reason, ADMISSION_REJECTED_V1,
                        "{label}: must be refused as an admission rejection, not a downstream \
                         precondition failure"
                    );
                }
                other => {
                    panic!("{label}: expected NotApplied(ADMISSION_REJECTED_V1), got {other:?}")
                }
            }

            // No repository row was ever written.
            let snapshot = store
                .repository_snapshot(&repository_id)
                .await
                .expect("repository snapshot lookup");
            assert!(
                snapshot.is_none(),
                "{label}: repository_create must not have written a domain row"
            );

            // The originally prepared row, under its own mediated key, is
            // left completely untouched by the failed consume attempt.
            let lookup = store
                .domain_operation_receipt_get(&mediated_key, &binding)
                .await
                .expect("receipt lookup under the mediated key");
            assert!(
                matches!(lookup, ReceiptLookup::Prepared { .. }),
                "{label}: the mediated-key row must remain PREPARED, untouched by the failed \
                 consume attempt under a different scope key"
            );
        }
    }
}

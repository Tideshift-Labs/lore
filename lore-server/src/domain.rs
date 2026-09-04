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
use lore_postgres::domain::coordinator::BranchSnapshot;
use lore_postgres::domain::coordinator::CAS_MISMATCH_V1;
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
use lore_postgres::domain::receipts::ReceiptKey;
use lore_revision::branch;
use lore_revision::repository;
use lore_storage::hash;
use tonic::Status;
use tonic::metadata::MetadataMap;
use tracing::debug;
use tracing::info;
use tracing::warn;

use crate::auth::jwt::AuthorizationToken;
use crate::event_relay::admission::OutboxAdmission;
use crate::grpc::domain_operation_metadata;
use crate::plugins::postgres::assert_domain_store_colocated;
use crate::plugins::postgres::connect_domain_store;
use crate::settings::Settings;
use crate::store::configuration::resolve_plugin_config_with_fallback;

/// The `mode` string that selects the Postgres backend.
const POSTGRES_MODE: &str = "postgres";
const CONTROL_PLANE_SERVICE_SUBJECT: &str = "lorehub-control-plane";

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
        }
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
    /// - `Ok(None)` — enforcement is off and the caller carried no operation
    ///   identity: the legacy carve-out, and the only path that reaches today's
    ///   unsynchronised writes.
    /// - `Ok(Some(_))` — a validated governed operation.
    /// - `Err(_)` — decisive pre-admission rejection. Under enforcement this
    ///   covers absence; in every mode it covers malformed, wrong-length,
    ///   wrong-version, non-UUIDv7, and divergent-duplicate carriage.
    pub fn admit(
        &self,
        metadata: &MetadataMap,
        authorization: Option<&AuthorizationToken>,
        scope: GovernedScope<'_>,
    ) -> Result<Option<AdmittedOperation>, Status> {
        let carried = if self.enforcement {
            Some(domain_operation_metadata::require(metadata)?)
        } else {
            domain_operation_metadata::extract(metadata)?
        };

        let Some(carried) = carried else {
            return Ok(None);
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
            carried,
        }))
    }
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
    /// The validated carriage.
    pub carried: domain_operation_metadata::DomainOperationMetadata,
}

impl AdmittedOperation {
    /// Complete the operation at the coordinator call site.
    pub fn into_governed(
        self,
        method: impl Into<String>,
        canonical_intent_digest: Vec<u8>,
    ) -> GovernedOperation {
        GovernedOperation {
            binding: OperationBinding {
                method: method.into(),
                // For a direct operation the binding's canonical scope and the
                // receipt's tenant scope are the same bytes: the operation
                // targets exactly the resource whose namespace admits it.
                scope: self.key.tenant_scope_key.clone(),
                fingerprint_version: self.carried.fingerprint_version,
                fingerprint: self.carried.fingerprint,
                canonical_intent_digest,
            },
            prepare_token: self.carried.prepare_token,
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
    pub fn prepare(
        domain: Option<&Arc<DomainContext>>,
        admitted: Option<AdmittedOperation>,
        method: &'static str,
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
        Ok(Some(Self {
            domain: domain.clone(),
            operation: admitted.into_governed(method, digest),
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
    pub fn prepare(
        domain: Option<&Arc<DomainContext>>,
        admitted: Option<AdmittedOperation>,
        method: &'static str,
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
                method,
                operation_id = %admitted.key.operation_id,
                "Refusing a governed repository create on a cell that is not enforcing"
            );
            return Err(Status::failed_precondition(
                "Governed repository create requires domain enforcement on this cell",
            ));
        }
        Ok(Some(Self {
            domain: domain.clone(),
            operation: admitted.into_governed(method, digest),
        }))
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
    pub fn prepare(
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
                "Refusing a governed repository delete on a cell that is not enforcing"
            );
            return Err(Status::failed_precondition(
                "Governed repository delete requires domain enforcement on this cell",
            ));
        }
        Ok(Some(Self {
            domain: domain.clone(),
            operation: admitted.into_governed(method, digest),
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
    let context = if lock_fencing {
        DomainContext::new_with_lock_coordinator(
            Arc::new(store),
            enforcement,
            Arc::new(lock_coordinator),
        )
    } else {
        DomainContext::new(Arc::new(store), enforcement)
    }
    .with_cell_id(cell_id);
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
    if readiness.lease_enabled {
        return Err(anyhow!(
            "Finite lock leases are enabled before token-capable public clients are available"
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
        async fn domain_operation_clock_get(&self) -> Result<std::time::SystemTime, DomainError> {
            unreachable!("DomainContext::admit tests never call the coordinator")
        }

        async fn domain_operation_prepare(
            &self,
            _key: &ReceiptKey,
            _binding: &OperationBinding,
            _witness: Option<&AuthorizationWitness>,
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
        async fn domain_operation_clock_get(&self) -> Result<std::time::SystemTime, DomainError> {
            unreachable!("ScriptedDomainStore only scripts branch_push_commit")
        }

        async fn domain_operation_prepare(
            &self,
            _key: &ReceiptKey,
            _binding: &OperationBinding,
            _witness: Option<&AuthorizationWitness>,
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

    use super::test_support::context;
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

        let expected_prepare_token = admitted.carried.prepare_token;
        let expected_fingerprint = admitted.carried.fingerprint.clone();
        let expected_scope = admitted.key.tenant_scope_key.clone();

        let governed =
            admitted.into_governed("lore.RepositoryService/RepositoryDelete", vec![0xAAu8; 8]);

        assert_eq!(governed.prepare_token, expected_prepare_token);
        assert_eq!(governed.binding.fingerprint, expected_fingerprint);
        assert_eq!(governed.binding.scope, expected_scope);
        assert_eq!(governed.binding.scope, governed.key.tenant_scope_key);
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
                method: "lore.RepositoryService/RepositoryCreate".to_string(),
                scope: mediated_key.tenant_scope_key.clone(),
                fingerprint_version: 1,
                fingerprint: rand::random::<[u8; 32]>().to_vec(),
                canonical_intent_digest: rand::random::<[u8; 32]>().to_vec(),
            };

            // Prepare exactly the way DomainOperationPrepare does: the
            // mediated key.
            let prepared = store
                .domain_operation_prepare(&mediated_key, &binding, None)
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

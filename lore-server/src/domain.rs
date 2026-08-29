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
//!   prove positively that they all address one database (R-SHOULD-1). A domain
//!   transaction that writes domain rows and `lore_mutable` rows together is
//!   only atomic if those rows live in one database; four independent URLs make
//!   that a configuration property, so it is checked rather than assumed.
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

use anyhow::Result;
use anyhow::anyhow;
use lore_postgres::domain::DomainSchemaState;
use lore_postgres::domain::coordinator::DomainTransactionStore;
use lore_postgres::domain::coordinator::GovernedOperation;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::ReceiptKey;
use tonic::Status;
use tonic::metadata::MetadataMap;
use tracing::debug;
use tracing::info;
use tracing::warn;

use crate::auth::jwt::AuthorizationToken;
use crate::grpc::domain_operation_metadata;
use crate::plugins::postgres::assert_domain_store_colocated;
use crate::plugins::postgres::connect_domain_store;
use crate::settings::Settings;
use crate::store::configuration::resolve_plugin_config_with_fallback;

/// The `mode` string that selects the Postgres backend.
const POSTGRES_MODE: &str = "postgres";

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
}

impl DomainContext {
    /// Wrap an already-connected coordinator with its enforcement state.
    pub fn new(store: Arc<dyn DomainTransactionStore>, enforcement: bool) -> Self {
        Self { store, enforcement }
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

        let tenant_scope_key = scope.tenant_scope_key()?;

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
/// three CR-007 stores connect to the same database at boot and already fail
/// hard, so a cell that cannot reach this database cannot serve anyway.
pub async fn configure_domain_context(settings: &Settings) -> Result<Option<Arc<DomainContext>>> {
    if settings.mutable_store.mode != POSTGRES_MODE {
        return Ok(None);
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

    Ok(Some(Arc::new(DomainContext::new(
        Arc::new(store),
        enforcement,
    ))))
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
    use lore_postgres::domain::coordinator::BranchPushCommitInput;
    use lore_postgres::domain::coordinator::BranchSnapshot;
    use lore_postgres::domain::coordinator::MetadataCasInput;
    use lore_postgres::domain::coordinator::MutationResult;
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

    use super::DomainContext;
    use super::DomainTransactionStore;
    use super::GovernedOperation;

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
    use crate::grpc::domain_operation_metadata::FINGERPRINT_KEY;
    use crate::grpc::domain_operation_metadata::FINGERPRINT_V1_LEN;
    use crate::grpc::domain_operation_metadata::FINGERPRINT_VERSION_V1;
    use crate::grpc::domain_operation_metadata::OPERATION_ID_KEY;
    use crate::grpc::domain_operation_metadata::PREPARE_TOKEN_KEY;
    use crate::grpc::domain_operation_metadata::PREPARE_TOKEN_LEN;
    use crate::grpc::domain_operation_metadata::SCOPE_PRINCIPAL_NAMESPACE_V1;

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
}

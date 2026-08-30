// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Transactional implementation of CR-030's fenced lock authority.

use std::collections::BTreeMap;
use std::mem::size_of;
use std::time::Duration;
use std::time::SystemTime;

use rand::RngCore;
use subtle::ConstantTimeEq;
use tokio_postgres::Transaction;

use super::schema;
use crate::domain::coordinator::GovernedOperation;
use crate::domain::coordinator::PendingEvent;
use crate::domain::errors::DomainError;
use crate::domain::errors::DomainOutcome;
use crate::domain::lock_order::LockClass;
use crate::domain::lock_order::LockSequence;
use crate::domain::lock_order::lock_branch;
use crate::domain::lock_order::lock_repository;
use crate::domain::outbox;
use crate::domain::receipts;
use crate::domain::receipts::ConsumeResult;
use crate::domain::receipts::OperationBinding;
use crate::domain::retry::classify_commit;
use crate::domain::store::PostgresDomainStore;

const STATE_LIVE: i16 = 0;
const MAX_IDENTITY_BYTES: usize = 512;
const MAX_DESCRIPTION_BYTES: usize = 1024;
const MAX_BATCH_RESOURCES: usize = 512;
const RESOURCE_HASH_BYTES: usize = 32;
const MAX_LEASE: Duration = Duration::from_secs(24 * 60 * 60);

const REASON_NOT_FOUND: &str = "LOCK_NOT_FOUND_V1";
const REASON_FOREIGN_OWNER: &str = "LOCK_FOREIGN_OWNER_V1";
const REASON_AUTHORITY_MISMATCH: &str = "LOCK_AUTHORITY_MISMATCH_V1";
const REASON_NAMESPACE_MISMATCH: &str = "LOCK_NAMESPACE_MISMATCH_V1";

/// Verified lock authority. Display names are not authority.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct VerifiedLockOwner {
    /// JWT issuer after signature and issuer-policy verification.
    pub verified_issuer: String,
    /// Authenticated JWT subject.
    pub authenticated_subject: String,
}

impl VerifiedLockOwner {
    /// Compare both authority fields without an early-exit byte scan.
    ///
    /// Owner identity decides release, renew, and push authority, so it gets
    /// the same treatment as the ownership token rather than `PartialEq`'s
    /// short-circuiting `==`. Both halves are always evaluated.
    pub fn ct_matches(&self, other: &Self) -> bool {
        let issuer = self
            .verified_issuer
            .as_bytes()
            .ct_eq(other.verified_issuer.as_bytes());
        let subject = self
            .authenticated_subject
            .as_bytes()
            .ct_eq(other.authenticated_subject.as_bytes());
        bool::from(issuer & subject)
    }
}

/// One resource in a sorted, atomic lock mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockResourceInput {
    /// BLAKE3 resource hash.
    pub resource_hash: Vec<u8>,
    /// Bounded display description.
    pub description: String,
    /// Required for renewal or release; absent only for a fresh acquire.
    pub expected_ownership_token: Option<[u8; 32]>,
}

/// Acquire absent resources or renew resources held by the exact owner/token.
#[derive(Debug, Clone)]
pub struct AcquireOrRenewInput {
    /// 16-byte repository identity.
    pub repository_id: Vec<u8>,
    /// 16-byte branch identity.
    pub branch_id: Vec<u8>,
    /// Verified owner pair.
    pub owner: VerifiedLockOwner,
    /// Acting administrator, only for dark admin acquisition.
    pub acting_owner: Option<VerifiedLockOwner>,
    /// Atomic resource batch.
    pub resources: Vec<LockResourceInput>,
    /// Finite expiry, disabled in production until token-capable clients land.
    pub lease_duration: Option<Duration>,
    /// Optional transaction-local outbox record.
    pub event: Option<PendingEvent>,
}

/// Token-checked normal release.
#[derive(Debug, Clone)]
pub struct ReleaseInput {
    /// 16-byte repository identity.
    pub repository_id: Vec<u8>,
    /// 16-byte branch identity.
    pub branch_id: Vec<u8>,
    /// Verified caller pair.
    pub owner: VerifiedLockOwner,
    /// Atomic resource batch.
    pub resources: Vec<LockResourceInput>,
    /// Optional transaction-local outbox record.
    pub event: Option<PendingEvent>,
}

/// Dark server-side force release. No current public RPC reaches it.
#[derive(Debug, Clone)]
pub struct ForceReleaseInput {
    /// 16-byte repository identity.
    pub repository_id: Vec<u8>,
    /// 16-byte branch identity.
    pub branch_id: Vec<u8>,
    /// Explicit target, never inferred from the current row.
    pub target_owner: VerifiedLockOwner,
    /// Verified acting administrator.
    pub acting_owner: VerifiedLockOwner,
    /// Atomic token-bearing resource batch.
    pub resources: Vec<LockResourceInput>,
    /// Optional transaction-local outbox record.
    pub event: Option<PendingEvent>,
}

/// One committed fenced lock returned by acquire/renew.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FencedLock {
    /// Branch identity carried by the legacy public projection.
    pub branch_id: Vec<u8>,
    /// Resource hash.
    pub resource_hash: Vec<u8>,
    /// Human-readable description carried by the legacy public projection.
    pub description: String,
    /// Verified owner.
    pub owner: VerifiedLockOwner,
    /// Opaque release/renew token.
    pub ownership_token: [u8; 32],
    /// Monotonic internal fence.
    pub fence: i64,
    /// Repository lock generation stamped on the row.
    pub repository_lock_generation: i64,
    /// Branch lock generation stamped on the row.
    pub branch_lock_generation: i64,
    /// Database-authoritative initial acquisition time.
    pub acquired_at: SystemTime,
    /// Database-authoritative expiry, if finite leases are active.
    pub expires_at: Option<SystemTime>,
}

/// Decisive non-application classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockRejection {
    /// No current matching row.
    NotFound,
    /// A live row belongs to another verified pair.
    ForeignOwner,
    /// Token, target pair, or acting authority did not match.
    AuthorityMismatch,
    /// Repository/branch/namespace state is absent or obsolete.
    NamespaceMismatch,
    /// The prepared receipt was not consumable.
    AdmissionRejected,
}

/// Result of one admitted mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockMutationResult {
    /// Receipt outcome.
    pub outcome: DomainOutcome,
    /// Fenced rows for an applied acquire/renew; empty for release.
    pub locks: Vec<FencedLock>,
    /// Typed decisive conflict.
    pub rejection: Option<LockRejection>,
    /// True when CR-029 returned an already-committed receipt outcome.
    pub replayed: bool,
}

/// O(1) preflight witness handed to WP-116.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PushLockWitness {
    /// Repository lock generation.
    pub repository_lock_generation: i64,
    /// Branch lock generation.
    pub branch_lock_generation: i64,
    /// Namespace fence at preflight.
    pub branch_lock_namespace_last_applied_fence: i64,
}

/// Explicit legacy-subject mapping. Missing entries are quarantined.
pub type BackfillIssuerMap = BTreeMap<String, String>;

/// Result of one restartable backfill pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackfillReport {
    /// Rows converted to fenced form during this pass.
    pub converted: u64,
    /// Rows held in quarantine.
    pub quarantined: u64,
    /// Whether cutover evidence was committed.
    pub complete: bool,
}

/// Readiness projection used by server construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockFencingReadiness {
    /// Whether the migration-owned SCHEMA-117 objects exist in this database.
    ///
    /// False is a routing answer, not an error: CR-030 N-7 keeps the fenced
    /// DDL migration-owned, so a cell the migration has not reached is simply
    /// a cell that has not been cut over, and it boots on the legacy route.
    pub provisioned: bool,
    /// Schema revision stored in the database.
    pub schema_version: i64,
    /// Backfill state.
    pub backfill_state: i16,
    /// Fenced routing is enabled.
    pub fencing_enabled: bool,
    /// Finite leases are enabled.
    pub lease_enabled: bool,
    /// Positive database-identity match.
    pub same_database: bool,
    /// Sequence headroom is above every persisted fence.
    pub sequence_headroom: bool,
    /// Quarantine row count.
    pub quarantined_rows: i64,
    /// Legacy rows that still lack fenced authority columns.
    pub unfenced_rows: i64,
}

impl LockFencingReadiness {
    /// The verdict for a database the SCHEMA-117 migration has not reached.
    ///
    /// Every field reads as "no fenced evidence" so a caller that only checks
    /// `fencing_enabled`, or that checks the full evidence set, reaches the
    /// same legacy-route conclusion.
    pub fn not_provisioned() -> Self {
        Self {
            provisioned: false,
            schema_version: 0,
            backfill_state: schema::BACKFILL_NOT_STARTED,
            fencing_enabled: false,
            lease_enabled: false,
            same_database: false,
            sequence_headroom: false,
            quarantined_rows: 0,
            unfenced_rows: 0,
        }
    }
}

/// Postgres-only CR-030 coordinator, sharing CR-029's pool.
#[derive(Clone)]
pub struct PostgresLockCoordinator {
    pool: deadpool_postgres::Pool,
    database_identity: String,
}

impl PostgresDomainStore {
    /// Obtain the lock coordinator on the exact CR-029 pool and database.
    pub fn lock_coordinator(&self) -> PostgresLockCoordinator {
        PostgresLockCoordinator {
            pool: self.pool().clone(),
            database_identity: self.identity().as_marker(),
        }
    }
}

/// Canonical receipt tenant scope for one repository/branch pair.
pub fn lock_tenant_scope_key(
    repository_id: &[u8],
    branch_id: &[u8],
) -> Result<Vec<u8>, DomainError> {
    validate_id("repository_id", repository_id)?;
    validate_id("branch_id", branch_id)?;
    let mut out = Vec::with_capacity(23 + 4 + 16 + 4 + 16);
    out.extend_from_slice(b"lock-tenant-scope-v1\0");
    out.extend_from_slice(&16u32.to_be_bytes());
    out.extend_from_slice(repository_id);
    out.extend_from_slice(&16u32.to_be_bytes());
    out.extend_from_slice(branch_id);
    Ok(out)
}

/// Build the exact receipt binding for an acquire, renew, or dark admin acquire.
pub fn acquire_or_renew_binding(
    input: &AcquireOrRenewInput,
) -> Result<OperationBinding, DomainError> {
    let ordered = sorted_resources(&input.resources)?;
    validate_lease_duration(input.lease_duration)?;
    validate_canonical_result_capacity(input, &ordered)?;
    let has_tokens = ordered
        .iter()
        .filter(|resource| resource.expected_ownership_token.is_some())
        .count();
    let method = if input.acting_owner.is_some() {
        if has_tokens != 0 {
            return Err(DomainError::InvalidInput(
                "dark admin acquire cannot renew an existing token".to_owned(),
            ));
        }
        "lock.admin_acquire"
    } else if has_tokens == 0 {
        "lock.acquire"
    } else if has_tokens == ordered.len() {
        "lock.renew"
    } else {
        return Err(DomainError::InvalidInput(
            "an acquire/renew batch cannot mix tokenless and token-bearing resources".to_owned(),
        ));
    };
    lock_binding(
        method,
        &input.repository_id,
        &input.branch_id,
        &input.owner,
        input.acting_owner.as_ref(),
        &ordered,
        input.lease_duration,
        false,
    )
}

/// Build the exact receipt binding for a normal release.
pub fn release_binding(input: &ReleaseInput) -> Result<OperationBinding, DomainError> {
    lock_binding(
        "lock.release",
        &input.repository_id,
        &input.branch_id,
        &input.owner,
        None,
        &sorted_resources_allow_empty(&input.resources)?,
        None,
        false,
    )
}

/// Build the exact receipt binding for the dark force-release method.
pub fn force_release_binding(input: &ForceReleaseInput) -> Result<OperationBinding, DomainError> {
    lock_binding(
        "lock.force_release",
        &input.repository_id,
        &input.branch_id,
        &input.target_owner,
        Some(&input.acting_owner),
        &sorted_resources(&input.resources)?,
        None,
        true,
    )
}

impl PostgresLockCoordinator {
    /// Install SCHEMA-117 for isolated component fixtures.
    ///
    /// Production construction does not call this method. Cells apply the
    /// migration-owned DDL before a binary starts, and readiness fails closed
    /// when that migration or its singleton identity is absent.
    pub async fn bootstrap(&self) -> Result<(), DomainError> {
        crate::pool::ensure_schema(&self.pool, schema::LOCK_SCHEMA)
            .await
            .map_err(|error| DomainError::Internal(format!("lock schema bootstrap: {error}")))?;
        let client = self.checkout().await?;
        client
            .execute(
                "INSERT INTO lore_domain_lock_schema_state ( \
                     id, schema_version, backfill_state, database_identity, updated_at \
                 ) VALUES (1, $1, $2, $3, clock_timestamp()) \
                 ON CONFLICT (id) DO NOTHING",
                &[
                    &schema::LOCK_SCHEMA_VERSION,
                    &schema::BACKFILL_NOT_STARTED,
                    &self.database_identity,
                ],
            )
            .await
            .map_err(|error| DomainError::from_pg("lock schema state insert", error))?;
        Ok(())
    }

    /// Acquire absent resources or renew exact current ownership.
    pub async fn acquire_or_renew(
        &self,
        operation: &GovernedOperation,
        input: &AcquireOrRenewInput,
    ) -> Result<LockMutationResult, DomainError> {
        validate_operation_binding(
            operation,
            &acquire_or_renew_binding(input)?,
            input.acting_owner.as_ref().unwrap_or(&input.owner),
        )?;
        validate_common(
            operation,
            &input.repository_id,
            &input.branch_id,
            &input.owner,
            &input.resources,
        )?;
        if let Some(actor) = &input.acting_owner {
            validate_owner(actor)?;
        }
        // `readiness()` is five round trips, two of them unindexed `lore_locks`
        // scans. Only the finite-lease question needs it, and finite leases stay
        // off until WP-120, so a tokenless acquire must not pay for it.
        if input.lease_duration.is_some() && !self.readiness().await?.lease_enabled {
            return Err(DomainError::NotReady(
                "finite lock leases are disabled until token-capable clients are active".to_owned(),
            ));
        }

        let mut client = self.checkout().await?;
        let mut sequence = LockSequence::new();
        let begun = begin_admitted(&mut client, operation, &mut sequence).await?;
        let (tx, admission_clock) = match begun {
            BeginAdmitted::Admitted(tx, clock) => (tx, clock),
            BeginAdmitted::Committed(outcome, public_result) => {
                let locks = match public_result {
                    Some(bytes) if matches!(outcome, DomainOutcome::Applied) => {
                        decode_canonical_result(&bytes)?
                    }
                    _ => Vec::new(),
                };
                return Ok(replayed(outcome, locks));
            }
            BeginAdmitted::Rejected => return Ok(admission_rejected()),
        };
        let Some(repository) = lock_repository(&tx, &mut sequence, &input.repository_id).await?
        else {
            return commit_rejection(
                tx,
                operation,
                admission_clock,
                LockRejection::NamespaceMismatch,
            )
            .await;
        };
        let Some(branch) =
            lock_branch(&tx, &mut sequence, &input.repository_id, &input.branch_id).await?
        else {
            return commit_rejection(
                tx,
                operation,
                admission_clock,
                LockRejection::NamespaceMismatch,
            )
            .await;
        };
        if repository.state != STATE_LIVE || branch.state != STATE_LIVE {
            return commit_rejection(
                tx,
                operation,
                admission_clock,
                LockRejection::NamespaceMismatch,
            )
            .await;
        }
        let namespace =
            lock_namespace(&tx, &mut sequence, &input.repository_id, &input.branch_id).await?;
        let clock = database_clock(&tx).await?;
        let expires_at = match input.lease_duration {
            Some(duration) => Some(clock.checked_add(duration).ok_or_else(|| {
                DomainError::InvalidInput("lease expiry overflows SystemTime".to_owned())
            })?),
            None => None,
        };

        let resources = sorted_resources(&input.resources)?;
        let hashes = resources
            .iter()
            .map(|resource| resource.resource_hash.as_slice())
            .collect::<Vec<_>>();
        let existing =
            load_resource_rows(&tx, &input.repository_id, &input.branch_id, &hashes).await?;
        let by_hash = existing
            .into_iter()
            .map(|row| (row.resource_hash.clone(), row))
            .collect::<BTreeMap<_, _>>();
        let mut committed = Vec::with_capacity(resources.len());

        // Validate the complete sorted batch before the first row mutation.
        // A decisive conflict commits a NOT_APPLIED receipt, so discovering it
        // after an earlier upsert would otherwise commit a partial batch.
        for resource in &resources {
            let existing = by_hash.get(&resource.resource_hash);
            if let Some(row) = existing.as_ref()
                && row_is_current(row, &namespace, clock)
            {
                if !row.owner.ct_matches(&input.owner) {
                    return commit_rejection(
                        tx,
                        operation,
                        admission_clock,
                        LockRejection::ForeignOwner,
                    )
                    .await;
                }
                let Some(expected) = resource.expected_ownership_token else {
                    return commit_rejection(
                        tx,
                        operation,
                        admission_clock,
                        LockRejection::AuthorityMismatch,
                    )
                    .await;
                };
                if !token_matches(&row.ownership_token, &expected) {
                    return commit_rejection(
                        tx,
                        operation,
                        admission_clock,
                        LockRejection::AuthorityMismatch,
                    )
                    .await;
                }
            }
        }

        for resource in &resources {
            let existing = by_hash.get(&resource.resource_hash);
            let fence = next_fence(&tx).await?;
            let mut token = [0u8; 32];
            rand::rng().fill_bytes(&mut token);
            let acquired_at = existing
                .filter(|row| row_is_current(row, &namespace, clock))
                .map_or(clock, |row| row.acquired_at);
            upsert_fenced_lock(
                &tx,
                &input.repository_id,
                &input.branch_id,
                resource,
                &input.owner,
                input.acting_owner.as_ref(),
                &namespace,
                &token,
                fence,
                acquired_at,
                clock,
                expires_at,
            )
            .await?;
            committed.push(FencedLock {
                branch_id: input.branch_id.clone(),
                resource_hash: resource.resource_hash.clone(),
                description: resource.description.clone(),
                owner: input.owner.clone(),
                ownership_token: token,
                fence,
                repository_lock_generation: namespace.repository_lock_generation,
                branch_lock_generation: namespace.branch_lock_generation,
                acquired_at,
                expires_at,
            });
        }

        let last_fence = committed
            .last()
            .map_or(namespace.last_applied_fence, |lock| lock.fence);
        update_namespace_fence(&tx, &input.repository_id, &input.branch_id, last_fence).await?;
        append_event(
            &tx,
            &mut sequence,
            &input.repository_id,
            repository.generation,
            input.event.as_ref(),
        )
        .await?;
        let outcome = DomainOutcome::Applied;
        let public = canonical_result(&committed)?;
        receipts::commit_terminal(
            &tx,
            &operation.key,
            &outcome,
            Some(&public),
            admission_clock,
        )
        .await?;
        classify_commit(tx.commit().await, "fenced lock acquire-or-renew commit")?;
        Ok(LockMutationResult {
            outcome,
            locks: committed,
            rejection: None,
            replayed: false,
        })
    }

    /// Release rows held by the exact verified pair, generations, and token.
    pub async fn release(
        &self,
        operation: &GovernedOperation,
        input: &ReleaseInput,
    ) -> Result<LockMutationResult, DomainError> {
        validate_operation_binding(operation, &release_binding(input)?, &input.owner)?;
        self.release_inner(
            operation,
            &input.repository_id,
            &input.branch_id,
            &input.owner,
            None,
            &input.resources,
            input.event.as_ref(),
        )
        .await
    }

    /// Force release with an explicit target and acting administrator.
    pub async fn force_release(
        &self,
        operation: &GovernedOperation,
        input: &ForceReleaseInput,
    ) -> Result<LockMutationResult, DomainError> {
        validate_operation_binding(
            operation,
            &force_release_binding(input)?,
            &input.acting_owner,
        )?;
        validate_owner(&input.acting_owner)?;
        self.release_inner(
            operation,
            &input.repository_id,
            &input.branch_id,
            &input.target_owner,
            Some(&input.acting_owner),
            &input.resources,
            input.event.as_ref(),
        )
        .await
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "one shared atomic path keeps normal and dark force-release authority checks identical"
    )]
    async fn release_inner(
        &self,
        operation: &GovernedOperation,
        repository_id: &[u8],
        branch_id: &[u8],
        target: &VerifiedLockOwner,
        _acting: Option<&VerifiedLockOwner>,
        resources: &[LockResourceInput],
        event: Option<&PendingEvent>,
    ) -> Result<LockMutationResult, DomainError> {
        validate_lock_target(operation, repository_id, branch_id, target)?;
        if resources.is_empty() {
            let mut client = self.checkout().await?;
            let mut sequence = LockSequence::new();
            return match begin_admitted(&mut client, operation, &mut sequence).await? {
                BeginAdmitted::Committed(outcome, _) => Ok(replayed(outcome, Vec::new())),
                BeginAdmitted::Rejected => Ok(admission_rejected()),
                BeginAdmitted::Admitted(tx, clock) => {
                    let outcome = DomainOutcome::Applied;
                    receipts::commit_terminal(
                        &tx,
                        &operation.key,
                        &outcome,
                        Some(b"empty-release-v1"),
                        clock,
                    )
                    .await?;
                    classify_commit(tx.commit().await, "empty fenced lock release commit")?;
                    Ok(LockMutationResult {
                        outcome,
                        locks: Vec::new(),
                        rejection: None,
                        replayed: false,
                    })
                }
            };
        }
        sorted_resources(resources)?;
        if resources
            .iter()
            .any(|resource| resource.expected_ownership_token.is_none())
        {
            return Err(DomainError::InvalidInput(
                "every release resource requires an ownership token".to_owned(),
            ));
        }
        let mut client = self.checkout().await?;
        let mut sequence = LockSequence::new();
        let begun = begin_admitted(&mut client, operation, &mut sequence).await?;
        let (tx, admission_clock) = match begun {
            BeginAdmitted::Admitted(tx, clock) => (tx, clock),
            BeginAdmitted::Committed(outcome, _) => return Ok(replayed(outcome, Vec::new())),
            BeginAdmitted::Rejected => return Ok(admission_rejected()),
        };
        let Some(repository) = lock_repository(&tx, &mut sequence, repository_id).await? else {
            return commit_rejection(tx, operation, admission_clock, LockRejection::NotFound).await;
        };
        if lock_branch(&tx, &mut sequence, repository_id, branch_id)
            .await?
            .is_none()
        {
            return commit_rejection(tx, operation, admission_clock, LockRejection::NotFound).await;
        }
        let namespace = lock_namespace(&tx, &mut sequence, repository_id, branch_id).await?;
        let clock = database_clock(&tx).await?;
        let ordered = sorted_resources(resources)?;
        let hashes = ordered
            .iter()
            .map(|resource| resource.resource_hash.as_slice())
            .collect::<Vec<_>>();
        let rows = load_resource_rows(&tx, repository_id, branch_id, &hashes).await?;
        if rows.len() != ordered.len() {
            return commit_rejection(tx, operation, admission_clock, LockRejection::NotFound).await;
        }
        let by_hash = rows
            .into_iter()
            .map(|row| (row.resource_hash.clone(), row))
            .collect::<BTreeMap<_, _>>();
        for resource in &ordered {
            let Some(row) = by_hash.get(&resource.resource_hash) else {
                return commit_rejection(tx, operation, admission_clock, LockRejection::NotFound)
                    .await;
            };
            if !row_is_current(row, &namespace, clock) {
                return commit_rejection(tx, operation, admission_clock, LockRejection::NotFound)
                    .await;
            }
            let expected = resource.expected_ownership_token.as_ref().ok_or_else(|| {
                DomainError::InvalidInput("release token vanished after validation".to_owned())
            })?;
            if !row.owner.ct_matches(target) || !token_matches(&row.ownership_token, expected) {
                return commit_rejection(
                    tx,
                    operation,
                    admission_clock,
                    LockRejection::AuthorityMismatch,
                )
                .await;
            }
        }
        for resource in &ordered {
            let row = by_hash.get(&resource.resource_hash).ok_or_else(|| {
                DomainError::Internal("validated release row vanished".to_owned())
            })?;
            let deleted = tx
                .execute(
                    "DELETE FROM lore_locks \
                  WHERE repository = $1 AND branch = $2 AND hash = $3 \
                    AND repository_lock_generation = $4 AND branch_lock_generation = $5 \
                    AND fence = $6",
                    &[
                        &repository_id,
                        &branch_id,
                        &resource.resource_hash,
                        &row.repository_lock_generation,
                        &row.branch_lock_generation,
                        &row.fence,
                    ],
                )
                .await
                .map_err(|error| DomainError::from_pg("fenced lock release", error))?;
            if deleted != 1 {
                return Err(DomainError::Contention(
                    "lock row changed during exact release".to_owned(),
                ));
            }
        }
        let fence = next_fence(&tx).await?;
        update_namespace_fence(&tx, repository_id, branch_id, fence).await?;
        append_event(
            &tx,
            &mut sequence,
            repository_id,
            repository.generation,
            event,
        )
        .await?;
        let outcome = DomainOutcome::Applied;
        receipts::commit_terminal(
            &tx,
            &operation.key,
            &outcome,
            Some(b"released-v1"),
            admission_clock,
        )
        .await?;
        classify_commit(tx.commit().await, "fenced lock release commit")?;
        Ok(LockMutationResult {
            outcome,
            locks: Vec::new(),
            rejection: None,
            replayed: false,
        })
    }

    /// Query current, unexpired rows, optionally scoped to one issuer/subject.
    pub async fn query(
        &self,
        repository_id: &[u8],
        branch_id: Option<&[u8]>,
        owner: Option<&VerifiedLockOwner>,
    ) -> Result<Vec<FencedLock>, DomainError> {
        self.query_filtered(repository_id, branch_id, owner, None)
            .await
    }

    /// Query current rows with the legacy wire's optional description filter.
    pub async fn query_filtered(
        &self,
        repository_id: &[u8],
        branch_id: Option<&[u8]>,
        owner: Option<&VerifiedLockOwner>,
        description: Option<&str>,
    ) -> Result<Vec<FencedLock>, DomainError> {
        validate_id("repository_id", repository_id)?;
        if let Some(branch) = branch_id {
            validate_id("branch_id", branch)?;
        }
        if let Some(owner) = owner {
            validate_owner(owner)?;
        }
        let client = self.checkout().await?;
        let rows = client
            .query(
                "SELECT locks.branch, locks.hash, locks.description, locks.owner_issuer, \
                        locks.owner_subject, locks.ownership_token, locks.acquired_at, \
                        locks.fence, locks.repository_lock_generation, locks.branch_lock_generation, \
                        locks.expires_at \
                   FROM lore_locks AS locks \
                   JOIN lore_domain_lock_namespaces AS namespace \
                     ON namespace.repository_id = locks.repository \
                    AND namespace.branch_id = locks.branch \
                  WHERE locks.repository = $1 \
                    AND ($2::bytea IS NULL OR locks.branch = $2) \
                    AND ($3::text IS NULL OR locks.owner_issuer = $3) \
                    AND ($4::text IS NULL OR locks.owner_subject = $4) \
                    AND ($5::text IS NULL OR locks.description = $5) \
                    AND locks.repository_lock_generation = namespace.repository_lock_generation \
                    AND locks.branch_lock_generation = namespace.branch_lock_generation \
                    AND locks.owner_issuer IS NOT NULL AND locks.owner_subject IS NOT NULL \
                    AND locks.ownership_token IS NOT NULL AND locks.fence IS NOT NULL \
                    AND locks.acquired_at IS NOT NULL AND locks.renewed_at IS NOT NULL \
                    AND (locks.expires_at IS NULL OR locks.expires_at > clock_timestamp()) \
                  ORDER BY locks.branch, locks.hash",
                &[
                    &repository_id,
                    &branch_id,
                    &owner.map(|value| value.verified_issuer.as_str()),
                    &owner.map(|value| value.authenticated_subject.as_str()),
                    &description,
                ],
            )
            .await
            .map_err(|error| DomainError::from_pg("fenced lock query", error))?;
        rows.into_iter().map(fenced_lock_from_row).collect()
    }

    /// Return one current row by exact identity.
    pub async fn status(
        &self,
        repository_id: &[u8],
        branch_id: &[u8],
        resource_hash: &[u8],
    ) -> Result<Option<FencedLock>, DomainError> {
        Ok(self
            .status_many(repository_id, &[(branch_id, resource_hash)])
            .await?
            .into_iter()
            .next())
    }

    /// Return the current rows for a batch of exact `(branch, hash)` pairs.
    ///
    /// One pool checkout and one query for the whole batch, matching what the
    /// legacy store does for the same wire call. Absent and obsolete resources
    /// are simply missing from the result; order follows the stored key, not
    /// the request, exactly as the legacy projection does.
    pub async fn status_many(
        &self,
        repository_id: &[u8],
        resources: &[(&[u8], &[u8])],
    ) -> Result<Vec<FencedLock>, DomainError> {
        validate_id("repository_id", repository_id)?;
        for (branch_id, resource_hash) in resources {
            validate_id("branch_id", branch_id)?;
            validate_hash(resource_hash)?;
        }
        if resources.is_empty() {
            return Ok(Vec::new());
        }
        let branches = resources
            .iter()
            .map(|(branch_id, _)| *branch_id)
            .collect::<Vec<_>>();
        let hashes = resources
            .iter()
            .map(|(_, resource_hash)| *resource_hash)
            .collect::<Vec<_>>();
        let client = self.checkout().await?;
        let rows = client
            .query(
                "SELECT locks.branch, locks.hash, locks.description, locks.owner_issuer, \
                        locks.owner_subject, locks.ownership_token, locks.acquired_at, \
                        locks.fence, locks.repository_lock_generation, locks.branch_lock_generation, \
                        locks.expires_at \
                   FROM unnest($2::bytea[], $3::bytea[]) AS requested(branch, hash) \
                   JOIN lore_locks AS locks \
                     ON locks.branch = requested.branch AND locks.hash = requested.hash \
                   JOIN lore_domain_lock_namespaces AS namespace \
                     ON namespace.repository_id = locks.repository \
                    AND namespace.branch_id = locks.branch \
                  WHERE locks.repository = $1 \
                    AND locks.repository_lock_generation = namespace.repository_lock_generation \
                    AND locks.branch_lock_generation = namespace.branch_lock_generation \
                    AND locks.owner_issuer IS NOT NULL AND locks.owner_subject IS NOT NULL \
                    AND locks.ownership_token IS NOT NULL AND locks.fence IS NOT NULL \
                    AND locks.acquired_at IS NOT NULL AND locks.renewed_at IS NOT NULL \
                    AND (locks.expires_at IS NULL OR locks.expires_at > clock_timestamp()) \
                  ORDER BY locks.branch, locks.hash",
                &[&repository_id, &branches, &hashes],
            )
            .await
            .map_err(|error| DomainError::from_pg("fenced lock status", error))?;
        rows.into_iter().map(fenced_lock_from_row).collect()
    }

    /// Advisory cleanup that can delete only the exact observed stale row.
    ///
    /// Deliberately does not bump `last_applied_fence`, and the push-witness
    /// contract depends on that: a fence bump here would invalidate every
    /// in-flight preflight witness for the branch on a purely advisory delete.
    /// It is sound only because the `WHERE` clause restricts the delete to a
    /// *logically absent* row — obsolete generations or an expired lease — which
    /// no reader can observe as a live lock anyway, so removing it changes
    /// nothing a witness reports. Widening that predicate to any current row
    /// would break the witness contract, not merely this method.
    pub async fn cleanup_exact(
        &self,
        repository_id: &[u8],
        branch_id: &[u8],
        resource_hash: &[u8],
        repository_lock_generation: i64,
        branch_lock_generation: i64,
        fence: i64,
    ) -> Result<bool, DomainError> {
        validate_id("repository_id", repository_id)?;
        validate_id("branch_id", branch_id)?;
        validate_hash(resource_hash)?;
        let mut client = self.checkout().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|error| DomainError::from_pg("lock cleanup transaction", error))?;
        let mut sequence = LockSequence::new();
        let namespace = lock_namespace(&tx, &mut sequence, repository_id, branch_id).await?;
        let clock = database_clock(&tx).await?;
        let deleted = tx
            .execute(
                "DELETE FROM lore_locks \
                  WHERE repository = $1 AND branch = $2 AND hash = $3 \
                    AND repository_lock_generation = $4 AND branch_lock_generation = $5 \
                    AND fence = $6 \
                    AND (repository_lock_generation <> $7 OR branch_lock_generation <> $8 \
                         OR expires_at <= $9)",
                &[
                    &repository_id,
                    &branch_id,
                    &resource_hash,
                    &repository_lock_generation,
                    &branch_lock_generation,
                    &fence,
                    &namespace.repository_lock_generation,
                    &namespace.branch_lock_generation,
                    &clock,
                ],
            )
            .await
            .map_err(|error| DomainError::from_pg("exact fenced lock cleanup", error))?;
        classify_commit(tx.commit().await, "fenced lock cleanup commit")?;
        Ok(deleted == 1)
    }

    /// Capture the exact three-scalar handoff, independently of CR-019.
    pub async fn capture_push_witness(
        &self,
        repository_id: &[u8],
        branch_id: &[u8],
    ) -> Result<PushLockWitness, DomainError> {
        validate_id("repository_id", repository_id)?;
        validate_id("branch_id", branch_id)?;
        let client = self.checkout().await?;
        let row = client
            .query_opt(
                "SELECT repository_lock_generation, branch_lock_generation, last_applied_fence \
                   FROM lore_domain_lock_namespaces \
                  WHERE repository_id = $1 AND branch_id = $2",
                &[&repository_id, &branch_id],
            )
            .await
            .map_err(|error| DomainError::from_pg("capture lock witness", error))?
            .ok_or_else(|| {
                DomainError::NotReady(
                    "branch lock namespace is absent; SCHEMA-117 backfill/cutover is incomplete"
                        .to_owned(),
                )
            })?;
        Ok(witness_from_row(&row))
    }

    /// Revalidate the witness inside the caller's final-push transaction.
    pub async fn revalidate_push_witness(
        tx: &Transaction<'_>,
        sequence: &mut LockSequence,
        repository_id: &[u8],
        branch_id: &[u8],
        expected: &PushLockWitness,
    ) -> Result<(), DomainError> {
        let actual = lock_namespace(tx, sequence, repository_id, branch_id).await?;
        let actual = PushLockWitness {
            repository_lock_generation: actual.repository_lock_generation,
            branch_lock_generation: actual.branch_lock_generation,
            branch_lock_namespace_last_applied_fence: actual.last_applied_fence,
        };
        if actual == *expected {
            Ok(())
        } else {
            Err(DomainError::Contention(format!(
                "branch lock witness changed before final publication: expected {expected:?}, \
                 observed {actual:?}; rerun preflight"
            )))
        }
    }

    /// Restartable deterministic legacy-row conversion.
    pub async fn backfill(
        &self,
        issuer_by_subject: &BackfillIssuerMap,
    ) -> Result<BackfillReport, DomainError> {
        let mut client = self.checkout().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|error| DomainError::from_pg("lock backfill transaction", error))?;
        tx.execute(
            "UPDATE lore_domain_lock_schema_state SET backfill_state = $1, updated_at = clock_timestamp() \
              WHERE id = 1 AND backfill_state <> $2",
            &[&schema::BACKFILL_RUNNING, &schema::BACKFILL_COMPLETE],
        )
        .await
        .map_err(|error| DomainError::from_pg("lock backfill state", error))?;
        tx.execute(
            "INSERT INTO lore_domain_lock_namespaces ( \
                 repository_id, branch_id, repository_lock_generation, branch_lock_generation) \
             SELECT branch.repository_id, branch.branch_id, repository.lock_generation, branch.lock_generation \
               FROM lore_domain_branches AS branch \
               JOIN lore_domain_repositories AS repository USING (repository_id) \
              ORDER BY branch.repository_id, branch.branch_id \
             ON CONFLICT (repository_id, branch_id) DO UPDATE SET \
                 repository_lock_generation = EXCLUDED.repository_lock_generation, \
                 branch_lock_generation = EXCLUDED.branch_lock_generation, \
                 updated_at = clock_timestamp()",
            &[],
        )
        .await
        .map_err(|error| DomainError::from_pg("lock namespace backfill", error))?;

        let legacy = tx
            .query(
                "SELECT locks.repository, locks.branch, locks.hash, locks.owner, \
                        namespace.repository_lock_generation, namespace.branch_lock_generation, \
                        repository.state AS repository_state, branch.state AS branch_state \
                   FROM lore_locks AS locks \
              LEFT JOIN lore_domain_lock_namespaces AS namespace \
                     ON namespace.repository_id = locks.repository AND namespace.branch_id = locks.branch \
              LEFT JOIN lore_domain_repositories AS repository ON repository.repository_id = locks.repository \
              LEFT JOIN lore_domain_branches AS branch \
                     ON branch.repository_id = locks.repository AND branch.branch_id = locks.branch \
                  WHERE locks.owner_issuer IS NULL \
                  ORDER BY locks.repository, locks.branch, locks.hash \
                  FOR UPDATE OF locks",
                &[],
            )
            .await
            .map_err(|error| DomainError::from_pg("legacy lock backfill select", error))?;
        let mut converted = 0u64;
        for row in legacy {
            let repository: Vec<u8> = row.get("repository");
            let branch: Vec<u8> = row.get("branch");
            let hash: Vec<u8> = row.get("hash");
            let subject: String = row.get("owner");
            let issuer = issuer_by_subject.get(&subject);
            let repository_state: Option<i16> = row.get("repository_state");
            let branch_state: Option<i16> = row.get("branch_state");
            let repository_generation: Option<i64> = row.get("repository_lock_generation");
            let branch_generation: Option<i64> = row.get("branch_lock_generation");
            let reason = if issuer.is_none() {
                Some("LEGACY_SUBJECT_HAS_NO_REVIEWED_ISSUER")
            } else if repository_state != Some(STATE_LIVE) || branch_state != Some(STATE_LIVE) {
                Some("LEGACY_LOCK_TARGET_IS_MISSING_OR_TOMBSTONED")
            } else if repository_generation.is_none() || branch_generation.is_none() {
                Some("LEGACY_LOCK_NAMESPACE_IS_MISSING")
            } else {
                None
            };
            if let Some(reason) = reason {
                tx.execute(
                    "INSERT INTO lore_domain_lock_backfill_quarantine ( \
                         repository_id, branch_id, resource_hash, legacy_subject, reason) \
                     VALUES ($1, $2, $3, $4, $5) \
                     ON CONFLICT (repository_id, branch_id, resource_hash) DO UPDATE SET \
                         legacy_subject = EXCLUDED.legacy_subject, reason = EXCLUDED.reason",
                    &[&repository, &branch, &hash, &subject, &reason],
                )
                .await
                .map_err(|error| DomainError::from_pg("lock backfill quarantine", error))?;
                continue;
            }
            let fence = next_fence(&tx).await?;
            let mut token = [0u8; 32];
            rand::rng().fill_bytes(&mut token);
            tx.execute(
                "UPDATE lore_locks SET \
                     repository_lock_generation = $4, branch_lock_generation = $5, \
                     owner_issuer = $6, owner_subject = owner, ownership_token = $7, fence = $8, \
                     acquired_at = to_timestamp(locked_at::double precision / 1000.0), \
                     renewed_at = to_timestamp(locked_at::double precision / 1000.0), expires_at = NULL \
                  WHERE repository = $1 AND branch = $2 AND hash = $3 AND owner_issuer IS NULL",
                &[
                    &repository,
                    &branch,
                    &hash,
                    &repository_generation,
                    &branch_generation,
                    &issuer,
                    &token.as_slice(),
                    &fence,
                ],
            )
            .await
            .map_err(|error| DomainError::from_pg("legacy lock backfill update", error))?;
            update_namespace_fence(&tx, &repository, &branch, fence).await?;
            tx.execute(
                "DELETE FROM lore_domain_lock_backfill_quarantine \
                  WHERE repository_id = $1 AND branch_id = $2 AND resource_hash = $3",
                &[&repository, &branch, &hash],
            )
            .await
            .map_err(|error| DomainError::from_pg("resolved lock quarantine delete", error))?;
            converted += 1;
        }
        let quarantined: i64 = tx
            .query_one(
                "SELECT count(*)::bigint FROM lore_domain_lock_backfill_quarantine",
                &[],
            )
            .await
            .map_err(|error| DomainError::from_pg("lock quarantine count", error))?
            .get(0);
        let unfenced: i64 = tx
            .query_one(
                "SELECT count(*)::bigint FROM lore_locks WHERE owner_issuer IS NULL",
                &[],
            )
            .await
            .map_err(|error| DomainError::from_pg("unfenced lock count", error))?
            .get(0);
        let complete = quarantined == 0 && unfenced == 0;
        if complete {
            let headroom = reserve_sequence_headroom(&tx).await?;
            tx.execute(
                "UPDATE lore_domain_lock_schema_state SET \
                     schema_version = $1, backfill_state = $2, backfill_cursor = NULL, \
                     cutover_at = clock_timestamp(), sequence_headroom_fence = $3, \
                     updated_at = clock_timestamp() WHERE id = 1",
                &[
                    &schema::LOCK_SCHEMA_VERSION,
                    &schema::BACKFILL_COMPLETE,
                    &headroom,
                ],
            )
            .await
            .map_err(|error| DomainError::from_pg("lock backfill complete", error))?;
        }
        classify_commit(tx.commit().await, "fenced lock backfill commit")?;
        Ok(BackfillReport {
            converted,
            quarantined: u64::try_from(quarantined).unwrap_or(u64::MAX),
            complete,
        })
    }

    /// Enable fenced routing only after all schema evidence passes.
    ///
    /// Refuses outright until WP-120's public mutation contract exists: see
    /// [`schema::PUBLIC_MUTATION_CONTRACT_AVAILABLE`] for why arming first
    /// produces a cell whose locks are unreleasable while readiness is green.
    /// The check is first so no evidence query can be read as permission.
    pub async fn enable_fencing(&self, lease_enabled: bool) -> Result<(), DomainError> {
        if !schema::PUBLIC_MUTATION_CONTRACT_AVAILABLE {
            return Err(DomainError::NotReady(
                schema::PUBLIC_MUTATION_CONTRACT_MISSING.to_owned(),
            ));
        }
        self.arm_fenced_routing(lease_enabled).await
    }

    /// Arm fenced routing for an isolated component fixture, skipping only the
    /// WP-120 public-contract gate.
    ///
    /// Every schema, backfill, quarantine, database-identity, and sequence-
    /// headroom check still runs, so a fixture proves the same evidence a real
    /// cutover would. This exists because the armed state must stay reachable
    /// under test while [`enable_fencing`](Self::enable_fencing) refuses it in
    /// production; `lore-server/tests/wp117_push_witness_wiring.rs` asserts no
    /// non-test source calls it.
    #[doc(hidden)]
    pub async fn enable_fencing_for_component_fixture(
        &self,
        lease_enabled: bool,
    ) -> Result<(), DomainError> {
        self.arm_fenced_routing(lease_enabled).await
    }

    async fn arm_fenced_routing(&self, lease_enabled: bool) -> Result<(), DomainError> {
        let mut client = self.checkout().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|error| DomainError::from_pg("lock fencing enable transaction", error))?;
        let state = tx
            .query_one(
                "SELECT schema_version, backfill_state, cutover_at, database_identity \
                   FROM lore_domain_lock_schema_state WHERE id = 1 FOR UPDATE",
                &[],
            )
            .await
            .map_err(|error| DomainError::from_pg("lock fencing state", error))?;
        let schema_version: i64 = state.get("schema_version");
        let backfill_state: i16 = state.get("backfill_state");
        let cutover_at: Option<SystemTime> = state.get("cutover_at");
        let database_identity: String = state.get("database_identity");
        if schema_version != schema::LOCK_SCHEMA_VERSION
            || backfill_state != schema::BACKFILL_COMPLETE
            || cutover_at.is_none()
            || database_identity != self.database_identity
        {
            return Err(DomainError::NotReady(format!(
                "lock fencing schema/backfill/database identity is not ready: schema={schema_version}, \
                 backfill={backfill_state}, cutover={}, database_match={}",
                cutover_at.is_some(),
                database_identity == self.database_identity
            )));
        }
        let quarantined: i64 = tx
            .query_one(
                "SELECT count(*)::bigint FROM lore_domain_lock_backfill_quarantine",
                &[],
            )
            .await
            .map_err(|error| DomainError::from_pg("lock fencing quarantine check", error))?
            .get(0);
        if quarantined != 0 {
            return Err(DomainError::NotReady(format!(
                "{quarantined} legacy lock rows remain quarantined"
            )));
        }
        let unfenced: i64 = tx
            .query_one(
                "SELECT count(*)::bigint FROM lore_locks WHERE owner_issuer IS NULL",
                &[],
            )
            .await
            .map_err(|error| DomainError::from_pg("lock fencing unfenced-row check", error))?
            .get(0);
        if unfenced != 0 {
            return Err(DomainError::NotReady(format!(
                "{unfenced} legacy lock rows remain unfenced"
            )));
        }
        let headroom = reserve_sequence_headroom(&tx).await?;
        tx.execute(
            "UPDATE lore_domain_lock_schema_state SET fencing_enabled = true, lease_enabled = $1, \
                    sequence_headroom_fence = $2, updated_at = clock_timestamp() WHERE id = 1",
            &[&lease_enabled, &headroom],
        )
        .await
        .map_err(|error| DomainError::from_pg("lock fencing enable", error))?;
        classify_commit(tx.commit().await, "lock fencing enable commit")
    }

    /// Current database-backed readiness evidence.
    ///
    /// This runs on the mandatory startup path, before the legacy lock-store
    /// plugin has connected, so it must tolerate two absences that are normal
    /// rather than exceptional: a database the SCHEMA-117 migration has not
    /// reached at all (CR-030 N-7 keeps that DDL migration-owned), and a
    /// `lore_locks` table the legacy plugin has not created yet. Both answer
    /// "not provisioned, use the legacy route" — reading them as errors aborted
    /// startup on every unmigrated cell (INV-EE P0-1).
    pub async fn readiness(&self) -> Result<LockFencingReadiness, DomainError> {
        let client = self.checkout().await?;
        if !fenced_schema_present(&client).await? {
            return Ok(LockFencingReadiness::not_provisioned());
        }
        let Some(row) = client
            .query_opt(
                "SELECT schema_version, backfill_state, fencing_enabled, lease_enabled, \
                        database_identity, sequence_headroom_fence \
                   FROM lore_domain_lock_schema_state WHERE id = 1",
                &[],
            )
            .await
            .map_err(|error| DomainError::from_pg("lock fencing readiness", error))?
        else {
            return Ok(LockFencingReadiness::not_provisioned());
        };
        // The legacy lock store creates `lore_locks` after this call in the
        // boot order, so its absence contributes no fences and no legacy rows.
        let legacy_locks_present = relation_present(&client, "lore_locks").await?;
        let max_fence: i64 = client
            .query_one(
                if legacy_locks_present {
                    "SELECT GREATEST( \
                        COALESCE((SELECT max(fence) FROM lore_locks), 0), \
                        COALESCE((SELECT max(last_applied_fence) \
                                    FROM lore_domain_lock_namespaces), 0))"
                } else {
                    "SELECT COALESCE((SELECT max(last_applied_fence) \
                                        FROM lore_domain_lock_namespaces), 0)"
                },
                &[],
            )
            .await
            .map_err(|error| DomainError::from_pg("lock fence maximum", error))?
            .get(0);
        let quarantined_rows: i64 = client
            .query_one(
                "SELECT count(*)::bigint FROM lore_domain_lock_backfill_quarantine",
                &[],
            )
            .await
            .map_err(|error| DomainError::from_pg("lock quarantine readiness", error))?
            .get(0);
        let unfenced_rows: i64 = if legacy_locks_present {
            client
                .query_one(
                    "SELECT count(*)::bigint FROM lore_locks \
                      WHERE repository_lock_generation IS NULL \
                         OR branch_lock_generation IS NULL \
                         OR owner_issuer IS NULL OR owner_subject IS NULL \
                         OR ownership_token IS NULL OR fence IS NULL \
                         OR acquired_at IS NULL OR renewed_at IS NULL",
                    &[],
                )
                .await
                .map_err(|error| DomainError::from_pg("unfenced lock readiness", error))?
                .get(0)
        } else {
            0
        };
        let evidence: Option<i64> = row.get("sequence_headroom_fence");
        let sequence = client
            .query_one(
                "SELECT last_value, is_called FROM lore_domain_lock_fence_seq",
                &[],
            )
            .await
            .map_err(|error| DomainError::from_pg("lock fence sequence readiness", error))?;
        let last_value: i64 = sequence.get("last_value");
        let is_called: bool = sequence.get("is_called");
        let next_value = if is_called {
            last_value.checked_add(1)
        } else {
            Some(last_value)
        };
        Ok(LockFencingReadiness {
            provisioned: true,
            schema_version: row.get("schema_version"),
            backfill_state: row.get("backfill_state"),
            fencing_enabled: row.get("fencing_enabled"),
            lease_enabled: row.get("lease_enabled"),
            same_database: row.get::<_, String>("database_identity") == self.database_identity,
            sequence_headroom: evidence.is_some()
                && next_value.is_some_and(|value| value > max_fence),
            quarantined_rows,
            unfenced_rows,
        })
    }

    async fn checkout(&self) -> Result<deadpool_postgres::Client, DomainError> {
        self.pool
            .get()
            .await
            .map_err(|error| DomainError::from_pool("lock coordinator pool", error))
    }
}

/// The migration-owned SCHEMA-117 relations `readiness` reads, excluding the
/// legacy `lore_locks` table the lock-store plugin creates later in boot.
const FENCED_SCHEMA_RELATIONS: [&str; 4] = [
    "lore_domain_lock_schema_state",
    "lore_domain_lock_namespaces",
    "lore_domain_lock_backfill_quarantine",
    "lore_domain_lock_fence_seq",
];

async fn relation_present(
    client: &deadpool_postgres::Client,
    relation: &str,
) -> Result<bool, DomainError> {
    client
        .query_one("SELECT to_regclass($1) IS NOT NULL", &[&relation])
        .await
        .map_err(|error| DomainError::from_pg("lock relation probe", error))
        .map(|row| row.get(0))
}

async fn fenced_schema_present(client: &deadpool_postgres::Client) -> Result<bool, DomainError> {
    let present: i64 = client
        .query_one(
            "SELECT count(*)::bigint FROM unnest($1::text[]) AS relation \
              WHERE to_regclass(relation) IS NOT NULL",
            &[&FENCED_SCHEMA_RELATIONS.as_slice()],
        )
        .await
        .map_err(|error| DomainError::from_pg("fenced lock schema probe", error))?
        .get(0);
    Ok(present == FENCED_SCHEMA_RELATIONS.len() as i64)
}

enum BeginAdmitted<'a> {
    Admitted(deadpool_postgres::Transaction<'a>, SystemTime),
    Committed(DomainOutcome, Option<Vec<u8>>),
    Rejected,
}

async fn begin_admitted<'a>(
    client: &'a mut deadpool_postgres::Client,
    operation: &GovernedOperation,
    sequence: &mut LockSequence,
) -> Result<BeginAdmitted<'a>, DomainError> {
    let tx = client
        .transaction()
        .await
        .map_err(|error| DomainError::from_pg("lock transaction begin", error))?;
    sequence.enter(LockClass::OperationReceipt)?;
    match receipts::consume(
        &tx,
        &operation.key,
        &operation.binding,
        &operation.prepare_token,
    )
    .await?
    {
        ConsumeResult::Admitted(admitted) => {
            Ok(BeginAdmitted::Admitted(tx, admitted.admission_clock))
        }
        ConsumeResult::Committed {
            outcome,
            public_result,
        } => {
            classify_commit(tx.commit().await, "lock admission replay commit")?;
            Ok(BeginAdmitted::Committed(outcome, public_result))
        }
        ConsumeResult::Rejected => {
            drop(tx);
            Ok(BeginAdmitted::Rejected)
        }
    }
}

#[derive(Debug)]
struct NamespaceRow {
    repository_lock_generation: i64,
    branch_lock_generation: i64,
    last_applied_fence: i64,
}

async fn lock_namespace(
    tx: &Transaction<'_>,
    sequence: &mut LockSequence,
    repository_id: &[u8],
    branch_id: &[u8],
) -> Result<NamespaceRow, DomainError> {
    sequence.enter(LockClass::LockNamespace)?;
    let row = tx
        .query_opt(
            "SELECT repository_lock_generation, branch_lock_generation, last_applied_fence \
               FROM lore_domain_lock_namespaces \
              WHERE repository_id = $1 AND branch_id = $2 FOR UPDATE",
            &[&repository_id, &branch_id],
        )
        .await
        .map_err(|error| DomainError::from_pg("branch lock namespace", error))?
        .ok_or_else(|| {
            DomainError::NotReady(
                "branch lock namespace is absent; SCHEMA-117 backfill/cutover is incomplete"
                    .to_owned(),
            )
        })?;
    Ok(NamespaceRow {
        repository_lock_generation: row.get("repository_lock_generation"),
        branch_lock_generation: row.get("branch_lock_generation"),
        last_applied_fence: row.get("last_applied_fence"),
    })
}

#[derive(Debug)]
struct LockRow {
    resource_hash: Vec<u8>,
    owner: VerifiedLockOwner,
    ownership_token: Vec<u8>,
    fence: i64,
    repository_lock_generation: i64,
    branch_lock_generation: i64,
    acquired_at: SystemTime,
    expires_at: Option<SystemTime>,
}

async fn load_resource_rows(
    tx: &Transaction<'_>,
    repository_id: &[u8],
    branch_id: &[u8],
    hashes: &[&[u8]],
) -> Result<Vec<LockRow>, DomainError> {
    let rows = tx
        .query(
            "SELECT hash, owner_issuer, owner_subject, ownership_token, fence, \
                    repository_lock_generation, branch_lock_generation, acquired_at, expires_at \
               FROM lore_locks \
              WHERE repository = $1 AND branch = $2 AND hash = ANY($3) \
              ORDER BY hash FOR UPDATE",
            &[&repository_id, &branch_id, &hashes],
        )
        .await
        .map_err(|error| DomainError::from_pg("fenced lock rows", error))?;
    rows.into_iter()
        .map(|row| {
            let issuer: Option<String> = row.get("owner_issuer");
            let subject: Option<String> = row.get("owner_subject");
            let token: Option<Vec<u8>> = row.get("ownership_token");
            let repository_generation: Option<i64> = row.get("repository_lock_generation");
            let branch_generation: Option<i64> = row.get("branch_lock_generation");
            let acquired_at: Option<SystemTime> = row.get("acquired_at");
            Ok(LockRow {
                resource_hash: row.get("hash"),
                owner: VerifiedLockOwner {
                    verified_issuer: issuer.ok_or_else(|| {
                        DomainError::NotReady(
                            "legacy unfenced lock row reached fenced routing".to_owned(),
                        )
                    })?,
                    authenticated_subject: subject.ok_or_else(|| {
                        DomainError::NotReady(
                            "legacy unfenced lock row reached fenced routing".to_owned(),
                        )
                    })?,
                },
                ownership_token: token.ok_or_else(|| {
                    DomainError::NotReady(
                        "legacy unfenced lock row reached fenced routing".to_owned(),
                    )
                })?,
                fence: row.get::<_, Option<i64>>("fence").ok_or_else(|| {
                    DomainError::NotReady(
                        "legacy unfenced lock row reached fenced routing".to_owned(),
                    )
                })?,
                repository_lock_generation: repository_generation.ok_or_else(|| {
                    DomainError::NotReady(
                        "legacy unfenced lock row reached fenced routing".to_owned(),
                    )
                })?,
                branch_lock_generation: branch_generation.ok_or_else(|| {
                    DomainError::NotReady(
                        "legacy unfenced lock row reached fenced routing".to_owned(),
                    )
                })?,
                acquired_at: acquired_at.ok_or_else(|| {
                    DomainError::NotReady(
                        "legacy unfenced lock row reached fenced routing".to_owned(),
                    )
                })?,
                expires_at: row.get("expires_at"),
            })
        })
        .collect()
}

fn row_is_current(row: &LockRow, namespace: &NamespaceRow, clock: SystemTime) -> bool {
    row.repository_lock_generation == namespace.repository_lock_generation
        && row.branch_lock_generation == namespace.branch_lock_generation
        && row.expires_at.is_none_or(|expiry| expiry > clock)
}

#[allow(clippy::too_many_arguments)]
async fn upsert_fenced_lock(
    tx: &Transaction<'_>,
    repository_id: &[u8],
    branch_id: &[u8],
    resource: &LockResourceInput,
    owner: &VerifiedLockOwner,
    acting_owner: Option<&VerifiedLockOwner>,
    namespace: &NamespaceRow,
    token: &[u8; 32],
    fence: i64,
    acquired_at: SystemTime,
    renewed_at: SystemTime,
    expires_at: Option<SystemTime>,
) -> Result<(), DomainError> {
    let locked_at = renewed_at
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| DomainError::Internal("database lock clock predates Unix epoch".to_owned()))?
        .as_millis();
    let locked_at = i64::try_from(locked_at)
        .map_err(|_| DomainError::Internal("database lock clock exceeds i64 millis".to_owned()))?;
    tx.execute(
        "INSERT INTO lore_locks ( \
             repository, branch, hash, owner, description, locked_at, \
             repository_lock_generation, branch_lock_generation, owner_issuer, owner_subject, \
             acting_issuer, acting_subject, ownership_token, fence, acquired_at, renewed_at, expires_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) \
         ON CONFLICT (repository, branch, hash) DO UPDATE SET \
             owner = EXCLUDED.owner, description = EXCLUDED.description, locked_at = EXCLUDED.locked_at, \
             repository_lock_generation = EXCLUDED.repository_lock_generation, \
             branch_lock_generation = EXCLUDED.branch_lock_generation, \
             owner_issuer = EXCLUDED.owner_issuer, owner_subject = EXCLUDED.owner_subject, \
             acting_issuer = EXCLUDED.acting_issuer, acting_subject = EXCLUDED.acting_subject, \
             ownership_token = EXCLUDED.ownership_token, fence = EXCLUDED.fence, \
             acquired_at = EXCLUDED.acquired_at, renewed_at = EXCLUDED.renewed_at, \
             expires_at = EXCLUDED.expires_at",
        &[
            &repository_id,
            &branch_id,
            &resource.resource_hash,
            &owner.authenticated_subject,
            &resource.description,
            &locked_at,
            &namespace.repository_lock_generation,
            &namespace.branch_lock_generation,
            &owner.verified_issuer,
            &owner.authenticated_subject,
            &acting_owner.map(|value| value.verified_issuer.as_str()),
            &acting_owner.map(|value| value.authenticated_subject.as_str()),
            &token.as_slice(),
            &fence,
            &acquired_at,
            &renewed_at,
            &expires_at,
        ],
    )
    .await
    .map_err(|error| DomainError::from_pg("fenced lock upsert", error))?;
    Ok(())
}

async fn next_fence(tx: &Transaction<'_>) -> Result<i64, DomainError> {
    tx.query_one("SELECT nextval('lore_domain_lock_fence_seq')", &[])
        .await
        .map_err(|error| DomainError::from_pg("lock fence allocation", error))
        .map(|row| row.get(0))
}

async fn reserve_sequence_headroom(tx: &Transaction<'_>) -> Result<i64, DomainError> {
    let max_fence: i64 = tx
        .query_one(
            "SELECT GREATEST( \
                COALESCE((SELECT max(fence) FROM lore_locks), 0), \
                COALESCE((SELECT max(last_applied_fence) FROM lore_domain_lock_namespaces), 0))",
            &[],
        )
        .await
        .map_err(|error| DomainError::from_pg("lock fence maximum", error))?
        .get(0);
    let mut headroom = next_fence(tx).await?;
    if headroom <= max_fence {
        tx.query_one(
            "SELECT setval('lore_domain_lock_fence_seq', $1, true)",
            &[&max_fence],
        )
        .await
        .map_err(|error| DomainError::from_pg("lock fence sequence restore", error))?;
        headroom = next_fence(tx).await?;
    }
    if headroom <= max_fence {
        return Err(DomainError::NotReady(format!(
            "lock fence sequence head {headroom} is not above persisted maximum {max_fence}"
        )));
    }
    Ok(headroom)
}

async fn database_clock(tx: &Transaction<'_>) -> Result<SystemTime, DomainError> {
    tx.query_one("SELECT clock_timestamp()", &[])
        .await
        .map_err(|error| DomainError::from_pg("lock lease clock", error))
        .map(|row| row.get(0))
}

async fn update_namespace_fence(
    tx: &Transaction<'_>,
    repository_id: &[u8],
    branch_id: &[u8],
    fence: i64,
) -> Result<(), DomainError> {
    tx.execute(
        "UPDATE lore_domain_lock_namespaces \
            SET last_applied_fence = $3, updated_at = clock_timestamp() \
          WHERE repository_id = $1 AND branch_id = $2 AND last_applied_fence <= $3",
        &[&repository_id, &branch_id, &fence],
    )
    .await
    .map_err(|error| DomainError::from_pg("lock namespace fence update", error))?;
    Ok(())
}

async fn append_event(
    tx: &Transaction<'_>,
    sequence: &mut LockSequence,
    repository_id: &[u8],
    repository_generation: i64,
    event: Option<&PendingEvent>,
) -> Result<(), DomainError> {
    let Some(event) = event else { return Ok(()) };
    sequence.enter(LockClass::OutboxInsert)?;
    outbox::append(
        tx,
        &outbox::OutboxEvent {
            cell_id: &event.cell_id,
            repository_id,
            repository_generation,
            event_kind: &event.event_kind,
            aggregate_kind: &event.aggregate_kind,
            aggregate_id: &event.aggregate_id,
            aggregate_version: &event.aggregate_version,
            payload_schema_version: event.payload_schema_version,
            payload: &event.payload,
        },
    )
    .await?;
    Ok(())
}

async fn commit_rejection(
    tx: deadpool_postgres::Transaction<'_>,
    operation: &GovernedOperation,
    admission_clock: SystemTime,
    rejection: LockRejection,
) -> Result<LockMutationResult, DomainError> {
    let reason = rejection_reason(rejection);
    let outcome = DomainOutcome::NotApplied {
        reason_version: 1,
        reason: reason.to_owned(),
    };
    receipts::commit_terminal(
        &tx,
        &operation.key,
        &outcome,
        Some(reason.as_bytes()),
        admission_clock,
    )
    .await?;
    classify_commit(tx.commit().await, "fenced lock rejection commit")?;
    Ok(LockMutationResult {
        outcome,
        locks: Vec::new(),
        rejection: Some(rejection),
        replayed: false,
    })
}

fn rejection_reason(rejection: LockRejection) -> &'static str {
    match rejection {
        LockRejection::NotFound => REASON_NOT_FOUND,
        LockRejection::ForeignOwner => REASON_FOREIGN_OWNER,
        LockRejection::AuthorityMismatch | LockRejection::AdmissionRejected => {
            REASON_AUTHORITY_MISMATCH
        }
        LockRejection::NamespaceMismatch => REASON_NAMESPACE_MISMATCH,
    }
}

fn replayed(outcome: DomainOutcome, locks: Vec<FencedLock>) -> LockMutationResult {
    LockMutationResult {
        outcome,
        locks,
        rejection: None,
        replayed: true,
    }
}

fn admission_rejected() -> LockMutationResult {
    LockMutationResult {
        outcome: DomainOutcome::NotApplied {
            reason_version: 1,
            reason: REASON_AUTHORITY_MISMATCH.to_owned(),
        },
        locks: Vec::new(),
        rejection: Some(LockRejection::AdmissionRejected),
        replayed: false,
    }
}

fn validate_common(
    operation: &GovernedOperation,
    repository_id: &[u8],
    branch_id: &[u8],
    owner: &VerifiedLockOwner,
    resources: &[LockResourceInput],
) -> Result<(), DomainError> {
    validate_lock_target(operation, repository_id, branch_id, owner)?;
    sorted_resources(resources).map(|_| ())
}

fn validate_lock_target(
    operation: &GovernedOperation,
    repository_id: &[u8],
    branch_id: &[u8],
    owner: &VerifiedLockOwner,
) -> Result<(), DomainError> {
    validate_id("repository_id", repository_id)?;
    validate_id("branch_id", branch_id)?;
    validate_owner(owner)?;
    if operation.key.tenant_scope_key != lock_tenant_scope_key(repository_id, branch_id)? {
        return Err(DomainError::InvalidInput(
            "lock receipt tenant scope does not match the target repository/branch".to_owned(),
        ));
    }
    Ok(())
}

fn validate_operation_binding(
    operation: &GovernedOperation,
    expected: &OperationBinding,
    principal: &VerifiedLockOwner,
) -> Result<(), DomainError> {
    if operation.key.verified_issuer != principal.verified_issuer
        || operation.key.authenticated_subject != principal.authenticated_subject
    {
        return Err(DomainError::InvalidInput(
            "lock receipt principal does not match the acting verified owner".to_owned(),
        ));
    }
    if operation.binding.method != expected.method
        || operation.binding.scope != expected.scope
        || operation.binding.fingerprint_version != expected.fingerprint_version
        || operation.binding.fingerprint != expected.fingerprint
        || operation.binding.canonical_intent_digest != expected.canonical_intent_digest
    {
        return Err(DomainError::InvalidInput(
            "lock receipt binding does not match the typed lock intent".to_owned(),
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn lock_binding(
    method: &str,
    repository_id: &[u8],
    branch_id: &[u8],
    target_owner: &VerifiedLockOwner,
    acting_owner: Option<&VerifiedLockOwner>,
    resources: &[LockResourceInput],
    lease_duration: Option<Duration>,
    force: bool,
) -> Result<OperationBinding, DomainError> {
    validate_id("repository_id", repository_id)?;
    validate_id("branch_id", branch_id)?;
    validate_owner(target_owner)?;
    if let Some(actor) = acting_owner {
        validate_owner(actor)?;
    }
    let scope = lock_tenant_scope_key(repository_id, branch_id)?;
    let mut body = Vec::new();
    append_framed(&mut body, method.as_bytes())?;
    append_framed(&mut body, &scope)?;
    append_framed(&mut body, target_owner.verified_issuer.as_bytes())?;
    append_framed(&mut body, target_owner.authenticated_subject.as_bytes())?;
    match acting_owner {
        Some(actor) => {
            body.push(1);
            append_framed(&mut body, actor.verified_issuer.as_bytes())?;
            append_framed(&mut body, actor.authenticated_subject.as_bytes())?;
        }
        None => body.push(0),
    }
    body.push(u8::from(force));
    body.extend_from_slice(
        &lease_duration
            .map(|duration| u64::try_from(duration.as_millis()))
            .transpose()
            .map_err(|_| DomainError::InvalidInput("lease milliseconds exceed u64".to_owned()))?
            .unwrap_or(0)
            .to_be_bytes(),
    );
    body.extend_from_slice(
        &u32::try_from(resources.len())
            .map_err(|_| DomainError::InvalidInput("too many lock resources".to_owned()))?
            .to_be_bytes(),
    );
    for resource in resources {
        append_framed(&mut body, &resource.resource_hash)?;
        append_framed(&mut body, resource.description.as_bytes())?;
        match resource.expected_ownership_token {
            Some(token) => {
                body.push(1);
                body.extend_from_slice(&token);
            }
            None => body.push(0),
        }
    }
    let fingerprint = blake3::hash(&[b"lock-fingerprint-v1\0".as_slice(), &body].concat())
        .as_bytes()
        .to_vec();
    let canonical_intent_digest =
        blake3::hash(&[b"lock-canonical-intent-v1\0".as_slice(), &body].concat())
            .as_bytes()
            .to_vec();
    Ok(OperationBinding {
        method: method.to_owned(),
        scope,
        fingerprint_version: 1,
        fingerprint,
        canonical_intent_digest,
    })
}

fn append_framed(target: &mut Vec<u8>, value: &[u8]) -> Result<(), DomainError> {
    target.extend_from_slice(
        &u32::try_from(value.len())
            .map_err(|_| DomainError::InvalidInput("lock binding field exceeds u32".to_owned()))?
            .to_be_bytes(),
    );
    target.extend_from_slice(value);
    Ok(())
}

fn validate_owner(owner: &VerifiedLockOwner) -> Result<(), DomainError> {
    for (field, value) in [
        ("verified_issuer", owner.verified_issuer.as_bytes()),
        (
            "authenticated_subject",
            owner.authenticated_subject.as_bytes(),
        ),
    ] {
        if value.is_empty() || value.len() > MAX_IDENTITY_BYTES {
            return Err(DomainError::InvalidInput(format!(
                "{field} must be 1..={MAX_IDENTITY_BYTES} UTF-8 bytes"
            )));
        }
    }
    Ok(())
}

fn validate_lease_duration(lease_duration: Option<Duration>) -> Result<(), DomainError> {
    if let Some(lease) = lease_duration
        && (lease < Duration::from_millis(1)
            || lease > MAX_LEASE
            || lease.subsec_nanos() % 1_000_000 != 0)
    {
        return Err(DomainError::InvalidInput(format!(
            "lease duration must be whole milliseconds in 1ms..={}ms",
            MAX_LEASE.as_millis()
        )));
    }
    Ok(())
}

fn validate_canonical_result_capacity(
    input: &AcquireOrRenewInput,
    resources: &[LockResourceInput],
) -> Result<(), DomainError> {
    let mut size = b"lock-result-v1\0".len() + size_of::<u32>();
    let expiry_size = if input.lease_duration.is_some() {
        12
    } else {
        0
    };
    for resource in resources {
        let fixed = 4
            + input.branch_id.len()
            + RESOURCE_HASH_BYTES
            + 4
            + 4
            + 4
            + 32
            + 3 * size_of::<i64>()
            + 12
            + 1
            + expiry_size;
        size = size
            .checked_add(fixed)
            .and_then(|value| value.checked_add(resource.description.len()))
            .and_then(|value| value.checked_add(input.owner.verified_issuer.len()))
            .and_then(|value| value.checked_add(input.owner.authenticated_subject.len()))
            .ok_or_else(|| DomainError::InvalidInput("lock result size overflows".to_owned()))?;
    }
    if size > receipts::PUBLIC_RESULT_MAX_BYTES {
        return Err(DomainError::InvalidInput(format!(
            "encoded lock result would exceed the receipt public-result limit of {} bytes",
            receipts::PUBLIC_RESULT_MAX_BYTES
        )));
    }
    Ok(())
}

fn validate_id(field: &str, value: &[u8]) -> Result<(), DomainError> {
    if value.len() != 16 {
        return Err(DomainError::InvalidInput(format!(
            "{field} must be 16 bytes, got {}",
            value.len()
        )));
    }
    Ok(())
}

fn validate_hash(value: &[u8]) -> Result<(), DomainError> {
    if value.len() != RESOURCE_HASH_BYTES {
        return Err(DomainError::InvalidInput(format!(
            "resource_hash must be {RESOURCE_HASH_BYTES} bytes, got {}",
            value.len()
        )));
    }
    Ok(())
}

fn sorted_resources(
    resources: &[LockResourceInput],
) -> Result<Vec<LockResourceInput>, DomainError> {
    if resources.is_empty() || resources.len() > MAX_BATCH_RESOURCES {
        return Err(DomainError::InvalidInput(format!(
            "lock resource batch must contain 1..={MAX_BATCH_RESOURCES} entries"
        )));
    }
    let mut ordered = resources.to_vec();
    ordered.sort_by(|left, right| left.resource_hash.cmp(&right.resource_hash));
    for resource in &ordered {
        validate_hash(&resource.resource_hash)?;
        if resource.description.len() > MAX_DESCRIPTION_BYTES {
            return Err(DomainError::InvalidInput(format!(
                "lock description exceeds {MAX_DESCRIPTION_BYTES} bytes"
            )));
        }
    }
    if ordered
        .windows(2)
        .any(|pair| pair[0].resource_hash == pair[1].resource_hash)
    {
        return Err(DomainError::InvalidInput(
            "lock resource batch contains a duplicate hash".to_owned(),
        ));
    }
    Ok(ordered)
}

fn sorted_resources_allow_empty(
    resources: &[LockResourceInput],
) -> Result<Vec<LockResourceInput>, DomainError> {
    if resources.is_empty() {
        Ok(Vec::new())
    } else {
        sorted_resources(resources)
    }
}

fn token_matches(stored: &[u8], expected: &[u8; 32]) -> bool {
    stored.len() == 32 && bool::from(stored.ct_eq(expected.as_slice()))
}

fn canonical_result(locks: &[FencedLock]) -> Result<Vec<u8>, DomainError> {
    let mut bytes = Vec::with_capacity(16 + locks.len() * 192);
    bytes.extend_from_slice(b"lock-result-v1\0");
    bytes.extend_from_slice(&(locks.len() as u32).to_be_bytes());
    for lock in locks {
        append_result_field(&mut bytes, &lock.branch_id);
        bytes.extend_from_slice(&lock.resource_hash);
        append_result_field(&mut bytes, lock.description.as_bytes());
        append_result_field(&mut bytes, lock.owner.verified_issuer.as_bytes());
        append_result_field(&mut bytes, lock.owner.authenticated_subject.as_bytes());
        bytes.extend_from_slice(&lock.ownership_token);
        bytes.extend_from_slice(&lock.fence.to_be_bytes());
        bytes.extend_from_slice(&lock.repository_lock_generation.to_be_bytes());
        bytes.extend_from_slice(&lock.branch_lock_generation.to_be_bytes());
        append_system_time(&mut bytes, lock.acquired_at)?;
        match lock.expires_at {
            Some(expires_at) => {
                bytes.push(1);
                append_system_time(&mut bytes, expires_at)?;
            }
            None => bytes.push(0),
        }
    }
    if bytes.len() > receipts::PUBLIC_RESULT_MAX_BYTES {
        return Err(DomainError::InvalidInput(format!(
            "encoded lock result exceeds the receipt public-result limit of {} bytes",
            receipts::PUBLIC_RESULT_MAX_BYTES
        )));
    }
    Ok(bytes)
}

fn append_result_field(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u32).to_be_bytes());
    target.extend_from_slice(value);
}

fn append_system_time(target: &mut Vec<u8>, value: SystemTime) -> Result<(), DomainError> {
    let duration = value
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| DomainError::Internal("database lock timestamp predates epoch".to_owned()))?;
    target.extend_from_slice(&duration.as_secs().to_be_bytes());
    target.extend_from_slice(&duration.subsec_nanos().to_be_bytes());
    Ok(())
}

fn decode_canonical_result(bytes: &[u8]) -> Result<Vec<FencedLock>, DomainError> {
    let mut reader = ResultReader::new(bytes);
    reader.expect_bytes(b"lock-result-v1\0")?;
    let count = usize::try_from(reader.u32()?)
        .map_err(|_| DomainError::Internal("stored lock result count exceeds usize".to_owned()))?;
    if count > MAX_BATCH_RESOURCES {
        return Err(DomainError::Internal(format!(
            "stored lock result count {count} exceeds {MAX_BATCH_RESOURCES}"
        )));
    }
    let mut locks = Vec::with_capacity(count);
    for _ in 0..count {
        let branch_id = reader.field(16)?;
        let resource_hash = reader.exact(RESOURCE_HASH_BYTES)?.to_vec();
        let description = reader.string(MAX_DESCRIPTION_BYTES)?;
        let verified_issuer = reader.string(MAX_IDENTITY_BYTES)?;
        let authenticated_subject = reader.string(MAX_IDENTITY_BYTES)?;
        let ownership_token = reader
            .exact(32)?
            .try_into()
            .map_err(|_| DomainError::Internal("stored lock token width changed".to_owned()))?;
        let fence = reader.i64()?;
        let repository_lock_generation = reader.i64()?;
        let branch_lock_generation = reader.i64()?;
        let acquired_at = reader.system_time()?;
        let expires_at = match reader.byte()? {
            0 => None,
            1 => Some(reader.system_time()?),
            value => {
                return Err(DomainError::Internal(format!(
                    "stored lock expiry presence is {value}, expected 0 or 1"
                )));
            }
        };
        locks.push(FencedLock {
            branch_id,
            resource_hash,
            description,
            owner: VerifiedLockOwner {
                verified_issuer,
                authenticated_subject,
            },
            ownership_token,
            fence,
            repository_lock_generation,
            branch_lock_generation,
            acquired_at,
            expires_at,
        });
    }
    if !reader.is_empty() {
        return Err(DomainError::Internal(
            "stored lock result has trailing bytes".to_owned(),
        ));
    }
    Ok(locks)
}

struct ResultReader<'a> {
    remaining: &'a [u8],
}

impl<'a> ResultReader<'a> {
    fn new(remaining: &'a [u8]) -> Self {
        Self { remaining }
    }

    fn exact(&mut self, len: usize) -> Result<&'a [u8], DomainError> {
        if self.remaining.len() < len {
            return Err(DomainError::Internal(
                "stored lock result is truncated".to_owned(),
            ));
        }
        let (value, remaining) = self.remaining.split_at(len);
        self.remaining = remaining;
        Ok(value)
    }

    fn expect_bytes(&mut self, expected: &[u8]) -> Result<(), DomainError> {
        if self.exact(expected.len())? != expected {
            return Err(DomainError::Internal(
                "stored lock result has an unsupported version".to_owned(),
            ));
        }
        Ok(())
    }

    fn byte(&mut self) -> Result<u8, DomainError> {
        Ok(self.exact(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, DomainError> {
        Ok(u32::from_be_bytes(self.exact(4)?.try_into().map_err(
            |_| DomainError::Internal("stored lock u32 is truncated".to_owned()),
        )?))
    }

    fn i64(&mut self) -> Result<i64, DomainError> {
        Ok(i64::from_be_bytes(self.exact(8)?.try_into().map_err(
            |_| DomainError::Internal("stored lock i64 is truncated".to_owned()),
        )?))
    }

    fn system_time(&mut self) -> Result<SystemTime, DomainError> {
        let secs = u64::from_be_bytes(self.exact(8)?.try_into().map_err(|_| {
            DomainError::Internal("stored lock timestamp seconds are truncated".to_owned())
        })?);
        let nanos = u32::from_be_bytes(self.exact(4)?.try_into().map_err(|_| {
            DomainError::Internal("stored lock timestamp nanos are truncated".to_owned())
        })?);
        if nanos >= 1_000_000_000 {
            return Err(DomainError::Internal(
                "stored lock timestamp nanos are out of range".to_owned(),
            ));
        }
        SystemTime::UNIX_EPOCH
            .checked_add(Duration::new(secs, nanos))
            .ok_or_else(|| DomainError::Internal("stored lock timestamp overflows".to_owned()))
    }

    fn field(&mut self, max: usize) -> Result<Vec<u8>, DomainError> {
        let len = usize::try_from(self.u32()?)
            .map_err(|_| DomainError::Internal("stored lock field exceeds usize".to_owned()))?;
        if len > max {
            return Err(DomainError::Internal(format!(
                "stored lock field length {len} exceeds {max}"
            )));
        }
        Ok(self.exact(len)?.to_vec())
    }

    fn string(&mut self, max: usize) -> Result<String, DomainError> {
        String::from_utf8(self.field(max)?)
            .map_err(|_| DomainError::Internal("stored lock string is not UTF-8".to_owned()))
    }

    fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

fn witness_from_row(row: &tokio_postgres::Row) -> PushLockWitness {
    PushLockWitness {
        repository_lock_generation: row.get("repository_lock_generation"),
        branch_lock_generation: row.get("branch_lock_generation"),
        branch_lock_namespace_last_applied_fence: row.get("last_applied_fence"),
    }
}

fn fenced_lock_from_row(row: tokio_postgres::Row) -> Result<FencedLock, DomainError> {
    let token: Vec<u8> = row.get("ownership_token");
    let ownership_token: [u8; 32] = token.try_into().map_err(|value: Vec<u8>| {
        DomainError::Internal(format!(
            "stored ownership token is {} bytes, expected 32",
            value.len()
        ))
    })?;
    Ok(FencedLock {
        branch_id: row.get("branch"),
        resource_hash: row.get("hash"),
        description: row.get("description"),
        owner: VerifiedLockOwner {
            verified_issuer: row.get("owner_issuer"),
            authenticated_subject: row.get("owner_subject"),
        },
        ownership_token,
        fence: row.get("fence"),
        repository_lock_generation: row.get("repository_lock_generation"),
        branch_lock_generation: row.get("branch_lock_generation"),
        acquired_at: row.get("acquired_at"),
        expires_at: row.get("expires_at"),
    })
}

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Governed-operation and repository/branch/lock fixtures.
//!
//! Every mutating coordinator method in this crate is CR-029 governed: it needs
//! a prepared receipt whose binding matches the input it is called with. That
//! admission is not what WP-109 is proving, so it lives here rather than in the
//! cases.
//!
//! Two things a reader should not mistake for incidental:
//!
//! - a receipt is **per attempt**, so each racer prepares its own. Two racers
//!   sharing one `GovernedOperation` would be testing CR-029's exact-retry
//!   replay, not a race, and the second caller would get a replayed outcome
//!   rather than contending;
//! - a lock operation's `ReceiptKey` carries the canonical
//!   `lock_tenant_scope_key(repository, branch)`, not a random scope. The
//!   coordinator validates the binding against that exact scope.

#![allow(dead_code)]

use std::time::SystemTime;

use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::coordinator::BranchPushCommitInput;
use lore_postgres::domain::coordinator::DomainTransactionStore;
use lore_postgres::domain::coordinator::GovernedOperation;
use lore_postgres::domain::coordinator::RepositoryCreateInput;
use lore_postgres::domain::coordinator::RepositoryDeleteInput;
use lore_postgres::domain::errors::DomainOutcome;
use lore_postgres::domain::locks::AcquireOrRenewInput;
use lore_postgres::domain::locks::LockResourceInput;
use lore_postgres::domain::locks::VerifiedLockOwner;
use lore_postgres::domain::locks::lock_tenant_scope_key;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptKey;
use uuid::NoContext;
use uuid::Timestamp;
use uuid::Uuid;

use super::tally::Identities;

fn uuid_v7_at(time: SystemTime) -> Uuid {
    let elapsed = time
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("receipt clock follows the epoch");
    Uuid::new_v7(Timestamp::from_unix(
        NoContext,
        elapsed.as_secs(),
        elapsed.subsec_nanos(),
    ))
}

/// A caller-known binding for `method`. Distinct per call, so two racers never
/// look like an exact retry of each other.
pub fn binding(method: &str, ids: &mut Identities) -> OperationBinding {
    OperationBinding {
        method: method.to_owned(),
        scope: ids.id16().to_vec(),
        fingerprint_version: 1,
        fingerprint: ids.id32().to_vec(),
        canonical_intent_digest: ids.id32().to_vec(),
    }
}

/// Prepare one fresh governed operation in its own receipt namespace.
pub async fn admitted(
    store: &PostgresDomainStore,
    method: &str,
    ids: &mut Identities,
) -> GovernedOperation {
    let clock = store
        .domain_operation_clock_get()
        .await
        .expect("read the authoritative receipt clock");
    let key = ReceiptKey {
        verified_issuer: format!("https://issuer.example/wp109/{:016x}", ids.id16()[0]),
        authenticated_subject: "svc:wp109-proof".to_owned(),
        tenant_scope_key: ids.id16().to_vec(),
        operation_id: uuid_v7_at(clock),
    };
    let binding = binding(method, ids);
    let prepared = store
        .domain_operation_prepare(&key, &binding, None, None)
        .await
        .expect("prepare governed operation");
    let PrepareResult::Prepared { token, .. } = prepared else {
        panic!("an admissible operation must prepare, got {prepared:?}");
    };
    GovernedOperation {
        key,
        binding,
        prepare_token: token,
    }
}

/// Prepare a lock operation bound to the canonical lock tenant scope.
pub async fn admitted_lock(
    store: &PostgresDomainStore,
    owner: &VerifiedLockOwner,
    repository_id: &[u8],
    branch_id: &[u8],
    binding: OperationBinding,
) -> GovernedOperation {
    let clock = store
        .domain_operation_clock_get()
        .await
        .expect("read the authoritative receipt clock");
    let key = ReceiptKey {
        verified_issuer: owner.verified_issuer.clone(),
        authenticated_subject: owner.authenticated_subject.clone(),
        tenant_scope_key: lock_tenant_scope_key(repository_id, branch_id)
            .expect("canonical lock tenant scope"),
        operation_id: uuid_v7_at(clock),
    };
    let prepared = store
        .domain_operation_prepare(&key, &binding, None, None)
        .await
        .expect("prepare lock operation");
    let PrepareResult::Prepared { token, .. } = prepared else {
        panic!("an admissible lock operation must prepare, got {prepared:?}");
    };
    GovernedOperation {
        key,
        binding,
        prepare_token: token,
    }
}

/// A repository-create input for `name` with a caller-chosen identity.
pub fn create_input(
    repository_id: [u8; 16],
    branch_id: [u8; 16],
    name: String,
    ids: &mut Identities,
) -> RepositoryCreateInput {
    RepositoryCreateInput {
        repository_id: repository_id.to_vec(),
        name,
        metadata_hash: ids.id32().to_vec(),
        default_branch_id: branch_id.to_vec(),
        default_branch_name: "main".to_owned(),
        default_branch_metadata_hash: ids.id32().to_vec(),
        default_branch_latest_hash: ids.id32().to_vec(),
        creation_fingerprint: ids.id32().to_vec(),
        creation_fingerprint_version: 1,
        projection: Vec::new(),
        events: Vec::new(),
    }
}

/// Create one repository through `store`, returning its identity, its default
/// branch, and the branch tip the create published.
pub async fn create_repository(
    store: &PostgresDomainStore,
    ids: &mut Identities,
    label: &str,
) -> ([u8; 16], [u8; 16], Vec<u8>) {
    let repository_id = ids.id16();
    let branch_id = ids.id16();
    let name = ids.name(label);
    let operation = admitted(store, "repository_create", ids).await;
    let input = create_input(repository_id, branch_id, name, ids);
    let tip = input.default_branch_latest_hash.clone();
    let result = store
        .repository_create(&operation, &input)
        .await
        .expect("repository_create must not error");
    assert_eq!(
        result.outcome,
        DomainOutcome::Applied,
        "the case fixture repository must be created"
    );
    (repository_id, branch_id, tip)
}

/// A delete input that tombstones whatever generation is current.
pub fn delete_input(repository_id: [u8; 16], ids: &mut Identities) -> RepositoryDeleteInput {
    RepositoryDeleteInput {
        repository_id: repository_id.to_vec(),
        expected_generation: None,
        delete_proof: ids.id32().to_vec(),
        projection: Vec::new(),
        events: Vec::new(),
    }
}

/// A push input carrying the exact five-scalar preflight the caller observed.
///
/// The lock generations and namespace fence are read from the lock coordinator
/// rather than assumed, because `begin_obliterate` and every lock mutation move
/// them; a hard-coded `1` makes a push case pass or fail for a reason that has
/// nothing to do with the race.
#[allow(clippy::too_many_arguments)]
pub fn push_input(
    repository_id: [u8; 16],
    branch_id: [u8; 16],
    expected_repository_generation: i64,
    expected_branch_generation: i64,
    witness: lore_postgres::domain::locks::PushLockWitness,
    expected_latest_hash: Vec<u8>,
    new_latest_hash: Vec<u8>,
) -> BranchPushCommitInput {
    BranchPushCommitInput {
        repository_id: repository_id.to_vec(),
        branch_id: branch_id.to_vec(),
        expected_repository_generation,
        expected_branch_generation,
        expected_repository_lock_generation: witness.repository_lock_generation,
        expected_branch_lock_generation: witness.branch_lock_generation,
        expected_branch_lock_namespace_last_applied_fence: witness
            .branch_lock_namespace_last_applied_fence,
        expected_latest_hash,
        new_latest_hash,
        projection: Vec::new(),
        event: None,
    }
}

/// A verified lock owner pair.
pub fn owner(issuer: &str, subject: &str) -> VerifiedLockOwner {
    VerifiedLockOwner {
        verified_issuer: issuer.to_owned(),
        authenticated_subject: subject.to_owned(),
    }
}

/// One lock resource, optionally carrying the token a renew or release needs.
pub fn resource(hash: [u8; 32], token: Option<[u8; 32]>) -> LockResourceInput {
    LockResourceInput {
        resource_hash: hash.to_vec(),
        description: format!("/Game/wp109/{:02x}.uasset", hash[0]),
        expected_ownership_token: token,
    }
}

/// An acquire/renew input over one resource batch.
pub fn acquire_input(
    repository_id: [u8; 16],
    branch_id: [u8; 16],
    owner: VerifiedLockOwner,
    resources: Vec<LockResourceInput>,
    lease: Option<std::time::Duration>,
) -> AcquireOrRenewInput {
    AcquireOrRenewInput {
        repository_id: repository_id.to_vec(),
        branch_id: branch_id.to_vec(),
        owner,
        acting_owner: None,
        resources,
        lease_duration: lease,
        outbox_cell_id: None,
    }
}

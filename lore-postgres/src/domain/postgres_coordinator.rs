// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! `PostgresDomainStore`'s implementation of [`DomainTransactionStore`].
//!
//! Every method has the same seven-step shape, and the order is the contract:
//!
//! 1. begin one transaction;
//! 2. lock and consume the `PREPARED` receipt row — F-032-3 position 0, before
//!    any domain state is touched;
//! 3. lock the repository, then the branch, in that order;
//! 4. evaluate preconditions. A failure here is a **decisive committed
//!    `NOT_APPLIED`**, not an error: the receipt records the exact public
//!    result, and no domain mutation or event happens;
//! 5. write the domain rows and every affected `lore_mutable` projection row;
//! 6. append the outbox event, always last;
//! 7. commit the terminal receipt in the same transaction, then commit and
//!    classify the acknowledgement.
//!
//! Step 4 is the part most likely to be misread. A losing writer today gets
//! silence, a swallowed error, or `Status::internal` depending on which of the
//! 37 call sites it hit (worklog 254 §A.1-A.5). Here it gets one committed,
//! versioned, retrievable answer.

use async_trait::async_trait;
use tokio_postgres::Transaction;

use crate::domain::coordinator::*;
use crate::domain::errors::DomainError;
use crate::domain::errors::DomainOutcome;
use crate::domain::lock_order::LockClass;
use crate::domain::lock_order::LockSequence;
use crate::domain::lock_order::lock_branch;
use crate::domain::lock_order::lock_repository;
use crate::domain::outbox;
use crate::domain::receipts;
use crate::domain::retry::classify_commit;
use crate::domain::schema;
use crate::domain::store::PostgresDomainStore;

/// Write every projection row in the same transaction as the domain rows.
///
/// A `None` value deletes, matching `MutableStore::store`'s zero-hash contract,
/// so the projection stays byte-compatible with what today's readers expect.
async fn apply_projection(
    tx: &Transaction<'_>,
    writes: &[ProjectionWrite],
) -> Result<(), DomainError> {
    for w in writes {
        match &w.value {
            Some(value) => {
                tx.execute(
                    "INSERT INTO lore_mutable (partition, key_type, key, value) \
                     VALUES ($1, $2, $3, $4) \
                     ON CONFLICT (partition, key_type, key) DO UPDATE SET value = EXCLUDED.value",
                    &[&w.partition, &w.key_type, &w.key, value],
                )
                .await
                .map_err(|e| DomainError::from_pg("projection upsert", e))?;
            }
            None => {
                tx.execute(
                    "DELETE FROM lore_mutable \
                     WHERE partition = $1 AND key_type = $2 AND key = $3",
                    &[&w.partition, &w.key_type, &w.key],
                )
                .await
                .map_err(|e| DomainError::from_pg("projection delete", e))?;
            }
        }
    }
    Ok(())
}

/// Append the classified event, always as the transaction's last write.
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

/// Guard every generation increment against wrap.
///
/// CR-029 makes overflow a permanent internal error rather than a wrap, because
/// a wrapped generation silently re-admits every stale writer that was fenced
/// out by the higher value.
fn next_generation(current: i64) -> Result<i64, DomainError> {
    current.checked_add(1).ok_or_else(|| {
        DomainError::Internal(
            "generation overflow: generations must not wrap, because a wrapped generation \
             silently re-admits every writer the higher value fenced out"
                .to_owned(),
        )
    })
}

impl PostgresDomainStore {
    /// Steps 1-2, shared by every mutation: open a transaction and consume the
    /// admission row.
    ///
    /// Returns `Ok(None)` when admission fails, which the caller turns into a
    /// decisive `NOT_APPLIED(ADMISSION_REJECTED_V1)` — never into an error, and
    /// never into a silent success.
    async fn begin_admitted<'a>(
        &self,
        client: &'a mut deadpool_postgres::Client,
        operation: &GovernedOperation,
        sequence: &mut LockSequence,
    ) -> Result<Option<(deadpool_postgres::Transaction<'a>, std::time::SystemTime)>, DomainError>
    {
        let tx = client
            .transaction()
            .await
            .map_err(|e| DomainError::from_pg("domain transaction begin", e))?;
        sequence.enter(LockClass::OperationReceipt)?;
        let admitted = receipts::consume(
            &tx,
            &operation.key,
            &operation.binding,
            &operation.prepare_token,
        )
        .await?;
        match admitted {
            Some(a) => Ok(Some((tx, a.admission_clock))),
            None => {
                // Nothing was mutated, so rolling back is the honest close.
                drop(tx);
                Ok(None)
            }
        }
    }

    async fn checkout(&self) -> Result<deadpool_postgres::Client, DomainError> {
        self.pool()
            .get()
            .await
            .map_err(|e| DomainError::from_pool("domain coordinator pool", e))
    }
}

#[async_trait]
impl DomainTransactionStore for PostgresDomainStore {
    async fn domain_operation_clock_get(&self) -> Result<std::time::SystemTime, DomainError> {
        let _t = self
            .instruments()
            .start("domain_operation_clock_get", self.pool().status());
        let mut client = self.checkout().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| DomainError::from_pg("domain operation clock transaction", e))?;
        let clock = receipts::admission_clock(&tx).await?;
        // This transaction is read-only. Dropping it rolls back without any
        // outcome-unknown ambiguity and creates no operation identity.
        drop(tx);
        Ok(clock)
    }

    async fn domain_operation_prepare(
        &self,
        key: &receipts::ReceiptKey,
        binding: &receipts::OperationBinding,
        witness: Option<&receipts::AuthorizationWitness>,
    ) -> Result<receipts::PrepareResult, DomainError> {
        let _t = self
            .instruments()
            .start("domain_operation_prepare", self.pool().status());
        let mut client = self.checkout().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| DomainError::from_pg("domain operation prepare transaction", e))?;
        let result = receipts::prepare(&tx, key, binding, witness).await?;
        classify_commit(tx.commit().await, "domain operation prepare commit")?;
        Ok(result)
    }

    async fn domain_operation_receipt_get(
        &self,
        key: &receipts::ReceiptKey,
        binding: &receipts::OperationBinding,
    ) -> Result<receipts::ReceiptLookup, DomainError> {
        let _t = self
            .instruments()
            .start("domain_operation_receipt_get", self.pool().status());
        let mut client = self.checkout().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| DomainError::from_pg("domain operation receipt transaction", e))?;
        // Lookup can terminalize a PREPARED row past its hard TTL, so it must
        // commit through the same outcome-unknown classifier as prepare.
        let result = receipts::receipt_get(&tx, key, binding).await?;
        classify_commit(tx.commit().await, "domain operation receipt commit")?;
        Ok(result)
    }

    async fn repository_snapshot(
        &self,
        repository_id: &[u8],
    ) -> Result<Option<RepositorySnapshot>, DomainError> {
        let client = self.checkout().await?;
        let row = client
            .query_opt(
                "SELECT state, generation, name, metadata_hash, default_branch_id \
                 FROM lore_domain_repositories WHERE repository_id = $1",
                &[&repository_id],
            )
            .await
            .map_err(|e| DomainError::from_pg("repository snapshot", e))?;
        Ok(row.map(|r| {
            let state: i16 = r.get("state");
            RepositorySnapshot {
                repository_id: repository_id.to_vec(),
                live: state == schema::STATE_LIVE,
                generation: r.get("generation"),
                name: r.get("name"),
                metadata_hash: r.get("metadata_hash"),
                default_branch_id: r.get("default_branch_id"),
            }
        }))
    }

    async fn branch_snapshot(
        &self,
        repository_id: &[u8],
        branch_id: &[u8],
    ) -> Result<Option<BranchSnapshot>, DomainError> {
        let client = self.checkout().await?;
        let row = client
            .query_opt(
                "SELECT state, generation, repository_generation, name, metadata_hash, latest_hash \
                 FROM lore_domain_branches WHERE repository_id = $1 AND branch_id = $2",
                &[&repository_id, &branch_id],
            )
            .await
            .map_err(|e| DomainError::from_pg("branch snapshot", e))?;
        Ok(row.map(|r| {
            let state: i16 = r.get("state");
            BranchSnapshot {
                repository_id: repository_id.to_vec(),
                branch_id: branch_id.to_vec(),
                live: state == schema::STATE_LIVE,
                generation: r.get("generation"),
                repository_generation: r.get("repository_generation"),
                name: r.get("name"),
                metadata_hash: r.get("metadata_hash"),
                latest_hash: r.get("latest_hash"),
            }
        }))
    }

    async fn repository_create(
        &self,
        operation: &GovernedOperation,
        input: &RepositoryCreateInput,
    ) -> Result<MutationResult, DomainError> {
        let _t = self
            .instruments()
            .start("repository_create", self.pool().status());
        let mut client = self.checkout().await?;
        let mut sequence = LockSequence::new();
        let Some((tx, clock)) = self
            .begin_admitted(&mut client, operation, &mut sequence)
            .await?
        else {
            return Ok(MutationResult::rejected(ADMISSION_REJECTED_V1));
        };

        // An exact create retry must return the durable original record; the
        // same ID with different intent must be refused.
        if let Some(existing) = lock_repository(&tx, &mut sequence, &input.repository_id).await? {
            let fingerprint_matches = tx
                .query_one(
                    "SELECT creation_fingerprint = $2 AND creation_fingerprint_version = $3 \
                            AS same \
                     FROM lore_domain_repositories WHERE repository_id = $1",
                    &[
                        &input.repository_id,
                        &input.creation_fingerprint,
                        &input.creation_fingerprint_version,
                    ],
                )
                .await
                .map_err(|e| DomainError::from_pg("create fingerprint compare", e))?
                .get::<_, bool>("same");

            let reason = if existing.state == schema::STATE_TOMBSTONED {
                // Identities are never reused, so this is permanent.
                TOMBSTONED_V1
            } else if fingerprint_matches {
                // Exact retry of a create that already succeeded.
                let outcome = DomainOutcome::Applied;
                receipts::commit_terminal(&tx, &operation.key, &outcome, None, clock).await?;
                classify_commit(tx.commit().await, "repository create retry commit")?;
                return Ok(MutationResult {
                    outcome,
                    repository_generation: Some(existing.generation),
                    branch_generation: None,
                });
            } else {
                FINGERPRINT_MISMATCH_V1
            };
            let result = MutationResult::rejected(reason);
            receipts::commit_terminal(&tx, &operation.key, &result.outcome, None, clock).await?;
            classify_commit(tx.commit().await, "repository create rejection commit")?;
            return Ok(result);
        }

        // The name row is the live-ownership claim. A live owner already holding
        // it is a decisive rejection, not a conflict to retry.
        let name_taken = tx
            .query_opt(
                "SELECT repository_id FROM lore_domain_repository_names WHERE name = $1 FOR UPDATE",
                &[&input.name],
            )
            .await
            .map_err(|e| DomainError::from_pg("repository name claim", e))?
            .is_some();
        if name_taken {
            let result = MutationResult::rejected(NAME_TAKEN_V1);
            receipts::commit_terminal(&tx, &operation.key, &result.outcome, None, clock).await?;
            classify_commit(tx.commit().await, "repository create name-taken commit")?;
            return Ok(result);
        }

        tx.execute(
            "INSERT INTO lore_domain_repositories ( \
                 repository_id, state, generation, name, metadata_hash, default_branch_id, \
                 creation_fingerprint_version, creation_fingerprint, created_at \
             ) VALUES ($1, $2, 1, $3, $4, $5, $6, $7, $8)",
            &[
                &input.repository_id,
                &schema::STATE_LIVE,
                &input.name,
                &input.metadata_hash,
                &input.default_branch_id,
                &input.creation_fingerprint_version,
                &input.creation_fingerprint,
                &clock,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("repository insert", e))?;

        tx.execute(
            "INSERT INTO lore_domain_repository_names \
                 (name, repository_id, repository_generation, created_at) \
             VALUES ($1, $2, 1, $3)",
            &[&input.name, &input.repository_id, &clock],
        )
        .await
        .map_err(|e| DomainError::from_pg("repository name insert", e))?;

        sequence.enter(LockClass::Branch)?;
        tx.execute(
            "INSERT INTO lore_domain_branches ( \
                 repository_id, branch_id, repository_generation, state, generation, \
                 name, metadata_hash, latest_hash, \
                 creation_fingerprint_version, creation_fingerprint, created_at \
             ) VALUES ($1, $2, 1, $3, 1, $4, $5, $6, $7, $8, $9)",
            &[
                &input.repository_id,
                &input.default_branch_id,
                &schema::STATE_LIVE,
                &input.default_branch_name,
                &input.default_branch_metadata_hash,
                &input.default_branch_latest_hash,
                &input.creation_fingerprint_version,
                &input.creation_fingerprint,
                &clock,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("default branch insert", e))?;

        // Branch names fold case; the repository name above does not.
        tx.execute(
            "INSERT INTO lore_domain_branch_names ( \
                 repository_id, name_key, display_name, branch_id, \
                 repository_generation, branch_generation, created_at \
             ) VALUES ($1, lower($2), $2, $3, 1, 1, $4)",
            &[
                &input.repository_id,
                &input.default_branch_name,
                &input.default_branch_id,
                &clock,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("default branch name insert", e))?;

        apply_projection(&tx, &input.projection).await?;
        append_event(
            &tx,
            &mut sequence,
            &input.repository_id,
            1,
            input.event.as_ref(),
        )
        .await?;

        let outcome = DomainOutcome::Applied;
        receipts::commit_terminal(&tx, &operation.key, &outcome, None, clock).await?;
        classify_commit(tx.commit().await, "repository create commit")?;

        Ok(MutationResult {
            outcome,
            repository_generation: Some(1),
            branch_generation: Some(1),
        })
    }

    async fn repository_delete(
        &self,
        operation: &GovernedOperation,
        input: &RepositoryDeleteInput,
    ) -> Result<MutationResult, DomainError> {
        let _t = self
            .instruments()
            .start("repository_delete", self.pool().status());
        let mut client = self.checkout().await?;
        let mut sequence = LockSequence::new();
        let Some((tx, clock)) = self
            .begin_admitted(&mut client, operation, &mut sequence)
            .await?
        else {
            return Ok(MutationResult::rejected(ADMISSION_REJECTED_V1));
        };

        let Some(existing) = lock_repository(&tx, &mut sequence, &input.repository_id).await?
        else {
            let result = MutationResult::rejected(NOT_FOUND_V1);
            receipts::commit_terminal(&tx, &operation.key, &result.outcome, None, clock).await?;
            classify_commit(tx.commit().await, "repository delete not-found commit")?;
            return Ok(result);
        };

        if existing.state == schema::STATE_TOMBSTONED {
            // The tombstone preserves its record, so an exact delete retry is
            // idempotent rather than an error.
            let outcome = DomainOutcome::Applied;
            receipts::commit_terminal(&tx, &operation.key, &outcome, None, clock).await?;
            classify_commit(tx.commit().await, "repository delete retry commit")?;
            return Ok(MutationResult {
                outcome,
                repository_generation: Some(existing.generation),
                branch_generation: None,
            });
        }

        if let Some(expected) = input.expected_generation
            && expected != existing.generation
        {
            let result = MutationResult::rejected(GENERATION_MISMATCH_V1);
            receipts::commit_terminal(&tx, &operation.key, &result.outcome, None, clock).await?;
            classify_commit(tx.commit().await, "repository delete generation commit")?;
            return Ok(result);
        }

        let generation = next_generation(existing.generation)?;

        tx.execute(
            "UPDATE lore_domain_repositories \
             SET state = $2, generation = $3, deleted_at = $4, delete_proof = $5 \
             WHERE repository_id = $1",
            &[
                &input.repository_id,
                &schema::STATE_TOMBSTONED,
                &generation,
                &clock,
                &input.delete_proof,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("repository tombstone", e))?;

        // The name is released in the SAME transaction that tombstones its
        // owner, so it is recyclable only after the tombstone exists.
        tx.execute(
            "DELETE FROM lore_domain_repository_names WHERE repository_id = $1",
            &[&input.repository_id],
        )
        .await
        .map_err(|e| DomainError::from_pg("repository name release", e))?;

        // Bounded and atomic, unlike the per-branch best-effort loop it
        // replaces: two statements regardless of branch count, and a crash
        // rolls the whole thing back rather than leaving orphaned branch rows.
        sequence.enter(LockClass::Branch)?;
        tx.execute(
            "DELETE FROM lore_domain_branch_names WHERE repository_id = $1",
            &[&input.repository_id],
        )
        .await
        .map_err(|e| DomainError::from_pg("branch name release", e))?;
        tx.execute(
            "UPDATE lore_domain_branches \
             SET state = $2, deleted_at = $3, delete_proof = $4, \
                 generation = generation + 1, repository_generation = $5 \
             WHERE repository_id = $1 AND state = $6",
            &[
                &input.repository_id,
                &schema::STATE_TOMBSTONED,
                &clock,
                &input.delete_proof,
                &generation,
                &schema::STATE_LIVE,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("branch tombstone", e))?;

        apply_projection(&tx, &input.projection).await?;
        append_event(
            &tx,
            &mut sequence,
            &input.repository_id,
            generation,
            input.event.as_ref(),
        )
        .await?;

        let outcome = DomainOutcome::Applied;
        receipts::commit_terminal(&tx, &operation.key, &outcome, None, clock).await?;
        classify_commit(tx.commit().await, "repository delete commit")?;

        Ok(MutationResult {
            outcome,
            repository_generation: Some(generation),
            branch_generation: None,
        })
    }

    async fn metadata_compare_and_swap(
        &self,
        operation: &GovernedOperation,
        input: &MetadataCasInput,
    ) -> Result<MutationResult, DomainError> {
        let _t = self
            .instruments()
            .start("metadata_cas", self.pool().status());
        let mut client = self.checkout().await?;
        let mut sequence = LockSequence::new();
        let Some((tx, clock)) = self
            .begin_admitted(&mut client, operation, &mut sequence)
            .await?
        else {
            return Ok(MutationResult::rejected(ADMISSION_REJECTED_V1));
        };

        let Some(repository) = lock_repository(&tx, &mut sequence, &input.repository_id).await?
        else {
            let result = MutationResult::rejected(NOT_FOUND_V1);
            receipts::commit_terminal(&tx, &operation.key, &result.outcome, None, clock).await?;
            classify_commit(tx.commit().await, "metadata cas not-found commit")?;
            return Ok(result);
        };
        if repository.state == schema::STATE_TOMBSTONED {
            let result = MutationResult::rejected(TOMBSTONED_V1);
            receipts::commit_terminal(&tx, &operation.key, &result.outcome, None, clock).await?;
            classify_commit(tx.commit().await, "metadata cas tombstone commit")?;
            return Ok(result);
        }

        let (current, branch) = match &input.branch_id {
            Some(branch_id) => {
                let Some(branch) =
                    lock_branch(&tx, &mut sequence, &input.repository_id, branch_id).await?
                else {
                    let result = MutationResult::rejected(NOT_FOUND_V1);
                    receipts::commit_terminal(&tx, &operation.key, &result.outcome, None, clock)
                        .await?;
                    classify_commit(tx.commit().await, "metadata cas branch not-found commit")?;
                    return Ok(result);
                };
                if branch.state == schema::STATE_TOMBSTONED {
                    let result = MutationResult::rejected(TOMBSTONED_V1);
                    receipts::commit_terminal(&tx, &operation.key, &result.outcome, None, clock)
                        .await?;
                    classify_commit(tx.commit().await, "metadata cas branch tombstone commit")?;
                    return Ok(result);
                }
                (branch.metadata_hash.clone(), Some(branch))
            }
            None => (repository.metadata_hash.clone(), None),
        };

        if current != input.expected_hash {
            let result = MutationResult::rejected(CAS_MISMATCH_V1);
            receipts::commit_terminal(&tx, &operation.key, &result.outcome, None, clock).await?;
            classify_commit(tx.commit().await, "metadata cas mismatch commit")?;
            return Ok(result);
        }

        let (repository_generation, branch_generation) = match branch {
            Some(branch) => {
                let branch_generation = next_generation(branch.generation)?;
                tx.execute(
                    "UPDATE lore_domain_branches \
                     SET metadata_hash = $3, generation = $4 \
                     WHERE repository_id = $1 AND branch_id = $2",
                    &[
                        &input.repository_id,
                        input
                            .branch_id
                            .as_ref()
                            .ok_or_else(|| DomainError::Internal("branch id vanished".into()))?,
                        &input.new_hash,
                        &branch_generation,
                    ],
                )
                .await
                .map_err(|e| DomainError::from_pg("branch metadata cas", e))?;
                (repository.generation, Some(branch_generation))
            }
            None => {
                let repository_generation = next_generation(repository.generation)?;
                tx.execute(
                    "UPDATE lore_domain_repositories \
                     SET metadata_hash = $2, generation = $3 WHERE repository_id = $1",
                    &[
                        &input.repository_id,
                        &input.new_hash,
                        &repository_generation,
                    ],
                )
                .await
                .map_err(|e| DomainError::from_pg("repository metadata cas", e))?;
                (repository_generation, None)
            }
        };

        apply_projection(&tx, &input.projection).await?;
        append_event(
            &tx,
            &mut sequence,
            &input.repository_id,
            repository_generation,
            input.event.as_ref(),
        )
        .await?;

        let outcome = DomainOutcome::Applied;
        receipts::commit_terminal(&tx, &operation.key, &outcome, None, clock).await?;
        classify_commit(tx.commit().await, "metadata cas commit")?;

        Ok(MutationResult {
            outcome,
            repository_generation: Some(repository_generation),
            branch_generation,
        })
    }

    async fn branch_push_commit(
        &self,
        operation: &GovernedOperation,
        input: &BranchPushCommitInput,
    ) -> Result<MutationResult, DomainError> {
        let _t = self
            .instruments()
            .start("branch_push_commit", self.pool().status());
        let mut client = self.checkout().await?;
        let mut sequence = LockSequence::new();
        let Some((tx, clock)) = self
            .begin_admitted(&mut client, operation, &mut sequence)
            .await?
        else {
            return Ok(MutationResult::rejected(ADMISSION_REJECTED_V1));
        };

        let Some(repository) = lock_repository(&tx, &mut sequence, &input.repository_id).await?
        else {
            let result = MutationResult::rejected(NOT_FOUND_V1);
            receipts::commit_terminal(&tx, &operation.key, &result.outcome, None, clock).await?;
            classify_commit(tx.commit().await, "push not-found commit")?;
            return Ok(result);
        };
        if repository.state == schema::STATE_TOMBSTONED {
            let result = MutationResult::rejected(TOMBSTONED_V1);
            receipts::commit_terminal(&tx, &operation.key, &result.outcome, None, clock).await?;
            classify_commit(tx.commit().await, "push repository tombstone commit")?;
            return Ok(result);
        }

        // The obliteration fence. Obliteration begin increments the repository
        // generation in the same transaction that records its fence, so a push
        // that observed the older generation is refused rather than committing
        // across it.
        if repository.generation != input.expected_repository_generation {
            let result = MutationResult::rejected(GENERATION_MISMATCH_V1);
            receipts::commit_terminal(&tx, &operation.key, &result.outcome, None, clock).await?;
            classify_commit(tx.commit().await, "push obliteration fence commit")?;
            return Ok(result);
        }

        let Some(branch) =
            lock_branch(&tx, &mut sequence, &input.repository_id, &input.branch_id).await?
        else {
            let result = MutationResult::rejected(NOT_FOUND_V1);
            receipts::commit_terminal(&tx, &operation.key, &result.outcome, None, clock).await?;
            classify_commit(tx.commit().await, "push branch not-found commit")?;
            return Ok(result);
        };

        // Push never resurrects a tombstoned branch. This is the surface the
        // v1 push path currently reinstates a deleted BranchId mapping through,
        // before its tip CAS (worklog 254 §A.4).
        if branch.state == schema::STATE_TOMBSTONED {
            let result = MutationResult::rejected(TOMBSTONED_V1);
            receipts::commit_terminal(&tx, &operation.key, &result.outcome, None, clock).await?;
            classify_commit(tx.commit().await, "push branch tombstone commit")?;
            return Ok(result);
        }

        if branch.generation != input.expected_branch_generation
            || branch.latest_hash != input.expected_latest_hash
        {
            let result = MutationResult::rejected(CAS_MISMATCH_V1);
            receipts::commit_terminal(&tx, &operation.key, &result.outcome, None, clock).await?;
            classify_commit(tx.commit().await, "push cas mismatch commit")?;
            return Ok(result);
        }

        let branch_generation = next_generation(branch.generation)?;
        tx.execute(
            "UPDATE lore_domain_branches \
             SET latest_hash = $3, generation = $4 \
             WHERE repository_id = $1 AND branch_id = $2",
            &[
                &input.repository_id,
                &input.branch_id,
                &input.new_latest_hash,
                &branch_generation,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("branch tip publish", e))?;

        apply_projection(&tx, &input.projection).await?;
        append_event(
            &tx,
            &mut sequence,
            &input.repository_id,
            repository.generation,
            input.event.as_ref(),
        )
        .await?;

        let outcome = DomainOutcome::Applied;
        receipts::commit_terminal(&tx, &operation.key, &outcome, None, clock).await?;
        classify_commit(tx.commit().await, "push commit")?;

        Ok(MutationResult {
            outcome,
            repository_generation: Some(repository.generation),
            branch_generation: Some(branch_generation),
        })
    }

    async fn begin_obliterate(
        &self,
        operation: &GovernedOperation,
        repository_id: &[u8],
    ) -> Result<MutationResult, DomainError> {
        let _t = self
            .instruments()
            .start("begin_obliterate", self.pool().status());
        let mut client = self.checkout().await?;
        let mut sequence = LockSequence::new();
        let Some((tx, clock)) = self
            .begin_admitted(&mut client, operation, &mut sequence)
            .await?
        else {
            return Ok(MutationResult::rejected(ADMISSION_REJECTED_V1));
        };

        let Some(repository) = lock_repository(&tx, &mut sequence, repository_id).await? else {
            let result = MutationResult::rejected(NOT_FOUND_V1);
            receipts::commit_terminal(&tx, &operation.key, &result.outcome, None, clock).await?;
            classify_commit(tx.commit().await, "obliterate not-found commit")?;
            return Ok(result);
        };

        // A tombstoned repository has no content left to obliterate, and bumping
        // its generation would move a fence that nothing can still be racing.
        // Every other mutation checks this; leaving it out here was an omission,
        // not a carve-out.
        if repository.state == schema::STATE_TOMBSTONED {
            let result = MutationResult::rejected(TOMBSTONED_V1);
            receipts::commit_terminal(&tx, &operation.key, &result.outcome, None, clock).await?;
            classify_commit(tx.commit().await, "obliterate tombstone commit")?;
            return Ok(result);
        }

        // Beginning an address obliteration increments the repository
        // generation in the same transaction that records the fence, which is
        // what any in-flight push is checked against.
        let generation = next_generation(repository.generation)?;
        tx.execute(
            "UPDATE lore_domain_repositories SET generation = $2 WHERE repository_id = $1",
            &[&repository_id, &generation],
        )
        .await
        .map_err(|e| DomainError::from_pg("obliteration fence", e))?;

        let outcome = DomainOutcome::Applied;
        receipts::commit_terminal(&tx, &operation.key, &outcome, None, clock).await?;
        classify_commit(tx.commit().await, "obliterate fence commit")?;

        Ok(MutationResult {
            outcome,
            repository_generation: Some(generation),
            branch_generation: None,
        })
    }
}

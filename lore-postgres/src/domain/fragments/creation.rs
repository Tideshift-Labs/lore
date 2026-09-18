// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Representation evidence and atomic associations for repository and branch creation.
use tokio_postgres::Transaction;

use super::*;

fn refused(reason: &str) -> DomainError {
    DomainError::PreconditionRejected {
        reason: format!("repository_create_metadata_{reason}"),
        reason_version: 1,
    }
}

impl PostgresFragmentCoordinator {
    /// Physical database binding already attested during construction.
    pub fn database_identity(&self) -> &str {
        &self.database_identity
    }

    /// Capture an unpublished, synchronously uploaded representation after commit_remote.
    /// This grants no repository read access and owns no database resource on return.
    /// None means a concurrent lifecycle change left no readable Remote witness.
    pub async fn capture_current_readable_epoch(
        &self,
        hash: &[u8],
    ) -> Result<Option<EpochWitness>, DomainError> {
        let mut client = self.checkout().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| DomainError::from_pg("create metadata capture begin", e))?;
        let mut sequence = LockSequence::new();
        let Some(head) = lock_fragment_head(&tx, &mut sequence, hash).await? else {
            classify_commit(tx.commit().await, "create metadata absent capture commit")?;
            return Ok(None);
        };
        let witness = EpochWitness {
            hash: hash.to_vec(),
            epoch: head.current_epoch,
            state: head.state,
            manifest_id: head.manifest_id.clone(),
            fence: head.last_fence,
        };
        let readable = witness.state == FragmentLifecycleState::Remote
            && remote_epoch_exists(&tx, &witness).await?;
        classify_commit(tx.commit().await, "create metadata capture commit")?;
        Ok(readable.then_some(witness))
    }

    /// Capture the current readable epoch backed by the requested authority.
    ///
    /// This grants no repository access or staged reader lease. The caller must
    /// revalidate the returned witness when publishing its association. No
    /// database resource is held on return. Missing, non-readable, or mismatched
    /// epoch evidence returns `None`, including an authority changed by promotion.
    /// The synchronous metadata path keeps its separate Remote-only capture.
    pub async fn capture_current_readable_epoch_for_authority(
        &self,
        hash: &[u8],
        authority: EpochAuthority,
    ) -> Result<Option<EpochWitness>, DomainError> {
        let mut client = self.checkout().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|error| DomainError::from_pg("authority epoch capture begin", error))?;
        let mut sequence = LockSequence::new();
        let Some(head) = lock_fragment_head(&tx, &mut sequence, hash).await? else {
            classify_commit(tx.commit().await, "authority epoch absent capture commit")?;
            return Ok(None);
        };
        let witness = EpochWitness {
            hash: hash.to_vec(),
            epoch: head.current_epoch,
            state: head.state,
            manifest_id: head.manifest_id.clone(),
            fence: head.last_fence,
        };
        let readable = if witness.state == authority.readable_state() {
            tx.query_one(
                "SELECT EXISTS(SELECT 1 FROM lore_fragment_epochs WHERE hash=$1 AND epoch=$2 \
                 AND manifest_id=$3 AND authority=$4 AND disposition=$5)",
                &[
                    &witness.hash,
                    &witness.epoch,
                    &witness.manifest_id,
                    &authority.bits(),
                    &schema::DISPOSITION_CURRENT_ELIGIBLE,
                ],
            )
            .await
            .map_err(|error| DomainError::from_pg("authority epoch capture evidence", error))?
            .get::<_, bool>(0)
        } else {
            false
        };
        classify_commit(tx.commit().await, "authority epoch capture commit")?;
        Ok(readable.then_some(witness))
    }
}

// Creation uses the synchronous provider route. An exact Remote epoch avoids treating a staged
// location or an expired lease as durable metadata publication evidence.
async fn validate_epoch(tx: &Transaction<'_>, witness: &EpochWitness) -> Result<(), DomainError> {
    if witness.state != FragmentLifecycleState::Remote {
        return Err(refused("not_remote"));
    }
    if !remote_epoch_exists(tx, witness).await? {
        return Err(refused("unreadable"));
    }
    Ok(())
}

async fn remote_epoch_exists(
    tx: &Transaction<'_>,
    witness: &EpochWitness,
) -> Result<bool, DomainError> {
    let valid: bool = tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM lore_fragment_epochs WHERE hash=$1 AND epoch=$2 \
         AND manifest_id=$3 AND authority=$4 AND disposition=$5)",
            &[
                &witness.hash,
                &witness.epoch,
                &witness.manifest_id,
                &EpochAuthority::Remote.bits(),
                &schema::DISPOSITION_CURRENT_ELIGIBLE,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("create metadata epoch", e))?
        .get(0);
    Ok(valid)
}

pub(crate) struct CreationMetadataEvents {
    advances: Vec<(Option<AssociationAdvance>, i64)>,
}

/// Bind one branch metadata epoch in an existing repository. Repository-create's
/// residue rule deliberately does not apply to an already shared live association.
pub(crate) async fn bind_branch_creation_metadata(
    tx: &Transaction<'_>,
    sequence: &mut LockSequence,
    input: &crate::domain::coordinator::BranchCreateInput,
) -> Result<CreationMetadataEvents, DomainError> {
    let reject = |reason: &str| DomainError::PreconditionRejected {
        reason: format!("branch_create_metadata_{reason}_v1"),
        reason_version: 1,
    };
    let exists: bool = tx
        .query_one(
            "SELECT to_regclass('lore_fragment_schema_state') IS NOT NULL",
            &[],
        )
        .await
        .map_err(|e| DomainError::from_pg("branch metadata schema", e))?
        .get(0);
    let lifecycle = if exists {
        tx.query_one("SELECT lifecycle_enabled OR write_capability=1 FROM lore_fragment_schema_state WHERE id=1", &[])
            .await.map_err(|e| DomainError::from_pg("branch metadata routing", e))?.get::<_,bool>(0)
    } else {
        false
    };
    if !lifecycle && !super::super::membership::enabled(tx).await? {
        if input.metadata_witness.is_some() {
            return Err(reject("inactive"));
        }
        return Ok(CreationMetadataEvents {
            advances: Vec::new(),
        });
    }
    let witness = input
        .metadata_witness
        .as_ref()
        .ok_or_else(|| reject("witness_required"))?;
    if input.events.len() + 1 > crate::domain::coordinator::MAX_PENDING_EVENTS {
        return Err(reject("event_limit"));
    }
    if witness.hash != input.metadata_hash || witness.hash.iter().all(|b| *b == 0) {
        return Err(reject("hash_mismatch"));
    }
    let head = lock_fragment_head(tx, sequence, &witness.hash)
        .await?
        .ok_or_else(|| reject("absent"))?;
    if !head.matches(witness) {
        return Err(reject("stale"));
    }
    if witness.state != FragmentLifecycleState::Remote || !remote_epoch_exists(tx, witness).await? {
        return Err(reject("unreadable"));
    }
    sequence.enter(LockClass::Associations)?;
    let context = [0_u8; 16];
    let existing = tx.query_opt("SELECT state, repository_generation FROM lore_fragment_associations WHERE hash=$1 AND repository_id=$2 AND context=$3 FOR UPDATE",
        &[&witness.hash,&input.repository_id,&&context[..]]).await
        .map_err(|e| DomainError::from_pg("branch metadata association lock", e))?;
    if existing.as_ref().is_some_and(|r| {
        r.get::<_, i16>("state") == schema::ASSOCIATION_LIVE
            && r.get::<_, i64>("repository_generation") == input.expected_repository_generation
    }) {
        return Ok(CreationMetadataEvents {
            advances: Vec::new(),
        });
    }
    super::super::membership::allow_association(tx).await?;
    let epoch = next_fence(tx).await?;
    tx.execute("INSERT INTO lore_fragment_associations(hash,repository_id,context,association_epoch,state,repository_generation) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(hash,repository_id,context) DO UPDATE SET association_epoch=EXCLUDED.association_epoch,state=EXCLUDED.state,repository_generation=EXCLUDED.repository_generation,updated_at=clock_timestamp()",
        &[&witness.hash,&input.repository_id,&&context[..],&epoch,&schema::ASSOCIATION_LIVE,&input.expected_repository_generation]).await
        .map_err(|e| DomainError::from_pg("branch metadata association publication", e))?;
    let advance = bump_association_generation(tx, &input.repository_id, existing.is_some()).await?;
    Ok(CreationMetadataEvents {
        advances: vec![(advance, epoch)],
    })
}

impl CreationMetadataEvents {
    /// Defer all outbox locks until the caller has finished associations and projections.
    pub(crate) async fn append(
        self,
        tx: &Transaction<'_>,
        sequence: &mut LockSequence,
        cell_id: Option<&str>,
        repository_id: &[u8],
    ) -> Result<(), DomainError> {
        for (advance, epoch) in self.advances {
            append_association_summary(tx, sequence, cell_id, repository_id, advance, epoch)
                .await?;
        }
        Ok(())
    }
}

/// Called only after the fresh repository/name/default branch inserts, in their transaction.
pub(crate) async fn bind_creation_metadata(
    tx: &Transaction<'_>,
    sequence: &mut LockSequence,
    input: &crate::domain::coordinator::RepositoryCreateInput,
) -> Result<CreationMetadataEvents, DomainError> {
    let exists: bool = tx
        .query_one(
            "SELECT to_regclass('lore_fragment_schema_state') IS NOT NULL",
            &[],
        )
        .await
        .map_err(|e| DomainError::from_pg("create metadata schema", e))?
        .get(0);
    let lifecycle_required = if exists {
        tx.query_one("SELECT lifecycle_enabled OR write_capability=1 FROM lore_fragment_schema_state WHERE id=1", &[])
            .await.map_err(|e| DomainError::from_pg("create metadata routing", e))?.get::<_, bool>(0)
    } else {
        false
    };
    let required = super::super::membership::enabled(tx).await? || lifecycle_required;
    if !required {
        if !input.metadata_witnesses.is_empty() {
            return Err(refused("inactive"));
        }
        return Ok(CreationMetadataEvents {
            advances: Vec::new(),
        });
    }
    let hashes: BTreeSet<&[u8]> = [
        input.metadata_hash.as_slice(),
        input.default_branch_metadata_hash.as_slice(),
    ]
    .into_iter()
    .collect();
    if input.default_branch_latest_hash.len() != 32
        || input.default_branch_latest_hash.iter().any(|b| *b != 0)
    {
        return Err(refused("nonempty_initial_branch"));
    }
    if input.events.len() + hashes.len() > crate::domain::coordinator::MAX_PENDING_EVENTS {
        return Err(refused("event_limit"));
    }
    if hashes
        .iter()
        .any(|hash| hash.len() != 32 || hash.iter().all(|b| *b == 0))
        || input.metadata_witnesses.len() != hashes.len()
    {
        return Err(refused("witnesses_required"));
    }
    let witnesses: BTreeMap<&[u8], &EpochWitness> = input
        .metadata_witnesses
        .iter()
        .map(|w| (w.hash.as_slice(), w))
        .collect();
    if witnesses.len() != hashes.len()
        || witnesses.keys().copied().collect::<BTreeSet<_>>() != hashes
    {
        return Err(refused("hash_mismatch"));
    }
    // All heads first, sorted by hash. Re-entering Fragments after Associations is forbidden.
    for witness in witnesses.values() {
        let head = lock_fragment_head(tx, sequence, &witness.hash)
            .await?
            .ok_or_else(|| refused("absent"))?;
        if !head.matches(witness) {
            return Err(refused("stale"));
        }
        validate_epoch(tx, witness).await?;
    }
    sequence.enter(LockClass::Associations)?;
    super::super::membership::allow_association(tx).await?;
    let mut advances = Vec::with_capacity(witnesses.len());
    let context = [0_u8; 16];
    for witness in witnesses.values() {
        // This repository was absent before this transaction. Existing associations are residue,
        // never adopted into a fresh identity's publication.
        if association_key_exists(tx, &witness.hash, &input.repository_id, &context).await? {
            return Err(refused("association_residue"));
        }
        let epoch = next_fence(tx).await?;
        tx.execute("INSERT INTO lore_fragment_associations(hash,repository_id,context,association_epoch,state,repository_generation) VALUES($1,$2,$3,$4,$5,1)",
            &[&witness.hash,&input.repository_id,&&context[..],&epoch,&schema::ASSOCIATION_LIVE])
            .await.map_err(|e| DomainError::from_pg("create metadata association", e))?;
        advances.push((
            bump_association_generation(tx, &input.repository_id, false).await?,
            epoch,
        ));
        failpoint!("repository_create.metadata_bound")?;
    }
    Ok(CreationMetadataEvents { advances })
}

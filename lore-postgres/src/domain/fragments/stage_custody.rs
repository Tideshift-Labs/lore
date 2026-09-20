// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Staged-file ownership. Every grant is committed before filesystem work.

use super::*;

/// Input already validated by the immutable store, retained for manifest replay.
#[derive(Debug, Clone, Copy)]
pub struct StageReservationInput {
    pub size_payload: u64,
    pub original_flags: u32,
}

/// A cleanup grant names one immutable placement, never a caller path.
#[derive(Debug, Clone)]
pub struct StageCleanupIntent {
    pub(super) target: FragmentPurgeTarget,
    pub(super) fence: i64,
}

impl StageCleanupIntent {
    pub fn target(&self) -> &FragmentPurgeTarget {
        &self.target
    }
}

#[derive(Debug, Clone)]
pub struct StageObservation {
    pub pending_bytes: i64,
    pub pending_files: i64,
    pub resident_bytes: i64,
    pub resident_files: i64,
    pub metadata_bytes: i64,
    pub metadata_rows: i64,
    pub cleanup_backlog: i64,
    pub oldest_pending: Option<SystemTime>,
    pub metadata_full: bool,
}

const FULL_METADATA_BYTES: i64 = 1024;
const COMPACT_METADATA_BYTES: i64 = 256;

pub(super) async fn reserve_stage_locked(
    tx: &Transaction<'_>,
    sequence: &mut LockSequence,
    hash: &[u8],
    epoch: i64,
    fence: i64,
    input: StageReservationInput,
) -> Result<(), DomainError> {
    let size = i64::try_from(input.size_payload)
        .map_err(|_error| DomainError::InvalidInput("stage size overflow".into()))?;
    if input.size_payload > MAX_FRAGMENT_WRITE_CLAIM_BODY_BYTES {
        return Err(DomainError::InvalidInput(
            "stage payload exceeds fragment cap".into(),
        ));
    }
    sequence.enter(LockClass::StageCustody)?;
    // The head is locked (or was inserted in this transaction). Reserve the
    // permanent marker now; physical cleanup cannot require a later allocation.
    let inserted = tx.execute(
        "INSERT INTO lore_fragment_stage_custody \
         (hash,epoch,operation_fence,original_flags,size_payload,prepare_deadline,state,metadata_bytes) \
         SELECT $1,$2,$3,$4,$5,clock_timestamp() + prepare_ttl_ms * interval '1 millisecond',0,$6 \
         FROM lore_fragment_stage_policy WHERE singleton AND expires_at > clock_timestamp()",
        &[&hash,&epoch,&fence,&i64::from(input.original_flags),&size,&FULL_METADATA_BYTES],
    ).await.map_err(|e| DomainError::from_pg("stage custody reserve",e))?;
    if inserted != 1 {
        return Err(DomainError::NotReady(
            "stage policy absent or expired".into(),
        ));
    }
    sequence.enter(LockClass::StageUsage)?;
    let charged = tx.execute(
        "UPDATE lore_fragment_stage_usage AS u SET \
         live_bytes=u.live_bytes+$1, live_files=u.live_files+1, \
         metadata_bytes=u.metadata_bytes+$2, metadata_rows=u.metadata_rows+1 \
         FROM lore_fragment_stage_policy AS p \
         WHERE u.singleton AND p.singleton \
           AND u.live_bytes <= p.max_bytes-$1 AND u.live_files < p.max_files \
           AND u.metadata_bytes <= p.max_metadata_bytes-$2 AND u.metadata_rows < p.max_metadata_rows",
        &[&size,&FULL_METADATA_BYTES],
    ).await.map_err(|e| DomainError::from_pg("stage capacity reserve",e))?;
    if charged != 1 {
        return Err(DomainError::NotReady("stage capacity exhausted".into()));
    }
    Ok(())
}

pub(super) async fn publish_stage_locked(
    tx: &Transaction<'_>,
    sequence: &mut LockSequence,
    intent: &FragmentIntent,
    manifest: &FragmentManifest,
) -> Result<bool, DomainError> {
    sequence.enter(LockClass::StageCustody)?;
    let n = tx
        .execute(
            "UPDATE lore_fragment_stage_custody SET state=1 \
         WHERE hash=$1 AND epoch=$2 AND operation_fence=$3 AND state=0 \
           AND prepare_deadline>clock_timestamp() AND size_payload=$4",
            &[
                &intent.hash,
                &intent.epoch,
                &intent.fence,
                &manifest.size_payload,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("stage custody publication", e))?;
    Ok(n == 1)
}

/// Caller has locked the exact head and every relevant custody row first.
pub(super) async fn release_stage_locked(
    tx: &Transaction<'_>,
    sequence: &mut LockSequence,
    hash: &[u8],
    epoch: i64,
) -> Result<(), DomainError> {
    sequence.enter(LockClass::StageCustody)?;
    let row = tx
        .query_opt(
            "SELECT state,size_payload,metadata_bytes FROM lore_fragment_stage_custody \
         WHERE hash=$1 AND epoch=$2 FOR UPDATE",
            &[&hash, &epoch],
        )
        .await
        .map_err(|e| DomainError::from_pg("stage release lock", e))?;
    let Some(row) = row else {
        return Err(DomainError::NotReady("stage custody missing".into()));
    };
    if row.get::<_, i16>("state") == 3 {
        return Ok(());
    }
    let size: i64 = row.get("size_payload");
    let metadata: i64 = row.get("metadata_bytes");
    sequence.enter(LockClass::StageUsage)?;
    tx.execute(
        "UPDATE lore_fragment_stage_usage SET live_bytes=live_bytes-$1,live_files=live_files-1, \
         metadata_bytes=metadata_bytes-$2 WHERE singleton",
        &[&size, &(metadata - COMPACT_METADATA_BYTES)],
    )
    .await
    .map_err(|e| DomainError::from_pg("stage capacity release", e))?;
    tx.execute(
        "UPDATE lore_fragment_stage_custody SET state=3, original_flags=NULL, \
         size_payload=0,metadata_bytes=$3,purged_at=clock_timestamp() WHERE hash=$1 AND epoch=$2",
        &[&hash, &epoch, &COMPACT_METADATA_BYTES],
    )
    .await
    .map_err(|e| DomainError::from_pg("stage release receipt", e))?;
    Ok(())
}

impl PostgresFragmentCoordinator {
    pub async fn verify_stage_capacity(&self, bytes: u64, files: u64) -> Result<(), DomainError> {
        let bytes = i64::try_from(bytes)
            .map_err(|_error| DomainError::InvalidInput("stage byte limit overflow".into()))?;
        let files = i64::try_from(files)
            .map_err(|_error| DomainError::InvalidInput("stage file limit overflow".into()))?;
        let client = self.checkout().await?;
        let row=client.query_opt("SELECT 1 FROM lore_fragment_stage_policy WHERE singleton AND max_bytes=$1 AND max_files=$2 AND expires_at>clock_timestamp()",&[&bytes,&files]).await
            .map_err(|e|DomainError::from_pg("stage capacity policy pin",e))?;
        if row.is_none() {
            return Err(DomainError::NotReady(
                "stage capacity configuration differs from policy".into(),
            ));
        }
        Ok(())
    }
    /// Pins shared stage capacity to the same immutable policy as dispatch.
    pub async fn verify_stage_policy(
        &self,
        cell: &str,
        revision: &str,
        digest: &[u8; 32],
    ) -> Result<(), DomainError> {
        let client = self.checkout().await?;
        let row = client
            .query_opt(
                "SELECT 1 FROM lore_fragment_stage_policy WHERE singleton \
            AND cell_id=$1 AND revision=$2 AND digest=$3 AND expires_at>clock_timestamp()",
                &[&cell, &revision, &&digest[..]],
            )
            .await
            .map_err(|e| DomainError::from_pg("stage policy pin", e))?;
        if row.is_none() {
            return Err(DomainError::NotReady(
                "stage policy pin absent, expired or divergent".into(),
            ));
        }
        Ok(())
    }
    pub async fn observe_stage(&self) -> Result<StageObservation, DomainError> {
        let client = self.checkout().await?;
        let row=client.query_one(
            "SELECT u.live_bytes,u.live_files,u.metadata_bytes,u.metadata_rows, \
             (u.metadata_bytes > p.max_metadata_bytes-1024 OR u.metadata_rows >= p.max_metadata_rows) AS metadata_full, \
             (SELECT count(*) FROM lore_fragment_lifecycle WHERE state=3)::bigint AS pending_files, \
             (SELECT coalesce(sum(e.size_payload),0)::bigint FROM lore_fragment_lifecycle l \
                JOIN lore_fragment_epochs e ON e.hash=l.hash AND e.epoch=l.current_epoch WHERE l.state=3) AS pending_bytes, \
             (SELECT min(updated_at) FROM lore_fragment_lifecycle WHERE state=3) AS oldest_pending, \
             (SELECT count(*) FROM lore_fragment_stage_custody c WHERE state=2 OR \
                (state=0 AND prepare_deadline<=clock_timestamp()) OR \
                (state=1 AND NOT EXISTS (SELECT 1 FROM lore_fragment_lifecycle l \
                 WHERE l.hash=c.hash AND l.current_epoch=c.epoch AND l.state=3)))::bigint AS cleanup_backlog \
             FROM lore_fragment_stage_usage u JOIN lore_fragment_stage_policy p USING(singleton) WHERE u.singleton", &[],
        ).await.map_err(|e|DomainError::from_pg("stage observation",e))?;
        Ok(StageObservation {
            pending_bytes: row.get("pending_bytes"),
            pending_files: row.get("pending_files"),
            resident_bytes: row.get("live_bytes"),
            resident_files: row.get("live_files"),
            metadata_bytes: row.get("metadata_bytes"),
            metadata_rows: row.get("metadata_rows"),
            cleanup_backlog: row.get("cleanup_backlog"),
            oldest_pending: row.get("oldest_pending"),
            metadata_full: row.get("metadata_full"),
        })
    }

    /// Selection is advisory. Filesystem enumeration revisits purged late residue.
    pub async fn stage_cleanup_candidates(
        &self,
        after: Option<(&[u8], i64)>,
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, i64)>, DomainError> {
        if !(1..=256).contains(&limit) {
            return Err(DomainError::InvalidInput("stage cleanup batch".into()));
        }
        let (hash, epoch) = after.unwrap_or((&[], 0));
        let client = self.checkout().await?;
        let rows = client
            .query(
                "SELECT c.hash,c.epoch FROM lore_fragment_stage_custody c \
             WHERE (c.hash,c.epoch)>($1,$2) AND (c.state=2 OR \
                (c.state=0 AND c.prepare_deadline<=clock_timestamp()) OR \
                (c.state=1 AND NOT EXISTS (SELECT 1 FROM lore_fragment_lifecycle l \
                 WHERE l.hash=c.hash AND l.current_epoch=c.epoch AND l.state=3))) \
             ORDER BY c.hash,c.epoch LIMIT $3",
                &[&hash, &epoch, &i64::from(limit)],
            )
            .await
            .map_err(|e| DomainError::from_pg("stage cleanup candidates", e))?;
        Ok(rows.into_iter().map(|r| (r.get(0), r.get(1))).collect())
    }

    pub async fn begin_stage_cleanup(
        &self,
        hash: &[u8],
        epoch: i64,
    ) -> Result<Option<StageCleanupIntent>, DomainError> {
        if hash.len() != 32 || epoch < 0 {
            return Err(DomainError::InvalidInput("stage cleanup identity".into()));
        }
        let mut client = self.checkout().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| DomainError::from_pg("stage cleanup begin", e))?;
        let mut sequence = LockSequence::new();
        let head = lock_fragment_head(&tx, &mut sequence, hash).await?;
        sequence.enter(LockClass::StageCustody)?;
        let custody = tx
            .query_opt(
                "SELECT state,operation_fence,prepare_deadline<=clock_timestamp() AS expired \
             FROM lore_fragment_stage_custody WHERE hash=$1 AND epoch=$2 FOR UPDATE",
                &[&hash, &epoch],
            )
            .await
            .map_err(|e| DomainError::from_pg("stage cleanup custody", e))?;
        let custody = if let Some(row) = custody {
            row
        } else {
            // A new producer must insert this exact unique custody key
            // before any filesystem operation. This insert serializes
            // with that producer even when there is no head row to lock.
            if head.as_ref().is_some_and(|h| h.current_epoch == epoch) {
                return Ok(None);
            }
            if tx
                .query_opt(
                    "SELECT 1 FROM lore_fragment_epochs WHERE hash=$1 AND epoch=$2",
                    &[&hash, &epoch],
                )
                .await
                .map_err(|e| DomainError::from_pg("stage orphan ownership", e))?
                .is_some()
            {
                return Ok(None);
            }
            let fence = next_fence(&tx).await?;
            reserve_stage_locked(
                &tx,
                &mut sequence,
                hash,
                epoch,
                fence,
                StageReservationInput {
                    size_payload: MAX_FRAGMENT_WRITE_CLAIM_BODY_BYTES,
                    original_flags: 0,
                },
            )
            .await?;
            tx.execute(
                "UPDATE lore_fragment_stage_custody SET state=2 WHERE hash=$1 AND epoch=$2",
                &[&hash, &epoch],
            )
            .await
            .map_err(|e| DomainError::from_pg("stage orphan seal", e))?;
            tx.query_one("SELECT state,operation_fence,true AS expired FROM lore_fragment_stage_custody WHERE hash=$1 AND epoch=$2",
                    &[&hash,&epoch]).await.map_err(|e|DomainError::from_pg("stage orphan grant",e))?
        };
        let state: i16 = custody.get("state");
        if state == 0 && !custody.get::<_, bool>("expired") {
            return Ok(None);
        }
        if let Some(head) = head.as_ref() {
            if head.state.is_deleting() {
                return Ok(None);
            }
            if head.current_epoch == epoch && head.state.is_readable() {
                return Ok(None);
            }
        }
        let leased=tx.query_opt(
            "SELECT 1 FROM lore_fragment_staged_lease_members m JOIN lore_fragment_staged_leases l USING(lease_id) \
             WHERE m.hash=$1 AND m.epoch=$2 AND NOT l.terminal AND l.deadline>clock_timestamp() LIMIT 1",
            &[&hash,&epoch],
        ).await.map_err(|e|DomainError::from_pg("stage cleanup lease check",e))?;
        if leased.is_some() {
            return Ok(None);
        }
        let fence: i64 = custody.get("operation_fence");
        if state < 2 {
            tx.execute(
                "UPDATE lore_fragment_stage_custody SET state=2 WHERE hash=$1 AND epoch=$2",
                &[&hash, &epoch],
            )
            .await
            .map_err(|e| DomainError::from_pg("stage cleanup seal", e))?;
        }
        classify_commit(tx.commit().await, "stage cleanup seal commit")?;
        Ok(Some(StageCleanupIntent {
            target: FragmentPurgeTarget {
                hash: hash.to_vec(),
                epoch,
                authority: EpochAuthority::Staged,
                object_key: staged_epoch_key(hash, epoch),
                provider_body_blake3: None,
                provider_body_size: None,
                provider_claim_fence: None,
            },
            fence,
        }))
    }

    pub async fn commit_stage_cleanup(
        &self,
        intent: &StageCleanupIntent,
    ) -> Result<(), DomainError> {
        let mut client = self.checkout().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| DomainError::from_pg("stage cleanup commit begin", e))?;
        let mut sequence = LockSequence::new();
        lock_fragment_head(&tx, &mut sequence, intent.target.hash()).await?;
        sequence.enter(LockClass::StageCustody)?;
        let row = tx
            .query_opt(
                "SELECT state FROM lore_fragment_stage_custody \
            WHERE hash=$1 AND epoch=$2 AND operation_fence=$3 AND state IN(2,3) FOR UPDATE",
                &[&intent.target.hash(), &intent.target.epoch(), &intent.fence],
            )
            .await
            .map_err(|e| DomainError::from_pg("stage cleanup commit custody", e))?;
        if row.is_none() {
            return Err(DomainError::NotReady("stage cleanup fence changed".into()));
        }
        release_stage_locked(
            &tx,
            &mut sequence,
            intent.target.hash(),
            intent.target.epoch(),
        )
        .await?;
        tx.execute("UPDATE lore_fragment_epochs SET disposition=$3 WHERE hash=$1 AND epoch=$2 AND authority=1",
            &[&intent.target.hash(),&intent.target.epoch(),&schema::DISPOSITION_PURGED]).await
            .map_err(|e|DomainError::from_pg("stage cleanup epoch purge",e))?;
        classify_commit(tx.commit().await, "stage cleanup commit")?;
        failpoint!("stage.cleanup.settled")?;
        Ok(())
    }
}

pub(super) async fn release_obliterated_stages_locked(
    tx: &Transaction<'_>,
    sequence: &mut LockSequence,
    targets: &[FragmentPurgeTarget],
) -> Result<(), DomainError> {
    let stages: Vec<_> = targets
        .iter()
        .filter(|t| t.authority == EpochAuthority::Staged)
        .collect();
    if stages.is_empty() {
        return Ok(());
    }
    let hashes: Vec<_> = stages.iter().map(|t| t.hash.as_slice()).collect();
    let epochs: Vec<_> = stages.iter().map(|t| t.epoch).collect();
    sequence.enter(LockClass::StageCustody)?;
    let rows=tx.query("SELECT c.hash,c.epoch,c.state,c.size_payload,c.metadata_bytes FROM lore_fragment_stage_custody c \
        JOIN unnest($1::bytea[],$2::bigint[]) m(hash,epoch) ON c.hash=m.hash AND c.epoch=m.epoch \
        ORDER BY c.hash,c.epoch FOR UPDATE OF c",&[&hashes,&epochs]).await
        .map_err(|e|DomainError::from_pg("obliterate custody lock",e))?;
    if rows.len() != stages.len() {
        return Err(DomainError::NotReady("obliterate custody missing".into()));
    }
    let mut bytes = 0i64;
    let mut files = 0i64;
    let mut metadata = 0i64;
    for row in rows {
        if row.get::<_, i16>("state") == 3 {
            continue;
        }
        bytes = bytes
            .checked_add(row.get("size_payload"))
            .ok_or_else(|| DomainError::Internal("stage release overflow".into()))?;
        files += 1;
        metadata = metadata
            .checked_add(row.get::<_, i64>("metadata_bytes") - COMPACT_METADATA_BYTES)
            .ok_or_else(|| DomainError::Internal("stage metadata release overflow".into()))?;
    }
    sequence.enter(LockClass::StageUsage)?;
    tx.execute("UPDATE lore_fragment_stage_usage SET live_bytes=live_bytes-$1,live_files=live_files-$2,metadata_bytes=metadata_bytes-$3 WHERE singleton",
        &[&bytes,&files,&metadata]).await.map_err(|e|DomainError::from_pg("obliterate capacity release",e))?;
    tx.execute("UPDATE lore_fragment_stage_custody c SET state=3,size_payload=0,original_flags=NULL,metadata_bytes=256,purged_at=clock_timestamp() \
        FROM unnest($1::bytea[],$2::bigint[]) m(hash,epoch) WHERE c.hash=m.hash AND c.epoch=m.epoch AND c.state<>3",
        &[&hashes,&epochs]).await.map_err(|e|DomainError::from_pg("obliterate custody release",e))?;
    Ok(())
}

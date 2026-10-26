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
    /// Every byte and file a reservation ever charged to `resident_*` (row 78).
    /// They only grow, so their growth between two reads is what was charged
    /// in between.
    pub charged_bytes: i64,
    pub charged_files: i64,
    pub metadata_bytes: i64,
    pub metadata_rows: i64,
    /// Released custody rows kept as cleanup authority (`state=3`). A row is
    /// kept only while no other durable row can re-authorize its late residue
    /// (WP-115 f1), so this is the residual the metadata budget still carries.
    pub kept_tombstones: i64,
    pub cleanup_backlog: i64,
    pub oldest_pending: Option<SystemTime>,
    pub metadata_full: bool,
}

/// One bounded pass of [`PostgresFragmentCoordinator::compact_stage_tombstones`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StageTombstoneSweep {
    /// Tombstones selected after the cursor.
    pub examined: u32,
    /// Tombstones deleted, each giving back one row and its bytes.
    pub compacted: u32,
    /// The last key examined; `None` once the walk reaches the end.
    pub last: Option<(Vec<u8>, i64)>,
}

/// Rollback recovery for the tombstone deletion (WP-115 f1). Run offline with
/// every replica stopped, before an older binary that needs a tombstone as its
/// only cleanup authority starts. It rebuilds one tombstone for each purged
/// staged epoch that has no custody row and charges it to the ledger again.
pub const STAGE_TOMBSTONE_REBUILD_SQL: &str =
    include_str!("../../../recovery/stage-tombstone-rebuild.sql");

const FULL_METADATA_BYTES: i64 = 1024;
const COMPACT_METADATA_BYTES: i64 = 256;

/// Whether a released custody row is redundant cleanup authority.
///
/// A late file under `staged/` needs a database row that lets
/// `begin_stage_cleanup` reclaim it. A custody row is redundant when another
/// durable fact already does that:
///
/// - the epoch row is staged and `PURGED`. Epochs come from the fence sequence
///   and are never reused, so only a fenced writer can still produce this file;
/// - or there is no epoch row and the head is absent or has moved on, which is
///   the orphan branch's own rule.
///
/// Otherwise (for example an expired preparation whose head still names this
/// epoch) the row stays as the only authority. The caller holds the head lock,
/// which every writer of the head and of epoch disposition takes first.
async fn stage_tombstone_redundant_locked(
    tx: &Transaction<'_>,
    hash: &[u8],
    epoch: i64,
) -> Result<bool, DomainError> {
    let row = tx
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM lore_fragment_epochs e WHERE e.hash=$1 AND e.epoch=$2 \
               AND e.authority=$3 AND e.disposition=$4) \
             OR (NOT EXISTS(SELECT 1 FROM lore_fragment_epochs e WHERE e.hash=$1 AND e.epoch=$2) \
               AND NOT EXISTS(SELECT 1 FROM lore_fragment_lifecycle l \
                 WHERE l.hash=$1 AND l.current_epoch=$2))",
            &[
                &hash,
                &epoch,
                &schema::AUTHORITY_STAGED,
                &schema::DISPOSITION_PURGED,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("stage tombstone authority", e))?;
    Ok(row.get(0))
}

/// Give back released stage usage. The table's CHECK constraints refuse an
/// underflow.
async fn release_stage_usage_locked(
    tx: &Transaction<'_>,
    live_bytes: i64,
    live_files: i64,
    metadata_bytes: i64,
    metadata_rows: i64,
) -> Result<(), DomainError> {
    tx.execute(
        "UPDATE lore_fragment_stage_usage SET live_bytes=live_bytes-$1,live_files=live_files-$2, \
         metadata_bytes=metadata_bytes-$3,metadata_rows=metadata_rows-$4 WHERE singleton",
        &[&live_bytes, &live_files, &metadata_bytes, &metadata_rows],
    )
    .await
    .map_err(|e| DomainError::from_pg("stage capacity release", e))?;
    Ok(())
}

/// The ledger backstop's refusal: the published policy has no room for this
/// reservation. Admission refuses first from observed occupancy; a PUT reaches
/// this only when that occupancy is stale between observations.
const STAGE_CAPACITY_EXHAUSTED: &str = "stage capacity exhausted";

/// Whether `error` is exactly the ledger backstop's capacity refusal, which a
/// later attempt clears once the drain frees room. Every other refusal,
/// including a missing ledger row or a reservation the policy can never hold,
/// stays a permanent error.
pub fn is_stage_capacity_exhausted(error: &DomainError) -> bool {
    matches!(error, DomainError::NotReady(detail) if detail == STAGE_CAPACITY_EXHAUSTED)
}

/// Another session committed this exact custody key first. Only a cleanup's
/// orphan reclaim can meet it: two replicas reclaiming one headless file.
const STAGE_CUSTODY_KEY_TAKEN: &str = "stage custody key already reserved";

/// Whether `error` is the losing side of a concurrent reserve of one custody
/// key. The winner owns the cleanup, so the loser has nothing to do.
pub fn is_stage_custody_key_taken(error: &DomainError) -> bool {
    matches!(error, DomainError::Contention(detail) if detail == STAGE_CUSTODY_KEY_TAKEN)
}

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
    // cleanup marker's charge now; physical cleanup cannot require a later
    // allocation. A headless orphan reclaim has no head to lock, so a rival
    // reserve of the same key waits on this insert and then inserts nothing.
    let inserted = tx.execute_cached(
        "INSERT INTO lore_fragment_stage_custody \
         (hash,epoch,operation_fence,original_flags,size_payload,prepare_deadline,state,metadata_bytes) \
         SELECT $1,$2,$3,$4,$5,clock_timestamp() + prepare_ttl_ms * interval '1 millisecond',0,$6 \
         FROM lore_fragment_stage_policy WHERE singleton AND expires_at > clock_timestamp() \
         ON CONFLICT (hash,epoch) DO NOTHING",
        &[&hash,&epoch,&fence,&i64::from(input.original_flags),&size,&FULL_METADATA_BYTES],
    ).await.map_err(|e| DomainError::from_pg("stage custody reserve",e))?;
    if inserted != 1 {
        // Zero rows is either no live policy or a conflict. Decide by the
        // policy, not by re-reading the key: that read takes a new snapshot,
        // in which the winner may already have released and deleted the row.
        let live = tx
            .query_opt(
                "SELECT 1 FROM lore_fragment_stage_policy \
                 WHERE singleton AND expires_at > clock_timestamp()",
                &[],
            )
            .await
            .map_err(|e| DomainError::from_pg("stage custody reserve policy", e))?;
        if live.is_some() {
            return Err(DomainError::Contention(STAGE_CUSTODY_KEY_TAKEN.into()));
        }
        return Err(DomainError::NotReady(
            "stage policy absent or expired".into(),
        ));
    }
    sequence.enter(LockClass::StageUsage)?;
    let charged = tx.execute_cached(
        "UPDATE lore_fragment_stage_usage AS u SET \
         live_bytes=u.live_bytes+$1, live_files=u.live_files+1, \
         charged_bytes=u.charged_bytes+$1, charged_files=u.charged_files+1, \
         metadata_bytes=u.metadata_bytes+$2, metadata_rows=u.metadata_rows+1 \
         FROM lore_fragment_stage_policy AS p \
         WHERE u.singleton AND p.singleton \
           AND u.live_bytes <= p.max_bytes-$1 AND u.live_files < p.max_files \
           AND u.metadata_bytes <= p.max_metadata_bytes-$2 AND u.metadata_rows < p.max_metadata_rows",
        &[&size,&FULL_METADATA_BYTES],
    ).await.map_err(|e| DomainError::from_pg("stage capacity reserve",e))?;
    if charged != 1 {
        // Zero rows is retryable pressure only when an empty ledger could hold
        // this reservation. A missing usage or policy row is corruption, and a
        // payload larger than `max_bytes` never fits; neither clears by
        // retrying, so neither may read as the capacity refusal. The policy's
        // CHECK constraints already guarantee room for one file and one full
        // metadata charge, so only the byte limit decides.
        let fits = tx
            .query_opt(
                "SELECT p.max_bytes >= $1 \
                 FROM lore_fragment_stage_usage AS u, lore_fragment_stage_policy AS p \
                 WHERE u.singleton AND p.singleton",
                &[&size],
            )
            .await
            .map_err(|e| DomainError::from_pg("stage capacity classification", e))?;
        return Err(match fits.map(|row| row.get::<_, bool>(0)) {
            None => DomainError::Internal("stage usage or policy row missing".into()),
            Some(false) => {
                DomainError::Internal("stage reservation exceeds the stage policy".into())
            }
            Some(true) => DomainError::NotReady(STAGE_CAPACITY_EXHAUSTED.into()),
        });
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
        .execute_cached(
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
    let released = row.get::<_, i16>("state") == 3;
    let size: i64 = row.get("size_payload");
    let metadata: i64 = row.get("metadata_bytes");
    let redundant = stage_tombstone_redundant_locked(tx, hash, epoch).await?;
    if released && !redundant {
        return Ok(());
    }
    sequence.enter(LockClass::StageUsage)?;
    if redundant {
        let (bytes, files) = if released { (0, 0) } else { (size, 1) };
        release_stage_usage_locked(tx, bytes, files, metadata, 1).await?;
        tx.execute(
            "DELETE FROM lore_fragment_stage_custody WHERE hash=$1 AND epoch=$2",
            &[&hash, &epoch],
        )
        .await
        .map_err(|e| DomainError::from_pg("stage release delete", e))?;
        return Ok(());
    }
    release_stage_usage_locked(tx, size, 1, metadata - COMPACT_METADATA_BYTES, 0).await?;
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
            "SELECT u.live_bytes,u.live_files,u.charged_bytes,u.charged_files,u.metadata_bytes,u.metadata_rows, \
             (u.metadata_bytes > p.max_metadata_bytes-1024 OR u.metadata_rows >= p.max_metadata_rows) AS metadata_full, \
             (SELECT count(*) FROM lore_fragment_lifecycle WHERE state=3)::bigint AS pending_files, \
             (SELECT coalesce(sum(e.size_payload),0)::bigint FROM lore_fragment_lifecycle l \
                JOIN lore_fragment_epochs e ON e.hash=l.hash AND e.epoch=l.current_epoch WHERE l.state=3) AS pending_bytes, \
             (SELECT min(updated_at) FROM lore_fragment_lifecycle WHERE state=3) AS oldest_pending, \
             (SELECT count(*) FROM lore_fragment_stage_custody WHERE state=3)::bigint AS kept_tombstones, \
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
            charged_bytes: row.get("charged_bytes"),
            charged_files: row.get("charged_files"),
            metadata_bytes: row.get("metadata_bytes"),
            metadata_rows: row.get("metadata_rows"),
            kept_tombstones: row.get("kept_tombstones"),
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
            // Reclaim only what a released row could have authorized: a
            // purged staged epoch, or an epoch nothing else names. Release
            // deletes its row under exactly this rule.
            if !stage_tombstone_redundant_locked(&tx, hash, epoch).await? {
                return Ok(None);
            }
            // A purged epoch's bytes were charged once and given back. Its
            // late or stale-scanned file takes a file slot but no new bytes,
            // as the tombstone it replaces charged none: a 256 KiB charge per
            // stale scan entry would widen the walk bound (row 78) by that
            // much. An unknown orphan keeps the full charge.
            let purged = tx
                .query_one(
                    "SELECT EXISTS(SELECT 1 FROM lore_fragment_epochs WHERE hash=$1 AND epoch=$2 \
                     AND authority=$3 AND disposition=$4)",
                    &[
                        &hash,
                        &epoch,
                        &schema::AUTHORITY_STAGED,
                        &schema::DISPOSITION_PURGED,
                    ],
                )
                .await
                .map_err(|e| DomainError::from_pg("stage orphan epoch", e))?
                .get::<_, bool>(0);
            let fence = next_fence(&tx).await?;
            reserve_stage_locked(
                &tx,
                &mut sequence,
                hash,
                epoch,
                fence,
                StageReservationInput {
                    size_payload: if purged {
                        0
                    } else {
                        MAX_FRAGMENT_WRITE_CLAIM_BODY_BYTES
                    },
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

    /// Withdraw this attempt's own `PreparingStage` intent after a failure
    /// that placed nothing under `staged/`.
    ///
    /// A compare-and-set on the exact head (`PreparingStage`, epoch, fence) and
    /// the exact live custody row. The custody row is sealed for cleanup
    /// (`state=2`), so the next `begin_stage` no longer sees a live preparation
    /// and admits a new epoch at once. The head takes a fresh fence, so a late
    /// commit of the withdrawn intent is `Fenced` on every observation, and the
    /// sealed row refuses `publish_stage_locked` as well. The capacity charge
    /// stays with the row until fenced cleanup releases it, exactly as for an
    /// expired preparation, so no residue is reclaimed twice.
    ///
    /// `Ok(false)` when the head or the row moved; nothing is written then. The
    /// caller must not call this once the attempt may have renamed its file.
    pub async fn withdraw_stage(&self, intent: &FragmentIntent) -> Result<bool, DomainError> {
        if intent.authority != EpochAuthority::Staged {
            return Err(DomainError::InvalidInput(
                "only a stage intent can be withdrawn".into(),
            ));
        }
        let mut client = self.checkout().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| DomainError::from_pg("stage withdraw begin", e))?;
        let mut sequence = LockSequence::new();
        let head = lock_fragment_head(&tx, &mut sequence, &intent.hash).await?;
        let owned = head.is_some_and(|head| {
            head.state == FragmentLifecycleState::PreparingStage
                && head.current_epoch == intent.epoch
                && head.last_fence == intent.fence
        });
        if !owned {
            return Ok(false);
        }
        sequence.enter(LockClass::StageCustody)?;
        let sealed = tx
            .execute(
                "UPDATE lore_fragment_stage_custody SET state=2 \
             WHERE hash=$1 AND epoch=$2 AND operation_fence=$3 AND state=0",
                &[&intent.hash, &intent.epoch, &intent.fence],
            )
            .await
            .map_err(|e| DomainError::from_pg("stage withdraw seal", e))?;
        if sealed != 1 {
            return Ok(false);
        }
        let fence = next_fence(&tx).await?;
        tx.execute(
            "UPDATE lore_fragment_lifecycle \
                SET last_fence = $2, updated_at = clock_timestamp() \
              WHERE hash = $1",
            &[&intent.hash, &fence],
        )
        .await
        .map_err(|e| DomainError::from_pg("stage withdraw fence stamp", e))?;
        classify_commit(tx.commit().await, "stage withdraw commit")?;
        Ok(true)
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
                "SELECT state,operation_fence FROM lore_fragment_stage_custody \
            WHERE hash=$1 AND epoch=$2 FOR UPDATE",
                &[&intent.target.hash(), &intent.target.epoch()],
            )
            .await
            .map_err(|e| DomainError::from_pg("stage cleanup commit custody", e))?;
        match row {
            Some(row)
                if row.get::<_, i64>("operation_fence") == intent.fence
                    && matches!(row.get::<_, i16>("state"), 2 | 3) =>
            {
                // Purge the epoch first: release deletes the row when that
                // purge leaves it redundant.
                tx.execute(
                    "UPDATE lore_fragment_epochs SET disposition=$3 \
                     WHERE hash=$1 AND epoch=$2 AND authority=1",
                    &[
                        &intent.target.hash(),
                        &intent.target.epoch(),
                        &schema::DISPOSITION_PURGED,
                    ],
                )
                .await
                .map_err(|e| DomainError::from_pg("stage cleanup epoch purge", e))?;
                release_stage_locked(
                    &tx,
                    &mut sequence,
                    intent.target.hash(),
                    intent.target.epoch(),
                )
                .await?;
            }
            // A replay after this cleanup deleted its own redundant row. The
            // release happened once; there is nothing left to give back.
            None if stage_tombstone_redundant_locked(
                &tx,
                intent.target.hash(),
                intent.target.epoch(),
            )
            .await? => {}
            _ => return Err(DomainError::NotReady("stage cleanup fence changed".into())),
        }
        classify_commit(tx.commit().await, "stage cleanup commit")?;
        failpoint!("stage.cleanup.settled")?;
        Ok(())
    }

    /// Delete tombstones that became redundant after their release: rows a
    /// release before WP-115 f1 kept, and rows whose head has since moved on.
    ///
    /// Selection is advisory and unlocked. Each row is then decided in its own
    /// transaction under the head lock and the row lock, with the same rule
    /// release uses, so two replicas sweeping one range delete each row once.
    /// A kept row costs one probe per walk.
    pub async fn compact_stage_tombstones(
        &self,
        after: Option<(&[u8], i64)>,
        limit: u32,
    ) -> Result<StageTombstoneSweep, DomainError> {
        if !(1..=256).contains(&limit) {
            return Err(DomainError::InvalidInput("stage tombstone batch".into()));
        }
        let (hash, epoch) = after.unwrap_or((&[], 0));
        let mut client = self.checkout().await?;
        let candidates: Vec<(Vec<u8>, i64)> = client
            .query(
                "SELECT hash,epoch FROM lore_fragment_stage_custody \
                 WHERE state=3 AND (hash,epoch)>($1,$2) ORDER BY hash,epoch LIMIT $3",
                &[&hash, &epoch, &i64::from(limit)],
            )
            .await
            .map_err(|e| DomainError::from_pg("stage tombstone candidates", e))?
            .into_iter()
            .map(|r| (r.get(0), r.get(1)))
            .collect();
        let mut sweep = StageTombstoneSweep::default();
        for (hash, epoch) in &candidates {
            sweep.examined += 1;
            let tx = client
                .transaction()
                .await
                .map_err(|e| DomainError::from_pg("stage tombstone begin", e))?;
            let mut sequence = LockSequence::new();
            lock_fragment_head(&tx, &mut sequence, hash).await?;
            sequence.enter(LockClass::StageCustody)?;
            let row = tx
                .query_opt(
                    "SELECT metadata_bytes FROM lore_fragment_stage_custody \
                     WHERE hash=$1 AND epoch=$2 AND state=3 FOR UPDATE",
                    &[hash, epoch],
                )
                .await
                .map_err(|e| DomainError::from_pg("stage tombstone lock", e))?;
            let Some(row) = row else {
                continue;
            };
            if !stage_tombstone_redundant_locked(&tx, hash, *epoch).await? {
                continue;
            }
            sequence.enter(LockClass::StageUsage)?;
            release_stage_usage_locked(&tx, 0, 0, row.get("metadata_bytes"), 1).await?;
            tx.execute(
                "DELETE FROM lore_fragment_stage_custody WHERE hash=$1 AND epoch=$2 AND state=3",
                &[hash, epoch],
            )
            .await
            .map_err(|e| DomainError::from_pg("stage tombstone delete", e))?;
            classify_commit(tx.commit().await, "stage tombstone commit")?;
            sweep.compacted += 1;
        }
        // A short page is the end of the walk; the caller starts over.
        if candidates.len() == limit as usize {
            sweep.last = candidates.into_iter().last();
        }
        Ok(sweep)
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
    // Every staged target needs its row, even though release may delete rows.
    // Obliterate names only the current epoch. A cleanup deletes a row only
    // once that epoch is PURGED or the head has left it, and a pre-purged
    // evidence epoch is already Fenced by the caller (coordinator.rs,
    // `commit_obliterate_payload`). So a missing row is corruption here. The
    // redundancy rule is not the test: the caller's own purge, earlier in this
    // transaction, would make it hold.
    if rows.len() != stages.len() {
        return Err(DomainError::NotReady("obliterate custody missing".into()));
    }
    let mut bytes = 0i64;
    let mut files = 0i64;
    let mut metadata = 0i64;
    let mut rows_back = 0i64;
    let mut compact: (Vec<Vec<u8>>, Vec<i64>) = (Vec::new(), Vec::new());
    let mut delete: (Vec<Vec<u8>>, Vec<i64>) = (Vec::new(), Vec::new());
    for row in rows {
        let hash: Vec<u8> = row.get("hash");
        let epoch: i64 = row.get("epoch");
        let released = row.get::<_, i16>("state") == 3;
        let redundant = stage_tombstone_redundant_locked(tx, &hash, epoch).await?;
        if released && !redundant {
            continue;
        }
        if !released {
            bytes = bytes
                .checked_add(row.get("size_payload"))
                .ok_or_else(|| DomainError::Internal("stage release overflow".into()))?;
            files += 1;
        }
        let row_metadata: i64 = row.get("metadata_bytes");
        let given = if redundant {
            rows_back += 1;
            delete.0.push(hash);
            delete.1.push(epoch);
            row_metadata
        } else {
            compact.0.push(hash);
            compact.1.push(epoch);
            row_metadata - COMPACT_METADATA_BYTES
        };
        metadata = metadata
            .checked_add(given)
            .ok_or_else(|| DomainError::Internal("stage metadata release overflow".into()))?;
    }
    sequence.enter(LockClass::StageUsage)?;
    release_stage_usage_locked(tx, bytes, files, metadata, rows_back).await?;
    tx.execute("UPDATE lore_fragment_stage_custody c SET state=3,size_payload=0,original_flags=NULL,metadata_bytes=256,purged_at=clock_timestamp() \
        FROM unnest($1::bytea[],$2::bigint[]) m(hash,epoch) WHERE c.hash=m.hash AND c.epoch=m.epoch AND c.state<>3",
        &[&compact.0,&compact.1]).await.map_err(|e|DomainError::from_pg("obliterate custody release",e))?;
    tx.execute(
        "DELETE FROM lore_fragment_stage_custody c USING unnest($1::bytea[],$2::bigint[]) m(hash,epoch) \
         WHERE c.hash=m.hash AND c.epoch=m.epoch",
        &[&delete.0, &delete.1],
    )
    .await
    .map_err(|e| DomainError::from_pg("obliterate custody delete", e))?;
    Ok(())
}

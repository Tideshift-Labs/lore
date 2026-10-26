-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
-- WP-115 f1 rollback recovery: rebuild the stage cleanup tombstones that release deleted.
--
-- Since WP-115 f1, a stage release deletes its custody row when the staged epoch row is PURGED,
-- because that epoch row re-authorizes late residue cleanup. A binary from before f1 does not
-- read the epoch row that way: with no custody row it refuses to reclaim a late file for such an
-- epoch, and the file stays on disk, over the ledger. Run this before such a binary starts.
--
-- Stop every loreserver replica first; NOWAIT refuses while a session holds a table. Run as the
-- owner of the fragment tables. It is idempotent: a second run inserts nothing.
-- Each rebuilt row is charged one row and 256 bytes again, so the cell may need a larger
-- max_metadata_rows (an offline stage policy rotation) before the old binary admits new stages.
BEGIN ISOLATION LEVEL SERIALIZABLE;
LOCK TABLE lore_fragment_lifecycle, lore_fragment_epochs, lore_fragment_stage_custody,
 lore_fragment_stage_usage IN ACCESS EXCLUSIVE MODE NOWAIT;
WITH rebuilt AS (
 INSERT INTO lore_fragment_stage_custody
  (hash,epoch,operation_fence,original_flags,size_payload,prepare_deadline,state,metadata_bytes,purged_at)
 SELECT e.hash,e.epoch,nextval('lore_fragment_fence_seq'),NULL,0,clock_timestamp(),3,256,clock_timestamp()
 FROM lore_fragment_epochs e
 WHERE e.authority=1 AND e.disposition=2
  AND NOT EXISTS(SELECT 1 FROM lore_fragment_stage_custody c WHERE c.hash=e.hash AND c.epoch=e.epoch)
 RETURNING metadata_bytes)
UPDATE lore_fragment_stage_usage
 SET metadata_rows=metadata_rows+(SELECT count(*) FROM rebuilt),
  metadata_bytes=metadata_bytes+(SELECT coalesce(sum(metadata_bytes),0) FROM rebuilt)
 WHERE singleton;
COMMIT;

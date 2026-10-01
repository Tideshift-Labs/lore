-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
-- WP-115 rows 56 and 66: reclaim superseded spool markers, and give the cleanup scan a due time.
--
-- A FORWARD STEP like 0028: no transaction control. The installer opens one SERIALIZABLE
-- transaction around this body, attests R29 inside it, and only then commits.
--
-- Row 56. metadata_rows only ever grew: a marker (state 4) kept its row and its 1024-byte charge
-- forever, so a cell wedged on metadata_max_rows. An offline policy rotation now marks every
-- existing custody row of that (boundary, cell) superseded. The new revision pin already fences
-- the database side: a replayed old-revision descriptor finds no custody row once the marker is
-- gone and is refused DRAIN_POLICY_MISMATCH by drain_policy_read_v1. The marker's one remaining
-- job is the filesystem: a stale process can still write a late .blob (the spool writer makes no
-- database check), and only a rescan unlinks it. So a superseded marker is deleted only by a
-- caller whose OWN claim came after both the rotation and the marker's state-4 transition: that
-- caller unlinked after its claim, so a blob written before that claim is gone. The deletion
-- gives back exactly the marker's row and bytes, and refuses an underflow like 0028. Both fence
-- times and every claim time come from clock_unix_ms_v1 (wall clock); this assumes that clock does
-- not step backwards across a rotation.
--
-- After a rotation, a physical spool larger than its ledger is a red signal: it is a late blob
-- that no remaining custody row will ever unlink.
--
-- Row 66. The cleanup scan was one FIFO over every custody row: released rows and markers were
-- rescanned once per cycle (about 300 s over 9,200 rows), and both replicas walked the same head.
-- due_ms now says when a row next needs a scan, per state:
--   1, 2  when cleanup_not_before passes (as before), or a lost release after its lease;
--   3     when compaction is due: at once if superseded, else after the old policy's expiry;
--   4     superseded: at once, until a post-fence rescan deletes it;
--         otherwise: one slow late-blob sweep per hour.
-- The candidates call leases what it picks for 30 s with FOR UPDATE SKIP LOCKED, so two replicas
-- take disjoint rows and a row lost with its replica comes back after 30 s.
SET LOCAL ROLE object_dispatch_retention_owner;

-- Replicas must be stopped, as in 0027's rotation and 0028.
LOCK TABLE object_store_retention.object_dispatch_spool_objects,
 object_store_retention.drain_spool_custody,object_store_retention.object_dispatch_quota_usage,
 object_store_retention.drain_policies IN ACCESS EXCLUSIVE MODE NOWAIT;

CREATE OR REPLACE FUNCTION object_store_retention.cell_schema_revision_v1() RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$ SELECT 29 $$;

-- Existing rows start not superseded, unfenced and unleased.
ALTER TABLE object_store_retention.drain_spool_custody
 ADD COLUMN superseded boolean NOT NULL DEFAULT false,
 ADD COLUMN marker_fence_ms bigint NOT NULL DEFAULT 0 CHECK(marker_fence_ms>=0),
 ADD COLUMN lease_until_ms bigint NOT NULL DEFAULT 0 CHECK(lease_until_ms>=0);
ALTER TABLE object_store_retention.drain_spool_custody
 ADD COLUMN due_ms bigint GENERATED ALWAYS AS (CASE
  WHEN state IN(1,2) THEN GREATEST(cleanup_not_before,lease_until_ms)
  WHEN state=3 THEN GREATEST(cleanup_not_before,CASE WHEN superseded THEN 0 ELSE policy_expiry_ms END,lease_until_ms)
  WHEN superseded THEN lease_until_ms
  ELSE GREATEST(last_scan_ms+3600000,lease_until_ms) END) STORED;
DROP INDEX object_store_retention.drain_spool_cleanup;
CREATE INDEX drain_spool_due ON object_store_retention.drain_spool_custody(boundary,cell,due_ms,spool_id);

-- The candidates call is the queue claim. It runs at READ COMMITTED, while claim, release and
-- compact stay SERIALIZABLE. Two reasons. Under SERIALIZABLE, two SKIP LOCKED scans of one index
-- page each read the other's leased row and abort each other with 40001, which is the head
-- contention this replaces. And the lease is only a hint: it changes which replica scans a row
-- first, never what a claim, release or compaction may do. Those keep their fence and state
-- checks, and a lease lost to a crash only delays a row by 30 s.
CREATE OR REPLACE FUNCTION object_store_retention.drain_cleanup_candidates_v1(boundary text,cell text,batch integer)
RETURNS TABLE(spool uuid) LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE observed_ms bigint:=object_store_retention.clock_unix_ms_v1();
BEGIN
 PERFORM object_store_retention.assert_dispatch_runtime_v1();
 IF batch NOT BETWEEN 1 AND 256 THEN RAISE EXCEPTION 'DRAIN_BATCH_INVALID'; END IF;
 RETURN QUERY WITH picked AS (
  SELECT x.spool_id FROM object_store_retention.drain_spool_custody x
  WHERE x.boundary=drain_cleanup_candidates_v1.boundary AND x.cell=drain_cleanup_candidates_v1.cell
  AND x.due_ms<=observed_ms
  ORDER BY x.due_ms,x.spool_id LIMIT batch FOR UPDATE SKIP LOCKED
 ), leased AS (
  UPDATE object_store_retention.drain_spool_custody x SET lease_until_ms=observed_ms+30000
  FROM picked WHERE x.spool_id=picked.spool_id RETURNING x.spool_id
 ) SELECT leased.spool_id FROM leased;
END $$;

-- A claim that lost to another session clears the caller's lease, so the row is due again at once
-- instead of after 30 s. Same rules as the lease: READ COMMITTED from the client, a hint only, and
-- a row another session holds is skipped because that session is working on it.
CREATE FUNCTION object_store_retention.drain_cleanup_unlease_v1(spool uuid)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM object_store_retention.assert_dispatch_runtime_v1();
 UPDATE object_store_retention.drain_spool_custody x SET lease_until_ms=0
 WHERE x.spool_id IN(SELECT y.spool_id FROM object_store_retention.drain_spool_custody y
  WHERE y.spool_id=spool FOR UPDATE SKIP LOCKED);
END $$;

-- Claim, returning the claim's own scan time. A row a peer has already deleted returns no row.
CREATE FUNCTION object_store_retention.drain_cleanup_claim_v2(spool uuid)
RETURNS TABLE(boundary text,logical_id uuid,attempt_id uuid,fence bigint,scanned_ms bigint)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE s object_store_retention.object_dispatch_spool_objects%ROWTYPE; c object_store_retention.drain_spool_custody%ROWTYPE;
DECLARE now_ms bigint;
BEGIN
 PERFORM object_store_retention.assert_dispatch_runtime_v1(); PERFORM object_store_retention.assert_serializable_write_v1();
 SELECT * INTO s FROM object_store_retention.object_dispatch_spool_objects x WHERE x.spool_object_id=spool FOR UPDATE;
 SELECT * INTO c FROM object_store_retention.drain_spool_custody x WHERE x.spool_id=spool FOR UPDATE;
 IF NOT FOUND THEN RETURN; END IF;
 now_ms:=object_store_retention.clock_unix_ms_v1();
 IF c.cleanup_not_before>now_ms THEN RAISE EXCEPTION 'DRAIN_CLEANUP_TOO_EARLY'; END IF;
 IF c.state=1 THEN
  UPDATE object_store_retention.drain_spool_custody x SET state=2,cleanup_fence=x.cleanup_fence+1 WHERE x.spool_id=spool RETURNING * INTO c;
 END IF;
 UPDATE object_store_retention.drain_spool_custody x SET last_scan_ms=now_ms WHERE x.spool_id=spool;
 RETURN QUERY SELECT c.boundary,c.logical_id,c.attempt_id,c.cleanup_fence,now_ms;
END $$;
DROP FUNCTION object_store_retention.drain_cleanup_claim_v1(uuid);

-- 0028's release, unchanged except that a row a peer has already deleted is a no-op.
CREATE OR REPLACE FUNCTION object_store_retention.drain_cleanup_release_v1(spool uuid,fence bigint)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE s object_store_retention.object_dispatch_spool_objects%ROWTYPE; c object_store_retention.drain_spool_custody%ROWTYPE;
DECLARE q object_store_retention.object_dispatch_quota_usage%ROWTYPE; n integer:=0; receipt bytea; computed_release_digest bytea;
DECLARE retained bigint;
BEGIN
 PERFORM object_store_retention.assert_dispatch_runtime_v1(); PERFORM object_store_retention.assert_serializable_write_v1();
 SELECT * INTO s FROM object_store_retention.object_dispatch_spool_objects x WHERE x.spool_object_id=spool FOR UPDATE;
 SELECT * INTO c FROM object_store_retention.drain_spool_custody x WHERE x.spool_id=spool FOR UPDATE;
 IF NOT FOUND THEN RETURN; END IF;
 IF c.cleanup_fence IS DISTINCT FROM fence OR c.state=1 THEN RAISE EXCEPTION 'DRAIN_CLEANUP_FENCED'; END IF;
 IF c.state IN(3,4) THEN RETURN; END IF;
 IF s.spool_object_id IS NULL THEN RAISE EXCEPTION 'DRAIN_CLEANUP_MISSING_ACCOUNTING'; END IF;
 FOR q IN SELECT * FROM object_store_retention.object_dispatch_quota_usage x
 WHERE x.provider_boundary_id=c.boundary AND x.quota_class=1 AND
 ((x.scope_kind=1 AND x.scope_id=c.boundary) OR (x.scope_kind=2 AND x.scope_id=c.cell) OR (x.scope_kind=3 AND x.scope_id=c.service))
 ORDER BY x.scope_kind FOR UPDATE LOOP
  IF q.used_bytes<s.quota_bytes OR q.used_rows<s.quota_rows OR q.used_concurrency<s.quota_concurrency THEN RAISE EXCEPTION 'DRAIN_COUNTER_UNDERFLOW'; END IF;
  n:=n+1;
 END LOOP;
 IF n<>3 THEN RAISE EXCEPTION 'DRAIN_COUNTER_MISSING'; END IF;
 UPDATE object_store_retention.object_dispatch_quota_usage x SET used_bytes=x.used_bytes-s.quota_bytes,
 used_rows=x.used_rows-s.quota_rows,used_concurrency=x.used_concurrency-s.quota_concurrency,counter_revision=x.counter_revision+1,
 updated_at_unix_ms=object_store_retention.clock_unix_ms_v1()
 WHERE x.provider_boundary_id=c.boundary AND x.quota_class=1 AND
 ((x.scope_kind=1 AND x.scope_id=c.boundary) OR (x.scope_kind=2 AND x.scope_id=c.cell) OR (x.scope_kind=3 AND x.scope_id=c.service));
 receipt:=convert_to('fragment-drain-release-v1','UTF8')||uuid_send(spool)||c.digest
 ||object_store_retention.local_canonical_u64_v1(fence::object_store_retention.uint64)
 ||object_store_retention.local_canonical_u64_v1(s.quota_bytes)
 ||object_store_retention.local_canonical_u64_v1(s.quota_rows)
 ||object_store_retention.local_canonical_u64_v1(s.quota_concurrency);
 computed_release_digest:=object_store_retention.local_blake3_v1(receipt);
 UPDATE object_store_retention.drain_spool_custody x SET state=3,release_receipt=receipt||computed_release_digest,release_digest=computed_release_digest
 WHERE x.spool_id=spool RETURNING * INTO c;
 retained:=object_store_retention.drain_retained_metadata_bytes_v1(c);
 IF retained<c.metadata_bytes THEN
  UPDATE object_store_retention.drain_spool_custody x SET metadata_bytes=retained WHERE x.spool_id=spool;
  UPDATE object_store_retention.drain_policies x
  SET metadata_bytes=(x.metadata_bytes::numeric-(c.metadata_bytes-retained))::object_store_retention.uint64
  WHERE x.boundary=c.boundary AND x.cell=c.cell AND x.metadata_bytes::numeric>=(c.metadata_bytes-retained);
  IF NOT FOUND THEN RAISE EXCEPTION 'DRAIN_METADATA_UNDERFLOW'; END IF;
 END IF;
END $$;

-- Compaction, with the claim's scan time. State 3 becomes a marker as before; a superseded row
-- does not wait for its old policy's expiry, because the new revision pin already refuses it.
-- A superseded marker is deleted only when scanned_ms is this caller's own claim (it never
-- exceeds the row's last_scan_ms) and that claim came after the marker fence.
CREATE FUNCTION object_store_retention.drain_cleanup_compact_v2(spool uuid,scanned_ms bigint)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE s object_store_retention.object_dispatch_spool_objects%ROWTYPE; c object_store_retention.drain_spool_custody%ROWTYPE;
DECLARE now_ms bigint;
BEGIN
 PERFORM object_store_retention.assert_dispatch_runtime_v1(); PERFORM object_store_retention.assert_serializable_write_v1();
 SELECT * INTO s FROM object_store_retention.object_dispatch_spool_objects x WHERE x.spool_object_id=spool FOR UPDATE;
 SELECT * INTO c FROM object_store_retention.drain_spool_custody x WHERE x.spool_id=spool FOR UPDATE;
 IF NOT FOUND THEN RETURN; END IF;
 now_ms:=object_store_retention.clock_unix_ms_v1();
 IF c.state=3 THEN
  IF greatest(s.expires_at_unix_ms,CASE WHEN c.superseded THEN 0 ELSE c.policy_expiry_ms END)>now_ms THEN RETURN; END IF;
  DELETE FROM object_store_retention.object_dispatch_spool_objects x WHERE x.spool_object_id=spool;
  UPDATE object_store_retention.drain_spool_custody x SET state=4,descriptor=NULL,canonical=NULL,metadata_bytes=1024,
   marker_fence_ms=greatest(x.marker_fence_ms,now_ms),lease_until_ms=0 WHERE x.spool_id=spool;
  UPDATE object_store_retention.drain_policies x SET metadata_bytes=x.metadata_bytes-(c.metadata_bytes-1024) WHERE x.boundary=c.boundary AND x.cell=c.cell;
  RETURN;
 END IF;
 IF c.state<>4 OR NOT c.superseded OR scanned_ms IS NULL
 OR scanned_ms<=c.marker_fence_ms OR scanned_ms>c.last_scan_ms THEN RETURN; END IF;
 DELETE FROM object_store_retention.drain_spool_custody x WHERE x.spool_id=spool;
 UPDATE object_store_retention.drain_policies x
 SET metadata_rows=(x.metadata_rows::numeric-1)::object_store_retention.uint64,
  metadata_bytes=(x.metadata_bytes::numeric-c.metadata_bytes)::object_store_retention.uint64
 WHERE x.boundary=c.boundary AND x.cell=c.cell AND x.metadata_rows::numeric>=1 AND x.metadata_bytes::numeric>=c.metadata_bytes;
 IF NOT FOUND THEN RAISE EXCEPTION 'DRAIN_METADATA_UNDERFLOW'; END IF;
END $$;
DROP FUNCTION object_store_retention.drain_cleanup_compact_v1(uuid);

-- 0027's rotation, with every existing custody row of the cell marked superseded and fenced at
-- the rotation time. The replay branch returns before that, so a retried rotation never marks
-- rows the new generation reserved.
CREATE OR REPLACE FUNCTION object_store_retention.drain_policy_rotate_v1(p jsonb, canonical bytea, digest bytea,
 expected_revision text, expected_digest bytea)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE old object_store_retention.drain_policies%ROWTYPE; now_ms bigint;
BEGIN
 IF session_user<>'object_dispatch_retention_maintenance' THEN RAISE EXCEPTION 'UNAUTHORIZED' USING ERRCODE='42501'; END IF;
 PERFORM object_store_retention.assert_serializable_write_v1();
 IF expected_revision IS NULL OR expected_digest IS NULL OR octet_length(expected_digest)<>32
 OR canonical IS DISTINCT FROM object_store_retention.drain_policy_bytes_v1(p) OR octet_length(p::text)>16384 THEN
  RAISE EXCEPTION 'DRAIN_ROTATION_INVALID';
 END IF;
 PERFORM object_store_retention.local_assert_blake3_v1(canonical,digest);
 LOCK TABLE object_store_retention.object_dispatch_spool_objects,
  object_store_retention.drain_spool_custody,object_store_retention.object_dispatch_quota_usage,
  object_store_retention.drain_policies IN ACCESS EXCLUSIVE MODE NOWAIT;
 SELECT * INTO STRICT old FROM object_store_retention.drain_policies x WHERE x.boundary=p->>'boundary' AND x.cell=p->>'cell';
 now_ms:=object_store_retention.clock_unix_ms_v1();
 IF old.policy=p AND old.canonical=canonical AND old.digest=digest THEN
  IF old.previous_revision IS DISTINCT FROM expected_revision OR old.previous_digest IS DISTINCT FROM expected_digest THEN
   RAISE EXCEPTION 'DRAIN_ROTATION_REPLAY_CONFLICT';
  END IF;
  PERFORM public.stage_policy_rotate_v1(p,digest,expected_revision,expected_digest);
  RETURN;
 END IF;
 IF old.revision IS DISTINCT FROM expected_revision OR old.digest IS DISTINCT FROM expected_digest
 OR (p->>'revision') COLLATE "C" <= old.revision COLLATE "C"
 OR p->>'service' IS DISTINCT FROM old.policy->>'service'
 OR (p->>'expires_at_ms')::bigint<=now_ms THEN RAISE EXCEPTION 'DRAIN_ROTATION_CONFLICT'; END IF;
 IF EXISTS(SELECT 1 FROM object_store_retention.drain_spool_custody c WHERE c.boundary=old.boundary AND c.cell=old.cell
    AND (c.state IN(1,2) OR c.cleanup_not_before>now_ms))
 OR EXISTS(SELECT 1 FROM object_store_retention.object_dispatch_quota_usage q WHERE q.provider_boundary_id=old.boundary
    AND q.quota_class=1 AND (q.used_bytes<>0 OR q.used_rows<>0 OR q.used_concurrency<>0)) THEN
  RAISE EXCEPTION 'DRAIN_ROTATION_NOT_QUIESCENT';
 END IF;
 IF old.metadata_rows>(p->>'metadata_max_rows')::numeric OR old.metadata_bytes>(p->>'metadata_max_bytes')::numeric THEN
  RAISE EXCEPTION 'DRAIN_ROTATION_CAPACITY';
 END IF;
 PERFORM public.stage_policy_rotate_v1(p,digest,expected_revision,expected_digest);
 UPDATE object_store_retention.drain_policies x SET revision=p->>'revision',policy=p,canonical=drain_policy_rotate_v1.canonical,
  digest=drain_policy_rotate_v1.digest,previous_revision=old.revision,previous_digest=old.digest
 WHERE x.boundary=old.boundary AND x.cell=old.cell;
 UPDATE object_store_retention.drain_spool_custody x SET superseded=true,
  marker_fence_ms=greatest(x.marker_fence_ms,now_ms),lease_until_ms=0
 WHERE x.boundary=old.boundary AND x.cell=old.cell;
END $$;

-- Observation gains the superseded rows still waiting for compaction or their post-fence rescan.
DROP FUNCTION object_store_retention.drain_observe_v1(text,text);
CREATE FUNCTION object_store_retention.drain_observe_v1(boundary text,cell text)
RETURNS TABLE(spool_bytes text,spool_files text,cleanup_backlog bigint,metadata_full boolean,superseded_pending bigint)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM object_store_retention.assert_dispatch_runtime_v1();
 RETURN QUERY SELECT coalesce(q.used_bytes,0)::text,coalesce(q.used_rows,0)::text,
 (SELECT count(*) FROM object_store_retention.drain_spool_custody c WHERE c.boundary=drain_observe_v1.boundary AND c.cell=drain_observe_v1.cell AND c.state IN(1,2) AND c.cleanup_not_before<=object_store_retention.clock_unix_ms_v1()),
 (p.metadata_rows+1>(p.policy->>'metadata_max_rows')::numeric OR p.metadata_bytes+16384>(p.policy->>'metadata_max_bytes')::numeric),
 (SELECT count(*) FROM object_store_retention.drain_spool_custody c WHERE c.boundary=drain_observe_v1.boundary AND c.cell=drain_observe_v1.cell AND c.superseded)
 FROM object_store_retention.drain_policies p LEFT JOIN object_store_retention.object_dispatch_quota_usage q
 ON q.provider_boundary_id=p.boundary AND q.scope_kind=2 AND q.scope_id=p.cell AND q.quota_class=1
 WHERE p.boundary=drain_observe_v1.boundary AND p.cell=drain_observe_v1.cell;
END $$;

REVOKE ALL ON FUNCTION object_store_retention.drain_cleanup_claim_v2(uuid),
 object_store_retention.drain_cleanup_unlease_v1(uuid),
 object_store_retention.drain_cleanup_compact_v2(uuid,bigint),
 object_store_retention.drain_observe_v1(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION object_store_retention.drain_cleanup_claim_v2(uuid),
 object_store_retention.drain_cleanup_unlease_v1(uuid),
 object_store_retention.drain_cleanup_compact_v2(uuid,bigint),
 object_store_retention.drain_observe_v1(text,text) TO object_dispatch_retention_runtime;

-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
-- CR-038: true up a released spool row's metadata charge to its actual retained size.
--
-- A FORWARD STEP, not a frozen install artifact. It carries no BEGIN or COMMIT: the installer
-- opens one SERIALIZABLE transaction around this body, attests the resulting catalog inside that
-- same transaction, and only then commits. A cell is therefore never left committed in a state
-- that does not attest. Fresh install runs this body through the same wrapper after 0027.
--
-- A reservation charges a flat 16384 metadata bytes before the row exists, which is right: the
-- size is not knowable then. The defect is that the charge was never trued up. A released row
-- held its worst-case allowance until compaction, and compaction waits for the policy
-- generation's expiry, so the byte counter reached metadata_max_bytes after
-- metadata_max_bytes / 16384 reservations and every replica refused writes. Observed on a live
-- cell: 8192 released rows holding exactly 134217728 bytes against a 134217728 cap, with zero
-- files in the spool directory.
--
-- This fixes the BYTE counter only. metadata_rows still never decreases (0026 increments it and
-- nothing decrements it); that is a separate, owner-held design question.
SET LOCAL ROLE object_dispatch_retention_owner;

-- Replicas must be stopped. NOWAIT turns a forgotten runtime transaction into a refusal rather
-- than a lock-order wait, the same rule as 0027's offline policy rotation.
LOCK TABLE object_store_retention.object_dispatch_spool_objects,
 object_store_retention.drain_spool_custody,object_store_retention.object_dispatch_quota_usage,
 object_store_retention.drain_policies IN ACCESS EXCLUSIVE MODE NOWAIT;

-- The runtime-visible schema revision. The catalog manifest covers this body, so the marker is
-- attested with everything else; a data column would not be. A binary that enables write-behind
-- refuses a cell whose marker is absent or names a revision it does not know.
CREATE FUNCTION object_store_retention.cell_schema_revision_v1() RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$ SELECT 28 $$;
REVOKE ALL ON FUNCTION object_store_retention.cell_schema_revision_v1() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION object_store_retention.cell_schema_revision_v1() TO object_dispatch_retention_runtime;

-- What a custody row still costs once it is released and its parts are all known.
--
-- ACTUAL size, not a flat constant: an undercounting charge lets a cell store more than
-- metadata_max_bytes while believing it is inside budget. Clamped to the charge the row already
-- holds, so a true-up only releases budget. The 1024 floor is compaction's marker charge and the
-- table's own CHECK(metadata_bytes>=1024).
CREATE FUNCTION object_store_retention.drain_retained_metadata_bytes_v1(
 c object_store_retention.drain_spool_custody) RETURNS bigint
LANGUAGE sql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT least(c.metadata_bytes, greatest(1024,
  1024
  + coalesce(octet_length(c.descriptor::text),0)
  + coalesce(octet_length(c.canonical),0)
  + coalesce(octet_length(c.release_receipt),0)
  + coalesce(octet_length(c.release_digest),0)));
$$;
REVOKE ALL ON FUNCTION object_store_retention.drain_retained_metadata_bytes_v1(
 object_store_retention.drain_spool_custody) FROM PUBLIC;

-- Release, with the true-up appended. Everything above the true-up is 0026's body unchanged.
-- CREATE OR REPLACE keeps the runtime role's existing EXECUTE grant.
CREATE OR REPLACE FUNCTION object_store_retention.drain_cleanup_release_v1(spool uuid,fence bigint)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE s object_store_retention.object_dispatch_spool_objects%ROWTYPE; c object_store_retention.drain_spool_custody%ROWTYPE;
DECLARE q object_store_retention.object_dispatch_quota_usage%ROWTYPE; n integer:=0; receipt bytea; computed_release_digest bytea;
DECLARE retained bigint;
BEGIN
 PERFORM object_store_retention.assert_dispatch_runtime_v1(); PERFORM object_store_retention.assert_serializable_write_v1();
 SELECT * INTO s FROM object_store_retention.object_dispatch_spool_objects x WHERE x.spool_object_id=spool FOR UPDATE;
 SELECT * INTO STRICT c FROM object_store_retention.drain_spool_custody x WHERE x.spool_id=spool FOR UPDATE;
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
 -- The true-up. The row is complete, so its worst-case allowance becomes its actual cost.
 -- Compaction later takes it to the 1024 marker and its decrement reads this same column, so
 -- nothing is released twice. An underflow is a bookkeeping error and fails closed.
 retained:=object_store_retention.drain_retained_metadata_bytes_v1(c);
 IF retained<c.metadata_bytes THEN
  UPDATE object_store_retention.drain_spool_custody x SET metadata_bytes=retained WHERE x.spool_id=spool;
  UPDATE object_store_retention.drain_policies x
  SET metadata_bytes=(x.metadata_bytes::numeric-(c.metadata_bytes-retained))::object_store_retention.uint64
  WHERE x.boundary=c.boundary AND x.cell=c.cell AND x.metadata_bytes::numeric>=(c.metadata_bytes-retained);
  IF NOT FOUND THEN RAISE EXCEPTION 'DRAIN_METADATA_UNDERFLOW'; END IF;
 END IF;
END $$;

-- Backfill. Every row already released carries an untrued reservation charge, so without this an
-- already-wedged cell stays wedged until its policy generation expires. Only state-3 rows still at
-- the charge the snapshot read are touched, so a row that compaction moved to state 4 is never
-- released a second time. Rows in states 1 and 2 are in flight and keep their full reservation.
DO $$
DECLARE f record;
BEGIN
 FOR f IN
  WITH trued AS (
   SELECT c.spool_id, c.boundary, c.cell, c.metadata_bytes AS charged,
    object_store_retention.drain_retained_metadata_bytes_v1(c) AS retained
   FROM object_store_retention.drain_spool_custody c WHERE c.state=3
  ), applied AS (
   UPDATE object_store_retention.drain_spool_custody x SET metadata_bytes=t.retained
   FROM trued t WHERE x.spool_id=t.spool_id AND x.state=3 AND x.metadata_bytes=t.charged AND t.retained<t.charged
   RETURNING t.boundary AS boundary, t.cell AS cell, t.charged-t.retained AS freed
  )
  SELECT boundary, cell, sum(freed) AS freed FROM applied GROUP BY boundary, cell
 LOOP
  UPDATE object_store_retention.drain_policies p
  SET metadata_bytes=(p.metadata_bytes::numeric-f.freed)::object_store_retention.uint64
  WHERE p.boundary=f.boundary AND p.cell=f.cell AND p.metadata_bytes::numeric>=f.freed;
  IF NOT FOUND THEN RAISE EXCEPTION 'DRAIN_METADATA_UNDERFLOW'; END IF;
 END LOOP;
END $$;

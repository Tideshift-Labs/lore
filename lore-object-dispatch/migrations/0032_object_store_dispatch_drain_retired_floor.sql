-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
-- WP-115 f2 (CR-041): spool custody rows are deleted online; a retired floor replaces the marker.
--
-- A FORWARD STEP like 0028-0031: no transaction control. The installer opens one SERIALIZABLE
-- transaction around this body, attests R32 inside it, and only then commits.
--
-- metadata_rows grew by one row per spool reservation for the life of a cell: a released row
-- became a state-4 marker, and only an offline rotation (0029) deleted markers. The marker had
-- two jobs.
--
-- * Database replay. A found row refuses a replayed descriptor. A released row is now deleted
--   only once cleanup_not_before has passed. cleanup_not_before >= hard_not_after >=
--   send_not_after (0026's descriptor check), so drain_reserve_v1 then refuses any replay with
--   DRAIN_EXPIRED before it looks for a row.
-- * Late files. The spool writer makes no database check, so a stale process can still write a
--   body after its row was released. Rows are now keyed for that by time instead of by row. Every
--   spool path names its UUIDv7 attempt id, and a body is written only after its reservation
--   committed. drain_policies.retired_floor_ms is a per-cell floor such that no custody row has
--   an attempt older than it, and drain_reserve_v1 refuses a new attempt older than it. So a
--   spool body whose attempt is older than the floor has no row and never will: the walk may
--   move it to quarantine. Reserve and the floor advance both write the policy row under
--   SERIALIZABLE, so they cannot interleave. The advance lags the clock by 15 minutes, which
--   bounds the time between minting an attempt id and reserving it plus clock skew between
--   replicas and the database.
SET LOCAL ROLE object_dispatch_retention_owner;

-- Replicas must be stopped, as in 0027's rotation and 0028-0031.
LOCK TABLE object_store_retention.object_dispatch_spool_objects,
 object_store_retention.drain_spool_custody,object_store_retention.object_dispatch_quota_usage,
 object_store_retention.drain_policies IN ACCESS EXCLUSIVE MODE NOWAIT;

CREATE OR REPLACE FUNCTION object_store_retention.cell_schema_revision_v1() RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$ SELECT 32 $$;

-- The unix-ms time of an RFC 9562 UUIDv7, or NULL for any other version or variant.
CREATE FUNCTION object_store_retention.drain_uuid_v7_ms_v1(u uuid) RETURNS bigint
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT CASE WHEN substr(h,13,1)='7' AND substr(h,17,1) IN('8','9','a','b')
  THEN ('x'||substr(h,1,12))::bit(48)::bigint END
 FROM (SELECT replace(u::text,'-','') AS h) t
$$;

ALTER TABLE object_store_retention.drain_policies
 ADD COLUMN retired_floor_ms bigint NOT NULL DEFAULT 0 CHECK(retired_floor_ms>=0);
CREATE INDEX drain_spool_attempt_ms ON object_store_retention.drain_spool_custody
 (boundary,cell,object_store_retention.drain_uuid_v7_ms_v1(attempt_id));

-- A released row is due when its cleanup time passes, and a legacy marker at once. There is no
-- hourly marker sweep any more: the floor walk finds late files.
ALTER TABLE object_store_retention.drain_spool_custody DROP COLUMN due_ms;
ALTER TABLE object_store_retention.drain_spool_custody
 ADD COLUMN due_ms bigint GENERATED ALWAYS AS (CASE
  WHEN state IN(1,2,3) THEN GREATEST(cleanup_not_before,lease_until_ms)
  ELSE lease_until_ms END) STORED;
CREATE INDEX drain_spool_due ON object_store_retention.drain_spool_custody(boundary,cell,due_ms,spool_id);

-- 0031's reservation, plus one refusal: a first-seen attempt older than the retired floor. A
-- logical or attempt id that is not a UUIDv7 never gets this far: drain_descriptor_bytes_v1 (0026)
-- runs 0013's local_uuid_v7_unix_ms_v1 over every id and raises INVALID_UUIDV7 (22023) first.
CREATE OR REPLACE FUNCTION object_store_retention.drain_reserve_v1(d jsonb, canonical bytea, digest bytea)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE p object_store_retention.drain_policies%ROWTYPE; s object_store_retention.object_dispatch_spool_objects%ROWTYPE;
DECLARE c object_store_retention.drain_spool_custody%ROWTYPE; r object_store_retention.dispatch_reserve_put_result_v1;
DECLARE snapshot record; q jsonb; now_ms bigint; charge bigint:=16384;
BEGIN
 PERFORM object_store_retention.assert_dispatch_runtime_v1(); PERFORM object_store_retention.assert_serializable_write_v1();
 IF octet_length(d::text)+octet_length(canonical)>10000 OR canonical IS DISTINCT FROM object_store_retention.drain_descriptor_bytes_v1(d) THEN RAISE EXCEPTION 'DRAIN_DESCRIPTOR_CANONICAL_MISMATCH'; END IF;
 IF digest IS NULL OR octet_length(digest)<>32 THEN RAISE EXCEPTION 'DRAIN_DESCRIPTOR_DIGEST_INVALID' USING ERRCODE='22000'; END IF;
 now_ms:=object_store_retention.clock_unix_ms_v1();
 IF (d->>'send_not_after_ms')::bigint<=now_ms THEN RAISE EXCEPTION 'DRAIN_EXPIRED'; END IF;
 -- Stable spool identity is always locked before custody, and before scope 1/2/3.
 SELECT * INTO s FROM object_store_retention.object_dispatch_spool_objects x
 WHERE x.logical_request_id=(d->>'logical_request_id')::uuid AND x.attempt_id=(d->>'attempt_id')::uuid AND x.payload_kind=1 FOR UPDATE;
 SELECT * INTO c FROM object_store_retention.drain_spool_custody x WHERE x.logical_id=(d->>'logical_request_id')::uuid AND x.attempt_id=(d->>'attempt_id')::uuid FOR UPDATE;
 IF FOUND THEN
  IF c.state<>1 OR c.canonical IS DISTINCT FROM canonical OR c.descriptor IS DISTINCT FROM d
   OR c.digest IS DISTINCT FROM digest
   OR s.spool_object_id IS NULL OR s.expires_at_unix_ms<=now_ms THEN RAISE EXCEPTION 'DRAIN_REPLAY_REFUSED'; END IF;
  -- Policy pins and expiry apply to replay too; allocation renewal does not rewrite d.
  SELECT * INTO STRICT p FROM object_store_retention.drain_policies x WHERE x.boundary=c.boundary AND x.cell=c.cell;
  IF p.revision IS DISTINCT FROM d->>'policy_revision' OR encode(p.digest,'hex') IS DISTINCT FROM d->>'policy_digest'
   OR (p.policy->>'expires_at_ms')::bigint<=now_ms THEN RAISE EXCEPTION 'DRAIN_POLICY_MISMATCH'; END IF;
  RETURN;
 END IF;
 IF s.spool_object_id IS NOT NULL THEN RAISE EXCEPTION 'DRAIN_UNOWNED_RESERVATION'; END IF;
 -- A first-seen attempt below the floor could own a path the floor walk already treats as retired.
 -- Fail closed: anything but a known attempt time at or above the floor is refused. A cell with
 -- no policy row is refused by drain_policy_read_v1 below, as before.
 SELECT * INTO p FROM object_store_retention.drain_policies x WHERE x.boundary=d->>'boundary' AND x.cell=d->>'cell';
 IF FOUND AND (object_store_retention.drain_uuid_v7_ms_v1((d->>'attempt_id')::uuid)>=p.retired_floor_ms) IS NOT TRUE THEN
  RAISE EXCEPTION 'DRAIN_ATTEMPT_RETIRED' USING ERRCODE='55000';
 END IF;
 SELECT * INTO STRICT snapshot FROM object_store_retention.drain_policy_read_v1(d->>'boundary',d->>'cell',d->>'policy_revision',decode(d->>'policy_digest','hex'));
 IF snapshot.allocation_revision IS DISTINCT FROM d->>'allocation_revision' OR snapshot.allocation_fence IS DISTINCT FROM (d->>'allocation_fence')::numeric
 OR snapshot.allocation_expiry_ms IS DISTINCT FROM (d->>'allocation_expiry_ms')::bigint
 OR snapshot.policy->>'service' IS DISTINCT FROM d->>'service'
 OR (d->>'prepared_ttl_ms')::numeric IS DISTINCT FROM (snapshot.policy->>'maximum_ttl_ms')::numeric THEN RAISE EXCEPTION 'DRAIN_SNAPSHOT_MISMATCH'; END IF;
 q:=snapshot.policy->'quotas';
 -- The retained reservation algebra owns row/byte/concurrency admission.
 r:=object_store_retention.object_store_dispatch_reserve_put_v1(
 'object-store-dispatch-reserve-put-v1','object-dispatch-v1',d->>'policy_revision',d->>'boundary',d->>'cell',d->>'service',
 (d->>'spool_object_id')::uuid,(d->>'logical_request_id')::uuid,(d->>'attempt_id')::uuid,(d->>'upload_id')::uuid,(d->>'upload_fence')::object_store_retention.uint64,
 decode(d->>'boundary_digest','hex'),d->>'boundary_token',decode(d->>'observation_digest','hex'),
 (d->>'body_size')::object_store_retention.uint64,decode(d->>'body_digest','hex'),digest,
 d->>'allocation_revision',(d->>'allocation_fence')::object_store_retention.uint64,(d->>'send_not_after_ms')::bigint,(d->>'allocation_expiry_ms')::bigint,
 (d->>'prepared_ttl_ms')::bigint,262144::object_store_retention.uint64,(snapshot.policy->>'quota_revision')::object_store_retention.uint64,
 (q->0->>0)::object_store_retention.uint64,(q->0->>1)::object_store_retention.uint64,(q->0->>2)::object_store_retention.uint64,(q->0->>3)::object_store_retention.uint64,(q->0->>4)::object_store_retention.uint64,(q->0->>5)::object_store_retention.uint64,
 (q->1->>0)::object_store_retention.uint64,(q->1->>1)::object_store_retention.uint64,(q->1->>2)::object_store_retention.uint64,(q->1->>3)::object_store_retention.uint64,(q->1->>4)::object_store_retention.uint64,(q->1->>5)::object_store_retention.uint64,
 (q->2->>0)::object_store_retention.uint64,(q->2->>1)::object_store_retention.uint64,(q->2->>2)::object_store_retention.uint64,(q->2->>3)::object_store_retention.uint64,(q->2->>4)::object_store_retention.uint64,(q->2->>5)::object_store_retention.uint64,256,256,16384);
 INSERT INTO object_store_retention.drain_spool_custody(spool_id,boundary,cell,service,logical_id,attempt_id,descriptor,canonical,digest,cleanup_not_before,metadata_bytes)
 VALUES(r.spool_object_id,d->>'boundary',d->>'cell',d->>'service',r.logical_request_id,r.attempt_id,d,canonical,digest,greatest(r.expires_at_unix_ms,(d->>'hard_not_after_ms')::bigint),charge);
 -- The reservation charged the ledger the body size and one row; the counters take the same.
 UPDATE object_store_retention.drain_policies x SET metadata_rows=x.metadata_rows+1,metadata_bytes=x.metadata_bytes+charge,
  charged_bytes=x.charged_bytes+(d->>'body_size')::numeric,charged_files=x.charged_files+1
 WHERE x.boundary=d->>'boundary' AND x.cell=d->>'cell'
 AND x.metadata_rows+1<=(x.policy->>'metadata_max_rows')::numeric AND x.metadata_bytes+charge<=(x.policy->>'metadata_max_bytes')::numeric;
 IF NOT FOUND THEN RAISE EXCEPTION 'DRAIN_METADATA_CAPACITY' USING ERRCODE='53000'; END IF;
END $$;

-- Raise the cell's floor to the oldest custody row's attempt time, never past now - 15 min and
-- never down. It writes the policy row only when the floor grows, so a concurrent first-seen
-- reserve (which also writes that row) and a growing advance cannot both commit.
CREATE FUNCTION object_store_retention.drain_retired_floor_advance_v1(boundary text,cell text)
RETURNS bigint LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE old bigint; oldest bigint; cap bigint; raised bigint;
BEGIN
 PERFORM object_store_retention.assert_dispatch_runtime_v1(); PERFORM object_store_retention.assert_serializable_write_v1();
 SELECT x.retired_floor_ms INTO STRICT old FROM object_store_retention.drain_policies x
 WHERE x.boundary=drain_retired_floor_advance_v1.boundary AND x.cell=drain_retired_floor_advance_v1.cell;
 cap:=object_store_retention.clock_unix_ms_v1()-900000;
 SELECT min(object_store_retention.drain_uuid_v7_ms_v1(c.attempt_id)) INTO oldest
 FROM object_store_retention.drain_spool_custody c
 WHERE c.boundary=drain_retired_floor_advance_v1.boundary AND c.cell=drain_retired_floor_advance_v1.cell;
 raised:=least(coalesce(oldest,cap),cap);
 IF raised<=old THEN RETURN old; END IF;
 UPDATE object_store_retention.drain_policies x SET retired_floor_ms=raised
 WHERE x.boundary=drain_retired_floor_advance_v1.boundary AND x.cell=drain_retired_floor_advance_v1.cell;
 RETURN raised;
END $$;

-- Compaction deletes a released row, or a legacy marker, with its spool object, and gives back
-- exactly its row and bytes. The cleanup_not_before guard is what makes a deleted descriptor's
-- replay a DRAIN_EXPIRED refusal; a claim already required it, so it never delays a real row.
CREATE FUNCTION object_store_retention.drain_cleanup_compact_v3(spool uuid)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE c object_store_retention.drain_spool_custody%ROWTYPE;
BEGIN
 PERFORM object_store_retention.assert_dispatch_runtime_v1(); PERFORM object_store_retention.assert_serializable_write_v1();
 PERFORM 1 FROM object_store_retention.object_dispatch_spool_objects x WHERE x.spool_object_id=spool FOR UPDATE;
 SELECT * INTO c FROM object_store_retention.drain_spool_custody x WHERE x.spool_id=spool FOR UPDATE;
 IF NOT FOUND OR c.state IN(1,2) OR c.cleanup_not_before>object_store_retention.clock_unix_ms_v1() THEN RETURN; END IF;
 UPDATE object_store_retention.drain_policies x
 SET metadata_rows=(x.metadata_rows::numeric-1)::object_store_retention.uint64,
  metadata_bytes=(x.metadata_bytes::numeric-c.metadata_bytes)::object_store_retention.uint64
 WHERE x.boundary=c.boundary AND x.cell=c.cell AND x.metadata_rows::numeric>=1 AND x.metadata_bytes::numeric>=c.metadata_bytes;
 IF NOT FOUND THEN RAISE EXCEPTION 'DRAIN_METADATA_UNDERFLOW'; END IF;
 DELETE FROM object_store_retention.object_dispatch_spool_objects x WHERE x.spool_object_id=spool;
 DELETE FROM object_store_retention.drain_spool_custody x WHERE x.spool_id=spool;
END $$;
DROP FUNCTION object_store_retention.drain_cleanup_compact_v2(uuid,bigint);

-- New functions are executable by PUBLIC by default; revoke that and every service role, then
-- grant the runtime the two it calls. The time helper stays owner-only.
REVOKE ALL ON FUNCTION object_store_retention.drain_uuid_v7_ms_v1(uuid),
 object_store_retention.drain_retired_floor_advance_v1(text,text),
 object_store_retention.drain_cleanup_compact_v3(uuid)
 FROM PUBLIC, object_dispatch_retention_runtime, object_dispatch_retention_maintenance, object_dispatch_retention_migrator;
GRANT EXECUTE ON FUNCTION object_store_retention.drain_retired_floor_advance_v1(text,text),
 object_store_retention.drain_cleanup_compact_v3(uuid) TO object_dispatch_retention_runtime;

-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
-- WP-115 row 78: running charge counters for the spool ledger.
--
-- A FORWARD STEP like 0029: no transaction control. The installer opens one SERIALIZABLE
-- transaction around this body, attests R30 inside it, and only then commits.
--
-- Write-behind compares a completed physical spool walk with the spool ledger. The ledger is a
-- live counter: a reservation charges it before its body is placed, and a release gives the
-- charge back after the body is unlinked. A walk takes time, and both happen while it runs, so a
-- walk can count a body that is released before the next ledger read and also a body charged
-- after the previous one. Neither read then bounds the walk. Row 77's faster drain made that the
-- normal case and both replicas refused staging on spool_*_over_ledger.
--
-- charged_bytes and charged_files only grow: drain_reserve_v1 adds exactly what it charges to
-- the cell's spool ledger (the body size and one row, the scope-2 class-1 counters
-- drain_observe_v1 reports). Every body a walk counts was either live at the read before the
-- walk or charged between that read and the read after it. So the ledger before the walk plus
-- the growth of these counters across the walk bounds the walk; only bytes no ledger ever
-- charged exceed it.
SET LOCAL ROLE object_dispatch_retention_owner;

-- Replicas must be stopped, as in 0027's rotation, 0028 and 0029.
LOCK TABLE object_store_retention.object_dispatch_spool_objects,
 object_store_retention.drain_spool_custody,object_store_retention.object_dispatch_quota_usage,
 object_store_retention.drain_policies IN ACCESS EXCLUSIVE MODE NOWAIT;

CREATE OR REPLACE FUNCTION object_store_retention.cell_schema_revision_v1() RETURNS integer
LANGUAGE sql IMMUTABLE SET search_path=pg_catalog AS $$ SELECT 30 $$;

-- Existing cells start at zero. Only the growth between two reads is ever used.
ALTER TABLE object_store_retention.drain_policies
 ADD COLUMN charged_bytes object_store_retention.uint64 NOT NULL DEFAULT 0,
 ADD COLUMN charged_files object_store_retention.uint64 NOT NULL DEFAULT 0;

-- 0026's reservation, unchanged except that the metadata charge also adds the spool charge to
-- the running counters, in the same statement and under the same capacity guard.
CREATE OR REPLACE FUNCTION object_store_retention.drain_reserve_v1(d jsonb, canonical bytea, digest bytea)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE p object_store_retention.drain_policies%ROWTYPE; s object_store_retention.object_dispatch_spool_objects%ROWTYPE;
DECLARE c object_store_retention.drain_spool_custody%ROWTYPE; r object_store_retention.dispatch_reserve_put_result_v1;
DECLARE snapshot record; q jsonb; now_ms bigint; charge bigint:=16384;
BEGIN
 PERFORM object_store_retention.assert_dispatch_runtime_v1(); PERFORM object_store_retention.assert_serializable_write_v1();
 IF octet_length(d::text)+octet_length(canonical)>10000 OR canonical IS DISTINCT FROM object_store_retention.drain_descriptor_bytes_v1(d) THEN RAISE EXCEPTION 'DRAIN_DESCRIPTOR_CANONICAL_MISMATCH'; END IF;
 PERFORM object_store_retention.local_assert_blake3_v1(canonical,digest);
 now_ms:=object_store_retention.clock_unix_ms_v1();
 IF (d->>'send_not_after_ms')::bigint<=now_ms THEN RAISE EXCEPTION 'DRAIN_EXPIRED'; END IF;
 -- Stable spool identity is always locked before custody, and before scope 1/2/3.
 SELECT * INTO s FROM object_store_retention.object_dispatch_spool_objects x
 WHERE x.logical_request_id=(d->>'logical_request_id')::uuid AND x.attempt_id=(d->>'attempt_id')::uuid AND x.payload_kind=1 FOR UPDATE;
 SELECT * INTO c FROM object_store_retention.drain_spool_custody x WHERE x.logical_id=(d->>'logical_request_id')::uuid AND x.attempt_id=(d->>'attempt_id')::uuid FOR UPDATE;
 IF FOUND THEN
  IF c.state<>1 OR c.canonical IS DISTINCT FROM canonical OR c.descriptor IS DISTINCT FROM d
   OR s.spool_object_id IS NULL OR s.expires_at_unix_ms<=now_ms THEN RAISE EXCEPTION 'DRAIN_REPLAY_REFUSED'; END IF;
  -- Policy pins and expiry apply to replay too; allocation renewal does not rewrite d.
  SELECT * INTO STRICT p FROM object_store_retention.drain_policies x WHERE x.boundary=c.boundary AND x.cell=c.cell;
  IF p.revision IS DISTINCT FROM d->>'policy_revision' OR encode(p.digest,'hex') IS DISTINCT FROM d->>'policy_digest'
   OR (p.policy->>'expires_at_ms')::bigint<=now_ms THEN RAISE EXCEPTION 'DRAIN_POLICY_MISMATCH'; END IF;
  RETURN;
 END IF;
 IF s.spool_object_id IS NOT NULL THEN RAISE EXCEPTION 'DRAIN_UNOWNED_RESERVATION'; END IF;
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

-- Observation gains the two running counters, read in the same statement as the ledger.
DROP FUNCTION object_store_retention.drain_observe_v1(text,text);
CREATE FUNCTION object_store_retention.drain_observe_v1(boundary text,cell text)
RETURNS TABLE(spool_bytes text,spool_files text,cleanup_backlog bigint,metadata_full boolean,superseded_pending bigint,
 charged_bytes text,charged_files text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM object_store_retention.assert_dispatch_runtime_v1();
 RETURN QUERY SELECT coalesce(q.used_bytes,0)::text,coalesce(q.used_rows,0)::text,
 (SELECT count(*) FROM object_store_retention.drain_spool_custody c WHERE c.boundary=drain_observe_v1.boundary AND c.cell=drain_observe_v1.cell AND c.state IN(1,2) AND c.cleanup_not_before<=object_store_retention.clock_unix_ms_v1()),
 (p.metadata_rows+1>(p.policy->>'metadata_max_rows')::numeric OR p.metadata_bytes+16384>(p.policy->>'metadata_max_bytes')::numeric),
 (SELECT count(*) FROM object_store_retention.drain_spool_custody c WHERE c.boundary=drain_observe_v1.boundary AND c.cell=drain_observe_v1.cell AND c.superseded),
 p.charged_bytes::text,p.charged_files::text
 FROM object_store_retention.drain_policies p LEFT JOIN object_store_retention.object_dispatch_quota_usage q
 ON q.provider_boundary_id=p.boundary AND q.scope_kind=2 AND q.scope_id=p.cell AND q.quota_class=1
 WHERE p.boundary=drain_observe_v1.boundary AND p.cell=drain_observe_v1.cell;
END $$;

REVOKE ALL ON FUNCTION object_store_retention.drain_observe_v1(text,text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION object_store_retention.drain_observe_v1(text,text) TO object_dispatch_retention_runtime;

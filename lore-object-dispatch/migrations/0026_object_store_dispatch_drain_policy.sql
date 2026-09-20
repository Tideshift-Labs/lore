-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
-- WP-122: immutable local policy and bounded unbound drain spool custody.
BEGIN;
SET LOCAL ROLE object_dispatch_retention_owner;

CREATE TABLE object_store_retention.drain_policies (
 boundary text NOT NULL, cell text NOT NULL, revision text NOT NULL,
 digest bytea NOT NULL CHECK (octet_length(digest)=32), policy jsonb NOT NULL,
 canonical bytea NOT NULL CHECK (octet_length(canonical)<=16384),
 metadata_rows object_store_retention.uint64 NOT NULL DEFAULT 0,
 metadata_bytes object_store_retention.uint64 NOT NULL DEFAULT 0,
 PRIMARY KEY(boundary,cell), UNIQUE(boundary,revision)
);
CREATE TABLE object_store_retention.drain_spool_custody (
 spool_id uuid PRIMARY KEY, boundary text NOT NULL, cell text NOT NULL,
 service text NOT NULL, logical_id uuid NOT NULL, attempt_id uuid NOT NULL,
 descriptor jsonb, canonical bytea, digest bytea NOT NULL CHECK(octet_length(digest)=32),
 cleanup_not_before bigint NOT NULL, state smallint NOT NULL DEFAULT 1 CHECK(state IN(1,2,3,4)),
 cleanup_fence bigint NOT NULL DEFAULT 0 CHECK(cleanup_fence>=0),
 last_scan_ms bigint NOT NULL DEFAULT 0 CHECK(last_scan_ms>=0),
 release_receipt bytea, release_digest bytea,
 metadata_bytes bigint NOT NULL CHECK(metadata_bytes>=1024),
 UNIQUE(logical_id,attempt_id), FOREIGN KEY(boundary,cell) REFERENCES object_store_retention.drain_policies
);
CREATE INDEX drain_spool_cleanup ON object_store_retention.drain_spool_custody
 (boundary,cell,GREATEST(cleanup_not_before,last_scan_ms),spool_id);

CREATE FUNCTION object_store_retention.drain_policy_bytes_v1(p jsonb) RETURNS bytea
LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE b bytea:=convert_to('fragment-drain-policy-v1','UTF8'); k text; q jsonb; v jsonb; n numeric;
BEGIN
 IF p IS NULL OR jsonb_typeof(p)<>'object' THEN RAISE EXCEPTION 'DRAIN_POLICY_INVALID'; END IF;
 FOREACH k IN ARRAY ARRAY['boundary','cell','service','revision'] LOOP
  b:=b||object_store_retention.local_canonical_text_v1(p->>k,256);
 END LOOP;
 IF p->>'boundary'=p->>'cell' OR p->>'boundary'=p->>'service' OR p->>'cell'=p->>'service'
 OR (p->>'quota_revision')::numeric<=0 OR (p->>'maximum_ttl_ms')::numeric<=0
 OR (p->>'maximum_ttl_ms')::numeric>9223372036854775807
 OR (p->>'expires_at_ms')::numeric>9223372036854775807
 OR (p->>'metadata_max_rows')::numeric<=0 OR (p->>'metadata_max_bytes')::numeric<16384
 OR jsonb_array_length(p->'quotas')<>3 THEN RAISE EXCEPTION 'DRAIN_POLICY_INVALID'; END IF;
 b:=b||object_store_retention.local_canonical_u64_v1((p->>'quota_revision')::object_store_retention.uint64);
 FOR q IN SELECT value FROM jsonb_array_elements(p->'quotas') LOOP
  IF jsonb_array_length(q)<>6 THEN RAISE EXCEPTION 'DRAIN_POLICY_INVALID'; END IF;
  FOR i IN 0..2 LOOP
   IF (q->>i)::numeric<=0 OR (q->>(i+3))::numeric >= (q->>i)::numeric THEN RAISE EXCEPTION 'DRAIN_POLICY_INVALID'; END IF;
  END LOOP;
  FOR v IN SELECT value FROM jsonb_array_elements(q) LOOP
   b:=b||object_store_retention.local_canonical_u64_v1(v::text::object_store_retention.uint64);
  END LOOP;
 END LOOP;
 FOREACH k IN ARRAY ARRAY['maximum_ttl_ms','expires_at_ms','metadata_max_rows','metadata_max_bytes'] LOOP
  b:=b||object_store_retention.local_canonical_u64_v1((p->>k)::object_store_retention.uint64);
 END LOOP;
 FOREACH k IN ARRAY ARRAY['max_bytes','max_files','max_metadata_bytes','max_metadata_rows','prepare_ttl_ms'] LOOP
  n:=(p->'stage'->>k)::numeric;
  IF n<=0 OR n>9223372036854775807 THEN RAISE EXCEPTION 'DRAIN_STAGE_POLICY_INVALID'; END IF;
  b:=b||object_store_retention.local_canonical_u64_v1(n::object_store_retention.uint64);
 END LOOP;
 IF (p->'stage'->>'max_metadata_bytes')::numeric<1024 OR (p->'stage'->>'prepare_ttl_ms')::numeric>2147483647 OR b IS NULL THEN RAISE EXCEPTION 'DRAIN_POLICY_INVALID'; END IF;
 RETURN b;
END $$;

CREATE FUNCTION object_store_retention.drain_cleanup_candidates_v1(boundary text,cell text,batch integer)
RETURNS TABLE(spool uuid) LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE observed_ms bigint:=object_store_retention.clock_unix_ms_v1();
BEGIN
 PERFORM object_store_retention.assert_dispatch_runtime_v1();
 IF batch NOT BETWEEN 1 AND 256 THEN RAISE EXCEPTION 'DRAIN_BATCH_INVALID'; END IF;
 RETURN QUERY SELECT x.spool_id FROM object_store_retention.drain_spool_custody x
 WHERE x.boundary=drain_cleanup_candidates_v1.boundary AND x.cell=drain_cleanup_candidates_v1.cell
 AND GREATEST(x.cleanup_not_before,x.last_scan_ms)<=observed_ms
 ORDER BY GREATEST(x.cleanup_not_before,x.last_scan_ms),x.spool_id LIMIT batch;
END $$;

CREATE FUNCTION object_store_retention.drain_cleanup_claim_v1(spool uuid)
RETURNS TABLE(boundary text,logical_id uuid,attempt_id uuid,fence bigint)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE s object_store_retention.object_dispatch_spool_objects%ROWTYPE; c object_store_retention.drain_spool_custody%ROWTYPE;
BEGIN
 PERFORM object_store_retention.assert_dispatch_runtime_v1(); PERFORM object_store_retention.assert_serializable_write_v1();
 -- Candidates carry no lock. All mutations take spool then custody.
 SELECT * INTO s FROM object_store_retention.object_dispatch_spool_objects x WHERE x.spool_object_id=spool FOR UPDATE;
 SELECT * INTO STRICT c FROM object_store_retention.drain_spool_custody x WHERE x.spool_id=spool FOR UPDATE;
 IF c.cleanup_not_before>object_store_retention.clock_unix_ms_v1() THEN RAISE EXCEPTION 'DRAIN_CLEANUP_TOO_EARLY'; END IF;
 IF c.state=1 THEN
  UPDATE object_store_retention.drain_spool_custody x SET state=2,cleanup_fence=x.cleanup_fence+1 WHERE x.spool_id=spool RETURNING * INTO c;
 END IF;
 UPDATE object_store_retention.drain_spool_custody x SET last_scan_ms=object_store_retention.clock_unix_ms_v1() WHERE x.spool_id=spool;
 RETURN QUERY SELECT c.boundary,c.logical_id,c.attempt_id,c.cleanup_fence;
END $$;

CREATE FUNCTION object_store_retention.drain_cleanup_release_v1(spool uuid,fence bigint)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE s object_store_retention.object_dispatch_spool_objects%ROWTYPE; c object_store_retention.drain_spool_custody%ROWTYPE;
DECLARE q object_store_retention.object_dispatch_quota_usage%ROWTYPE; n integer:=0; receipt bytea; computed_release_digest bytea;
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
 UPDATE object_store_retention.drain_spool_custody x SET state=3,release_receipt=receipt||computed_release_digest,release_digest=computed_release_digest WHERE x.spool_id=spool;
END $$;

CREATE FUNCTION object_store_retention.drain_cleanup_compact_v1(spool uuid)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE s object_store_retention.object_dispatch_spool_objects%ROWTYPE; c object_store_retention.drain_spool_custody%ROWTYPE; p object_store_retention.drain_policies%ROWTYPE;
BEGIN
 PERFORM object_store_retention.assert_dispatch_runtime_v1(); PERFORM object_store_retention.assert_serializable_write_v1();
 SELECT * INTO s FROM object_store_retention.object_dispatch_spool_objects x WHERE x.spool_object_id=spool FOR UPDATE;
 SELECT * INTO STRICT c FROM object_store_retention.drain_spool_custody x WHERE x.spool_id=spool FOR UPDATE;
 IF c.state<>3 THEN RETURN; END IF;
 SELECT * INTO STRICT p FROM object_store_retention.drain_policies x WHERE x.boundary=c.boundary AND x.cell=c.cell FOR UPDATE;
 IF greatest(s.expires_at_unix_ms,(p.policy->>'expires_at_ms')::bigint)>object_store_retention.clock_unix_ms_v1() THEN RETURN; END IF;
 DELETE FROM object_store_retention.object_dispatch_spool_objects x WHERE x.spool_object_id=spool;
 UPDATE object_store_retention.drain_spool_custody x SET state=4,descriptor=NULL,canonical=NULL,metadata_bytes=1024 WHERE x.spool_id=spool;
 UPDATE object_store_retention.drain_policies x SET metadata_bytes=x.metadata_bytes-(c.metadata_bytes-1024) WHERE x.boundary=c.boundary AND x.cell=c.cell;
 -- Marker rows and their prepaid 1024-byte charge survive indefinitely. Expiry is
 -- never evidence that an old filesystem producer cannot resume.
END $$;

CREATE FUNCTION object_store_retention.drain_descriptor_bytes_v1(d jsonb) RETURNS bytea
LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE b bytea:=convert_to('fragment-drain-reservation-v1','UTF8'); k text; id uuid;
BEGIN
 FOREACH k IN ARRAY ARRAY['policy_revision','policy_digest','boundary','cell','service'] LOOP
  b:=b||object_store_retention.local_canonical_text_v1(d->>k,256);
 END LOOP;
 FOREACH k IN ARRAY ARRAY['logical_request_id','attempt_id','upload_id','spool_object_id'] LOOP
  id:=(d->>k)::uuid; PERFORM object_store_retention.local_uuid_v7_unix_ms_v1(id); b:=b||uuid_send(id);
 END LOOP;
 b:=b||object_store_retention.local_canonical_u64_v1((d->>'upload_fence')::object_store_retention.uint64)
  ||object_store_retention.local_canonical_text_v1(d->>'source_hash',256)
  ||object_store_retention.local_canonical_u64_v1((d->>'source_epoch')::object_store_retention.uint64)
  ||object_store_retention.local_canonical_bytes_v1(decode(d->>'source_manifest','hex'),32)
  ||object_store_retention.local_canonical_u64_v1((d->>'remote_epoch')::object_store_retention.uint64)
  ||object_store_retention.local_canonical_u64_v1((d->>'remote_fence')::object_store_retention.uint64)
  ||object_store_retention.local_canonical_text_v1(d->>'object_key',1024)
  ||object_store_retention.local_canonical_bytes_v1(decode(d->>'body_digest','hex'),32);
 FOREACH k IN ARRAY ARRAY['body_size','send_not_after_ms','hard_not_after_ms','prepared_ttl_ms','max_chunk_bytes'] LOOP
  b:=b||object_store_retention.local_canonical_u64_v1((d->>k)::object_store_retention.uint64);
 END LOOP;
 IF b IS NULL OR octet_length(b)>8192 OR octet_length(decode(d->>'source_manifest','hex'))<>32
 OR octet_length(decode(d->>'body_digest','hex'))<>32 OR (d->>'body_size')::numeric>262144
 OR (d->>'upload_fence')::numeric<=0 OR (d->>'prepared_ttl_ms')::numeric<=0
 OR (d->>'send_not_after_ms')::numeric>(d->>'hard_not_after_ms')::numeric
 OR (d->>'hard_not_after_ms')::numeric>9223372036854775807
 OR (d->>'max_chunk_bytes')::numeric<>262144 THEN RAISE EXCEPTION 'DRAIN_DESCRIPTOR_INVALID'; END IF;
 RETURN b;
END $$;

CREATE FUNCTION object_store_retention.drain_policy_publish_v1(p jsonb, canonical bytea, digest bytea)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE old object_store_retention.drain_policies%ROWTYPE;
BEGIN
 IF session_user<>'object_dispatch_retention_maintenance' THEN RAISE EXCEPTION 'UNAUTHORIZED' USING ERRCODE='42501'; END IF;
 PERFORM object_store_retention.assert_serializable_write_v1();
 IF octet_length(p::text)>16384 OR canonical IS DISTINCT FROM object_store_retention.drain_policy_bytes_v1(p) THEN RAISE EXCEPTION 'DRAIN_POLICY_CANONICAL_MISMATCH'; END IF;
 PERFORM object_store_retention.local_assert_blake3_v1(canonical,digest);
 IF (p->>'expires_at_ms')::bigint<=object_store_retention.clock_unix_ms_v1() THEN RAISE EXCEPTION 'DRAIN_POLICY_EXPIRED'; END IF;
 INSERT INTO object_store_retention.drain_policies(boundary,cell,revision,digest,policy,canonical)
 VALUES(p->>'boundary',p->>'cell',p->>'revision',digest,p,canonical) ON CONFLICT DO NOTHING;
 SELECT * INTO STRICT old FROM object_store_retention.drain_policies x WHERE x.boundary=p->>'boundary' AND x.cell=p->>'cell' FOR UPDATE;
 IF old.policy IS DISTINCT FROM p OR old.digest IS DISTINCT FROM digest OR old.canonical IS DISTINCT FROM canonical THEN RAISE EXCEPTION 'DRAIN_POLICY_IMMUTABLE'; END IF;
END $$;

CREATE FUNCTION object_store_retention.drain_policy_read_v1(boundary text,cell text,revision text,digest bytea)
RETURNS TABLE(policy jsonb,allocation_revision text,allocation_fence object_store_retention.uint64,allocation_expiry_ms bigint,observed_at_ms bigint)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE p object_store_retention.drain_policies%ROWTYPE; h object_store_retention.object_dispatch_current_budget_configuration%ROWTYPE;
DECLARE expiry bigint;
BEGIN
 PERFORM object_store_retention.assert_dispatch_runtime_v1();
 SELECT * INTO STRICT p FROM object_store_retention.drain_policies x WHERE x.boundary=drain_policy_read_v1.boundary AND x.cell=drain_policy_read_v1.cell;
 IF p.revision IS DISTINCT FROM revision OR p.digest IS DISTINCT FROM digest
 OR (p.policy->>'expires_at_ms')::bigint<=object_store_retention.clock_unix_ms_v1() THEN RAISE EXCEPTION 'DRAIN_POLICY_MISMATCH'; END IF;
 PERFORM object_store_retention.local_assert_blake3_v1(object_store_retention.drain_policy_bytes_v1(p.policy),p.digest);
 SELECT * INTO STRICT h FROM object_store_retention.object_dispatch_current_budget_configuration x WHERE x.provider_boundary_id=boundary;
 PERFORM object_store_retention.assert_dispatch_budget_resolved_v1(boundary,h.allocation_revision,h.allocation_fence);
 SELECT x.hard_expires_at_unix_ms INTO STRICT expiry FROM object_store_retention.object_dispatch_budget_configurations x
 WHERE x.provider_boundary_id=boundary AND x.allocation_revision=h.allocation_revision AND x.allocation_fence=h.allocation_fence;
 IF expiry<=object_store_retention.clock_unix_ms_v1() THEN RAISE EXCEPTION 'DRAIN_BUDGET_EXPIRED'; END IF;
 RETURN QUERY SELECT p.policy,h.allocation_revision,h.allocation_fence,expiry,object_store_retention.clock_unix_ms_v1();
END $$;

CREATE FUNCTION object_store_retention.drain_reserve_v1(d jsonb, canonical bytea, digest bytea)
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
 UPDATE object_store_retention.drain_policies x SET metadata_rows=x.metadata_rows+1,metadata_bytes=x.metadata_bytes+charge
 WHERE x.boundary=d->>'boundary' AND x.cell=d->>'cell'
 AND x.metadata_rows+1<=(x.policy->>'metadata_max_rows')::numeric AND x.metadata_bytes+charge<=(x.policy->>'metadata_max_bytes')::numeric;
 IF NOT FOUND THEN RAISE EXCEPTION 'DRAIN_METADATA_CAPACITY' USING ERRCODE='53000'; END IF;
END $$;

CREATE FUNCTION object_store_retention.drain_check_ready_v1(spool uuid,attempt uuid,record_digest bytea,object_key text,deadline bigint)
RETURNS TABLE(effective_deadline bigint,remaining_ms bigint) LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE s object_store_retention.object_dispatch_spool_objects%ROWTYPE; c object_store_retention.drain_spool_custody%ROWTYPE; now_ms bigint; policy_expiry bigint;
BEGIN
 PERFORM object_store_retention.assert_dispatch_runtime_v1();
 SELECT * INTO STRICT s FROM object_store_retention.object_dispatch_spool_objects x WHERE x.spool_object_id=spool FOR UPDATE;
 SELECT * INTO STRICT c FROM object_store_retention.drain_spool_custody x WHERE x.spool_id=spool FOR UPDATE;
 now_ms:=object_store_retention.clock_unix_ms_v1();
 IF c.state<>1 OR s.lifecycle_state<>2 OR s.attempt_id IS DISTINCT FROM attempt OR s.record_blake3 IS DISTINCT FROM record_digest
 OR s.expires_at_unix_ms<=now_ms OR deadline<=now_ms OR deadline>(c.descriptor->>'send_not_after_ms')::bigint
 OR c.descriptor->>'object_key' IS DISTINCT FROM object_key THEN RAISE EXCEPTION 'DRAIN_READY_REFUSED'; END IF;
 SELECT (p.policy->>'expires_at_ms')::bigint INTO STRICT policy_expiry FROM object_store_retention.drain_policies p WHERE p.boundary=c.boundary AND p.cell=c.cell;
 IF policy_expiry<=now_ms THEN RAISE EXCEPTION 'DRAIN_POLICY_EXPIRED'; END IF;
 RETURN QUERY SELECT least(deadline,s.expires_at_unix_ms,policy_expiry),least(deadline,s.expires_at_unix_ms,policy_expiry)-now_ms;
END $$;
CREATE OR REPLACE FUNCTION object_store_retention.object_store_dispatch_put_spool_ready_v1(
  api_revision text,
  protocol_revision text,
  provider_boundary_id text,
  authenticated_cell_id text,
  authenticated_tenant_id text,
  logical_request_id uuid,
  attempt_id uuid,
  upload_id uuid,
  upload_fence object_store_retention.uint64,
  final_chunk_index object_store_retention.uint64,
  fsynced_body_size object_store_retention.uint64,
  fsynced_body_blake3 bytea,
  durable_handle text,
  maximum_identity_bytes integer,
  maximum_boundary_token_bytes integer,
  maximum_durable_handle_bytes integer,
  maximum_record_bytes integer
)
RETURNS object_store_retention.dispatch_put_spool_ready_result_v1
LANGUAGE plpgsql
VOLATILE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
DECLARE schema_state object_store_retention.object_dispatch_retention_schema_state%ROWTYPE;
DECLARE stored object_store_retention.object_dispatch_spool_objects%ROWTYPE;
DECLARE next_ack object_store_retention.local_canonical_record_v1;
DECLARE next_record object_store_retention.local_canonical_record_v1;
DECLARE database_now bigint;
DECLARE next_revision numeric;
DECLARE affected_rows integer;
BEGIN
  PERFORM object_store_retention.assert_dispatch_runtime_v1();
  PERFORM object_store_retention.assert_dispatch_put_spool_ready_api_revision_v1(api_revision);
  PERFORM object_store_retention.assert_serializable_write_v1();
  -- WP-122: freshness and custody precede the historical ready replay branch.
  PERFORM 1 FROM object_store_retention.object_dispatch_spool_objects x
   WHERE x.logical_request_id=object_store_dispatch_put_spool_ready_v1.logical_request_id
   AND x.attempt_id=object_store_dispatch_put_spool_ready_v1.attempt_id AND x.payload_kind=1 FOR UPDATE;
  PERFORM 1 FROM object_store_retention.drain_spool_custody c
   JOIN object_store_retention.object_dispatch_spool_objects s ON s.spool_object_id=c.spool_id
   JOIN object_store_retention.drain_policies p ON p.boundary=c.boundary AND p.cell=c.cell
   WHERE c.logical_id=object_store_dispatch_put_spool_ready_v1.logical_request_id
   AND c.attempt_id=object_store_dispatch_put_spool_ready_v1.attempt_id
   AND c.state=1 AND s.expires_at_unix_ms>object_store_retention.clock_unix_ms_v1()
   AND (p.policy->>'expires_at_ms')::bigint>object_store_retention.clock_unix_ms_v1()
   FOR UPDATE OF c;
  IF NOT FOUND THEN RAISE EXCEPTION 'DRAIN_READY_EXPIRED_OR_FENCED'; END IF;

  SELECT * INTO STRICT schema_state
    FROM object_store_retention.object_dispatch_retention_schema_state
   WHERE singleton
   FOR SHARE;
  IF schema_state.schema_revision IS DISTINCT FROM 'object-store-retention-authority-schema-v1'
     OR schema_state.migration_blake3 IS DISTINCT FROM
        pg_catalog.decode('f86d1a574cab9346ef39843fed6ffb849cafe5967881a45d0c6d89028780f6dd', 'hex')
     OR schema_state.local_authority_schema_revision IS DISTINCT FROM
        'object-store-dispatch-authority-schema-v1'
     OR schema_state.local_authority_migration_blake3 IS DISTINCT FROM
        pg_catalog.decode('d762b841bd31a37908a6ff95c2292d5abfca234fa9b7d3c0c639ec63dcf3a7ff', 'hex')
     OR schema_state.put_reservation_schema_revision IS DISTINCT FROM
        'object-store-dispatch-put-reservation-schema-v1'
     OR schema_state.put_reservation_migration_blake3 IS DISTINCT FROM
        pg_catalog.decode('56b6b891f6fa44875494a9d644b1a8ad66f1f87be5f886efeb324da05cb2ae67', 'hex') THEN
    RAISE EXCEPTION 'DISPATCH_PUT_SPOOL_READY_SCHEMA_UNAVAILABLE'
      USING ERRCODE = '55000';
  END IF;

  SELECT * INTO stored
    FROM object_store_retention.object_dispatch_spool_objects AS spool
   WHERE spool.logical_request_id = object_store_dispatch_put_spool_ready_v1.logical_request_id
     AND spool.attempt_id = object_store_dispatch_put_spool_ready_v1.attempt_id
     AND spool.payload_kind = 1
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'EXPIRED_OR_UNKNOWN' USING ERRCODE = '22023';
  END IF;
  IF stored.protocol_revision IS DISTINCT FROM protocol_revision
     OR stored.provider_boundary_id IS DISTINCT FROM provider_boundary_id
     OR stored.authenticated_cell_id IS DISTINCT FROM authenticated_cell_id
     OR stored.authenticated_tenant_id IS DISTINCT FROM authenticated_tenant_id
     OR stored.logical_request_id IS DISTINCT FROM logical_request_id
     OR stored.attempt_id IS DISTINCT FROM attempt_id
     OR stored.upload_id IS DISTINCT FROM upload_id
     OR stored.upload_fence IS DISTINCT FROM upload_fence THEN
    RAISE EXCEPTION 'UPLOAD_STREAM_IDENTITY_MISMATCH' USING ERRCODE = '22023';
  END IF;

  PERFORM object_store_retention.project_dispatch_reserved_put_v1(stored, 'REPLAY');
  IF final_chunk_index IS NULL OR fsynced_body_size IS NULL
     OR fsynced_body_blake3 IS NULL
     OR pg_catalog.octet_length(fsynced_body_blake3) <> 32
     OR durable_handle IS NULL THEN
    RAISE EXCEPTION 'DISPATCH_PUT_SPOOL_READY_INVALID_ARGUMENT'
      USING ERRCODE = '22023';
  END IF;

  IF stored.lifecycle_state = 2 THEN
    IF final_chunk_index IS DISTINCT FROM stored.spool_revision - 2
       OR fsynced_body_size IS DISTINCT FROM stored.committed_size
       OR fsynced_body_blake3 IS DISTINCT FROM stored.committed_blake3
       OR durable_handle IS DISTINCT FROM stored.durable_handle THEN
      RAISE EXCEPTION 'DISPATCH_PUT_SPOOL_READY_REPLAY_CONFLICT'
        USING ERRCODE = '23505';
    END IF;
    RETURN object_store_retention.project_dispatch_put_spool_ready_v1(stored, 'REPLAY');
  END IF;
  IF stored.lifecycle_state IS DISTINCT FROM 1 THEN
    RAISE EXCEPTION 'UPLOAD_CLOSED' USING ERRCODE = '55000';
  END IF;
  IF final_chunk_index < stored.partial_temp_chunks THEN
    RAISE EXCEPTION 'DISPATCH_PUT_SPOOL_READY_REPLAY_CONFLICT'
      USING ERRCODE = '23505';
  END IF;
  IF final_chunk_index > stored.partial_temp_chunks THEN
    RAISE EXCEPTION 'DISPATCH_PUT_UPLOAD_CHUNK_GAP' USING ERRCODE = '22023';
  END IF;
  IF maximum_identity_bytes IS NULL OR maximum_identity_bytes NOT BETWEEN 1 AND 1024
     OR maximum_boundary_token_bytes IS NULL
     OR maximum_boundary_token_bytes NOT BETWEEN 1 AND 4096
     OR maximum_durable_handle_bytes IS NULL
     OR maximum_durable_handle_bytes NOT BETWEEN 1 AND 4096
     OR maximum_record_bytes IS NULL OR maximum_record_bytes NOT BETWEEN 1 AND 16777216 THEN
    RAISE EXCEPTION 'DISPATCH_PUT_SPOOL_READY_INVALID_ARGUMENT'
      USING ERRCODE = '22023';
  END IF;
  IF stored.spool_revision = 18446744073709551615 THEN
    RAISE EXCEPTION 'DISPATCH_PUT_SPOOL_READY_COUNTER_OVERFLOW'
      USING ERRCODE = '22003';
  END IF;
  IF fsynced_body_size IS DISTINCT FROM stored.expected_size
     OR fsynced_body_blake3 IS DISTINCT FROM stored.expected_blake3
     OR NOT (
       (
         stored.expected_size = 0 AND stored.partial_temp_bytes = 0
         AND final_chunk_index = 0
       ) OR (
         stored.expected_size > stored.partial_temp_bytes
         AND stored.expected_size - stored.partial_temp_bytes <= stored.max_chunk_bytes
       )
     ) THEN
    RAISE EXCEPTION 'DISPATCH_PUT_SPOOL_READY_INVALID_ARGUMENT'
      USING ERRCODE = '22023';
  END IF;

  database_now := object_store_retention.clock_unix_ms_v1();
  IF database_now < 0 OR database_now < stored.admission_clock_unix_ms THEN
    RAISE EXCEPTION 'DISPATCH_PUT_SPOOL_READY_TIME_INVALID' USING ERRCODE = '22023';
  END IF;
  IF database_now >= stored.expires_at_unix_ms THEN
    RAISE EXCEPTION 'UPLOAD_CLOSED' USING ERRCODE = '55000';
  END IF;

  next_revision := stored.spool_revision + 1;
  next_ack := object_store_retention.local_reserve_put_ack_v1(
    stored.protocol_revision, stored.policy_revision, stored.provider_boundary_id,
    stored.authenticated_cell_id, stored.authenticated_tenant_id,
    stored.logical_request_id, stored.attempt_id, stored.upload_id, stored.upload_fence,
    2::smallint, stored.quota_bytes, stored.quota_rows, stored.quota_concurrency,
    stored.expires_at_unix_ms, stored.max_chunk_bytes, durable_handle,
    fsynced_body_size, fsynced_body_blake3, database_now,
    stored.admission_clock_unix_ms, stored.allocation_hard_expiry_unix_ms,
    maximum_identity_bytes, maximum_durable_handle_bytes, maximum_record_bytes
  );
  next_record := object_store_retention.local_put_spool_ready_record_v1(
    stored.protocol_revision, stored.policy_revision, stored.provider_boundary_id,
    stored.authenticated_cell_id, stored.authenticated_tenant_id, stored.spool_object_id,
    stored.logical_request_id, stored.attempt_id, stored.upload_id, stored.upload_fence,
    stored.boundary_blake3, stored.boundary_token, stored.observation_binding_blake3,
    stored.expected_size, stored.expected_blake3, fsynced_body_size,
    fsynced_body_blake3, durable_handle, 0, 0, 0,
    stored.put_reservation_fingerprint, stored.allocation_revision, stored.allocation_fence,
    stored.reservation_deadline_unix_ms, stored.allocation_hard_expiry_unix_ms,
    stored.admission_clock_unix_ms, stored.prepared_ttl_ms, stored.expires_at_unix_ms,
    database_now, stored.max_chunk_bytes, stored.quota_bytes, stored.quota_rows,
    stored.quota_concurrency, stored.quota_revision,
    next_ack.canonical_bytes, next_ack.record_blake3, next_revision,
    maximum_identity_bytes, maximum_boundary_token_bytes,
    maximum_durable_handle_bytes, maximum_record_bytes
  );

  UPDATE object_store_retention.object_dispatch_spool_objects AS spool
     SET lifecycle_state = 2,
         committed_size = fsynced_body_size,
         committed_blake3 = fsynced_body_blake3,
         durable_handle = object_store_dispatch_put_spool_ready_v1.durable_handle,
         partial_temp_bytes = 0,
         partial_temp_chunks = 0,
         partial_temp_files = 0,
         reserve_put_ack_canonical_bytes = next_ack.canonical_bytes,
         reserve_put_ack_blake3 = next_ack.record_blake3,
         canonical_record_bytes = next_record.canonical_bytes,
         record_blake3 = next_record.record_blake3,
         spool_revision = next_revision,
         ready_at_unix_ms = database_now
   WHERE spool.logical_request_id = object_store_dispatch_put_spool_ready_v1.logical_request_id
     AND spool.attempt_id = object_store_dispatch_put_spool_ready_v1.attempt_id
     AND spool.payload_kind = 1
     AND spool.spool_revision = stored.spool_revision
  RETURNING * INTO stored;
  GET DIAGNOSTICS affected_rows = ROW_COUNT;
  IF affected_rows <> 1 THEN
    RAISE EXCEPTION 'DISPATCH_PUT_SPOOL_READY_CONFLICT' USING ERRCODE = '40001';
  END IF;
  RETURN object_store_retention.project_dispatch_put_spool_ready_v1(stored, 'APPLIED');
EXCEPTION WHEN no_data_found OR too_many_rows THEN
  RAISE EXCEPTION 'DISPATCH_PUT_SPOOL_READY_UNAVAILABLE' USING ERRCODE = '55000';
END
$$;
CREATE FUNCTION object_store_retention.drain_policy_verify_v1(p jsonb, canonical bytea, digest bytea)
RETURNS void LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE stored object_store_retention.drain_policies%ROWTYPE;
BEGIN
 IF session_user<>'object_dispatch_retention_maintenance' THEN RAISE EXCEPTION 'UNAUTHORIZED' USING ERRCODE='42501'; END IF;
 SELECT * INTO STRICT stored FROM object_store_retention.drain_policies x WHERE x.boundary=p->>'boundary' AND x.cell=p->>'cell';
 IF stored.policy IS DISTINCT FROM p OR stored.canonical IS DISTINCT FROM canonical OR stored.digest IS DISTINCT FROM digest
 OR (p->>'expires_at_ms')::bigint<=object_store_retention.clock_unix_ms_v1() THEN RAISE EXCEPTION 'DRAIN_POLICY_MISMATCH'; END IF;
 PERFORM object_store_retention.local_assert_blake3_v1(object_store_retention.drain_policy_bytes_v1(p),digest);
END $$;

CREATE FUNCTION object_store_retention.drain_observe_v1(boundary text,cell text)
RETURNS TABLE(spool_bytes text,spool_files text,cleanup_backlog bigint,metadata_full boolean)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM object_store_retention.assert_dispatch_runtime_v1();
 RETURN QUERY SELECT coalesce(q.used_bytes,0)::text,coalesce(q.used_rows,0)::text,
 (SELECT count(*) FROM object_store_retention.drain_spool_custody c WHERE c.boundary=drain_observe_v1.boundary AND c.cell=drain_observe_v1.cell AND c.state IN(1,2) AND c.cleanup_not_before<=object_store_retention.clock_unix_ms_v1()),
 (p.metadata_rows+1>(p.policy->>'metadata_max_rows')::numeric OR p.metadata_bytes+16384>(p.policy->>'metadata_max_bytes')::numeric)
 FROM object_store_retention.drain_policies p LEFT JOIN object_store_retention.object_dispatch_quota_usage q
 ON q.provider_boundary_id=p.boundary AND q.scope_kind=2 AND q.scope_id=p.cell AND q.quota_class=1
 WHERE p.boundary=drain_observe_v1.boundary AND p.cell=drain_observe_v1.cell;
END $$;
-- Remove every raw caller-ceiling and progress bypass after the final chain.
DO $revoke$
DECLARE f record;
BEGIN
 FOR f IN SELECT p.oid::regprocedure AS signature FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
 WHERE n.nspname='object_store_retention' AND (p.proname LIKE 'drain_%' OR p.proname IN('object_store_dispatch_reserve_put_v1','object_store_dispatch_put_upload_progress_v1')) LOOP
  EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC, object_dispatch_retention_runtime, object_dispatch_retention_maintenance, object_dispatch_retention_migrator',f.signature);
 END LOOP;
END $revoke$;
REVOKE ALL ON object_store_retention.drain_policies,object_store_retention.drain_spool_custody FROM PUBLIC,object_dispatch_retention_runtime,object_dispatch_retention_maintenance,object_dispatch_retention_migrator;
GRANT EXECUTE ON FUNCTION object_store_retention.drain_policy_verify_v1(jsonb,bytea,bytea), object_store_retention.drain_policy_publish_v1(jsonb,bytea,bytea) TO object_dispatch_retention_maintenance;
GRANT EXECUTE ON FUNCTION object_store_retention.drain_observe_v1(text,text), object_store_retention.drain_policy_read_v1(text,text,text,bytea),object_store_retention.drain_reserve_v1(jsonb,bytea,bytea),object_store_retention.drain_check_ready_v1(uuid,uuid,bytea,text,bigint),object_store_retention.drain_cleanup_candidates_v1(text,text,integer),object_store_retention.drain_cleanup_claim_v1(uuid),object_store_retention.drain_cleanup_release_v1(uuid,bigint),object_store_retention.drain_cleanup_compact_v1(uuid) TO object_dispatch_retention_runtime;
COMMIT;

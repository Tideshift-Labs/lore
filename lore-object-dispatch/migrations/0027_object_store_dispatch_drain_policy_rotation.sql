-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
-- Offline policy rollover preserves all custody and accounting.
BEGIN;
SET LOCAL ROLE object_dispatch_retention_owner;
ALTER TABLE object_store_retention.drain_policies
 ADD COLUMN previous_revision text,
 ADD COLUMN previous_digest bytea CHECK(previous_digest IS NULL OR octet_length(previous_digest)=32);
ALTER TABLE object_store_retention.drain_spool_custody ADD COLUMN policy_expiry_ms bigint;
UPDATE object_store_retention.drain_spool_custody c SET policy_expiry_ms=(p.policy->>'expires_at_ms')::bigint
 FROM object_store_retention.drain_policies p WHERE p.boundary=c.boundary AND p.cell=c.cell;
ALTER TABLE object_store_retention.drain_spool_custody ALTER COLUMN policy_expiry_ms SET NOT NULL;
ALTER TABLE object_store_retention.drain_spool_custody ADD CHECK(policy_expiry_ms>0);

CREATE FUNCTION object_store_retention.drain_custody_policy_expiry_v1() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 SELECT (p.policy->>'expires_at_ms')::bigint INTO STRICT NEW.policy_expiry_ms
 FROM object_store_retention.drain_policies p WHERE p.boundary=NEW.boundary AND p.cell=NEW.cell
 AND p.revision=NEW.descriptor->>'policy_revision' AND encode(p.digest,'hex')=NEW.descriptor->>'policy_digest';
 RETURN NEW;
END $$;
CREATE TRIGGER drain_custody_policy_expiry BEFORE INSERT ON object_store_retention.drain_spool_custody
 FOR EACH ROW EXECUTE FUNCTION object_store_retention.drain_custody_policy_expiry_v1();
REVOKE ALL ON FUNCTION object_store_retention.drain_custody_policy_expiry_v1() FROM PUBLIC;

CREATE OR REPLACE FUNCTION object_store_retention.drain_cleanup_compact_v1(spool uuid)
RETURNS void LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE s object_store_retention.object_dispatch_spool_objects%ROWTYPE; c object_store_retention.drain_spool_custody%ROWTYPE;
BEGIN
 PERFORM object_store_retention.assert_dispatch_runtime_v1(); PERFORM object_store_retention.assert_serializable_write_v1();
 SELECT * INTO s FROM object_store_retention.object_dispatch_spool_objects x WHERE x.spool_object_id=spool FOR UPDATE;
 SELECT * INTO STRICT c FROM object_store_retention.drain_spool_custody x WHERE x.spool_id=spool FOR UPDATE;
 IF c.state<>3 THEN RETURN; END IF;
 IF greatest(s.expires_at_unix_ms,c.policy_expiry_ms)>object_store_retention.clock_unix_ms_v1() THEN RETURN; END IF;
 DELETE FROM object_store_retention.object_dispatch_spool_objects x WHERE x.spool_object_id=spool;
 UPDATE object_store_retention.drain_spool_custody x SET state=4,descriptor=NULL,canonical=NULL,metadata_bytes=1024 WHERE x.spool_id=spool;
 UPDATE object_store_retention.drain_policies x SET metadata_bytes=x.metadata_bytes-(c.metadata_bytes-1024) WHERE x.boundary=c.boundary AND x.cell=c.cell;
END $$;

CREATE FUNCTION object_store_retention.drain_policy_rotate_v1(p jsonb, canonical bytea, digest bytea,
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
 -- The operator must stop and exclude every replica before this offline command.
 -- NOWAIT turns a forgotten transaction into refusal, never a lock-order wait.
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
 -- Paired publication is one transaction. A stage refusal rolls everything back.
 PERFORM public.stage_policy_rotate_v1(p,digest,expected_revision,expected_digest);
 UPDATE object_store_retention.drain_policies x SET revision=p->>'revision',policy=p,canonical=drain_policy_rotate_v1.canonical,
  digest=drain_policy_rotate_v1.digest,previous_revision=old.revision,previous_digest=old.digest
 WHERE x.boundary=old.boundary AND x.cell=old.cell;
END $$;
REVOKE ALL ON FUNCTION object_store_retention.drain_policy_rotate_v1(jsonb,bytea,bytea,text,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION object_store_retention.drain_policy_rotate_v1(jsonb,bytea,bytea,text,bytea) TO object_dispatch_retention_maintenance;
COMMIT;

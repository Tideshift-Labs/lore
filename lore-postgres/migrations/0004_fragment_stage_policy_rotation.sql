-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
BEGIN;
ALTER TABLE lore_fragment_stage_policy ADD COLUMN IF NOT EXISTS previous_revision text;
ALTER TABLE lore_fragment_stage_policy ADD COLUMN IF NOT EXISTS previous_digest bytea
 CHECK(previous_digest IS NULL OR octet_length(previous_digest)=32);
DO $install$ BEGIN
 EXECUTE format($definition$
CREATE OR REPLACE FUNCTION %1$I.stage_policy_rotate_v1(p jsonb,p_digest bytea,expected_revision text,expected_digest bytea)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE old %1$I.lore_fragment_stage_policy; usage %1$I.lore_fragment_stage_usage;
BEGIN
 IF session_user IS DISTINCT FROM 'object_dispatch_retention_maintenance' THEN
  RAISE EXCEPTION 'STAGE_POLICY_MAINTENANCE_REQUIRED' USING ERRCODE='42501';
 END IF;
 IF current_setting('transaction_isolation')<>'serializable' OR p IS NULL OR p_digest IS NULL
 OR octet_length(p_digest)<>32 OR expected_revision IS NULL OR expected_digest IS NULL OR octet_length(expected_digest)<>32 THEN
  RAISE EXCEPTION 'STAGE_ROTATION_INVALID';
 END IF;
 -- Caller excludes replicas. A conflicting live transaction must refuse promptly.
 LOCK TABLE %1$I.lore_fragment_lifecycle,%1$I.lore_fragment_epochs,%1$I.lore_fragment_staged_leases,
  %1$I.lore_fragment_stage_custody,%1$I.lore_fragment_stage_usage,%1$I.lore_fragment_stage_policy
  IN ACCESS EXCLUSIVE MODE NOWAIT;
 SELECT * INTO STRICT old FROM %1$I.lore_fragment_stage_policy WHERE singleton;
 IF old.cell_id=p->>'cell' AND old.revision=p->>'revision' AND old.digest=p_digest THEN
  IF old.previous_revision IS DISTINCT FROM expected_revision OR old.previous_digest IS DISTINCT FROM expected_digest
  OR old.max_bytes IS DISTINCT FROM (p->'stage'->>'max_bytes')::bigint
  OR old.max_files IS DISTINCT FROM (p->'stage'->>'max_files')::bigint
  OR old.max_metadata_bytes IS DISTINCT FROM (p->'stage'->>'max_metadata_bytes')::bigint
  OR old.max_metadata_rows IS DISTINCT FROM (p->'stage'->>'max_metadata_rows')::bigint
  OR old.prepare_ttl_ms IS DISTINCT FROM (p->'stage'->>'prepare_ttl_ms')::bigint
  OR old.expires_at IS DISTINCT FROM to_timestamp((p->>'expires_at_ms')::double precision/1000) THEN
   RAISE EXCEPTION 'STAGE_ROTATION_REPLAY_CONFLICT';
  END IF;
  RETURN;
 END IF;
 IF old.cell_id IS DISTINCT FROM p->>'cell' OR old.revision IS DISTINCT FROM expected_revision
 OR old.digest IS DISTINCT FROM expected_digest OR (p->>'revision') COLLATE "C" <= old.revision COLLATE "C"
 OR (p->>'expires_at_ms')::bigint <= floor(extract(epoch FROM clock_timestamp())*1000)::bigint THEN
  RAISE EXCEPTION 'STAGE_ROTATION_CONFLICT';
 END IF;
 SELECT * INTO STRICT usage FROM %1$I.lore_fragment_stage_usage WHERE singleton;
 IF usage.live_bytes<>0 OR usage.live_files<>0
 OR EXISTS(SELECT 1 FROM %1$I.lore_fragment_stage_custody WHERE state<>3)
 OR EXISTS(SELECT 1 FROM %1$I.lore_fragment_lifecycle WHERE state=3 OR active_operation IS NOT NULL) THEN
  RAISE EXCEPTION 'STAGE_ROTATION_NOT_QUIESCENT';
 END IF;
 IF usage.metadata_bytes>(p->'stage'->>'max_metadata_bytes')::bigint
 OR usage.metadata_rows>(p->'stage'->>'max_metadata_rows')::bigint THEN RAISE EXCEPTION 'STAGE_ROTATION_CAPACITY'; END IF;
 UPDATE %1$I.lore_fragment_stage_policy SET revision=p->>'revision',digest=p_digest,
  max_bytes=(p->'stage'->>'max_bytes')::bigint,max_files=(p->'stage'->>'max_files')::bigint,
  max_metadata_bytes=(p->'stage'->>'max_metadata_bytes')::bigint,max_metadata_rows=(p->'stage'->>'max_metadata_rows')::bigint,
  prepare_ttl_ms=(p->'stage'->>'prepare_ttl_ms')::bigint,expires_at=to_timestamp((p->>'expires_at_ms')::double precision/1000),
  previous_revision=old.revision,previous_digest=old.digest WHERE singleton;
END $$;
$definition$,current_schema());
END $install$;
REVOKE ALL ON FUNCTION stage_policy_rotate_v1(jsonb,bytea,text,bytea) FROM PUBLIC;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='object_dispatch_retention_owner') THEN
  GRANT EXECUTE ON FUNCTION stage_policy_rotate_v1(jsonb,bytea,text,bytea) TO object_dispatch_retention_owner;
 END IF;
END $$;
UPDATE lore_fragment_schema_state SET schema_version = 6 WHERE schema_version = 5;
COMMIT;

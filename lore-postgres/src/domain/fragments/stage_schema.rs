// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! WP-122 staged-file custody and maintenance-published capacity.

pub const STAGE_CUSTODY_SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS lore_fragment_stage_policy (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 cell_id text NOT NULL CHECK(length(cell_id) BETWEEN 1 AND 256),
 revision text NOT NULL CHECK(length(revision) BETWEEN 1 AND 256),
 digest bytea NOT NULL CHECK(octet_length(digest)=32),
 max_bytes bigint NOT NULL CHECK(max_bytes>0),
 max_files bigint NOT NULL CHECK(max_files>0),
 max_metadata_bytes bigint NOT NULL CHECK(max_metadata_bytes>=1024),
 max_metadata_rows bigint NOT NULL CHECK(max_metadata_rows>0),
 prepare_ttl_ms bigint NOT NULL CHECK(prepare_ttl_ms BETWEEN 1 AND 2147483647),
 expires_at timestamptz NOT NULL
);
CREATE TABLE IF NOT EXISTS lore_fragment_stage_usage (
 singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
 live_bytes bigint NOT NULL DEFAULT 0 CHECK(live_bytes>=0),
 live_files bigint NOT NULL DEFAULT 0 CHECK(live_files>=0),
 metadata_bytes bigint NOT NULL DEFAULT 0 CHECK(metadata_bytes>=0),
 metadata_rows bigint NOT NULL DEFAULT 0 CHECK(metadata_rows>=0)
);
INSERT INTO lore_fragment_stage_usage(singleton) VALUES(true) ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS lore_fragment_stage_custody (
 hash bytea NOT NULL CHECK(octet_length(hash)=32),
 epoch bigint NOT NULL CHECK(epoch>=0),
 operation_fence bigint NOT NULL CHECK(operation_fence>0),
 original_flags bigint CHECK(original_flags BETWEEN 0 AND 4294967295),
 size_payload bigint NOT NULL CHECK(size_payload BETWEEN 0 AND 262144),
 prepare_deadline timestamptz NOT NULL,
 state smallint NOT NULL CHECK(state BETWEEN 0 AND 3),
 metadata_bytes bigint NOT NULL CHECK(metadata_bytes IN(256,1024)),
 purged_at timestamptz,
 PRIMARY KEY(hash,epoch),
 CHECK((state=3 AND purged_at IS NOT NULL AND original_flags IS NULL AND size_payload=0 AND metadata_bytes=256)
    OR (state<>3 AND purged_at IS NULL AND original_flags IS NOT NULL AND metadata_bytes=1024))
);
CREATE INDEX IF NOT EXISTS lore_fragment_stage_custody_cleanup ON lore_fragment_stage_custody(state,hash,epoch);
CREATE INDEX IF NOT EXISTS lore_fragment_stage_drain_recovery ON lore_fragment_lifecycle(hash)
 WHERE state=3 AND (active_operation IS NULL OR active_operation=decode('77703131352d70726f6d6f74652d7631','hex'));
DO $install$ BEGIN
 EXECUTE format($definition$
CREATE OR REPLACE FUNCTION %1$I.stage_policy_publish_v1(
 p_cell text,p_revision text,p_digest bytea,p_bytes bigint,p_files bigint,
 p_metadata_bytes bigint,p_metadata_rows bigint,p_prepare_ms bigint,p_expiry_ms bigint)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE existing %1$I.lore_fragment_stage_policy;
BEGIN
 IF session_user IS DISTINCT FROM 'object_dispatch_retention_maintenance' THEN
   RAISE EXCEPTION 'STAGE_POLICY_MAINTENANCE_REQUIRED' USING ERRCODE='42501';
 END IF;
 IF p_cell IS NULL OR p_revision IS NULL OR p_digest IS NULL OR p_bytes IS NULL OR p_files IS NULL
    OR p_metadata_bytes IS NULL OR p_metadata_rows IS NULL OR p_prepare_ms IS NULL OR p_expiry_ms IS NULL
    OR p_expiry_ms <= floor(extract(epoch FROM clock_timestamp())*1000)::bigint THEN
   RAISE EXCEPTION 'STAGE_POLICY_INVALID' USING ERRCODE='22023';
 END IF;
 INSERT INTO %1$I.lore_fragment_stage_policy VALUES(true,p_cell,p_revision,p_digest,p_bytes,p_files,
    p_metadata_bytes,p_metadata_rows,p_prepare_ms,to_timestamp(p_expiry_ms::double precision/1000))
 ON CONFLICT(singleton) DO NOTHING;
 SELECT * INTO STRICT existing FROM %1$I.lore_fragment_stage_policy WHERE singleton FOR UPDATE;
 IF existing.cell_id IS DISTINCT FROM p_cell OR existing.revision IS DISTINCT FROM p_revision
    OR existing.digest IS DISTINCT FROM p_digest OR existing.max_bytes IS DISTINCT FROM p_bytes
    OR existing.max_files IS DISTINCT FROM p_files OR existing.max_metadata_bytes IS DISTINCT FROM p_metadata_bytes
    OR existing.max_metadata_rows IS DISTINCT FROM p_metadata_rows OR existing.prepare_ttl_ms IS DISTINCT FROM p_prepare_ms
    OR existing.expires_at IS DISTINCT FROM to_timestamp(p_expiry_ms::double precision/1000) THEN
   RAISE EXCEPTION 'STAGE_POLICY_CONFLICT' USING ERRCODE='22023';
 END IF;
END $$;
CREATE OR REPLACE FUNCTION %1$I.stage_policy_verify_v1(
 p_cell text,p_revision text,p_digest bytea,p_bytes bigint,p_files bigint,
 p_metadata_bytes bigint,p_metadata_rows bigint,p_prepare_ms bigint,p_expiry_ms bigint)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF session_user IS DISTINCT FROM 'object_dispatch_retention_maintenance' THEN
   RAISE EXCEPTION 'STAGE_POLICY_MAINTENANCE_REQUIRED' USING ERRCODE='42501';
 END IF;
 RETURN EXISTS(SELECT 1 FROM %1$I.lore_fragment_stage_policy p WHERE p.singleton
   AND p.cell_id=p_cell AND p.revision=p_revision AND p.digest=p_digest
   AND p.max_bytes=p_bytes AND p.max_files=p_files AND p.max_metadata_bytes=p_metadata_bytes
   AND p.max_metadata_rows=p_metadata_rows AND p.prepare_ttl_ms=p_prepare_ms
   AND p.expires_at=to_timestamp(p_expiry_ms::double precision/1000) AND p.expires_at>clock_timestamp());
END $$;
$definition$, current_schema());
END $install$;
REVOKE ALL ON FUNCTION stage_policy_verify_v1(text,text,bytea,bigint,bigint,bigint,bigint,bigint,bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION stage_policy_publish_v1(text,text,bytea,bigint,bigint,bigint,bigint,bigint,bigint) FROM PUBLIC;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM pg_roles WHERE rolname='object_dispatch_retention_maintenance') THEN
   GRANT EXECUTE ON FUNCTION stage_policy_publish_v1(text,text,bytea,bigint,bigint,bigint,bigint,bigint,bigint)
     TO object_dispatch_retention_maintenance;
   GRANT EXECUTE ON FUNCTION stage_policy_verify_v1(text,text,bytea,bigint,bigint,bigint,bigint,bigint,bigint)
     TO object_dispatch_retention_maintenance;
 END IF;
END $$;
UPDATE lore_fragment_schema_state SET schema_version = 5 WHERE schema_version = 4;
";

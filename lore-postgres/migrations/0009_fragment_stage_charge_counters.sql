-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
-- WP-115 row 78: running charge counters on the stage ledger. Apply before a schema-version 7
-- server starts, with every replica stopped: a revision-6 replica still running reserves without
-- adding to the counters, which makes the write-behind walk bound fall back to the two ledger
-- reads (a false capacity refusal, never a masked orphan). Same DDL as `stage_charge_schema.rs`.
BEGIN;
ALTER TABLE lore_fragment_stage_usage ADD COLUMN IF NOT EXISTS charged_bytes bigint NOT NULL DEFAULT 0;
ALTER TABLE lore_fragment_stage_usage ADD COLUMN IF NOT EXISTS charged_files bigint NOT NULL DEFAULT 0;
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='lore_fragment_stage_usage'::regclass
    AND conname='lore_fragment_stage_usage_charged_nonnegative') THEN
  ALTER TABLE lore_fragment_stage_usage ADD CONSTRAINT lore_fragment_stage_usage_charged_nonnegative
   CHECK(charged_bytes>=0 AND charged_files>=0) NOT VALID;
 END IF;
END $$;
-- The table is one row, so the proof is immediate.
ALTER TABLE lore_fragment_stage_usage VALIDATE CONSTRAINT lore_fragment_stage_usage_charged_nonnegative;
UPDATE lore_fragment_schema_state SET schema_version = 7 WHERE schema_version = 6;
COMMIT;

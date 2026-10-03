// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! WP-115 row 78: running charge counters on the stage ledger (revision 7).
//!
//! Write-behind compares a completed physical stage walk with the stage ledger,
//! `live_bytes`/`live_files`. A walk takes time, and stage reservations and
//! releases both happen while it runs, so a walk can count a file released
//! before the next ledger read and also a file charged after the previous one.
//! `charged_bytes`/`charged_files` only grow: every reservation adds exactly
//! what it adds to `live_*`. The ledger before a walk plus their growth across
//! the walk bounds the walk: only bytes no reservation charged exceed it.

pub const STAGE_CHARGE_COUNTER_SCHEMA: &str = r"
-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
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
";

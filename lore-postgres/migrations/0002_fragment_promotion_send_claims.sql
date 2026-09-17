-- SPDX-FileCopyrightText: 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
--
-- WP-115 write-behind — the durable promotion send claim (SCHEMA-118 revision 4).
--
-- The first numbered follow-on this crate has ever had. It is a NEW file rather
-- than an edit to `0001_init.sql` on purpose: editing `0001` in place would
-- silently skip every cell already provisioned from it, because nothing re-reads
-- a migration a cell has already applied.
--
-- WHO APPLIES THIS, AND WHEN
--
-- `lore-postgres` has no migration runner, so this file is applied by hand or by
-- the provisioning tooling, BEFORE a revision-4 binary serves the cell. It is
-- idempotent and may be applied twice.
--
-- Apply it to EVERY database that already carries `lore_fragment_write_claims`,
-- including long-lived local development slots and test fixtures.
-- `FRAGMENT_SCHEMA`'s `CREATE TABLE IF NOT EXISTS` is a no-op on an existing
-- table, so `PostgresFragmentCoordinator::bootstrap` alone would not have added
-- these columns to such a database — which is why `FRAGMENT_SCHEMA` carries the
-- same ALTERs. Freshly built fixtures get them either way, so a stale developer
-- database is the one case a green test run cannot tell you about.
--
-- A cell that has run only `0001_init.sql` records revision 3 and has none of
-- these columns. That is the intended fail-closed state: `ready_for_lifecycle`'s
-- clean-init arm requires revision 4 and `enable_lifecycle` requires an exact
-- match, so such a cell routes legacy instead of half-enabling and dying at
-- runtime on SQLSTATE 42703.

-- ---------------------------------------------------------------------------
-- Promotion send-claim columns
-- ---------------------------------------------------------------------------
--
-- `kind` 0 is a direct write or a repair — the only shape that existed before
-- WP-115, and the DEFAULT is what makes every pre-existing row legal. 1 is a
-- promotion, and only a promotion carries the exact staged witness it was
-- admitted against.
--
-- `epoch`/`fence` keep their existing meaning on both kinds: the REMOTE
-- successor epoch and the operation fence. `source_epoch`/`source_manifest_id`
-- are the staged predecessor the promotion was admitted against, so
-- `authorize_write_claim` can recognise a staged source without trusting the
-- head's mutable current view. `source_epoch < epoch` makes promotion's
-- successor rule a database invariant rather than a code comment.
--
-- No index change. Both existing partial indexes already cover these rows, and
-- the new predicates are too low-selectivity to earn a place in either key.
ALTER TABLE lore_fragment_write_claims
    ADD COLUMN IF NOT EXISTS kind smallint NOT NULL DEFAULT 0 CHECK (kind IN (0, 1)),
    ADD COLUMN IF NOT EXISTS source_epoch bigint CHECK (source_epoch IS NULL
                                                        OR source_epoch >= 1),
    ADD COLUMN IF NOT EXISTS source_manifest_id bytea CHECK (source_manifest_id IS NULL
                                                        OR octet_length(source_manifest_id) = 32);

-- Postgres has no ADD CONSTRAINT IF NOT EXISTS, and there is no migration
-- runner here to remember that this file already ran.
DO $promotion_shape$ BEGIN
    ALTER TABLE lore_fragment_write_claims
        ADD CONSTRAINT lore_fragment_write_claim_promotion_shape CHECK (
            (kind = 1) = (source_epoch IS NOT NULL)
        AND (kind = 1) = (source_manifest_id IS NOT NULL)
        AND (kind = 0 OR source_epoch < epoch)
        );
EXCEPTION WHEN duplicate_object THEN NULL;
END $promotion_shape$;

-- ---------------------------------------------------------------------------
-- Recorded revision
-- ---------------------------------------------------------------------------
--
-- Last, and only after the shape above is installed, so an interrupted apply
-- never leaves a cell claiming a revision whose columns it does not have.
-- Monotonic: it never lowers a revision a newer binary wrote.
UPDATE lore_fragment_schema_state
   SET schema_version = 4, updated_at = clock_timestamp()
 WHERE id = 1 AND schema_version < 4;

-- SPDX-FileCopyrightText: 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
--
-- Operator audit for `loreserver outbox retire-generation` (WP-115 ledger row
-- 68 review): who retired a receiver generation, why, and when.
--
-- This file is the ONLY declaration of these columns. The boot-time path
-- (`lore_postgres::domain::outbox::schema::OUTBOX_RETIREMENT_AUDIT_SCHEMA`) is
-- an `include_str!` of this file, so the two cannot drift.
--
-- The audit lives ON the generation's row, the same choice the replay audit
-- (`replay_actor`/`replay_reason` on `lore_outbox_events`) and the dead-letter
-- disposition (`disposition_actor`/`disposition_reason`) make: what an operator
-- needs when they find a retired generation is why it is retired, and a side
-- table is a join they will forget to write.
--
-- Only the operator command writes these columns. A generation that
-- `readiness_cas` retired on a placement mismatch, or that an accepted reset
-- retired, carries NULL in all three, which is itself the record that no
-- operator retired it. A rerun of the same command on an already retired
-- generation writes nothing, so the first actor and reason stand.
--
-- Nullable with no default, and every constraint named and `NOT VALID`, so this
-- never scans the table under `ensure_schema_online`'s 250 ms statement timeout.
-- The existing rows cannot violate the constraints: the columns are new here and
-- NULL on every such row. PostgreSQL enforces `NOT VALID` constraints on every
-- later insert and update.
ALTER TABLE lore_outbox_receiver_membership
    ADD COLUMN IF NOT EXISTS retirement_actor text,
    ADD COLUMN IF NOT EXISTS retirement_reason text,
    ADD COLUMN IF NOT EXISTS retirement_recorded_at timestamptz;

DO $outbox_retirement_audit_constraints$
BEGIN
    -- The same widths as the replay and disposition audits.
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'lore_outbox_receiver_membership_retirement_bounds'
          AND conrelid = 'lore_outbox_receiver_membership'::regclass
    ) THEN
        ALTER TABLE lore_outbox_receiver_membership
            ADD CONSTRAINT lore_outbox_receiver_membership_retirement_bounds CHECK (
                octet_length(retirement_actor) BETWEEN 1 AND 256
                AND octet_length(retirement_reason) BETWEEN 1 AND 1024
            ) NOT VALID;
    END IF;
    -- The three facts are one fact, and only a retired row carries them. Two
    -- pairwise equalities of IS NULL tests, which are never NULL themselves, so
    -- the shape CHECK cannot pass vacuously. The width CHECK above passes on
    -- NULL, which is why this one exists beside it.
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'lore_outbox_receiver_membership_retirement_shape'
          AND conrelid = 'lore_outbox_receiver_membership'::regclass
    ) THEN
        ALTER TABLE lore_outbox_receiver_membership
            ADD CONSTRAINT lore_outbox_receiver_membership_retirement_shape CHECK (
                (retirement_recorded_at IS NULL) = (retirement_actor IS NULL)
                AND (retirement_recorded_at IS NULL) = (retirement_reason IS NULL)
                AND (retirement_recorded_at IS NULL OR state = 'retired')
            ) NOT VALID;
    END IF;
END
$outbox_retirement_audit_constraints$;

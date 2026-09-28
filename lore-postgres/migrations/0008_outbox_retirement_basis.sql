-- SPDX-FileCopyrightText: 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
--
-- Which proof let `loreserver outbox retire-generation` retire a receiver
-- generation (WP-115 ledger row 68, KV ruling 2026-09-28).
--
-- This file is the ONLY declaration of this column. The boot-time path
-- (`lore_postgres::domain::outbox::schema::OUTBOX_RETIREMENT_BASIS_SCHEMA`) is
-- an `include_str!` of this file, so the two cannot drift.
--
-- `retire_generation` accepts three proofs, and an operator reading a retired
-- row needs to know which one held:
--
-- * `graceful_drain`: the receiver's own graceful shutdown marked the
--   generation `draining`, and its checkpoint had reached every accepted row;
-- * `replacement`: a greater generation of the same receiver was `ready`;
-- * `confirmed_stopped`: the operator passed `--confirm-receiver-stopped` for
--   a receiver that died without a graceful stop, and its checkpoint had
--   reached every accepted row. The one basis that rests on an operator's word
--   that the process is gone, which is why it is recorded.
--
-- Written by the same statement that writes the actor, reason, and time from
-- migration 0007, so the four are one fact.
--
-- Nullable with no default, and the constraint named and `NOT VALID`, so this
-- never scans the table under `ensure_schema_online`'s 250 ms statement timeout.
-- A row retired before this migration carries an actor and a NULL basis; the
-- constraint is not checked against it, and nothing updates a retired row.
ALTER TABLE lore_outbox_receiver_membership
    ADD COLUMN IF NOT EXISTS retirement_basis text;

DO $outbox_retirement_basis_constraints$
BEGIN
    -- Equality of two IS NULL tests is never NULL, so this cannot pass
    -- vacuously. The IN list is guarded the same way.
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'lore_outbox_receiver_membership_retirement_basis'
          AND conrelid = 'lore_outbox_receiver_membership'::regclass
    ) THEN
        ALTER TABLE lore_outbox_receiver_membership
            ADD CONSTRAINT lore_outbox_receiver_membership_retirement_basis CHECK (
                (retirement_basis IS NULL) = (retirement_recorded_at IS NULL)
                AND (retirement_basis IS NULL
                     OR retirement_basis IN ('graceful_drain', 'replacement',
                                             'confirmed_stopped'))
            ) NOT VALID;
    END IF;
END
$outbox_retirement_basis_constraints$;

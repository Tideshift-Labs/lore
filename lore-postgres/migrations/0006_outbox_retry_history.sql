-- SPDX-FileCopyrightText: 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
--
-- Outbox retry history: the cause of a row's most recent release for retry,
-- kept after the row is accepted (WP-115 ledger row 60, fix 2; INV-FS).
--
-- This file is the ONLY declaration of these columns. The boot-time path
-- (`lore_postgres::domain::outbox::schema::OUTBOX_RETRY_HISTORY_SCHEMA`) is an
-- `include_str!` of this file, so the two cannot drift. It is a new file rather
-- than an edit to `0001_init.sql` or to `OUTBOX_SCHEMA`, so an
-- already-provisioned cell is not silently skipped.
--
-- Why a second pair of columns rather than keeping `last_error_class`:
-- `last_error_class` is the input of the relay's repetition rule
-- (`EventRelayWorker::terminal_is_final`), which reads it as "the immediately
-- preceding attempt failed this way". Acceptance must clear it, or a replayed
-- row that fails once would be judged a repeat of a failure from its earlier
-- cycle. That same clear erased the only record of what delayed a row, so a
-- drained backlog could not say why it had been slow.
--
-- `last_retry_class` is written by every `release_for_retry` (the same bounded
-- class `last_error_class` gets) and no update clears it: not acceptance, not a
-- replay, not an epoch-reset requeue. A row that leaves this table (a dead
-- letter, a `live_only` retirement) does not carry it; the dead letter's own
-- `terminal_class` is that path's record. `last_retry_at` is the database
-- clock at that release. A row's retry COUNT is already `attempt_count`, which
-- acceptance also keeps, so no third counter is added. Compare `last_retry_at`
-- with `unpublished_since` to tell whether the record belongs to the row's
-- current publication cycle or to one before a replay.
--
-- The name says "retry", not "refusal", on purpose: a release records every
-- retry cause, including a transport timeout that no gateway refused.
--
-- Both columns are nullable with no default, so adding them does not rewrite a
-- populated table.
ALTER TABLE lore_outbox_events
    ADD COLUMN IF NOT EXISTS last_retry_class text
        CHECK (octet_length(last_retry_class) BETWEEN 1 AND 64),
    ADD COLUMN IF NOT EXISTS last_retry_at timestamptz;

DO $outbox_retry_history_constraints$
BEGIN
    -- A class and its timestamp are one fact: both set or both null. Written as
    -- an equality of two IS NULL tests, which are never NULL themselves, so the
    -- CHECK cannot pass vacuously.
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'lore_outbox_events_retry_history_shape'
          AND conrelid = 'lore_outbox_events'::regclass
    ) THEN
        ALTER TABLE lore_outbox_events
            ADD CONSTRAINT lore_outbox_events_retry_history_shape CHECK (
                (last_retry_class IS NULL) = (last_retry_at IS NULL)
            );
    END IF;
END
$outbox_retry_history_constraints$;

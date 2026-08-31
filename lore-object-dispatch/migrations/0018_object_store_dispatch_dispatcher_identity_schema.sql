-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
-- WP-114 CD-3 per-participant dispatcher identity (CR-033 D8): the schema edge.
-- Runtime code never installs this artifact. Migration 0019 installs and attests it.
--
-- Migration 0007 froze a single-active-dispatcher model. With boundary equal to the cell's one
-- bucket that means at most one ACTIVE dispatcher per cell, which contradicts the revised CR-033's
-- "every loreserver replica and every drain worker is an equal participant; there is no
-- write-primary". D8 decided per-participant identity instead: each participant registers its own
-- dispatcher row and owns its own lease chain, and ACTIVE-uniqueness narrows to
-- one-per-(boundary, participant).
--
-- The participant identity is `dispatcher_id`, not `service_instance_id`. 0007 already keys the
-- attempt foreign key on (provider_boundary_id, dispatcher_id, lease_generation) against the
-- matching UNIQUE constraint, so `dispatcher_id` is already the column the frozen schema treats as
-- the lease chain's owner. It must also be stable across a process restart, because D8's fence
-- argument is that "a crashed participant's successor process increments its own generation": an
-- identity that changed on every boot would start a fresh chain at generation 1 each time and make
-- `lease_generation` decorative. `service_instance_id` is the per-boot value and keeps its own
-- index; it is not the participant.
--
-- 0007 is a frozen artifact and is not edited (CR-033 D6 hard rule 1). This migration replaces its
-- constraints instead.
--
-- **Two constraints, not one.** D8's review finding named only the partial unique index
-- (0007:263-265). A live run of this migration with only that index replaced showed that is not
-- enough: 0007's PRIMARY KEY (provider_boundary_id, lease_generation) is itself a
-- single-active-dispatcher artifact. It admits one dispatcher row per (boundary, generation) across
-- *all* participants, so the second participant to register cannot take generation 1 --
--   ERROR: duplicate key value violates unique constraint
--   "object_dispatch_dispatchers_pkey"
--   DETAIL: Key (provider_boundary_id, lease_generation)=(boundary-a, 1) already exists.
-- -- and participants would have to draw generations from one shared per-boundary sequence, which
-- is the coordination point D1 removed and the write-primary D8 rejected. Swapping the index alone
-- would have produced a migration that looked correct, installed cleanly, attested cleanly, and
-- failed the first time a cell ran two replicas.
--
-- The primary key is therefore dropped, and the table's identity becomes 0007's own
-- UNIQUE (provider_boundary_id, dispatcher_id, lease_generation) -- which already exists, is
-- already the exact target of `object_dispatch_attempts`' foreign key, and is left untouched here.
-- No replacement PRIMARY KEY is declared over those same three columns: it would build a second
-- unique index identical to the one the foreign key depends on, and the constraint cannot be
-- promoted in place because a unique constraint already owns its index. The invariant a reader
-- should hold on to is stated as an assertion in 0019 rather than as a redundant index here: no
-- uniqueness on this table may be enforced across participants.

BEGIN;
SET LOCAL ROLE object_dispatch_retention_owner;

DROP INDEX object_store_retention.object_dispatch_dispatchers_one_active_generation_idx;

ALTER TABLE object_store_retention.object_dispatch_dispatchers
  DROP CONSTRAINT object_dispatch_dispatchers_pkey;

CREATE UNIQUE INDEX object_dispatch_dispatchers_one_active_participant_idx
  ON object_store_retention.object_dispatch_dispatchers (provider_boundary_id, dispatcher_id)
  WHERE state = 1;

COMMIT;

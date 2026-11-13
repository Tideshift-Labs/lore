-- Copyright 2026 Tideshift Labs
-- SPDX-License-Identifier: MIT
--
-- WP-115 drain guard follow-up: operator loss rulings for staged fragments the
-- guarded drain keeps `Staged` forever (`loreserver stage resolve-lost`).
--
-- The guard never reads a missing staged file as absent unless the reader
-- process confirmed its stager in its own stage directory. A file whose
-- stager left before any reader confirmed it (or that has no recorded
-- stager) is kept `Staged` and retried on every pass. An operator who has
-- checked the cause records a ruling here. The command never reads the
-- stage: the running drain carries the ruling out on its normal pass, with
-- its own pinned read, its own guard state and its own evidence check, and
-- only then marks the fragment `Missing`, in the same transaction that
-- writes the outcome below.
--
-- A ruling row is never deleted. It holds no challenge or echo content.
--
-- `selection`: why the representation was listed. `no_stager` (no stager
-- row) needs `attested`. `stager_not_fresh` names the stager.
-- `attested`: the operator ran with `--attest-mounts-checked` (checked the
-- stage mount on every web host). Without it the drain needs echo evidence.
-- `repositories`: distinct repositories with a live association when the
-- ruling was applied. More than one needs `multi_repository` (Lore has no
-- org concept, so a repository is the narrowest tenant boundary it can see).
-- `outcome` is NULL while the ruling is open. It is written once:
-- `marked_missing` (with `evidence` `echo` or `none` and the drain's
-- identity), `found` (the drain's pinned read found the file), `fenced` (the
-- head left the ruled epoch or manifest by another path), `expired` (not
-- carried out before `expires_at`; written by a drain refresh, or with no
-- drain identity by an `apply` that rules the representation again), or
-- `no_evidence` (no echo evidence and no attestation).
--
-- This file is the ONLY declaration of this relation. The boot-time path
-- (`lore_postgres::domain::fragments::STAGE_LOSS_SCHEMA`) is an
-- `include_str!` of this file. Additive only: one new table, one partial
-- index, and the audit triggers on that table, so a binary one revision
-- behind is unaffected.
CREATE TABLE IF NOT EXISTS lore_domain_stage_loss_rulings (
    ruling_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    hash bytea NOT NULL,
    epoch bigint NOT NULL,
    manifest_id bytea NOT NULL,
    selection text NOT NULL,
    stager_replica_id text,
    stager_incarnation text,
    actor text NOT NULL,
    reason text NOT NULL,
    attested boolean NOT NULL,
    multi_repository boolean NOT NULL,
    repositories bigint NOT NULL,
    min_age_ms bigint NOT NULL,
    token text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    outcome text,
    evidence text,
    decided_at timestamptz,
    drain_replica_id text,
    drain_incarnation text,
    CONSTRAINT lore_domain_stage_loss_rulings_bounded CHECK (
        octet_length(hash) = 32
        AND epoch >= 0
        AND octet_length(manifest_id) = 32
        AND octet_length(actor) BETWEEN 1 AND 256
        AND octet_length(reason) BETWEEN 1 AND 1024
        AND octet_length(token) BETWEEN 1 AND 128
        AND repositories >= 0
        AND min_age_ms >= 3600000
        AND expires_at > created_at
    ),
    CONSTRAINT lore_domain_stage_loss_rulings_selection CHECK (
        selection IN ('no_stager', 'stager_not_fresh')
        AND (selection = 'no_stager') = (stager_replica_id IS NULL)
        AND (stager_replica_id IS NULL) = (stager_incarnation IS NULL)
        AND (stager_replica_id IS NULL OR octet_length(stager_replica_id) BETWEEN 1 AND 128)
        AND (stager_incarnation IS NULL OR octet_length(stager_incarnation) BETWEEN 1 AND 64)
        AND (selection <> 'no_stager' OR attested)
        AND (repositories <= 1 OR multi_repository)
    ),
    CONSTRAINT lore_domain_stage_loss_rulings_outcome CHECK (
        (outcome IS NULL OR outcome IN
            ('marked_missing', 'found', 'fenced', 'expired', 'no_evidence'))
        AND (outcome IS NULL) = (decided_at IS NULL)
        AND (evidence IS NULL OR evidence IN ('echo', 'none'))
        AND (outcome IS NOT NULL
            OR (evidence IS NULL AND drain_replica_id IS NULL AND drain_incarnation IS NULL))
        AND (outcome IS DISTINCT FROM 'marked_missing'
            OR (evidence IS NOT NULL AND drain_replica_id IS NOT NULL
                AND drain_incarnation IS NOT NULL))
        AND (evidence IS DISTINCT FROM 'none' OR attested)
        AND (drain_replica_id IS NULL OR octet_length(drain_replica_id) BETWEEN 1 AND 128)
        AND (drain_incarnation IS NULL OR octet_length(drain_incarnation) BETWEEN 1 AND 64)
    )
);
-- At most one open ruling per representation. The drain reads open rulings
-- through this index on every refresh. An open ruling past `expires_at` still
-- holds its slot until something writes its `expired` outcome: the drain's
-- refresh, or `apply` for the representation it is about to rule again.
CREATE UNIQUE INDEX IF NOT EXISTS lore_domain_stage_loss_rulings_open
    ON lore_domain_stage_loss_rulings (hash, epoch) WHERE outcome IS NULL;
-- The audit rule, held by the database rather than by the callers: a row is
-- never deleted (nor the table truncated), a row is inserted open (every
-- outcome column NULL), the ruling columns never change, and the outcome
-- columns change once, from all NULL to a decided outcome (the outcome CHECK
-- above refuses any half-written state). A decided row never changes again.
-- The triggers bind non-owner roles and application bugs. The table owner and
-- a superuser can still disable or drop them; every install enables them
-- again. The online bootstrap accepts only guarded blocks for
-- anything but tables and indexes, so the function and the triggers are
-- created inside one.
DO $stage_loss_guard$
BEGIN
    CREATE OR REPLACE FUNCTION lore_domain_stage_loss_rulings_guard()
    RETURNS trigger LANGUAGE plpgsql AS $fn$
    BEGIN
        IF TG_OP = 'INSERT' THEN
            IF NEW.outcome IS NOT NULL OR NEW.evidence IS NOT NULL
               OR NEW.decided_at IS NOT NULL OR NEW.drain_replica_id IS NOT NULL
               OR NEW.drain_incarnation IS NOT NULL THEN
                RAISE EXCEPTION 'a stage loss ruling is inserted open, never decided'
                    USING ERRCODE = 'restrict_violation';
            END IF;
            RETURN NEW;
        END IF;
        IF TG_OP = 'DELETE' OR TG_OP = 'TRUNCATE' THEN
            RAISE EXCEPTION 'a stage loss ruling is never deleted'
                USING ERRCODE = 'restrict_violation';
        END IF;
        IF (NEW.ruling_id, NEW.hash, NEW.epoch, NEW.manifest_id, NEW.selection,
            NEW.stager_replica_id, NEW.stager_incarnation, NEW.actor, NEW.reason,
            NEW.attested, NEW.multi_repository, NEW.repositories, NEW.min_age_ms,
            NEW.token, NEW.created_at, NEW.expires_at)
           IS DISTINCT FROM
           (OLD.ruling_id, OLD.hash, OLD.epoch, OLD.manifest_id, OLD.selection,
            OLD.stager_replica_id, OLD.stager_incarnation, OLD.actor, OLD.reason,
            OLD.attested, OLD.multi_repository, OLD.repositories, OLD.min_age_ms,
            OLD.token, OLD.created_at, OLD.expires_at) THEN
            RAISE EXCEPTION 'a stage loss ruling''s ruling columns never change'
                USING ERRCODE = 'restrict_violation';
        END IF;
        IF OLD.outcome IS NOT NULL
           AND (NEW.outcome, NEW.evidence, NEW.decided_at, NEW.drain_replica_id,
                NEW.drain_incarnation)
               IS DISTINCT FROM
               (OLD.outcome, OLD.evidence, OLD.decided_at, OLD.drain_replica_id,
                OLD.drain_incarnation) THEN
            RAISE EXCEPTION 'a decided stage loss ruling never changes'
                USING ERRCODE = 'restrict_violation';
        END IF;
        RETURN NEW;
    END
    $fn$;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger
                    WHERE tgname = 'lore_domain_stage_loss_rulings_guard_row'
                      AND tgrelid = 'lore_domain_stage_loss_rulings'::regclass) THEN
        CREATE TRIGGER lore_domain_stage_loss_rulings_guard_row
        BEFORE UPDATE OR DELETE ON lore_domain_stage_loss_rulings
        FOR EACH ROW EXECUTE FUNCTION lore_domain_stage_loss_rulings_guard();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger
                    WHERE tgname = 'lore_domain_stage_loss_rulings_guard_truncate'
                      AND tgrelid = 'lore_domain_stage_loss_rulings'::regclass) THEN
        CREATE TRIGGER lore_domain_stage_loss_rulings_guard_truncate
        BEFORE TRUNCATE ON lore_domain_stage_loss_rulings
        FOR EACH STATEMENT EXECUTE FUNCTION lore_domain_stage_loss_rulings_guard();
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_trigger
                    WHERE tgname = 'lore_domain_stage_loss_rulings_guard_insert'
                      AND tgrelid = 'lore_domain_stage_loss_rulings'::regclass) THEN
        CREATE TRIGGER lore_domain_stage_loss_rulings_guard_insert
        BEFORE INSERT ON lore_domain_stage_loss_rulings
        FOR EACH ROW EXECUTE FUNCTION lore_domain_stage_loss_rulings_guard();
    END IF;
    -- A trigger left disabled (`ALTER TABLE ... DISABLE TRIGGER`) is enabled
    -- again on every install. Only a trigger that is not already 'O' is
    -- altered, so a normal reinstall takes no table lock here.
    IF EXISTS (SELECT 1 FROM pg_trigger
                WHERE tgname = 'lore_domain_stage_loss_rulings_guard_row'
                  AND tgrelid = 'lore_domain_stage_loss_rulings'::regclass
                  AND tgenabled <> 'O') THEN
        ALTER TABLE lore_domain_stage_loss_rulings
            ENABLE TRIGGER lore_domain_stage_loss_rulings_guard_row;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_trigger
                WHERE tgname = 'lore_domain_stage_loss_rulings_guard_truncate'
                  AND tgrelid = 'lore_domain_stage_loss_rulings'::regclass
                  AND tgenabled <> 'O') THEN
        ALTER TABLE lore_domain_stage_loss_rulings
            ENABLE TRIGGER lore_domain_stage_loss_rulings_guard_truncate;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_trigger
                WHERE tgname = 'lore_domain_stage_loss_rulings_guard_insert'
                  AND tgrelid = 'lore_domain_stage_loss_rulings'::regclass
                  AND tgenabled <> 'O') THEN
        ALTER TABLE lore_domain_stage_loss_rulings
            ENABLE TRIGGER lore_domain_stage_loss_rulings_guard_insert;
    END IF;
END
$stage_loss_guard$;

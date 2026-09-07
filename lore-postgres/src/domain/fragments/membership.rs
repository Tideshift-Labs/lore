// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Persistent writer fences for the server-side push membership protocol.
//!
//! Installing these fences is an explicit maintenance action, never bootstrap.
//! The transaction marker distinguishes upgraded code from old binaries. It is
//! not a security boundary against an administrator with arbitrary SQL access.

use tokio_postgres::Transaction;

use crate::domain::errors::DomainError;

/// Read the committed protocol and attest its unconditional database fences.
/// An absent table is the supported pre-migration, dark state.
pub async fn enabled(tx: &Transaction<'_>) -> Result<bool, DomainError> {
    let exists: bool = tx
        .query_one(
            "SELECT to_regclass('lore_fragment_membership_protocol') IS NOT NULL",
            &[],
        )
        .await
        .map_err(|e| DomainError::from_pg("membership protocol catalog", e))?
        .get(0);
    if !exists {
        return inactive_without_fences(tx).await;
    }
    let active: bool = tx.query_one(
        "SELECT EXISTS (SELECT 1 FROM lore_fragment_membership_protocol WHERE id = 1 AND revision = 1)", &[],
    ).await.map_err(|e| DomainError::from_pg("membership protocol state", e))?.get(0);
    if !active {
        return inactive_without_fences(tx).await;
    }
    let count: i64 = tx.query_one(
        "SELECT count(*)::bigint FROM pg_trigger t \
         WHERE t.tgenabled = 'A' AND t.tgqual IS NULL AND t.tgnargs = 0 \
           AND t.tgattr = ''::int2vector \
           AND t.tgfoid = 'lore_membership_writer_guard()'::regprocedure \
           AND ((t.tgrelid = ANY(ARRAY['lore_fragment_associations'::regclass, \
             'lore_fragments'::regclass, 'lore_mutable'::regclass, 'lore_domain_branches'::regclass]) \
             AND ((t.tgname = 'lore_membership_writer_fence' AND t.tgtype = 31) \
               OR (t.tgname = 'lore_membership_truncate_fence' AND t.tgtype = 34))) \
             OR (t.tgrelid = 'lore_fragment_membership_protocol'::regclass \
               AND ((t.tgname = 'lore_membership_protocol_permanent' AND t.tgtype = 27) \
                 OR (t.tgname = 'lore_membership_protocol_no_truncate' AND t.tgtype = 34))))", &[],
    ).await.map_err(|e| DomainError::from_pg("membership protocol fences", e))?.get(0);
    if count != 10 {
        return Err(DomainError::Internal(
            "membership protocol fence is missing or disabled".into(),
        ));
    }
    Ok(true)
}

async fn inactive_without_fences(tx: &Transaction<'_>) -> Result<bool, DomainError> {
    let fenced: bool = tx.query_one(
        "SELECT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname IN \
         ('lore_membership_writer_fence', 'lore_membership_truncate_fence', \
          'lore_membership_protocol_permanent', 'lore_membership_protocol_no_truncate') \
          AND tgrelid IN (SELECT c.oid FROM pg_class c WHERE c.relnamespace = current_schema()::regnamespace))", &[],
    ).await.map_err(|e| DomainError::from_pg("membership inactive fence check", e))?.get(0);
    if fenced {
        return Err(DomainError::Internal(
            "membership fences exist without the protocol record".into(),
        ));
    }
    Ok(false)
}

/// Mark only a transaction whose caller already holds the Repository lock.
pub(crate) async fn allow_association(tx: &Transaction<'_>) -> Result<(), DomainError> {
    tx.execute(
        "SELECT set_config('lore.membership_writer_protocol', '1', true)",
        &[],
    )
    .await
    .map_err(|e| DomainError::from_pg("membership writer marker", e))?;
    Ok(())
}

/// Called by the governed publication path after its preconditions succeed.
pub(crate) async fn allow_publication(tx: &Transaction<'_>) -> Result<(), DomainError> {
    tx.execute(
        "SELECT set_config('lore.membership_publication_protocol', '1', true)",
        &[],
    )
    .await
    .map_err(|e| DomainError::from_pg("membership publication marker", e))?;
    Ok(())
}

/// Activate under table locks that drain all prior writes and repository
/// preflights. An old transaction whose first write comes later sees the
/// unconditional trigger, even with a pre-activation Repeatable Read snapshot.
/// This does not rotate provider credentials: ClaimsRequired remains required.
pub(crate) async fn activate(tx: &Transaction<'_>) -> Result<(), DomainError> {
    tx.batch_execute(
        "LOCK TABLE lore_domain_repositories, lore_domain_branches, lore_mutable, \
         lore_fragment_associations, lore_fragments IN ACCESS EXCLUSIVE MODE",
    )
    .await
    .map_err(|e| DomainError::from_pg("membership activation drain", e))?;
    let ready: bool = tx
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM lore_domain_schema_state WHERE enforcement_enabled) \
         AND EXISTS (SELECT 1 FROM lore_domain_lock_schema_state WHERE fencing_enabled) \
         AND EXISTS (SELECT 1 FROM lore_fragment_schema_state WHERE lifecycle_enabled \
           AND (backfill_state = 3 OR (to_jsonb(lore_fragment_schema_state)->>'clean_initialized_at') IS NOT NULL) AND write_capability = 1)",
            &[],
        )
        .await
        .map_err(|e| DomainError::from_pg("membership activation readiness", e))?
        .get(0);
    if !ready {
        return Err(DomainError::InvalidInput(
            "membership activation requires domain, lock and fragment enforcement with write claims"
                .into(),
        ));
    }
    tx.batch_execute(INSTALL_FENCES)
        .await
        .map_err(|e| DomainError::from_pg("membership activation fences", e))?;
    tx.execute("INSERT INTO lore_fragment_membership_protocol (id, revision) VALUES (1, 1) ON CONFLICT (id) DO NOTHING", &[])
        .await.map_err(|e| DomainError::from_pg("membership activation record", e))?;
    Ok(())
}

const INSTALL_FENCES: &str = r#"
CREATE OR REPLACE FUNCTION lore_membership_writer_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE allowed boolean := false;
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        RAISE EXCEPTION 'membership_writer_protocol_required' USING ERRCODE = '55000';
    END IF;
    IF TG_TABLE_NAME = 'lore_fragment_associations' THEN
        allowed := current_setting('lore.membership_writer_protocol', true) = '1';
    ELSIF TG_TABLE_NAME = 'lore_mutable' THEN
        -- BranchLatestPointer = 3; both old and new keys matter for UPDATE.
        IF (TG_OP = 'INSERT' AND NEW.key_type <> 3)
           OR (TG_OP = 'DELETE' AND OLD.key_type <> 3)
           OR (TG_OP = 'UPDATE' AND OLD.key_type <> 3 AND NEW.key_type <> 3) THEN
            allowed := true;
        ELSE
            allowed := current_setting('lore.membership_publication_protocol', true) = '1';
        END IF;
    ELSIF TG_TABLE_NAME = 'lore_domain_branches' THEN
        IF TG_OP <> 'UPDATE' OR NEW.latest_hash IS NOT DISTINCT FROM OLD.latest_hash THEN
            allowed := true;
        ELSE
            allowed := current_setting('lore.membership_publication_protocol', true) = '1';
        END IF;
    END IF;
    -- lore_fragments is legacy-only: every mutation remains refused.
    IF allowed IS NOT TRUE THEN
        RAISE EXCEPTION 'membership_writer_protocol_required' USING ERRCODE = '55000';
    END IF;
    IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END $$;
DO $$
DECLARE relation_name text;
BEGIN
    FOREACH relation_name IN ARRAY ARRAY['lore_fragment_associations', 'lore_fragments', 'lore_mutable', 'lore_domain_branches'] LOOP
        EXECUTE format('CREATE OR REPLACE TRIGGER lore_membership_writer_fence BEFORE INSERT OR UPDATE OR DELETE ON %I FOR EACH ROW EXECUTE FUNCTION lore_membership_writer_guard()', relation_name);
        EXECUTE format('ALTER TABLE %I ENABLE ALWAYS TRIGGER lore_membership_writer_fence', relation_name);
        EXECUTE format('CREATE OR REPLACE TRIGGER lore_membership_truncate_fence BEFORE TRUNCATE ON %I FOR EACH STATEMENT EXECUTE FUNCTION lore_membership_writer_guard()', relation_name);
        EXECUTE format('ALTER TABLE %I ENABLE ALWAYS TRIGGER lore_membership_truncate_fence', relation_name);
    END LOOP;
END $$;
CREATE OR REPLACE TRIGGER lore_membership_protocol_permanent
BEFORE UPDATE OR DELETE ON lore_fragment_membership_protocol
FOR EACH ROW EXECUTE FUNCTION lore_membership_writer_guard();
ALTER TABLE lore_fragment_membership_protocol ENABLE ALWAYS TRIGGER lore_membership_protocol_permanent;
CREATE OR REPLACE TRIGGER lore_membership_protocol_no_truncate
BEFORE TRUNCATE ON lore_fragment_membership_protocol
FOR EACH STATEMENT EXECUTE FUNCTION lore_membership_writer_guard();
ALTER TABLE lore_fragment_membership_protocol ENABLE ALWAYS TRIGGER lore_membership_protocol_no_truncate;
"#;

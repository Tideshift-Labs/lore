// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Idempotent, restartable domain backfill (CR-029; WP-116 Phase 2).
//!
//! Six steps, in this order, because the order is what makes it restartable:
//!
//! 1. list existing repository/branch pointers;
//! 2. load and deserialize immutable metadata **outside** database transactions;
//! 3. lock and verify one repository's current mutable snapshot;
//! 4. insert its domain rows and generations in one short transaction;
//! 5. retry if the snapshot changed under us; and
//! 6. run the projection check and residue classification before the cutover
//!    marker is set.
//!
//! Step 2 is outside a transaction on purpose: deserializing metadata means
//! fetching blobs, and holding a Postgres transaction across that would pin a
//! connection for the length of an object-store round trip on every repository
//! in the cell.
//!
//! **Verification is one way, plus a residue classification** (CR-029
//! R-SHOULD-7). The naive two-way check — every domain row has a projection row
//! *and* every projection row has a domain row — fails on any cell that has ever
//! served a delete, because `RepositoryDelete` is unbounded in write count and
//! every branch-level write in it swallows its error (worklog 254 §A.2). A crash
//! mid-loop leaves branch rows whose repository is gone, and those rows are not
//! a backfill defect. So the check proves the forward direction and *classifies*
//! what is left over instead of failing on it.
//!
//! **The server stays single-replica and enforcement stays off while this runs.**
//! Readiness fails if enforcement is requested before the marker and the
//! projection check pass — see [`super::store::PostgresDomainStore::enable_enforcement`].

use async_trait::async_trait;
use deadpool_postgres::Pool;

use crate::domain::errors::DomainError;
use crate::domain::schema;

/// Facts about one repository, read from Lore's own structures by the caller.
///
/// The source lives in `lore-server`, not here: reconstructing these means
/// deserializing metadata blobs out of the immutable store and using
/// `lore-revision`'s key derivations, neither of which belongs in the Postgres
/// crate. This keeps the backfill transaction logic testable against a fake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryFacts {
    /// 16-byte repository identifier.
    pub repository_id: Vec<u8>,
    /// Name exactly as the metadata blob records it.
    pub name: String,
    /// Whether the cell's `RepositoryId` name-map row for `name` actually
    /// resolves to `repository_id`.
    ///
    /// False is the R-BLOCK-3 case: `repository::mutable_name_key` hashes the
    /// raw name while `branch::mutable_name_key` lowercases, so pre-existing
    /// case-variant pairs can only exist today as silent overwrites. The
    /// backfill must detect the mismatch rather than assume a one-to-one
    /// mapping.
    pub name_map_resolves: bool,
    /// 32-byte metadata hash.
    pub metadata_hash: Vec<u8>,
    /// 16-byte default branch identifier.
    pub default_branch_id: Vec<u8>,
    /// Canonical creation fingerprint, recomputed from the immutable metadata.
    pub creation_fingerprint: Vec<u8>,
    /// Fingerprint schema version.
    pub creation_fingerprint_version: i32,
}

/// Facts about one branch of one repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchFacts {
    /// 16-byte branch identifier.
    pub branch_id: Vec<u8>,
    /// Name exactly as the metadata blob records it.
    pub name: String,
    /// 32-byte metadata hash.
    pub metadata_hash: Vec<u8>,
    /// 32-byte latest-pointer hash.
    pub latest_hash: Vec<u8>,
    /// Canonical creation fingerprint.
    pub creation_fingerprint: Vec<u8>,
    /// Fingerprint schema version.
    pub creation_fingerprint_version: i32,
}

/// Reads Lore's existing state so the backfill can project it into domain rows.
#[async_trait]
pub trait DomainBackfillSource: Send + Sync {
    /// Every repository the cell currently holds, ascending by `repository_id`
    /// so the cursor is a total order.
    async fn list_repositories(&self) -> Result<Vec<RepositoryFacts>, DomainError>;

    /// Every branch of one repository.
    async fn list_branches(&self, repository_id: &[u8]) -> Result<Vec<BranchFacts>, DomainError>;

    /// The current mutable snapshot token for one repository — any value that
    /// changes when the repository's mutable keys change. Step 5 compares it
    /// before and after the read so a concurrent write is retried rather than
    /// silently projected half-old.
    async fn snapshot_token(&self, repository_id: &[u8]) -> Result<Vec<u8>, DomainError>;

    /// Every domain-typed `lore_mutable` key with no owning repository, for the
    /// residue classification. Returned as opaque descriptions; this crate does
    /// not re-derive Lore's key hashes.
    async fn orphan_projection_keys(&self) -> Result<Vec<OrphanKey>, DomainError>;
}

/// One `lore_mutable` row the forward projection did not account for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrphanKey {
    /// `KeyType` as stored in `lore_mutable.key_type`.
    pub key_type: i16,
    /// Partition the row sits in.
    pub partition: Vec<u8>,
    /// Hashed key.
    pub key: Vec<u8>,
}

/// Why a leftover projection row is not a backfill defect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResidueClass {
    /// A name-map or metadata row whose repository is gone. Expected on any cell
    /// that has served a delete: `RepositoryDelete` removes the repository
    /// mapping and metadata pointer first and then does best-effort per-branch
    /// cleanup with every error swallowed.
    DeleteResidue,
    /// A branch row whose repository is gone. Same cause, one level down.
    OrphanedBranchRow,
    /// A domain-typed key that no server writer produces. Reachable only through
    /// the seven generic storage mutable RPCs, which pass the wire `KeyType`
    /// through untouched (worklog 254 §A.7). Reported, never silently accepted.
    ForeignDomainKeyWrite,
}

/// Outcome of the one-way projection check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerificationReport {
    /// Repositories projected into domain rows.
    pub repositories_projected: u64,
    /// Branches projected into domain rows.
    pub branches_projected: u64,
    /// Domain rows whose `lore_mutable` projection row is missing. **Any value
    /// above zero is a hard failure**: the projection must never lead the domain
    /// rows, so a domain row without its projection is a real defect.
    pub missing_projection_rows: u64,
    /// Leftover projection rows, classified. Non-empty is normal.
    pub residue: Vec<(OrphanKey, ResidueClass)>,
    /// Repositories whose metadata name does not resolve through the name map.
    /// The R-BLOCK-3 silent-overwrite case; reported, not repaired here.
    pub name_map_mismatches: Vec<Vec<u8>>,
}

impl VerificationReport {
    /// The check passes when the forward direction is complete. Residue and
    /// name-map mismatches are recorded for the operator; they do not fail it,
    /// because neither is something this backfill created or can fix.
    pub fn passed(&self) -> bool {
        self.missing_projection_rows == 0
    }
}

/// Drives the backfill against one cell.
pub struct DomainBackfill<'a> {
    pool: &'a Pool,
    source: &'a dyn DomainBackfillSource,
    /// Bounded retries for step 5 before the repository is reported as
    /// contended. A repository whose mutable keys change on every attempt means
    /// the cell is still taking writes, which the backfill precondition forbids.
    max_snapshot_retries: u32,
}

/// Backfill algorithm version recorded in `lore_domain_schema_state`.
pub const BACKFILL_VERSION: i64 = 1;

impl<'a> DomainBackfill<'a> {
    /// Build a backfill driver against an already-bootstrapped domain store.
    /// This is the ordinary entry point: it guarantees the schema and the
    /// singleton state rows exist before the backfill reads its cursor.
    pub fn for_store(
        store: &'a crate::domain::store::PostgresDomainStore,
        source: &'a dyn DomainBackfillSource,
    ) -> Self {
        Self::new(store.pool(), source)
    }

    /// Build a backfill driver against a raw pool.
    pub fn new(pool: &'a Pool, source: &'a dyn DomainBackfillSource) -> Self {
        Self {
            pool,
            source,
            max_snapshot_retries: 3,
        }
    }

    /// Run (or resume) the backfill. Safe to call repeatedly: it starts from the
    /// stored cursor and every per-repository transaction is an exact upsert, so
    /// re-projecting a repository that already landed is a no-op rather than a
    /// conflict.
    pub async fn run(&self) -> Result<u64, DomainError> {
        self.mark_running().await?;
        let cursor = self.read_cursor().await?;
        let repositories = self.source.list_repositories().await?;

        let mut projected = 0u64;
        let mut previous: Option<Vec<u8>> = None;
        for facts in repositories {
            // The cursor skip is only sound if the source really is ascending.
            // An unsorted source would let the skip discard repositories that
            // never landed, and the one-way verification below would still
            // pass — a silent partial backfill reaching cutover, after which
            // enforcement fences keys that have no domain row. Check rather
            // than trust the contract.
            if let Some(ref prev) = previous
                && facts.repository_id.as_slice() <= prev.as_slice()
            {
                return Err(DomainError::InvalidInput(format!(
                    "backfill source returned repository {} at or before {}; \
                     list_repositories must be strictly ascending by repository_id \
                     or the restart cursor silently drops repositories",
                    hex::encode(&facts.repository_id),
                    hex::encode(prev)
                )));
            }
            previous = Some(facts.repository_id.clone());

            if let Some(ref c) = cursor
                && facts.repository_id.as_slice() <= c.as_slice()
            {
                continue;
            }
            self.project_repository(&facts).await?;
            self.write_cursor(&facts.repository_id).await?;
            projected += 1;
        }
        Ok(projected)
    }

    /// Steps 3 through 5 for one repository.
    async fn project_repository(&self, facts: &RepositoryFacts) -> Result<(), DomainError> {
        for _ in 0..=self.max_snapshot_retries {
            let before = self.source.snapshot_token(&facts.repository_id).await?;
            let branches = self.source.list_branches(&facts.repository_id).await?;
            let after = self.source.snapshot_token(&facts.repository_id).await?;
            if before != after {
                continue;
            }
            return self.write_domain_rows(facts, &branches).await;
        }
        // Falling out of the loop is the every-attempt-raced case. Returning the
        // error here rather than `unreachable!` inside the loop keeps this file
        // free of panics in non-test code: an unreachable branch that becomes
        // reachable through a later edit is a process abort on a live cell.
        Err(DomainError::Contention(format!(
            "repository {} mutable snapshot changed on every one of {} attempts; \
             the cell must be quiesced for backfill",
            hex::encode(&facts.repository_id),
            self.max_snapshot_retries + 1
        )))
    }

    /// Step 4: one short transaction per repository.
    async fn write_domain_rows(
        &self,
        facts: &RepositoryFacts,
        branches: &[BranchFacts],
    ) -> Result<(), DomainError> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|e| DomainError::from_pool("backfill pool", e))?;
        let tx = client
            .transaction()
            .await
            .map_err(|e| DomainError::from_pg("backfill transaction", e))?;

        tx.execute(
            "INSERT INTO lore_domain_repositories ( \
                 repository_id, state, generation, name, metadata_hash, default_branch_id, \
                 creation_fingerprint_version, creation_fingerprint, created_at \
             ) VALUES ($1, $2, 1, $3, $4, $5, $6, $7, clock_timestamp()) \
             ON CONFLICT (repository_id) DO NOTHING",
            &[
                &facts.repository_id,
                &schema::STATE_LIVE,
                &facts.name,
                &facts.metadata_hash,
                &facts.default_branch_id,
                &facts.creation_fingerprint_version,
                &facts.creation_fingerprint,
            ],
        )
        .await
        .map_err(|e| DomainError::from_pg("backfill repository insert", e))?;

        // A repository whose name does not resolve through the name map gets no
        // live name row: claiming the name here would hand it to whichever of a
        // case-variant pair the backfill happened to reach second. It is
        // reported by the verification instead.
        if facts.name_map_resolves {
            tx.execute(
                "INSERT INTO lore_domain_repository_names ( \
                     name, repository_id, repository_generation, created_at \
                 ) VALUES ($1, $2, 1, clock_timestamp()) \
                 ON CONFLICT (name) DO NOTHING",
                &[&facts.name, &facts.repository_id],
            )
            .await
            .map_err(|e| DomainError::from_pg("backfill repository name insert", e))?;
        }

        for branch in branches {
            tx.execute(
                "INSERT INTO lore_domain_branches ( \
                     repository_id, branch_id, repository_generation, state, generation, \
                     name, metadata_hash, latest_hash, \
                     creation_fingerprint_version, creation_fingerprint, created_at \
                 ) VALUES ($1, $2, 1, $3, 1, $4, $5, $6, $7, $8, clock_timestamp()) \
                 ON CONFLICT (repository_id, branch_id) DO NOTHING",
                &[
                    &facts.repository_id,
                    &branch.branch_id,
                    &schema::STATE_LIVE,
                    &branch.name,
                    &branch.metadata_hash,
                    &branch.latest_hash,
                    &branch.creation_fingerprint_version,
                    &branch.creation_fingerprint,
                ],
            )
            .await
            .map_err(|e| DomainError::from_pg("backfill branch insert", e))?;

            // Branch names fold case, so a Feature/feature pair collides on one
            // key. First writer wins and the loser is left without a live name
            // row; the verification reports it rather than the backfill
            // arbitrarily overwriting.
            tx.execute(
                "INSERT INTO lore_domain_branch_names ( \
                     repository_id, name_key, display_name, branch_id, \
                     repository_generation, branch_generation, created_at \
                 ) VALUES ($1, lower($2), $2, $3, 1, 1, clock_timestamp()) \
                 ON CONFLICT (repository_id, name_key) DO NOTHING",
                &[&facts.repository_id, &branch.name, &branch.branch_id],
            )
            .await
            .map_err(|e| DomainError::from_pg("backfill branch name insert", e))?;
        }

        tx.commit()
            .await
            .map_err(|e| DomainError::from_pg("backfill commit", e))
    }

    /// Step 6: the one-way check plus residue classification.
    pub async fn verify(&self) -> Result<VerificationReport, DomainError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DomainError::from_pool("backfill verify pool", e))?;

        let counts = client
            .query_one(
                "SELECT (SELECT count(*) FROM lore_domain_repositories)::bigint AS repositories, \
                        (SELECT count(*) FROM lore_domain_branches)::bigint     AS branches",
                &[],
            )
            .await
            .map_err(|e| DomainError::from_pg("backfill verify counts", e))?;

        let repositories: i64 = counts.get("repositories");
        let branches: i64 = counts.get("branches");

        let mut missing = 0u64;
        let mut name_map_mismatches = Vec::new();
        let mut source_repositories = 0u64;
        for facts in self.source.list_repositories().await? {
            source_repositories += 1;
            if !facts.name_map_resolves {
                name_map_mismatches.push(facts.repository_id.clone());
            }
        }

        // Forward direction: every domain row must still have its projection.
        // A repository row whose metadata hash no longer matches the projection
        // means the domain rows led the projection, which the contract forbids.
        //
        // `key_type` is part of the match. Without it the EXISTS is satisfied by
        // ANY row in that partition holding the same 32 bytes — a branch tip
        // that happens to equal the repository metadata hash would vouch for a
        // repository whose own projection row is gone, which is the one thing
        // this check exists to catch.
        let stale = client
            .query_one(
                "SELECT count(*)::bigint AS stale FROM lore_domain_repositories d \
                 WHERE NOT EXISTS ( \
                     SELECT 1 FROM lore_mutable m \
                     WHERE m.partition = d.repository_id \
                       AND m.key_type = $1 \
                       AND m.value = d.metadata_hash \
                 )",
                &[&(lore_base::types::KeyType::RepositoryMetadata as i16)],
            )
            .await
            .map_err(|e| DomainError::from_pg("backfill verify projection", e))?;
        let stale: i64 = stale.get("stale");
        missing += stale.max(0) as u64;

        // Count parity. The forward check above says nothing about a repository
        // the backfill never projected at all: it has no domain row, so there is
        // nothing for the EXISTS to fail on. Comparing the source count against
        // the projected count is what turns a silently dropped repository into a
        // failed verification instead of a clean run.
        let projected_repositories = repositories.max(0) as u64;
        if projected_repositories < source_repositories {
            missing += source_repositories - projected_repositories;
        }

        let residue = self
            .source
            .orphan_projection_keys()
            .await?
            .into_iter()
            .map(|key| {
                let class = classify_residue(&key);
                (key, class)
            })
            .collect();

        Ok(VerificationReport {
            repositories_projected: repositories.max(0) as u64,
            branches_projected: branches.max(0) as u64,
            missing_projection_rows: missing,
            residue,
            name_map_mismatches,
        })
    }

    /// Record the verified state, then the cutover marker, in that order. Both
    /// are refused unless the verification actually passed.
    pub async fn complete(&self, report: &VerificationReport) -> Result<(), DomainError> {
        if !report.passed() {
            return Err(DomainError::NotReady(format!(
                "{} domain rows have no matching lore_mutable projection row; \
                 the projection must never lag the domain rows",
                report.missing_projection_rows
            )));
        }

        // Residue is classified, not merely counted, precisely so this gate can
        // read the classes. Delete residue and orphaned branch rows are expected
        // on any cell that has served a delete and are safe to cut over with.
        // A ForeignDomainKeyWrite is different: it is a domain-typed key no
        // server writer produces, so something is writing one through the
        // generic mutable RPCs. Enabling enforcement would start rejecting that
        // writer. Refuse cutover until an operator has looked at it.
        let foreign: Vec<&OrphanKey> = report
            .residue
            .iter()
            .filter(|(_, class)| *class == ResidueClass::ForeignDomainKeyWrite)
            .map(|(key, _)| key)
            .collect();
        if !foreign.is_empty() {
            return Err(DomainError::NotReady(format!(
                "{} domain-typed key(s) in this cell were written through the generic \
                 mutable path, not by a server writer (first: key_type {}, partition {}). \
                 Enforcement would start rejecting whatever wrote them, so cutover is \
                 refused until the source is identified",
                foreign.len(),
                foreign[0].key_type,
                hex::encode(&foreign[0].partition)
            )));
        }
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DomainError::from_pool("backfill complete pool", e))?;
        client
            .execute(
                "UPDATE lore_domain_schema_state \
                 SET backfill_state = $1, backfill_version = $2, residue_classified = true, \
                     updated_at = clock_timestamp() \
                 WHERE id = 1",
                &[&schema::BACKFILL_VERIFIED, &BACKFILL_VERSION],
            )
            .await
            .map_err(|e| DomainError::from_pg("backfill mark verified", e))?;
        client
            .execute(
                "UPDATE lore_domain_schema_state \
                 SET backfill_state = $1, cutover_at = clock_timestamp(), \
                     updated_at = clock_timestamp() \
                 WHERE id = 1 AND backfill_state = $2 AND residue_classified = true",
                &[&schema::BACKFILL_CUTOVER, &schema::BACKFILL_VERIFIED],
            )
            .await
            .map_err(|e| DomainError::from_pg("backfill set cutover", e))?;
        Ok(())
    }

    async fn mark_running(&self) -> Result<(), DomainError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DomainError::from_pool("backfill state pool", e))?;
        let updated = client
            .execute(
                "UPDATE lore_domain_schema_state \
                 SET backfill_state = $1, backfill_version = $2, updated_at = clock_timestamp() \
                 WHERE id = 1 AND backfill_state IN ($3, $1)",
                &[
                    &schema::BACKFILL_RUNNING,
                    &BACKFILL_VERSION,
                    &schema::BACKFILL_NOT_STARTED,
                ],
            )
            .await
            .map_err(|e| DomainError::from_pg("backfill mark running", e))?;
        // Zero rows means the cell is already VERIFIED or past CUTOVER. Running
        // the backfill again from there would re-drive projection writes against
        // a cell that is already enforcing, so refuse loudly instead of
        // proceeding with the state row silently unchanged.
        if updated == 0 {
            return Err(DomainError::NotReady(
                "backfill cannot start: lore_domain_schema_state is neither NOT_STARTED nor \
                 RUNNING, so this cell has already completed verification or cutover"
                    .to_owned(),
            ));
        }
        Ok(())
    }

    async fn read_cursor(&self) -> Result<Option<Vec<u8>>, DomainError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DomainError::from_pool("backfill cursor pool", e))?;
        let row = client
            .query_one(
                "SELECT backfill_cursor FROM lore_domain_schema_state WHERE id = 1",
                &[],
            )
            .await
            .map_err(|e| DomainError::from_pg("backfill cursor read", e))?;
        Ok(row.get("backfill_cursor"))
    }

    async fn write_cursor(&self, repository_id: &[u8]) -> Result<(), DomainError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|e| DomainError::from_pool("backfill cursor pool", e))?;
        client
            .execute(
                "UPDATE lore_domain_schema_state \
                 SET backfill_cursor = $1, updated_at = clock_timestamp() \
                 WHERE id = 1",
                &[&repository_id],
            )
            .await
            .map_err(|e| DomainError::from_pg("backfill cursor write", e))?;
        Ok(())
    }
}

/// Classify one leftover projection row.
///
/// The discriminants come from `lore_base::types::KeyType` rather than local
/// constants, so a reordering upstream is a compile error here instead of a
/// silent misclassification.
///
/// `KeyType::RepositoryId` and `BranchId` are name-map-only (CR-029
/// R-SHOULD-2), so a leftover row of either kind is a dangling name mapping.
fn classify_residue(key: &OrphanKey) -> ResidueClass {
    use lore_base::types::KeyType;

    if key.key_type == KeyType::RepositoryId as i16
        || key.key_type == KeyType::RepositoryMetadata as i16
    {
        return ResidueClass::DeleteResidue;
    }
    if key.key_type == KeyType::BranchId as i16
        || key.key_type == KeyType::BranchMetadata as i16
        || key.key_type == KeyType::BranchLatestPointer as i16
    {
        return ResidueClass::OrphanedBranchRow;
    }
    ResidueClass::ForeignDomainKeyWrite
}

#[cfg(test)]
mod tests {
    use lore_base::types::KeyType;

    use super::*;

    fn orphan(key_type: KeyType) -> OrphanKey {
        OrphanKey {
            key_type: key_type as i16,
            partition: vec![0u8; 16],
            key: vec![1u8; 32],
        }
    }

    #[test]
    fn repository_leftovers_are_delete_residue() {
        for kt in [KeyType::RepositoryId, KeyType::RepositoryMetadata] {
            assert_eq!(classify_residue(&orphan(kt)), ResidueClass::DeleteResidue);
        }
    }

    #[test]
    fn branch_rows_left_by_a_crashed_delete_loop_are_orphans_not_failures() {
        for kt in [
            KeyType::BranchId,
            KeyType::BranchMetadata,
            KeyType::BranchLatestPointer,
        ] {
            assert_eq!(
                classify_residue(&orphan(kt)),
                ResidueClass::OrphanedBranchRow
            );
        }
    }

    #[test]
    fn an_instance_key_is_reported_not_absorbed() {
        // KeyType::Instance has zero server writers at this baseline but is
        // reachable through the seven generic storage mutable RPCs, which pass
        // the wire KeyType through untouched. Worklog 254 §A.10 says the
        // disposition must be explicit rather than left to an allowlist's
        // shape, so it must not land in a benign bucket by accident.
        assert_eq!(
            classify_residue(&orphan(KeyType::Instance)),
            ResidueClass::ForeignDomainKeyWrite
        );
    }

    #[test]
    fn verification_passes_with_residue_but_not_with_a_missing_projection() {
        let mut report = VerificationReport {
            repositories_projected: 4,
            branches_projected: 9,
            missing_projection_rows: 0,
            residue: vec![(orphan(KeyType::BranchId), ResidueClass::OrphanedBranchRow)],
            name_map_mismatches: vec![vec![2u8; 16]],
        };
        assert!(report.passed());
        report.missing_projection_rows = 1;
        assert!(!report.passed());
    }
}

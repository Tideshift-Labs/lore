// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The first real [`DomainBackfillSource`] (CR-029; WP-120).
//!
//! `lore-postgres` deliberately does not implement this trait: reconstructing a
//! repository's facts means deserializing metadata blobs out of the immutable
//! store and reproducing `lore-revision`'s key derivations, neither of which
//! belongs in the Postgres crate. Until now the only implementations were
//! `EmptyBackfillSource` fixtures, which report a cell with nothing in it.
//!
//! **An empty source on a non-empty cell is the silent failure this module
//! exists to prevent.** `DomainBackfill::verify` compares the source's own
//! repository count against the projected count, so an empty source over a cell
//! that holds repositories passes verification, reaches cutover, and enables
//! enforcement over a domain table with no rows — after which every governed
//! mutation on a real repository is refused for a repository the coordinator
//! cannot find.
//!
//! # Where each fact comes from
//!
//! | Fact | Source |
//! |---|---|
//! | repository identities | [`repository::list_local`] (the global `KeyType::RepositoryId` name-map rows) UNIONED with every partition holding a `KeyType::RepositoryMetadata` row |
//! | name, default branch | the repository metadata blob, through [`repository::metadata`] |
//! | `name_map_resolves` | [`repository::id_from_name`] round trip (R-BLOCK-3's case-variant overwrite) |
//! | branch identities | [`branch::list`] — the repository's `KeyType::BranchId` rows |
//! | branch name, metadata, tip | the branch metadata blob and its `branch-head` pointer |
//! | snapshot token | a digest of every `lore_mutable` row in that repository's partition |
//! | orphan projection keys | every domain-typed `lore_mutable` row this walk did not account for |
//!
//! The last two need the cell database directly, because `lore_mutable` keys are
//! salted hashes: nothing can recover a name from a key, so the residue set is
//! computed as "every domain-typed row" minus "every key this walk derived".
//!
//! # Why this needs the immutable store
//!
//! Names live in metadata blobs, not in the mutable rows. On a Postgres-mode
//! cell those blobs are S3 objects, so a cutover on a cell that holds any
//! repository needs a working object store. A cell that holds none does not, but
//! the difference is not knowable before the walk, so the caller opens both.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;
use futures::StreamExt;
use lore_base::types::Context;
use lore_base::types::KeyType;
use lore_base::types::RepositoryId;
use lore_postgres::domain::backfill::BranchFacts;
use lore_postgres::domain::backfill::DomainBackfillSource;
use lore_postgres::domain::backfill::OrphanKey;
use lore_postgres::domain::backfill::RepositoryFacts;
use lore_postgres::domain::bypass;
use lore_postgres::domain::errors::DomainError;
use lore_postgres::pool::Pool;
use lore_revision::branch;
use lore_revision::repository;
use lore_revision::repository::RepositoryContext;
use lore_storage::ImmutableStore;
use lore_storage::MutableStore;
use lore_storage::hash;

use super::operator::backfill_branch_fingerprint;
use super::operator::backfill_repository_fingerprint;
use crate::domain::operator::BACKFILL_FINGERPRINT_VERSION;

/// The `KeyType` discriminants the residue scan covers.
///
/// Derived from `bypass::is_domain_owned`, the one authority for what CR-029
/// owns, rather than from a second list here. Enumerated by round-tripping every
/// `u8` through `KeyType::try_from`, so a variant added upstream is picked up
/// without anyone remembering to add it — the alternative, a hand-written array,
/// is exactly how a residue set silently stops covering a new key type.
///
/// The set is the five lifecycle types **plus `Instance`**, and `Instance` is
/// the reason this is not the shorter list it looks like it should be. It has no
/// server writer, but a client can write an `Instance`-typed key through any of
/// the seven generic mutable RPCs, and it is the only member of this set that
/// `classify_residue` maps to `ResidueClass::ForeignDomainKeyWrite` — the one
/// class `DomainBackfill::complete` refuses cutover on. Scanning only the five
/// made that gate unreachable: every row the scan could return classified as
/// benign residue, so the refusal existed and could never fire. Caught in
/// review.
fn domain_key_types() -> Vec<i16> {
    (0u8..=u8::MAX)
        .filter_map(|discriminant| KeyType::try_from(discriminant).ok())
        .filter(|key_type| bypass::is_domain_owned(*key_type))
        .map(|key_type| key_type as i16)
        .collect()
}

/// One `lore_mutable` row's identity: the primary key, nothing else.
type KeyIdentity = (Vec<u8>, i16, Vec<u8>);

/// Why one repository's facts could not be read.
///
/// `missing` is the whole reason this type exists rather than a bare
/// [`DomainError`]. A repository found only by its metadata row is skipped as
/// delete residue when its blob is genuinely gone, and that skip must not
/// swallow a transient object-store failure — a `SlowDown` treated as "deleted"
/// silently drops a live repository from the projection, which is the exact
/// silent-partial-backfill this module exists to prevent.
struct FactsFailure {
    /// The read failed because nothing is there, not because the read failed.
    missing: bool,
    error: DomainError,
}

/// Whether a repository read failed because the thing is absent.
///
/// The not-found family only. Everything else — transport, `SlowDown`,
/// authorization, an unreadable payload — says the read failed, not that the
/// repository is gone, and must never be read as an absence.
fn is_missing(error: &repository::RepositoryError) -> bool {
    error.is_repository_not_found()
        || error.is_address_not_found()
        || error.is_payload_not_found()
        || error.is_not_found()
}

/// How a repository identity was found, which decides what an unreadable
/// repository means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Discovery {
    /// The cell's global name map resolves to it. A live repository, and a
    /// failure to read its metadata is a hard error: projecting the cell without
    /// it would enforce over a repository that has no domain row.
    NameMap,
    /// It has a `RepositoryMetadata` row in its own partition but no name-map
    /// row pointing at it. Either a repository whose name row was lost, which
    /// must still be projected, or delete residue whose metadata blob is already
    /// gone, which must not stop the cutover. Reading the metadata is what tells
    /// the two apart.
    MetadataRow,
}

/// Reads one live Postgres-mode cell's real repositories and branches.
pub struct CellBackfillSource {
    /// The cell database, for the facts the stores cannot answer: a partition's
    /// row digest, the full domain-typed row set, and the partitions that hold a
    /// repository metadata row.
    pool: Pool,
    /// A null-identity context over the cell's two stores. Every per-repository
    /// context is derived from it with `to_server_context`, so all of them share
    /// one pair of store handles.
    base: Arc<RepositoryContext>,
    /// Facts already read, keyed by repository identity.
    ///
    /// `DomainBackfill` calls `list_repositories` twice (once in `run`, once in
    /// `verify`) and this module's own residue walk calls it a third time. Each
    /// call reads a metadata blob out of the object store and does a name
    /// lookup per repository, so without this the cutover pays three object
    /// round trips per repository to answer the same question.
    facts: parking_lot::Mutex<BTreeMap<[u8; 16], RepositoryFacts>>,
}

impl CellBackfillSource {
    /// Bind the source to one cell's pool and stores.
    ///
    /// The pool must address the same database as the domain coordinator; the
    /// caller proves that positively before constructing this (the same
    /// `assert_domain_store_colocated` check server startup runs), because a
    /// residue set computed against a different database would report every real
    /// row as an orphan.
    pub fn new(
        pool: Pool,
        immutable: Arc<dyn ImmutableStore>,
        mutable: Arc<dyn MutableStore>,
    ) -> Self {
        Self {
            pool,
            base: Arc::new(RepositoryContext::new_null_context(immutable, mutable)),
            facts: parking_lot::Mutex::new(BTreeMap::new()),
        }
    }

    /// A read-only server context scoped to one repository.
    fn repository_context(&self, repository_id: RepositoryId) -> Arc<RepositoryContext> {
        Arc::new(self.base.to_server_context(repository_id))
    }

    /// Every repository identity this cell holds, ascending and deduplicated,
    /// with how each was found.
    ///
    /// **Two sources, unioned, and the second one is not redundant.** The name
    /// map answers "what can be resolved by name", which is what a client sees.
    /// It is not the same question as "what does this cell hold": a repository
    /// whose name-map row was lost — a create that crashed between the metadata
    /// write and the name write, a delete that removed the name row and stopped
    /// — still has its metadata row, still has branches, and would be invisible
    /// to a name-map-only walk. `DomainBackfill::verify` could not catch that,
    /// because its parity check compares the source's own count against the
    /// projected count and a walk that under-reports does so in both. Enforcement
    /// would then come on over a repository with no domain row.
    ///
    /// Ascending because `DomainBackfill::run` skips everything at or before its
    /// restart cursor and checks the order rather than trusting it. Deduplicated
    /// because two names can map to one identity, and the same repository
    /// projected twice would be counted twice against that same parity check.
    async fn repository_ids(&self) -> Result<Vec<(RepositoryId, Discovery)>, DomainError> {
        let stream = repository::list_local(self.base.clone())
            .await
            .map_err(|error| {
                DomainError::Internal(format!("list the cell's repository name map: {error}"))
            })?;
        let mut found: BTreeMap<[u8; 16], Discovery> = Box::pin(stream)
            .collect::<Vec<Context>>()
            .await
            .into_iter()
            .map(RepositoryId::from)
            // A zero identity is the null repository, not a repository. It is
            // the partition the name map itself lives in, so projecting it
            // would invent a domain row for the index.
            .filter(|id| !id.is_zero())
            .map(|id| (*id.data(), Discovery::NameMap))
            .collect();

        for partition in self.metadata_row_partitions().await? {
            found.entry(partition).or_insert(Discovery::MetadataRow);
        }

        Ok(found
            .into_iter()
            .map(|(bytes, discovery)| {
                let mut id = RepositoryId::default();
                *id.data_mut() = bytes;
                (id, discovery)
            })
            .collect())
    }

    /// Every partition holding a repository metadata row, other than the global
    /// one.
    ///
    /// One row per live repository by construction: the key is
    /// `hash_function_arg(salt, repository::METADATA, hex(repository_id))` in
    /// that repository's own partition, so the partition *is* the identity and
    /// no derivation is needed to recover it.
    async fn metadata_row_partitions(&self) -> Result<Vec<[u8; 16]>, DomainError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|error| DomainError::from_pool("backfill metadata scan pool", error))?;
        let rows = client
            .query(
                "SELECT DISTINCT partition FROM lore_mutable \
                  WHERE key_type = $1 AND octet_length(partition) = 16 \
                    AND partition <> $2",
                &[
                    &(KeyType::RepositoryMetadata as i16),
                    &RepositoryId::default().data().as_slice(),
                ],
            )
            .await
            .map_err(|error| DomainError::from_pg("backfill metadata partition scan", error))?;
        rows.into_iter()
            .map(|row| {
                let partition: Vec<u8> = row.get("partition");
                partition.as_slice().try_into().map_err(|_| {
                    DomainError::Internal(format!(
                        "a repository metadata row sits in a {}-byte partition; \
                         a repository identity is 16 bytes",
                        partition.len()
                    ))
                })
            })
            .collect()
    }

    /// One repository's facts, or a failure that says whether the repository was
    /// merely absent.
    async fn repository_facts(
        &self,
        repository_id: RepositoryId,
    ) -> Result<RepositoryFacts, FactsFailure> {
        // The cache is read and written without holding the lock across an
        // await, so it cannot deadlock the walk. Entries are immutable facts
        // about one pass; the cutover quiesces the cell, and a repository whose
        // metadata moved mid-pass is caught by the snapshot token, not here.
        if let Some(cached) = self.facts.lock().get(repository_id.data()) {
            return Ok(cached.clone());
        }
        let context = self.repository_context(repository_id);
        let hex = hex::encode(repository_id.data());
        let metadata_hash = repository::metadata_hash(context.clone())
            .await
            .map_err(|error| FactsFailure {
                missing: is_missing(&error),
                error: DomainError::Internal(format!(
                    "read repository {hex}'s metadata pointer: {error}"
                )),
            })?;
        let metadata = repository::metadata(context.clone(), metadata_hash)
            .await
            .map_err(|error| FactsFailure {
                missing: is_missing(&error),
                error: DomainError::Internal(format!(
                    "deserialize repository {hex}'s metadata blob {}: {error}",
                    hex::encode(metadata_hash.data())
                )),
            })?;
        // A failed lookup and a lookup resolving elsewhere are the same answer
        // here: this name does not resolve to this repository. The backfill
        // records that rather than claiming the name, and the verification
        // reports it to the operator.
        let name_map_resolves = repository::id_from_name(context, metadata.name.as_str())
            .await
            .is_ok_and(|resolved| resolved.data() == repository_id.data());
        let default_branch_id = metadata.default_branch.data().to_vec();
        let facts = RepositoryFacts {
            creation_fingerprint: backfill_repository_fingerprint(
                repository_id.data(),
                metadata.name.as_str(),
                metadata_hash.data(),
                &default_branch_id,
            ),
            creation_fingerprint_version: BACKFILL_FINGERPRINT_VERSION,
            repository_id: repository_id.data().to_vec(),
            name: metadata.name,
            name_map_resolves,
            metadata_hash: metadata_hash.data().to_vec(),
            default_branch_id,
        };
        self.facts
            .lock()
            .insert(*repository_id.data(), facts.clone());
        Ok(facts)
    }

    /// Every `lore_mutable` key this walk accounts for, across every repository.
    ///
    /// Reproduced from each module's own derivation rule, never from the other's:
    /// `repository::mutable_name_key` hashes the exact name while
    /// `branch::mutable_name_key` hashes its lowercase form, and the two helpers
    /// have identical signatures.
    async fn accounted_keys(&self) -> Result<BTreeSet<KeyIdentity>, DomainError> {
        let salt = self.base.salt();
        let global = RepositoryId::default().data().to_vec();
        let mut accounted = BTreeSet::new();
        // Driven from `list_repositories` rather than from `repository_ids`, so
        // the accounted set covers exactly the repositories the backfill
        // projected. Deriving it from a different set would report a projected
        // repository's own keys as residue, or the reverse.
        for facts in self.list_repositories().await? {
            let repository_hex = hex::encode(&facts.repository_id);
            let partition = facts.repository_id.clone();
            accounted.insert((
                partition.clone(),
                KeyType::RepositoryMetadata as i16,
                hash::hash_function_arg(salt, repository::METADATA, &repository_hex)
                    .as_ref()
                    .to_vec(),
            ));
            accounted.insert((
                global.clone(),
                KeyType::RepositoryId as i16,
                hash::hash_function_arg(salt, repository::ID, facts.name.as_str())
                    .as_ref()
                    .to_vec(),
            ));
            for branch_facts in self.list_branches(&facts.repository_id).await? {
                let branch_hex = hex::encode(&branch_facts.branch_id);
                accounted.insert((
                    partition.clone(),
                    KeyType::BranchMetadata as i16,
                    hash::hash_function_args(salt, branch::METADATA, &repository_hex, &branch_hex)
                        .as_ref()
                        .to_vec(),
                ));
                accounted.insert((
                    partition.clone(),
                    KeyType::BranchLatestPointer as i16,
                    hash::hash_function_args(salt, branch::LATEST, &repository_hex, &branch_hex)
                        .as_ref()
                        .to_vec(),
                ));
                accounted.insert((
                    partition.clone(),
                    KeyType::BranchId as i16,
                    hash::hash_function_arg(
                        salt,
                        branch::ID,
                        branch_facts.name.to_lowercase().as_str(),
                    )
                    .as_ref()
                    .to_vec(),
                ));
            }
        }
        Ok(accounted)
    }
}

#[async_trait]
impl DomainBackfillSource for CellBackfillSource {
    async fn list_repositories(&self) -> Result<Vec<RepositoryFacts>, DomainError> {
        let mut facts = Vec::new();
        for (repository_id, discovery) in self.repository_ids().await? {
            match (self.repository_facts(repository_id).await, discovery) {
                (Ok(one), _) => facts.push(one),
                // A name-map row points at it, so it is a repository this cell
                // serves. Failing to read it stops the cutover rather than
                // projecting the cell without it.
                (Err(failure), Discovery::NameMap) => return Err(failure.error),
                // Found only by its metadata row, and the metadata is genuinely
                // ABSENT: a crashed delete's leftover pointer. Reported and
                // skipped; the leftover rows are then classified as residue by
                // the verification, which is what residue is for.
                (Err(failure), Discovery::MetadataRow) if failure.missing => {
                    crate::domain::operator::step(&format!(
                        "WARNING: partition {} holds a repository metadata row that no name \
                         resolves to and whose metadata is absent ({}); treating it as delete \
                         residue and not projecting it",
                        hex::encode(repository_id.data()),
                        failure.error
                    ));
                }
                // Found only by its metadata row, and the read FAILED rather
                // than answering "absent". A transient object-store failure
                // skipped here would drop a live repository from the projection
                // and the one-way verification could not see the gap, because
                // it recounts through this same source. Refuse instead.
                (Err(failure), Discovery::MetadataRow) => return Err(failure.error),
            }
        }
        Ok(facts)
    }

    /// Every live branch of one repository.
    ///
    /// A branch whose metadata cannot be read is an **error**, not a skip. A
    /// skipped branch is projected nowhere, has no domain row after cutover, and
    /// the one-way verification cannot see its absence — the repository's own
    /// row is present, so nothing fails. Refusing here stops the cutover with
    /// the branch named instead.
    async fn list_branches(&self, repository_id: &[u8]) -> Result<Vec<BranchFacts>, DomainError> {
        let repository_id = repository_identity(repository_id)?;
        let context = self.repository_context(repository_id);
        let stream = branch::list(context.clone()).await.map_err(|error| {
            DomainError::Internal(format!(
                "list repository {}'s branches: {error}",
                hex::encode(repository_id.data())
            ))
        })?;
        let mut branch_ids: Vec<Context> = Box::pin(stream).collect().await;
        branch_ids.sort_by(|left, right| left.data().cmp(right.data()));
        branch_ids.dedup_by(|left, right| left.data() == right.data());

        let mut facts = Vec::with_capacity(branch_ids.len());
        for branch_id in branch_ids {
            if branch_id.is_zero() {
                continue;
            }
            let branch_hex = hex::encode(branch_id.data());
            let metadata_hash = branch::metadata_hash(context.clone(), branch_id)
                .await
                .map_err(|error| {
                    DomainError::Internal(format!(
                        "read branch {branch_hex}'s metadata pointer: {error}"
                    ))
                })?;
            let metadata = branch::load_metadata(context.clone(), metadata_hash)
                .await
                .map_err(|error| {
                    DomainError::Internal(format!(
                        "deserialize branch {branch_hex}'s metadata blob: {error}"
                    ))
                })?;
            let name = branch::name(&metadata)
                .map_err(|error| {
                    DomainError::Internal(format!("read branch {branch_hex}'s name: {error}"))
                })?
                .to_owned();
            // A branch with no revision pushed yet legitimately has a zero tip;
            // `load_latest` answers the zero hash for it rather than failing,
            // and the domain row's 32-byte CHECK accepts those bytes.
            let latest_hash = branch::load_latest(context.clone(), branch_id)
                .await
                .map_err(|error| {
                    DomainError::Internal(format!("read branch {branch_hex}'s tip: {error}"))
                })?;
            facts.push(BranchFacts {
                creation_fingerprint: backfill_branch_fingerprint(
                    repository_id.data(),
                    branch_id.data(),
                    name.as_str(),
                    metadata_hash.data(),
                ),
                creation_fingerprint_version: BACKFILL_FINGERPRINT_VERSION,
                branch_id: branch_id.data().to_vec(),
                name,
                metadata_hash: metadata_hash.data().to_vec(),
                latest_hash: latest_hash.data().to_vec(),
            });
        }
        Ok(facts)
    }

    /// A digest over every `lore_mutable` row in this repository's partition.
    ///
    /// The trait asks for "any value that changes when the repository's mutable
    /// keys change", and this is that value read from the rows themselves rather
    /// than reconstructed from the walk above — so a key the walk does not know
    /// about still moves the token, which is exactly the concurrent write the
    /// backfill retries on.
    async fn snapshot_token(&self, repository_id: &[u8]) -> Result<Vec<u8>, DomainError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|error| DomainError::from_pool("backfill snapshot pool", error))?;
        let row = client
            .query_one(
                "SELECT coalesce( \
                     md5(string_agg( \
                         key_type::text || ':' || encode(key, 'hex') \
                                       || '=' || encode(value, 'hex'), \
                         ',' ORDER BY key_type, key)), \
                     '') AS token \
                   FROM lore_mutable WHERE partition = $1",
                &[&repository_id],
            )
            .await
            .map_err(|error| DomainError::from_pg("backfill snapshot token", error))?;
        let token: String = row.get("token");
        Ok(token.into_bytes())
    }

    /// Every domain-typed `lore_mutable` row the walk above did not account for.
    async fn orphan_projection_keys(&self) -> Result<Vec<OrphanKey>, DomainError> {
        let accounted = self.accounted_keys().await?;
        let client = self
            .pool
            .get()
            .await
            .map_err(|error| DomainError::from_pool("backfill residue pool", error))?;
        let rows = client
            .query(
                "SELECT partition, key_type, key FROM lore_mutable \
                  WHERE key_type = ANY($1) \
                  ORDER BY key_type, partition, key",
                &[&domain_key_types().as_slice()],
            )
            .await
            .map_err(|error| DomainError::from_pg("backfill residue scan", error))?;
        Ok(rows
            .into_iter()
            .map(|row| OrphanKey {
                key_type: row.get("key_type"),
                partition: row.get("partition"),
                key: row.get("key"),
            })
            .filter(|orphan| {
                !accounted.contains(&(
                    orphan.partition.clone(),
                    orphan.key_type,
                    orphan.key.clone(),
                ))
            })
            .collect())
    }
}

/// Refuse an identity that is not the 16 bytes every repository identity is.
///
/// The trait hands `list_branches` a `&[u8]` that came from this same source's
/// own `list_repositories`, so a wrong width is a defect rather than input — but
/// silently truncating or padding it would scope the branch walk to the wrong
/// repository, which the backfill has no way to notice.
fn repository_identity(repository_id: &[u8]) -> Result<RepositoryId, DomainError> {
    let bytes: [u8; 16] = repository_id.try_into().map_err(|_| {
        DomainError::InvalidInput(format!(
            "repository identity must be 16 bytes, got {}",
            repository_id.len()
        ))
    })?;
    let mut id = RepositoryId::default();
    *id.data_mut() = bytes;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The scan must cover exactly what `bypass::is_domain_owned` fences.
    ///
    /// A type in the scan that is not fenced would make a legitimate row look
    /// like residue; a fenced type missing from the scan hides a write the
    /// cutover gate exists to refuse on.
    #[test]
    fn the_residue_scan_covers_exactly_what_the_bypass_guard_fences() {
        let types = domain_key_types();
        for key_type in (0u8..=u8::MAX).filter_map(|value| KeyType::try_from(value).ok()) {
            assert_eq!(
                types.contains(&(key_type as i16)),
                bypass::is_domain_owned(key_type),
                "{key_type:?} must be scanned exactly when the bypass guard fences it"
            );
        }
    }

    /// `Instance` is the only scanned type `classify_residue` maps to
    /// `ForeignDomainKeyWrite`, and that class is the only one
    /// `DomainBackfill::complete` refuses cutover on. Omitting it from the scan
    /// left that refusal unreachable while every gate stayed green.
    #[test]
    fn the_scan_reaches_the_one_class_that_refuses_cutover() {
        let types = domain_key_types();
        assert!(
            types.contains(&(KeyType::Instance as i16)),
            "an Instance-typed row is reachable from a client through the seven generic \
             mutable RPCs and is what the cutover's foreign-write gate exists to catch"
        );
        for absent in [KeyType::Untyped, KeyType::Resolve] {
            assert!(
                !types.contains(&(absent as i16)),
                "{absent:?} is acceleration or resolution, not domain lifecycle; scanning it \
                 would report ordinary rows as foreign writes and block every cutover"
            );
        }
    }

    #[test]
    fn a_repository_identity_must_be_sixteen_bytes() {
        assert!(repository_identity(&[7u8; 16]).is_ok());
        for width in [0usize, 15, 17, 32] {
            let error = repository_identity(&vec![7u8; width])
                .expect_err("a non-16-byte identity must be refused");
            assert!(
                error.to_string().contains(&width.to_string()),
                "the refusal must name the observed width, got: {error}"
            );
        }
    }

    #[test]
    fn a_sixteen_byte_identity_round_trips_its_bytes() {
        let bytes: [u8; 16] = std::array::from_fn(|index| index as u8);
        let id = repository_identity(&bytes).expect("16 bytes is a valid identity");
        assert_eq!(id.data(), &bytes);
    }
}

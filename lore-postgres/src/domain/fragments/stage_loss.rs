// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! WP-115 drain guard follow-up: operator loss rulings for staged fragments
//! the guarded drain keeps `Staged` forever (`loreserver stage resolve-lost`).
//!
//! The drain guard reads a missing staged file as absent only when the
//! reader process confirmed the file's stager in its own stage. A file whose
//! stager left before any reader confirmed it, or that has no recorded
//! stager, is kept `Staged` and retried on every pass, and a GET of it
//! answers `SlowDown`. This module is the database half of the way out:
//!
//! - [`list_lost_staged`] selects the kept candidates (read-only, the
//!   operator's dry run), and [`confirm_token`] binds that exact set.
//! - [`apply_loss_rulings`] re-selects the set as of the token's issue time,
//!   checks the token, the attestation and the tenant rule, and records one
//!   ruling row per file. It never touches the lifecycle and never reads the
//!   stage.
//! - The running drain carries a ruling out: on its normal pass, after its
//!   own pinned read missed the file, its guard is healthy and its evidence
//!   check passed, [`PostgresFragmentCoordinator::carry_out_loss_ruling`]
//!   marks the fragment `Missing` and closes the ruling in ONE transaction.
//!
//! A ruling row is never deleted. Nothing here deletes from the table.
//!
//! # What a ruling cannot prove
//!
//! Where a departed stager wrote. Echo evidence (its `.echo` file in the
//! drain's own pinned `liveness/`) proves that stager wrote the drain's root.
//! Without it the operator's attestation is the only proof, and a stager on
//! another directory that stopped cleanly leaves a file there that this path
//! marks `Missing` here. That risk is accepted by the attestation.

use tokio_postgres::GenericClient;

use super::*;

/// The boot-time declaration of the ruling table. An `include_str!` of the
/// migration, so the two cannot drift.
pub const STAGE_LOSS_SCHEMA: &str =
    include_str!("../../../migrations/0012_write_behind_stage_loss_rulings.sql");

/// The least age (database clock, from the epoch row) a staged
/// representation must have before it can be listed, ruled or marked. A
/// floor: no flag lowers it. 60 times the guard's own minimum staged age and
/// longer than the one-hour stager-row prune.
pub const MIN_LOSS_RULING_AGE: Duration = Duration::from_secs(3_600);

/// The most rows one list, apply or status returns or writes.
pub const MAX_LOSS_RULING_ROWS: i64 = 1_000;

/// How long an open ruling waits for the drain. Then it closes `expired`.
pub const LOSS_RULING_TTL: Duration = Duration::from_secs(24 * 3_600);

/// How long a confirm token from `list` stays valid for `apply`.
pub const LOSS_CONFIRM_TOKEN_TTL: Duration = Duration::from_secs(15 * 60);

/// The longest actor the table accepts, in bytes.
pub const MAX_LOSS_ACTOR_BYTES: usize = 256;
/// The longest reason the table accepts, in bytes.
pub const MAX_LOSS_REASON_BYTES: usize = 1_024;

/// The token's format version prefix.
const TOKEN_PREFIX: &str = "v1";
/// A token issued this far after the database clock is refused.
const TOKEN_CLOCK_SKEW_MS: i64 = 60_000;

/// Why a representation was listed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossSelection {
    /// No stager row: an older binary, stage liveness off, a full-role
    /// replica, or a pruned row. Never has evidence; needs attestation.
    NoStager,
    /// The recorded stager's `(replica, incarnation)` is not fresh in the
    /// cell's liveness table.
    StagerNotFresh,
}

impl LossSelection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoStager => "no_stager",
            Self::StagerNotFresh => "stager_not_fresh",
        }
    }
}

/// A ruling's terminal outcome, written once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossOutcome {
    /// The drain marked the fragment `Missing` under this ruling.
    MarkedMissing,
    /// The drain's pinned read found the file. Promotion goes on as usual.
    Found,
    /// The head left the ruled epoch or manifest by another path.
    Fenced,
    /// Not carried out before the ruling's expiry.
    Expired,
    /// No echo evidence and no attestation.
    NoEvidence,
}

impl LossOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MarkedMissing => "marked_missing",
            Self::Found => "found",
            Self::Fenced => "fenced",
            Self::Expired => "expired",
            Self::NoEvidence => "no_evidence",
        }
    }

    /// Decode a stored outcome.
    pub fn from_stored(value: &str) -> Option<Self> {
        Some(match value {
            "marked_missing" => Self::MarkedMissing,
            "found" => Self::Found,
            "fenced" => Self::Fenced,
            "expired" => Self::Expired,
            "no_evidence" => Self::NoEvidence,
            _ => return None,
        })
    }
}

/// What proved the stager wrote the drain's root when it marked `Missing`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossEvidence {
    /// The stager's `.echo` file, naming its incarnation, in the drain's
    /// pinned `liveness/`.
    Echo,
    /// No evidence; the ruling's attestation is the only proof.
    None,
}

impl LossEvidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Echo => "echo",
            Self::None => "none",
        }
    }
}

/// The drain process that decides a ruling, recorded on the row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LossRulingReader {
    pub replica_id: String,
    pub incarnation: String,
}

/// The operator's selection filters. `repository` selects by association
/// only; it never limits the effect (a hash is shared by every repository
/// that holds it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LossFilter {
    pub hash: Option<Vec<u8>>,
    pub stager: Option<String>,
    pub repository: Option<Vec<u8>>,
    /// At least [`MIN_LOSS_RULING_AGE`].
    pub min_age: Duration,
    /// 1 to [`MAX_LOSS_RULING_ROWS`].
    pub limit: i64,
}

impl LossFilter {
    /// Refuse a filter outside the bounds. A bound is refused, never clamped.
    ///
    /// # Errors
    ///
    /// [`DomainError::InvalidInput`] naming the field.
    pub fn validate(&self) -> Result<(), DomainError> {
        if self.min_age < MIN_LOSS_RULING_AGE {
            return Err(DomainError::InvalidInput(format!(
                "min age must be at least {} s",
                MIN_LOSS_RULING_AGE.as_secs()
            )));
        }
        if self.min_age > LOSS_RULING_TTL * 365 {
            return Err(DomainError::InvalidInput("min age is too large".to_owned()));
        }
        if !(1..=MAX_LOSS_RULING_ROWS).contains(&self.limit) {
            return Err(DomainError::InvalidInput(format!(
                "limit must be 1..={MAX_LOSS_RULING_ROWS}"
            )));
        }
        if self.hash.as_ref().is_some_and(|hash| hash.len() != 32) {
            return Err(DomainError::InvalidInput(
                "hash must be 32 bytes (64 hex characters)".to_owned(),
            ));
        }
        if self
            .repository
            .as_ref()
            .is_some_and(|repository| repository.len() != 16)
        {
            return Err(DomainError::InvalidInput(
                "repository must be 16 bytes (32 hex characters)".to_owned(),
            ));
        }
        if self
            .stager
            .as_ref()
            .is_some_and(|stager| stager.is_empty() || stager.len() > MAX_STAGE_LIVENESS_ID_BYTES)
        {
            return Err(DomainError::InvalidInput(format!(
                "stager must be 1..={MAX_STAGE_LIVENESS_ID_BYTES} bytes"
            )));
        }
        Ok(())
    }

    fn min_age_ms(&self) -> i64 {
        i64::try_from(self.min_age.as_millis()).unwrap_or(i64::MAX)
    }
}

/// One staged representation the guarded drain keeps, as listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LostStagedFile {
    pub hash: Vec<u8>,
    pub epoch: i64,
    pub manifest_id: Vec<u8>,
    /// `None` for [`LossSelection::NoStager`].
    pub stager: Option<StagerIdentity>,
    /// Age of the epoch row, database clock, at the listing.
    pub age: Duration,
    /// Distinct repositories with a live association.
    pub repositories: i64,
    /// An open ruling's id, if one exists.
    pub open_ruling: Option<i64>,
}

impl LostStagedFile {
    pub fn selection(&self) -> LossSelection {
        if self.stager.is_some() {
            LossSelection::StagerNotFresh
        } else {
            LossSelection::NoStager
        }
    }
}

/// A listing and the database clock it was taken at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LossListing {
    pub files: Vec<LostStagedFile>,
    /// Database clock, milliseconds since the Unix epoch.
    pub db_now_ms: i64,
    /// The instant the age cutoff was taken at (the token's issue time on
    /// apply), milliseconds since the Unix epoch.
    pub as_of_ms: i64,
}

/// The relations the command reads. A cell whose replicas have not yet
/// booted this build has no ruling table; the command refuses rather than
/// creating it (the drain that carries rulings out must be of this build).
const REQUIRED_RELATIONS: [&str; 6] = [
    "lore_domain_stage_loss_rulings",
    "lore_domain_write_behind_stagers",
    "lore_domain_write_behind_stage_progress",
    "lore_fragment_stage_custody",
    "lore_fragment_lifecycle",
    "lore_fragment_associations",
];

async fn require_relations(client: &impl GenericClient) -> Result<(), DomainError> {
    let names: Vec<&str> = REQUIRED_RELATIONS.to_vec();
    let rows = client
        .query(
            "SELECT name FROM unnest($1::text[]) AS name WHERE to_regclass(name) IS NULL",
            &[&names],
        )
        .await
        .map_err(|error| DomainError::from_pg_detailed("stage loss relations", error))?;
    if rows.is_empty() {
        return Ok(());
    }
    let missing: Vec<String> = rows.iter().map(|row| row.get(0)).collect();
    Err(DomainError::NotReady(format!(
        "this cell database has no {}; start a loreserver of this build against it first",
        missing.join(", ")
    )))
}

/// List the staged representations the guarded drain keeps, as of `as_of_ms`
/// (database clock now when `None`): `Staged` head, live custody, epoch row
/// at least `filter.min_age` old at `as_of_ms`, and no stager row or a stager
/// `(replica, incarnation)` with no progress row published within
/// `stager_fresh`.
///
/// Every other condition is the drain candidate query's own
/// (`staged_drain_candidates_after`: no active operation but the drain's own
/// promotion, no barrier write claim), so the list never shows a file the
/// drain never picks up and so never carries a ruling out for. A source pin
/// (`fragment_provider_source_pins.rs`) holds the two texts equal.
///
/// Stager freshness is read under ANY `cell_id`, not only `cell_id`: the
/// database is one cell's, so a progress row under another cell id is still
/// a live process on this database, and a mistyped cell id in one replica's
/// configuration must not make its live stager look departed. `cell_id`
/// binds the confirm token only.
///
/// # Errors
///
/// A filter out of bounds, a missing relation, or a database failure.
pub async fn list_lost_staged(
    client: &impl GenericClient,
    cell_id: &str,
    stager_fresh: Duration,
    filter: &LossFilter,
    as_of_ms: Option<i64>,
) -> Result<LossListing, DomainError> {
    filter.validate()?;
    if cell_id.is_empty() || cell_id.len() > MAX_STAGE_LIVENESS_ID_BYTES {
        return Err(DomainError::InvalidInput(
            "cell id must be 1..=128 bytes".to_owned(),
        ));
    }
    require_relations(client).await?;
    let fresh_ms = i64::try_from(stager_fresh.as_millis()).unwrap_or(i64::MAX);
    let clock = client
        .query_one(
            "SELECT (extract(epoch FROM clock_timestamp()) * 1000)::bigint AS now_ms",
            &[],
        )
        .await
        .map_err(|error| DomainError::from_pg_detailed("stage loss clock", error))?;
    let db_now_ms: i64 = clock.get("now_ms");
    let as_of_ms = as_of_ms.unwrap_or(db_now_ms);
    let rows = client
        .query(
            "SELECT l.hash, l.current_epoch AS epoch, l.manifest_id, \
                    s.replica_id, s.incarnation, \
                    greatest(0, (extract(epoch FROM clock_timestamp() - e.created_at) * 1000) \
                        ::bigint) AS age_ms, \
                    (SELECT count(DISTINCT a.repository_id) FROM lore_fragment_associations a \
                      WHERE a.hash = l.hash AND a.state = $8) AS repositories, \
                    (SELECT r.ruling_id FROM lore_domain_stage_loss_rulings r \
                      WHERE r.hash = l.hash AND r.epoch = l.current_epoch \
                        AND r.outcome IS NULL \
                        AND r.expires_at > clock_timestamp()) AS open_ruling \
               FROM lore_fragment_lifecycle AS l \
               JOIN lore_fragment_epochs AS e \
                 ON e.hash = l.hash \
                AND e.epoch = l.current_epoch \
                AND e.manifest_id = l.manifest_id \
               JOIN lore_fragment_stage_custody AS c ON c.hash=l.hash AND c.epoch=l.current_epoch AND c.state=1 \
               LEFT JOIN lore_domain_write_behind_stagers s \
                 ON s.hash = l.hash AND s.epoch = l.current_epoch \
              WHERE l.state = 3 \
                AND (l.active_operation IS NULL OR l.active_operation = decode('77703131352d70726f6d6f74652d7631','hex')) \
                AND e.authority = 1 \
                AND e.disposition = 0 \
                AND NOT EXISTS ( \
                    SELECT 1 FROM lore_fragment_write_claims AS active \
                     WHERE active.hash = l.hash \
                       AND active.state IN (0, 1, 3) \
                       AND (CASE WHEN active.state = 0 \
                                 THEN active.send_not_after \
                                 ELSE active.hard_not_after END) \
                           > clock_timestamp()) \
                AND e.created_at <= to_timestamp($7::bigint / 1000.0) \
                                    - ($1::bigint * interval '1 millisecond') \
                AND (s.replica_id IS NULL OR NOT EXISTS ( \
                      SELECT 1 FROM lore_domain_write_behind_stage_progress p \
                       WHERE p.replica_id = s.replica_id \
                         AND p.incarnation = s.incarnation \
                         AND p.published_at > clock_timestamp() \
                                              - ($2::bigint * interval '1 millisecond'))) \
                AND ($3::bytea IS NULL OR l.hash = $3) \
                AND ($4::text IS NULL OR s.replica_id = $4) \
                AND ($5::bytea IS NULL OR EXISTS ( \
                      SELECT 1 FROM lore_fragment_associations a \
                       WHERE a.hash = l.hash AND a.repository_id = $5 AND a.state = $8)) \
              ORDER BY l.hash \
              LIMIT $6",
            &[
                &filter.min_age_ms(),
                &fresh_ms,
                &filter.hash,
                &filter.stager,
                &filter.repository,
                &filter.limit,
                &as_of_ms,
                &schema::ASSOCIATION_LIVE,
            ],
        )
        .await
        .map_err(|error| DomainError::from_pg_detailed("stage loss list", error))?;
    let mut files = Vec::with_capacity(rows.len());
    for row in rows {
        let replica: Option<String> = row.get("replica_id");
        let incarnation: Option<String> = row.get("incarnation");
        let stager = match (replica, incarnation) {
            (Some(replica), Some(incarnation)) => Some(StagerIdentity {
                replica_id: replica,
                incarnation,
            }),
            (None, None) => None,
            _ => {
                return Err(DomainError::Internal(
                    "a stager row has half an identity".to_owned(),
                ));
            }
        };
        let age_ms: i64 = row.get("age_ms");
        files.push(LostStagedFile {
            hash: row.get("hash"),
            epoch: row.get("epoch"),
            manifest_id: row.get("manifest_id"),
            stager,
            age: Duration::from_millis(u64::try_from(age_ms).unwrap_or(0)),
            repositories: row.get("repositories"),
            open_ruling: row.get("open_ruling"),
        });
    }
    Ok(LossListing {
        files,
        db_now_ms,
        as_of_ms,
    })
}

/// The confirm token for one listing: `v1-<issued_ms>-<32 hex>`. The digest
/// covers the cell, every filter, and the exact `(hash, epoch, manifest)`
/// set in hash order. It is a binding, not a secret: it stops `apply` from
/// acting on a set the operator did not see.
pub fn confirm_token(
    issued_ms: i64,
    cell_id: &str,
    filter: &LossFilter,
    files: &[LostStagedFile],
) -> String {
    format!(
        "{TOKEN_PREFIX}-{issued_ms}-{}",
        token_digest(issued_ms, cell_id, filter, files)
    )
}

fn token_digest(
    issued_ms: i64,
    cell_id: &str,
    filter: &LossFilter,
    files: &[LostStagedFile],
) -> String {
    fn field(hasher: &mut blake3::Hasher, value: Option<&[u8]>) {
        match value {
            None => {
                hasher.update(&[0]);
            }
            Some(bytes) => {
                hasher.update(&[1]);
                hasher.update(&(bytes.len() as u64).to_le_bytes());
                hasher.update(bytes);
            }
        }
    }
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"lore-stage-loss-confirm-v1\0");
    hasher.update(&issued_ms.to_le_bytes());
    field(&mut hasher, Some(cell_id.as_bytes()));
    field(&mut hasher, filter.hash.as_deref());
    field(&mut hasher, filter.stager.as_deref().map(str::as_bytes));
    field(&mut hasher, filter.repository.as_deref());
    hasher.update(&filter.min_age_ms().to_le_bytes());
    hasher.update(&filter.limit.to_le_bytes());
    let mut set: Vec<(&[u8], i64, &[u8])> = files
        .iter()
        .map(|file| {
            (
                file.hash.as_slice(),
                file.epoch,
                file.manifest_id.as_slice(),
            )
        })
        .collect();
    set.sort();
    hasher.update(&(set.len() as u64).to_le_bytes());
    for (hash, epoch, manifest) in set {
        field(&mut hasher, Some(hash));
        hasher.update(&epoch.to_le_bytes());
        field(&mut hasher, Some(manifest));
    }
    hex::encode(&hasher.finalize().as_bytes()[..16])
}

/// Why a confirm token is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenRefusal {
    /// Not a token `list` prints.
    Malformed,
    /// Older than [`LOSS_CONFIRM_TOKEN_TTL`] by the database clock.
    Expired,
    /// Issued more than a minute after the database clock.
    IssuedInFuture,
    /// The selection is no longer the set the token was issued for.
    SetChanged,
    /// An earlier `apply` already recorded rulings with this token. A token
    /// orders one set of rulings once; a second `apply` needs a new `list`.
    Replayed,
}

impl TokenRefusal {
    pub fn describe(self) -> &'static str {
        match self {
            Self::Malformed => "the confirm token is not one `resolve-lost list` printed",
            Self::Expired => "the confirm token is older than 15 minutes; run list again",
            Self::IssuedInFuture => "the confirm token names a time after the database clock",
            Self::SetChanged => {
                "the selection changed since list; run list again and check the new set"
            }
            Self::Replayed => {
                "an earlier apply already used this confirm token; run list again for a new one"
            }
        }
    }
}

/// The issue time a token names, or [`TokenRefusal::Malformed`].
pub fn token_issued_ms(token: &str) -> Result<i64, TokenRefusal> {
    let mut parts = token.splitn(3, '-');
    let (Some(prefix), Some(issued), Some(digest)) = (parts.next(), parts.next(), parts.next())
    else {
        return Err(TokenRefusal::Malformed);
    };
    if prefix != TOKEN_PREFIX
        || digest.len() != 32
        || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(TokenRefusal::Malformed);
    }
    let issued: i64 = issued.parse().map_err(|_error| TokenRefusal::Malformed)?;
    if issued < 0 {
        return Err(TokenRefusal::Malformed);
    }
    Ok(issued)
}

/// Check `token` against a re-selection taken as of its own issue time.
///
/// # Errors
///
/// The first [`TokenRefusal`] that applies: malformed, then expired or from
/// the future (by `now_ms`, the database clock), then a changed set.
pub fn check_confirm_token(
    token: &str,
    now_ms: i64,
    cell_id: &str,
    filter: &LossFilter,
    files: &[LostStagedFile],
) -> Result<(), TokenRefusal> {
    let issued = token_issued_ms(token)?;
    let ttl = i64::try_from(LOSS_CONFIRM_TOKEN_TTL.as_millis()).unwrap_or(i64::MAX);
    if issued > now_ms.saturating_add(TOKEN_CLOCK_SKEW_MS) {
        return Err(TokenRefusal::IssuedInFuture);
    }
    if now_ms.saturating_sub(issued) > ttl {
        return Err(TokenRefusal::Expired);
    }
    if confirm_token(issued, cell_id, filter, files) != token {
        return Err(TokenRefusal::SetChanged);
    }
    Ok(())
}

/// The operator's decision for `apply`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LossApply<'a> {
    pub actor: &'a str,
    pub reason: &'a str,
    /// `--attest-mounts-checked`.
    pub attested: bool,
    /// `--multi-repository`.
    pub multi_repository: bool,
    pub token: &'a str,
}

/// Why `apply` wrote nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LossApplyRefusal {
    Token(TokenRefusal),
    /// The set is empty.
    Empty,
    /// These hashes have no stager row and the operator did not attest.
    NeedsAttestation(Vec<Vec<u8>>),
    /// These hashes are associated with more than one repository and the
    /// operator did not pass `--multi-repository`.
    NeedsMultiRepository(Vec<Vec<u8>>),
    /// The transaction met a serialization failure (40001) or a deadlock
    /// (40P01), for example a drain refresh expiring the same ruling at the
    /// same time. It rolled back, so this attempt did not use the token.
    /// Nothing retries it automatically.
    Contended,
}

/// Map an `apply` that failed on contention to
/// [`LossApplyRefusal::Contended`]. Every other result passes through.
///
/// # Errors
///
/// Every error but [`DomainError::Contention`], unchanged.
pub fn refuse_contended_apply(
    result: Result<LossApplyOutcome, DomainError>,
) -> Result<LossApplyOutcome, DomainError> {
    match result {
        Err(DomainError::Contention(_)) => {
            Ok(LossApplyOutcome::Refused(LossApplyRefusal::Contended))
        }
        other => other,
    }
}

/// One ruling `apply` recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedLossRuling {
    pub ruling_id: i64,
    pub hash: Vec<u8>,
    pub epoch: i64,
}

/// What `apply` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LossApplyOutcome {
    Applied {
        rulings: Vec<AppliedLossRuling>,
        /// Representations that already had an open ruling (kept as is).
        already_open: Vec<(Vec<u8>, i64)>,
    },
    Refused(LossApplyRefusal),
}

/// Record one ruling per file of the confirmed set, in one transaction.
///
/// The set is selected again inside the transaction, with the age cutoff at
/// the token's issue time (so files that aged past the cutoff since `list`
/// do not change it) and stager freshness at the database clock now (so a
/// stager that came back does). Every refusal writes nothing. A
/// serialization failure or deadlock is [`LossApplyRefusal::Contended`].
///
/// # Errors
///
/// Bounds, a missing relation, or a database failure.
pub async fn apply_loss_rulings(
    client: &mut deadpool_postgres::Client,
    cell_id: &str,
    stager_fresh: Duration,
    filter: &LossFilter,
    apply: &LossApply<'_>,
) -> Result<LossApplyOutcome, DomainError> {
    refuse_contended_apply(
        apply_loss_rulings_once(client, cell_id, stager_fresh, filter, apply).await,
    )
}

async fn apply_loss_rulings_once(
    client: &mut deadpool_postgres::Client,
    cell_id: &str,
    stager_fresh: Duration,
    filter: &LossFilter,
    apply: &LossApply<'_>,
) -> Result<LossApplyOutcome, DomainError> {
    for (field, value, max) in [
        ("actor", apply.actor, MAX_LOSS_ACTOR_BYTES),
        ("reason", apply.reason, MAX_LOSS_REASON_BYTES),
    ] {
        if value.trim().is_empty() || value.len() > max {
            return Err(DomainError::InvalidInput(format!(
                "{field} must be 1..={max} bytes and not blank"
            )));
        }
    }
    let issued = match token_issued_ms(apply.token) {
        Ok(issued) => issued,
        Err(refusal) => {
            return Ok(LossApplyOutcome::Refused(LossApplyRefusal::Token(refusal)));
        }
    };
    let tx = client
        .build_transaction()
        .isolation_level(tokio_postgres::IsolationLevel::RepeatableRead)
        .start()
        .await
        .map_err(|error| DomainError::from_pg_detailed("stage loss apply begin", error))?;
    let listing = list_lost_staged(&*tx, cell_id, stager_fresh, filter, Some(issued)).await?;
    if let Err(refusal) = check_confirm_token(
        apply.token,
        listing.db_now_ms,
        cell_id,
        filter,
        &listing.files,
    ) {
        return Ok(LossApplyOutcome::Refused(LossApplyRefusal::Token(refusal)));
    }
    // One token orders one set of rulings once. Two concurrent applies of one
    // token both pass this read, then meet on the open-ruling unique index:
    // under repeatable read the second fails with a serialization error and
    // writes nothing.
    let replayed: bool = tx
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM lore_domain_stage_loss_rulings WHERE token = $1)",
            &[&apply.token],
        )
        .await
        .map_err(|error| DomainError::from_pg_detailed("stage loss token replay", error))?
        .get(0);
    if replayed {
        return Ok(LossApplyOutcome::Refused(LossApplyRefusal::Token(
            TokenRefusal::Replayed,
        )));
    }
    if listing.files.is_empty() {
        return Ok(LossApplyOutcome::Refused(LossApplyRefusal::Empty));
    }
    // KV ruling 2: no evidence is possible without a stager row, so such a
    // ruling needs the operator's attestation. One isolated branch.
    let unattested: Vec<Vec<u8>> = listing
        .files
        .iter()
        .filter(|file| file.stager.is_none() && !apply.attested)
        .map(|file| file.hash.clone())
        .collect();
    if !unattested.is_empty() {
        return Ok(LossApplyOutcome::Refused(
            LossApplyRefusal::NeedsAttestation(unattested),
        ));
    }
    let shared: Vec<Vec<u8>> = listing
        .files
        .iter()
        .filter(|file| file.repositories > 1 && !apply.multi_repository)
        .map(|file| file.hash.clone())
        .collect();
    if !shared.is_empty() {
        return Ok(LossApplyOutcome::Refused(
            LossApplyRefusal::NeedsMultiRepository(shared),
        ));
    }
    // An undecided ruling past its expiry still holds the open slot of its
    // representation until a drain refresh writes `expired`. Write that
    // outcome here first, with no drain identity (the row says `apply`
    // closed it), so ruling the representation again does not depend on a
    // drain having run. Nothing is deleted.
    let hashes: Vec<&[u8]> = listing
        .files
        .iter()
        .map(|file| file.hash.as_slice())
        .collect();
    let epochs: Vec<i64> = listing.files.iter().map(|file| file.epoch).collect();
    tx.execute(
        "UPDATE lore_domain_stage_loss_rulings r \
            SET outcome = 'expired', decided_at = clock_timestamp() \
           FROM unnest($1::bytea[], $2::bigint[]) AS ruled(hash, epoch) \
          WHERE r.hash = ruled.hash AND r.epoch = ruled.epoch \
            AND r.outcome IS NULL AND r.expires_at <= clock_timestamp()",
        &[&hashes, &epochs],
    )
    .await
    .map_err(|error| DomainError::from_pg_detailed("stage loss expire before apply", error))?;
    let ttl_ms = i64::try_from(LOSS_RULING_TTL.as_millis()).unwrap_or(i64::MAX);
    let mut rulings = Vec::new();
    let mut already_open = Vec::new();
    for file in &listing.files {
        let (replica, incarnation) = match file.stager.as_ref() {
            Some(stager) => (
                Some(stager.replica_id.as_str()),
                Some(stager.incarnation.as_str()),
            ),
            None => (None, None),
        };
        let inserted = tx
            .query_opt(
                "INSERT INTO lore_domain_stage_loss_rulings ( \
                     hash, epoch, manifest_id, selection, stager_replica_id, \
                     stager_incarnation, actor, reason, attested, multi_repository, repositories, \
                     min_age_ms, token, created_at, expires_at) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, \
                     clock_timestamp(), clock_timestamp() + ($14::bigint * interval '1 millisecond')) \
                 ON CONFLICT (hash, epoch) WHERE outcome IS NULL DO NOTHING \
                 RETURNING ruling_id",
                &[
                    &file.hash,
                    &file.epoch,
                    &file.manifest_id,
                    &file.selection().as_str(),
                    &replica,
                    &incarnation,
                    &apply.actor,
                    &apply.reason,
                    &apply.attested,
                    &apply.multi_repository,
                    &file.repositories,
                    &filter.min_age_ms(),
                    &apply.token,
                    &ttl_ms,
                ],
            )
            .await
            .map_err(|error| DomainError::from_pg_detailed("stage loss ruling insert", error))?;
        match inserted {
            Some(row) => rulings.push(AppliedLossRuling {
                ruling_id: row.get(0),
                hash: file.hash.clone(),
                epoch: file.epoch,
            }),
            None => already_open.push((file.hash.clone(), file.epoch)),
        }
    }
    classify_commit(tx.commit().await, "stage loss apply commit")?;
    Ok(LossApplyOutcome::Applied {
        rulings,
        already_open,
    })
}

/// One ruling row, for `status`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LossRulingRecord {
    pub ruling_id: i64,
    pub hash: Vec<u8>,
    pub epoch: i64,
    pub selection: String,
    pub stager: Option<StagerIdentity>,
    pub actor: String,
    pub reason: String,
    pub attested: bool,
    pub multi_repository: bool,
    pub repositories: i64,
    pub created_ms: i64,
    pub expires_ms: i64,
    pub outcome: Option<String>,
    pub evidence: Option<String>,
    pub decided_ms: Option<i64>,
    pub drain_replica_id: Option<String>,
    /// Undecided but past its expiry by the database clock: no drain will
    /// carry it out. The next drain refresh, or an `apply` that rules the
    /// representation again, writes its `expired` outcome.
    pub expired_pending: bool,
}

/// Ruling rows, newest first: open ones only (undecided and not past their
/// expiry), or all; one hash, or every hash; at most `limit` (1 to [`MAX_LOSS_RULING_ROWS`]).
///
/// # Errors
///
/// Bounds, a missing relation, or a database failure.
pub async fn loss_rulings(
    client: &impl GenericClient,
    hash: Option<&[u8]>,
    open_only: bool,
    limit: i64,
) -> Result<Vec<LossRulingRecord>, DomainError> {
    if !(1..=MAX_LOSS_RULING_ROWS).contains(&limit) {
        return Err(DomainError::InvalidInput(format!(
            "limit must be 1..={MAX_LOSS_RULING_ROWS}"
        )));
    }
    if hash.is_some_and(|hash| hash.len() != 32) {
        return Err(DomainError::InvalidInput(
            "hash must be 32 bytes".to_owned(),
        ));
    }
    require_relations(client).await?;
    let rows = client
        .query(
            "SELECT ruling_id, hash, epoch, selection, stager_replica_id, stager_incarnation, \
                    actor, reason, attested, multi_repository, repositories, \
                    (extract(epoch FROM created_at) * 1000)::bigint AS created_ms, \
                    (extract(epoch FROM expires_at) * 1000)::bigint AS expires_ms, \
                    outcome, evidence, \
                    (extract(epoch FROM decided_at) * 1000)::bigint AS decided_ms, \
                    drain_replica_id, \
                    (outcome IS NULL AND expires_at <= clock_timestamp()) AS expired_pending \
               FROM lore_domain_stage_loss_rulings \
              WHERE ($1::bytea IS NULL OR hash = $1) \
                AND (NOT $2 OR (outcome IS NULL AND expires_at > clock_timestamp())) \
              ORDER BY ruling_id DESC LIMIT $3",
            &[&hash, &open_only, &limit],
        )
        .await
        .map_err(|error| DomainError::from_pg_detailed("stage loss rulings", error))?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let replica: Option<String> = row.get("stager_replica_id");
            let incarnation: Option<String> = row.get("stager_incarnation");
            LossRulingRecord {
                ruling_id: row.get("ruling_id"),
                hash: row.get("hash"),
                epoch: row.get("epoch"),
                selection: row.get("selection"),
                stager: replica
                    .zip(incarnation)
                    .map(|(replica_id, incarnation)| StagerIdentity {
                        replica_id,
                        incarnation,
                    }),
                actor: row.get("actor"),
                reason: row.get("reason"),
                attested: row.get("attested"),
                multi_repository: row.get("multi_repository"),
                repositories: row.get("repositories"),
                created_ms: row.get("created_ms"),
                expires_ms: row.get("expires_ms"),
                outcome: row.get("outcome"),
                evidence: row.get("evidence"),
                decided_ms: row.get("decided_ms"),
                drain_replica_id: row.get("drain_replica_id"),
                expired_pending: row.get("expired_pending"),
            }
        })
        .collect())
}

// ---------------------------------------------------------------------------
// The drain's half
// ---------------------------------------------------------------------------

/// An open ruling as the drain reads it before carrying it out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenLossRuling {
    pub ruling_id: i64,
    pub hash: Vec<u8>,
    pub epoch: i64,
    pub manifest_id: Vec<u8>,
    pub stager: Option<StagerIdentity>,
    pub attested: bool,
    /// The epoch row is at least `greatest(min_age, 1 h)` old now
    /// (database clock).
    pub old_enough: bool,
}

/// One ruling a refresh closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosedLossRuling {
    pub ruling_id: i64,
    pub hash: Vec<u8>,
    pub epoch: i64,
    pub outcome: LossOutcome,
}

/// What one refresh did and found.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LossRulingRefresh {
    /// Open rulings' `(hash, epoch)`, at most the refresh limit.
    pub open: Vec<(Vec<u8>, i64)>,
    /// Rulings this refresh closed (`expired` or `fenced`).
    pub closed: Vec<ClosedLossRuling>,
}

/// The ruling a [`PostgresFragmentCoordinator::mark_missing_with`] closes.
#[derive(Debug, Clone, Copy)]
pub struct RulingCarryOut<'a> {
    pub ruling_id: i64,
    pub evidence: LossEvidence,
    pub reader: &'a LossRulingReader,
}

/// What [`PostgresFragmentCoordinator::carry_out_loss_ruling`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MarkMissingOutcome {
    /// `Missing` published and the ruling closed `marked_missing`, together.
    Published,
    /// The head no longer matches the witness. Nothing was written.
    HeadMoved,
    /// The ruling is closed, expired, for another manifest, too young, or
    /// has neither evidence nor attestation. Nothing was written.
    RulingNotEligible,
}

/// What [`PostgresFragmentCoordinator::fence_loss_ruling_if_head_moved`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LossRulingFence {
    /// The locked head left the ruled representation; the ruling is closed
    /// `fenced`.
    Fenced,
    /// The locked head is still `Staged` at the ruled epoch and manifest.
    /// Nothing was written; the ruling stays open.
    StillStaged,
    /// The ruling was not open. Nothing was written.
    NotOpen,
}

/// Close `ruling` as `marked_missing` inside the caller's transaction, after
/// the head is locked and matched. `false` (nothing written) unless the
/// ruling is open, unexpired, for exactly this representation, old enough
/// by the database clock, and has echo evidence or an attestation.
pub(super) async fn claim_ruling_locked(
    tx: &Transaction<'_>,
    witness: &EpochWitness,
    ruling: &RulingCarryOut<'_>,
) -> Result<bool, DomainError> {
    let floor_ms = i64::try_from(MIN_LOSS_RULING_AGE.as_millis()).unwrap_or(i64::MAX);
    let claimed = tx
        .execute(
            "UPDATE lore_domain_stage_loss_rulings r \
                SET outcome = 'marked_missing', evidence = $5::text, \
                    decided_at = clock_timestamp(), drain_replica_id = $6, \
                    drain_incarnation = $7 \
              WHERE r.ruling_id = $1 AND r.outcome IS NULL \
                AND r.hash = $2 AND r.epoch = $3 AND r.manifest_id = $4 \
                AND r.expires_at > clock_timestamp() \
                AND ($5::text = 'echo' OR r.attested) \
                AND EXISTS (SELECT 1 FROM lore_fragment_epochs e \
                             WHERE e.hash = r.hash AND e.epoch = r.epoch \
                               AND e.created_at <= clock_timestamp() \
                                   - (greatest(r.min_age_ms, $8::bigint) \
                                      * interval '1 millisecond'))",
            &[
                &ruling.ruling_id,
                &witness.hash,
                &witness.epoch,
                &witness.manifest_id,
                &ruling.evidence.as_str(),
                &ruling.reader.replica_id,
                &ruling.reader.incarnation,
                &floor_ms,
            ],
        )
        .await
        .map_err(|error| DomainError::from_pg_detailed("stage loss ruling claim", error))?;
    Ok(claimed == 1)
}

impl PostgresFragmentCoordinator {
    /// The drain's one bounded ruling statement, run at most every few
    /// seconds: close open rulings past their expiry as `expired`, close
    /// open rulings whose head is no longer `Staged` at the ruled epoch and
    /// manifest as `fenced`, and read the remaining open `(hash, epoch)`.
    /// At most `limit` rows per part. Every update re-checks `outcome IS
    /// NULL` on the row it locks, so two drains cannot both decide one.
    pub async fn refresh_loss_rulings(
        &self,
        limit: i64,
        reader: &LossRulingReader,
    ) -> Result<LossRulingRefresh, DomainError> {
        let limit = limit.clamp(1, MAX_LOSS_RULING_ROWS);
        let client = self.checkout().await?;
        let rows = client
            .query(
                "WITH expired AS ( \
                   UPDATE lore_domain_stage_loss_rulings r \
                      SET outcome = 'expired', decided_at = clock_timestamp(), \
                          drain_replica_id = $2, drain_incarnation = $3 \
                    WHERE r.outcome IS NULL AND r.ruling_id IN ( \
                          SELECT ruling_id FROM lore_domain_stage_loss_rulings \
                           WHERE outcome IS NULL AND expires_at <= clock_timestamp() \
                           ORDER BY ruling_id LIMIT $1) \
                   RETURNING r.ruling_id, r.hash, r.epoch), \
                 moved AS ( \
                   UPDATE lore_domain_stage_loss_rulings r \
                      SET outcome = 'fenced', decided_at = clock_timestamp(), \
                          drain_replica_id = $2, drain_incarnation = $3 \
                    WHERE r.outcome IS NULL AND r.ruling_id IN ( \
                          SELECT o.ruling_id FROM lore_domain_stage_loss_rulings o \
                           WHERE o.outcome IS NULL AND o.expires_at > clock_timestamp() \
                             AND NOT EXISTS (SELECT 1 FROM lore_fragment_lifecycle l \
                                  WHERE l.hash = o.hash AND l.current_epoch = o.epoch \
                                    AND l.state = 3 AND l.manifest_id = o.manifest_id) \
                           ORDER BY o.ruling_id LIMIT $1) \
                   RETURNING r.ruling_id, r.hash, r.epoch), \
                 still_open AS ( \
                   SELECT o.ruling_id, o.hash, o.epoch FROM lore_domain_stage_loss_rulings o \
                    WHERE o.outcome IS NULL AND o.expires_at > clock_timestamp() \
                      AND o.ruling_id NOT IN (SELECT ruling_id FROM moved) \
                    ORDER BY o.ruling_id LIMIT $1) \
                 SELECT 'expired' AS kind, ruling_id, hash, epoch FROM expired \
                 UNION ALL SELECT 'fenced', ruling_id, hash, epoch FROM moved \
                 UNION ALL SELECT 'open', ruling_id, hash, epoch FROM still_open",
                &[&limit, &reader.replica_id, &reader.incarnation],
            )
            .await
            .map_err(|error| DomainError::from_pg_detailed("stage loss ruling refresh", error))?;
        let mut refresh = LossRulingRefresh::default();
        for row in rows {
            let kind: String = row.get("kind");
            let hash: Vec<u8> = row.get("hash");
            let epoch: i64 = row.get("epoch");
            let ruling_id: i64 = row.get("ruling_id");
            match kind.as_str() {
                "open" => refresh.open.push((hash, epoch)),
                "expired" => refresh.closed.push(ClosedLossRuling {
                    ruling_id,
                    hash,
                    epoch,
                    outcome: LossOutcome::Expired,
                }),
                _ => refresh.closed.push(ClosedLossRuling {
                    ruling_id,
                    hash,
                    epoch,
                    outcome: LossOutcome::Fenced,
                }),
            }
        }
        Ok(refresh)
    }

    /// The open ruling of `(hash, epoch)`, if any.
    pub async fn open_loss_ruling(
        &self,
        hash: &[u8],
        epoch: i64,
    ) -> Result<Option<OpenLossRuling>, DomainError> {
        let floor_ms = i64::try_from(MIN_LOSS_RULING_AGE.as_millis()).unwrap_or(i64::MAX);
        let client = self.checkout().await?;
        let row = client
            .query_opt(
                "SELECT r.ruling_id, r.hash, r.epoch, r.manifest_id, r.stager_replica_id, \
                        r.stager_incarnation, r.attested, \
                        COALESCE((SELECT e.created_at <= clock_timestamp() \
                                         - (greatest(r.min_age_ms, $3::bigint) \
                                            * interval '1 millisecond') \
                                    FROM lore_fragment_epochs e \
                                   WHERE e.hash = r.hash AND e.epoch = r.epoch), false) \
                          AS old_enough \
                   FROM lore_domain_stage_loss_rulings r \
                  WHERE r.hash = $1 AND r.epoch = $2 AND r.outcome IS NULL \
                    AND r.expires_at > clock_timestamp()",
                &[&hash, &epoch, &floor_ms],
            )
            .await
            .map_err(|error| DomainError::from_pg_detailed("stage loss ruling read", error))?;
        Ok(row.map(|row| {
            let replica: Option<String> = row.get("stager_replica_id");
            let incarnation: Option<String> = row.get("stager_incarnation");
            OpenLossRuling {
                ruling_id: row.get("ruling_id"),
                hash: row.get("hash"),
                epoch: row.get("epoch"),
                manifest_id: row.get("manifest_id"),
                stager: replica
                    .zip(incarnation)
                    .map(|(replica_id, incarnation)| StagerIdentity {
                        replica_id,
                        incarnation,
                    }),
                attested: row.get("attested"),
                old_enough: row.get("old_enough"),
            }
        }))
    }

    /// Close an open ruling with `outcome` (`found`, `fenced` or
    /// `no_evidence`; `marked_missing` only ever closes with the head, and
    /// `expired` only in a refresh). `false` when it was no longer open.
    pub async fn close_loss_ruling(
        &self,
        ruling_id: i64,
        outcome: LossOutcome,
        reader: &LossRulingReader,
    ) -> Result<bool, DomainError> {
        if matches!(outcome, LossOutcome::MarkedMissing | LossOutcome::Expired) {
            return Err(DomainError::InvalidInput(format!(
                "a ruling is not closed as {} here",
                outcome.as_str()
            )));
        }
        let client = self.checkout().await?;
        let closed = client
            .execute(
                "UPDATE lore_domain_stage_loss_rulings \
                    SET outcome = $2, decided_at = clock_timestamp(), \
                        drain_replica_id = $3, drain_incarnation = $4 \
                  WHERE ruling_id = $1 AND outcome IS NULL",
                &[
                    &ruling_id,
                    &outcome.as_str(),
                    &reader.replica_id,
                    &reader.incarnation,
                ],
            )
            .await
            .map_err(|error| DomainError::from_pg_detailed("stage loss ruling close", error))?;
        Ok(closed == 1)
    }

    /// Close `ruling_id` `fenced` only if the lifecycle head itself, locked,
    /// is no longer `Staged` at the ruling's `(epoch, manifest)`. The drain
    /// calls this when its candidate names another manifest than the ruling:
    /// the candidate may be stale (read before the pass), and a stale
    /// candidate must never close a valid ruling. Lock order: the head
    /// (`LockClass::Fragments`) first, then the ruling row, as in
    /// `mark_missing_with`.
    pub async fn fence_loss_ruling_if_head_moved(
        &self,
        ruling_id: i64,
        reader: &LossRulingReader,
    ) -> Result<LossRulingFence, DomainError> {
        let mut client = self.checkout().await?;
        let tx = client
            .transaction()
            .await
            .map_err(|error| DomainError::from_pg("stage loss fence begin", error))?;
        let Some(ruling) = tx
            .query_opt(
                "SELECT hash, epoch, manifest_id FROM lore_domain_stage_loss_rulings \
                  WHERE ruling_id = $1 AND outcome IS NULL",
                &[&ruling_id],
            )
            .await
            .map_err(|error| DomainError::from_pg_detailed("stage loss fence read", error))?
        else {
            return Ok(LossRulingFence::NotOpen);
        };
        let hash: Vec<u8> = ruling.get("hash");
        let epoch: i64 = ruling.get("epoch");
        let manifest_id: Vec<u8> = ruling.get("manifest_id");
        let mut sequence = LockSequence::new();
        // `None` locks nothing, and means the head row is gone: it cannot be
        // `Staged` at the ruled epoch again, so the ruling is fenced.
        let head = lock_fragment_head(&tx, &mut sequence, &hash).await?;
        let still_staged = head.is_some_and(|head| {
            head.current_epoch == epoch
                && head.state == FragmentLifecycleState::Staged
                && head.manifest_id.as_deref() == Some(manifest_id.as_slice())
        });
        if still_staged {
            return Ok(LossRulingFence::StillStaged);
        }
        let closed = tx
            .execute(
                "UPDATE lore_domain_stage_loss_rulings \
                    SET outcome = 'fenced', decided_at = clock_timestamp(), \
                        drain_replica_id = $2, drain_incarnation = $3 \
                  WHERE ruling_id = $1 AND outcome IS NULL",
                &[&ruling_id, &reader.replica_id, &reader.incarnation],
            )
            .await
            .map_err(|error| DomainError::from_pg_detailed("stage loss fence close", error))?;
        classify_commit(tx.commit().await, "stage loss fence commit")?;
        Ok(if closed == 1 {
            LossRulingFence::Fenced
        } else {
            LossRulingFence::NotOpen
        })
    }

    /// Mark `witness` `Missing` (diagnostic `Absent`) under ruling
    /// `ruling_id`, closing the ruling `marked_missing` in the same
    /// transaction. The caller (the drain) has already read the file as
    /// absent through its pinned stage, checked its guard and taken its
    /// evidence. See [`MarkMissingOutcome`].
    pub async fn carry_out_loss_ruling(
        &self,
        witness: &EpochWitness,
        ruling_id: i64,
        evidence: LossEvidence,
        reader: &LossRulingReader,
    ) -> Result<MarkMissingOutcome, DomainError> {
        if witness.state != FragmentLifecycleState::Staged || witness.manifest_id.is_none() {
            return Err(DomainError::InvalidInput(
                "a loss ruling is carried out only on a Staged witness".to_owned(),
            ));
        }
        self.mark_missing_with(
            witness,
            MissingDiagnostic::Absent,
            Some(&RulingCarryOut {
                ruling_id,
                evidence,
                reader,
            }),
        )
        .await
    }
}

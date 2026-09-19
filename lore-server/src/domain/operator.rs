// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! `loreserver domain <status|cutover>` — the CR-029/CR-030 cell arming surface
//! (WP-120).
//!
//! Before this existed, the only code that could arm a Postgres-mode cell was a
//! test fixture: `crate::domain::test_support::configured_enforcing_context` and
//! `lore-integration-tests`' harness, both over an `EmptyBackfillSource`. A
//! staging or development cell could not be armed at all, which is why WP-120's
//! live proof ran against a cell whose `lore_domain_schema_state` still read
//! `enforcement_enabled = false`, `backfill_state = 0` — every push took the
//! legacy path and filed no attempt receipt, exactly as designed for an unarmed
//! cell, and nothing said so.
//!
//! Both subcommands load the same settings a serving `loreserver` would, prove
//! the same Postgres-mode and co-location preconditions server startup proves,
//! run one bounded operation, print, and exit. No endpoint is bound.
//!
//! # Why a subcommand
//!
//! Same reasoning as `crate::event_relay::operator`, which this module follows
//! deliberately rather than inventing a second shape: `cutover` carries flags
//! (`--dry-run`, `--force-release-legacy-locks`, `--legacy-lock-issuer`) that
//! are meaningless on `status`, and flattening them onto the root `Cli` would
//! make every combination parseable.
//!
//! # `cutover` runs the real state machine, never a shortcut
//!
//! Every step is a production API, in the order the rollout requires, and each
//! one re-reads state rather than trusting the previous step:
//!
//! 1. [`PostgresDomainStore::connect`] — domain, mediated-proof and outbox DDL.
//! 2. the Postgres mutable and immutable stores — `lore_mutable` must exist
//!    before the domain backfill verifies against it, and the immutable store is
//!    where repository and branch names actually live.
//! 3. `lock_coordinator().bootstrap()` — SCHEMA-117.
//! 4. the legacy-lock precondition — refuse, or release under
//!    `--force-release-legacy-locks`. **Everything above this point is
//!    idempotent DDL that arms nothing**, so a refusal here leaves the cell's
//!    lifecycle state exactly as it was. Anything below it changes that state,
//!    which is why the check sits between the two rather than beside the lock
//!    backfill it guards.
//! 5. `DomainBackfill::for_store(...)` over a **real**
//!    [`CellBackfillSource`](crate::domain::backfill_source::CellBackfillSource),
//!    then `run`, `verify`, `complete`.
//! 6. `lock_coordinator().backfill(...)` over the cell's live legacy lock rows.
//! 7. `enable_fencing(false)`.
//! 8. `enable_enforcement()` — **last**, so that a failure at any earlier step
//!    leaves the cell with enforcement off, which is the legacy path it was
//!    already on. The reverse order left a failed lock backfill on an
//!    enforcement-ON, fencing-OFF cell, where a released client's governed push
//!    is refused `UNIMPLEMENTED`.
//!
//! Steps 7 and 8 both re-check their own evidence in the database and refuse
//! rather than trusting this command, so a restart after any step is safe and a
//! second full run is a no-op.
//!
//! # The cell must be restarted afterwards
//!
//! `ServerInfo`'s capability list is computed once, when the gRPC endpoint is
//! built. A cell armed while it is running keeps advertising the capability set
//! it booted with until it is restarted, so `domain_operation_receipt_v2` stays
//! withdrawn even though receipts are now being filed. The command says so in
//! its closing report.
//!
//! # Enforcement and fencing are armed together, or not at all
//!
//! A released client can push on an enforcing cell only if fenced lock routing
//! is armed as well — see `DomainContext::admit_internal`'s note on
//! `reject_unwired_governed_operation`. So `cutover` refuses up front on a cell
//! whose settings would make `resolve_lock_fencing` fail at the next boot,
//! before it changes anything: arming enforcement on such a cell would leave it
//! unable to serve a governed push, and arming fencing would make the server
//! refuse to start.

use std::collections::BTreeSet;
use std::sync::Arc;

use anyhow::Result;
use anyhow::anyhow;
use clap::Subcommand;
use lore_postgres::domain::PostgresDomainStore;
use lore_postgres::domain::backfill::DomainBackfill;
use lore_postgres::domain::backfill::ResidueClass;
use lore_postgres::domain::backfill::VerificationReport;
use lore_postgres::domain::locks::BackfillIssuerMap;
use lore_postgres::domain::locks::BackfillReport;
use lore_postgres::domain::locks::LockFencingReadiness;
use lore_postgres::domain::locks::PostgresLockCoordinator;
use lore_postgres::domain::schema;
use lore_postgres::pool::Pool;
use lore_storage::ImmutableStore;
use lore_storage::MutableStore;
use serde_json::Value;
use serde_json::json;

use crate::domain::backfill_source::CellBackfillSource;
use crate::domain::lock_fencing_settings_preconditions;
use crate::plugins::postgres::assert_domain_store_colocated;
use crate::plugins::postgres::connect_domain_store;
use crate::plugins::postgres::connect_immutable_store;
use crate::plugins::postgres::connect_mutable_store;
use crate::settings::Settings;
use crate::store::configuration::resolve_plugin_config_with_fallback;

/// The `mode` string that selects the Postgres backend.
const POSTGRES_MODE: &str = "postgres";

/// Connections this command opens on the cell database for its own reads.
///
/// Two rather than one: the backfill source holds a checkout while it digests a
/// repository's partition, and the residue scan opens its own alongside it.
/// Sized apart from the serving pools on purpose — this invocation is not a
/// server and must not look like one to the cell's connection budget.
const OPERATOR_POOL_MAX: u32 = 2;

/// Fingerprint schema version recorded on every row this backfill projects.
///
/// **Deliberately not 1.** A governed create writes version 1 with the v1
/// canonical-intent digest, and `postgres_coordinator`'s exact-retry check
/// compares the fingerprint **and** the version before deciding that a repeated
/// `repository_create` is a replay rather than a conflicting intent. A
/// backfilled row describes state this cell already held; no caller ever
/// expressed an intent for it, so no create may ever match it. Giving these rows
/// their own version makes that a property of the comparison rather than of the
/// digest happening to differ.
pub const BACKFILL_FINGERPRINT_VERSION: i32 = 2;

/// Report one step, or one warning, to stderr.
///
/// **Not `tracing`.** `server_main` dispatches a maintenance command before
/// `async_main` installs a subscriber, so an `info!` on this path is written to
/// nothing at all — a step log that exists in the source and never reaches an
/// operator. That is exactly the shape of silent failure this command was built
/// to end, so the steps go somewhere that always works.
///
/// stderr rather than stdout, so `--json`'s contract holds: stdout carries one
/// JSON object and nothing else, and a deployment script can still read the
/// progress on the other stream.
pub(crate) fn step(message: &str) {
    eprintln!("[domain] {message}");
}

/// Domain separator for a backfilled repository's creation fingerprint.
const BACKFILL_REPOSITORY_DOMAIN_V1: &[u8] = b"lore-domain-backfill-repository-v1\0";

/// Domain separator for a backfilled branch's creation fingerprint.
const BACKFILL_BRANCH_DOMAIN_V1: &[u8] = b"lore-domain-backfill-branch-v1\0";

/// A maintenance operation on this cell's CR-029 domain state.
#[derive(Debug, Subcommand)]
pub enum DomainCommand {
    /// Bind an empty cell to its observed fresh broker stream without declaring receivers ready.
    InitializeEvents {
        #[arg(long)]
        stream_identity: String,
        #[arg(long)]
        stream_epoch: i64,
        /// Actual broker last sequence; must be zero on first initialization.
        #[arg(long)]
        broker_last_sequence: i64,
        #[arg(long)]
        confirm_writers_stopped: bool,
        #[arg(long)]
        json: bool,
    },
    /// Initialize fragment lifecycle for a deliberately empty cell after domain cutover.
    InitializeFragments {
        /// Revision of fresh scoped credentials whose old writers have been excluded.
        #[arg(long, value_name = "REV")]
        provider_write_authority_revision: String,
        /// Attest that legacy writers are stopped and their provider write authority revoked.
        #[arg(long)]
        confirm_legacy_writers_excluded: bool,
        /// Print one JSON object.
        #[arg(long)]
        json: bool,
    },
    /// Report this cell's domain and SCHEMA-117 lock cutover state.
    Status {
        /// Print one JSON object instead of the human-readable report.
        #[arg(long)]
        json: bool,
    },
    /// Arm this cell: bootstrap, backfill, verify, cut over, then enable domain
    /// enforcement and fenced lock routing.
    ///
    /// Idempotent and restartable. Every step re-reads the database and skips
    /// itself when its evidence is already committed, so a run interrupted
    /// anywhere is resumed by running it again.
    ///
    /// Refuses before changing anything when this cell holds legacy lock rows
    /// that no reviewed issuer covers: converting them needs
    /// `--legacy-lock-issuer`, and discarding them needs
    /// `--force-release-legacy-locks`, which releases the lock rather than
    /// preserving it.
    Cutover {
        /// Report what each step would do and change no row.
        ///
        /// The domain schema DDL still runs, because opening the coordinator is
        /// how this command reads the state at all and it is the same
        /// `CREATE TABLE IF NOT EXISTS` path every server boot runs.
        #[arg(long)]
        dry_run: bool,
        /// Delete this cell's remaining legacy lock rows instead of converting
        /// them. The locks they represent are released; a client still holding
        /// one finds it gone.
        #[arg(long)]
        force_release_legacy_locks: bool,
        /// A reviewed issuer for one legacy lock subject, as `SUBJECT=ISSUER`.
        /// Repeatable. A legacy row whose subject has no reviewed issuer cannot
        /// be converted, because the fenced store records who owns a lock as an
        /// (issuer, subject) pair and the legacy row records only the subject.
        #[arg(long, value_name = "SUBJECT=ISSUER")]
        legacy_lock_issuer: Vec<String>,
        /// Print JSON instead of the human-readable report.
        #[arg(long)]
        json: bool,
    },
}

/// Run one domain maintenance command against the configured cell.
///
/// # Errors
/// A configuration refusal (not Postgres mode, no `[plugins.postgres]`, settings
/// that would make fenced routing unbootable), a co-location failure, a
/// precondition this command refuses rather than forces, or a database failure.
pub async fn run(command: &DomainCommand, settings: &Settings) -> Result<()> {
    match command {
        DomainCommand::InitializeEvents {
            stream_identity,
            stream_epoch,
            broker_last_sequence,
            confirm_writers_stopped,
            json,
        } => {
            crate::domain::event_operator::initialize(
                settings,
                stream_identity,
                *stream_epoch,
                *broker_last_sequence,
                *confirm_writers_stopped,
                *json,
            )
            .await
        }
        DomainCommand::InitializeFragments {
            provider_write_authority_revision,
            confirm_legacy_writers_excluded,
            json,
        } => {
            crate::domain::fragment_operator::initialize(
                settings,
                provider_write_authority_revision,
                *confirm_legacy_writers_excluded,
                *json,
            )
            .await
        }
        DomainCommand::Status { json } => {
            let context = DomainOperatorContext::open(settings).await?;
            let status = context.status().await?;
            print_report(&status.render(), status.as_json(), *json);
            Ok(())
        }
        DomainCommand::Cutover {
            dry_run,
            force_release_legacy_locks,
            legacy_lock_issuer,
            json,
        } => {
            let issuers = parse_legacy_lock_issuers(legacy_lock_issuer)?;
            // Before any connection: a cell whose settings fail this check
            // cannot serve a governed push once armed, and would refuse to boot
            // at all once fencing is on.
            lock_fencing_settings_preconditions(settings)?;
            let context = DomainOperatorContext::open(settings).await?;
            context
                .cutover(
                    settings,
                    CutoverOptions {
                        dry_run: *dry_run,
                        force_release_legacy_locks: *force_release_legacy_locks,
                        issuers,
                    },
                    *json,
                )
                .await
        }
    }
}

/// Parse the repeated `--legacy-lock-issuer SUBJECT=ISSUER` values.
///
/// Split on the **first** `=` only: a subject is an authenticated principal
/// identifier and an issuer is a URL, and a URL may legitimately contain `=`.
/// Splitting on the last one, or refusing a value with two, would reject a
/// well-formed issuer.
///
/// # Errors
/// A value with no `=`, an empty subject, an empty issuer, or two mappings for
/// one subject. Each refusal names the offending value, because an operator
/// passing several of these needs to know which one.
pub fn parse_legacy_lock_issuers(values: &[String]) -> Result<BackfillIssuerMap> {
    let mut map = BackfillIssuerMap::new();
    for value in values {
        let Some((subject, issuer)) = value.split_once('=') else {
            return Err(anyhow!(
                "--legacy-lock-issuer expects SUBJECT=ISSUER; '{value}' has no '='"
            ));
        };
        if subject.is_empty() {
            return Err(anyhow!(
                "--legacy-lock-issuer '{value}' has an empty subject; a legacy lock row is \
                 matched by its recorded subject"
            ));
        }
        if issuer.is_empty() {
            return Err(anyhow!(
                "--legacy-lock-issuer '{value}' has an empty issuer; the fenced store records \
                 ownership as an (issuer, subject) pair"
            ));
        }
        if let Some(existing) = map.insert(subject.to_owned(), issuer.to_owned())
            && existing != issuer
        {
            return Err(anyhow!(
                "--legacy-lock-issuer '{value}' maps subject '{subject}' to a second issuer; \
                 it was already mapped to '{existing}'"
            ));
        }
    }
    Ok(map)
}

/// The creation fingerprint recorded for a repository this backfill projects.
///
/// BLAKE3-256 over a domain-separated preimage in which **every** component is
/// length-prefixed, including the name, so no two distinct repositories can
/// frame to the same bytes by moving a byte across a boundary.
///
/// It names observed state, not a caller's intent. That is the whole reason it
/// carries [`BACKFILL_FINGERPRINT_VERSION`] rather than the governed create's
/// version 1.
#[must_use]
pub fn backfill_repository_fingerprint(
    repository_id: &[u8],
    name: &str,
    metadata_hash: &[u8],
    default_branch_id: &[u8],
) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(BACKFILL_REPOSITORY_DOMAIN_V1);
    framed(&mut hasher, repository_id);
    framed(&mut hasher, name.as_bytes());
    framed(&mut hasher, metadata_hash);
    framed(&mut hasher, default_branch_id);
    hasher.finalize().as_bytes().to_vec()
}

/// The creation fingerprint recorded for a branch this backfill projects.
///
/// A separate domain separator from the repository fingerprint, so a repository
/// and a branch that happen to carry the same component bytes cannot produce one
/// digest.
#[must_use]
pub fn backfill_branch_fingerprint(
    repository_id: &[u8],
    branch_id: &[u8],
    name: &str,
    metadata_hash: &[u8],
) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new();
    hasher.update(BACKFILL_BRANCH_DOMAIN_V1);
    framed(&mut hasher, repository_id);
    framed(&mut hasher, branch_id);
    framed(&mut hasher, name.as_bytes());
    framed(&mut hasher, metadata_hash);
    hasher.finalize().as_bytes().to_vec()
}

/// Absorb one component under an 8-byte big-endian length prefix.
fn framed(hasher: &mut blake3::Hasher, component: &[u8]) {
    hasher.update(&(component.len() as u64).to_be_bytes());
    hasher.update(component);
}

/// What one `cutover` invocation was asked to do.
struct CutoverOptions {
    dry_run: bool,
    force_release_legacy_locks: bool,
    issuers: BackfillIssuerMap,
}

/// The coordinator, its pool, and the resolved plugin configuration.
struct DomainOperatorContext {
    store: PostgresDomainStore,
    lock_coordinator: PostgresLockCoordinator,
    pool: Pool,
    plugin_config: toml::Value,
    mutable_store_mode: String,
    immutable_store_mode: String,
    lock_store_mode: Option<String>,
    auth_enabled: bool,
    auth_url_present: bool,
}

impl DomainOperatorContext {
    /// Open the coordinator and prove the same co-location server startup does.
    ///
    /// The co-location proof is not optional politeness. A CR-029 transaction
    /// writes its domain rows and the affected `lore_mutable` rows in one
    /// Postgres transaction, and this command's own residue scan and snapshot
    /// digests read `lore_mutable` through a separate pool. Both are only
    /// meaningful if every URL resolves to one physical database.
    async fn open(settings: &Settings) -> Result<Self> {
        if settings.mutable_store.mode != POSTGRES_MODE {
            return Err(anyhow!(
                "`loreserver domain` requires mutable_store.mode = postgres; effective mode is \
                 '{}'",
                settings.mutable_store.mode
            ));
        }
        let plugin_config =
            resolve_plugin_config_with_fallback(&settings.plugins, POSTGRES_MODE, "mutable_store")
                .ok_or_else(|| {
                    anyhow!(
                        "`loreserver domain` needs a [plugins.postgres] section for the cell \
                     database; none resolves for the mutable store"
                    )
                })?;

        let store = connect_domain_store(&plugin_config)
            .await
            .map_err(|error| anyhow!("Failed to open the Postgres domain coordinator: {error}"))?;

        for (label, store_type, mode) in [
            (
                "mutable store",
                "mutable_store",
                settings.mutable_store.mode.as_str(),
            ),
            (
                "immutable store",
                "immutable_store",
                settings.immutable_store.mode.as_str(),
            ),
            (
                "lock store",
                "lock_store",
                settings
                    .lock_store
                    .as_ref()
                    .map(|lock_store| lock_store.mode.as_str())
                    .unwrap_or_default(),
            ),
        ] {
            if mode != POSTGRES_MODE {
                continue;
            }
            let other =
                resolve_plugin_config_with_fallback(&settings.plugins, POSTGRES_MODE, store_type)
                    .ok_or_else(|| {
                    anyhow!(
                        "The {label} is in postgres mode but no [plugins.postgres] configuration \
                         resolves for it, so its co-location with the domain coordinator cannot \
                         be proven"
                    )
                })?;
            assert_domain_store_colocated(&store, label, &other)
                .await
                .map_err(|error| anyhow!("{error}"))?;
        }

        let pool = crate::event_relay::wiring::build_operator_pool(settings, OPERATOR_POOL_MAX)?;
        let lock_coordinator = store.lock_coordinator();
        let auth = settings.server.auth.as_ref();
        Ok(Self {
            store,
            lock_coordinator,
            pool,
            plugin_config,
            mutable_store_mode: settings.mutable_store.mode.clone(),
            immutable_store_mode: settings.immutable_store.mode.clone(),
            lock_store_mode: settings
                .lock_store
                .as_ref()
                .map(|lock_store| lock_store.mode.clone()),
            auth_enabled: auth.is_some_and(|auth| auth.jwk.is_some()),
            auth_url_present: settings
                .environment
                .as_ref()
                .and_then(|environment| environment.endpoint.as_ref())
                .and_then(|endpoint| endpoint.auth_url.as_ref())
                .is_some(),
        })
    }

    /// Read everything `status` reports, in one pass.
    async fn status(&self) -> Result<DomainStatusReport> {
        let domain = self
            .store
            .schema_state()
            .await
            .map_err(|error| anyhow!("Failed to read the domain schema state: {error}"))?;
        let lock = self
            .lock_coordinator
            .readiness()
            .await
            .map_err(|error| anyhow!("Failed to read SCHEMA-117 lock readiness: {error}"))?;
        let rows = self.row_counts().await?;
        Ok(DomainStatusReport {
            mutable_store_mode: self.mutable_store_mode.clone(),
            immutable_store_mode: self.immutable_store_mode.clone(),
            lock_store_mode: self.lock_store_mode.clone(),
            auth_enabled: self.auth_enabled,
            auth_url_present: self.auth_url_present,
            ready_for_enforcement: domain.ready_for_enforcement(),
            domain,
            lock,
            rows,
        })
    }

    /// The row counts a schema-state row alone cannot answer.
    async fn row_counts(&self) -> Result<RowCounts> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|error| anyhow!("Failed to check out an operator connection: {error}"))?;
        let row = client
            .query_one(
                "SELECT \
                   (SELECT count(*) FROM lore_domain_repositories WHERE state = $1)::bigint \
                       AS repositories_live, \
                   (SELECT count(*) FROM lore_domain_repositories WHERE state = $2)::bigint \
                       AS repositories_tombstoned, \
                   (SELECT count(*) FROM lore_domain_branches WHERE state = $1)::bigint \
                       AS branches_live, \
                   (SELECT count(*) FROM lore_domain_branches WHERE state = $2)::bigint \
                       AS branches_tombstoned",
                &[&schema::STATE_LIVE, &schema::STATE_TOMBSTONED],
            )
            .await
            .map_err(|error| anyhow!("Failed to count domain rows: {error}"))?;
        let locks = legacy_lock_counts(&client).await?;
        Ok(RowCounts {
            repositories_live: row.get("repositories_live"),
            repositories_tombstoned: row.get("repositories_tombstoned"),
            branches_live: row.get("branches_live"),
            branches_tombstoned: row.get("branches_tombstoned"),
            locks,
        })
    }

    /// Arm the cell, or report what arming it would do.
    async fn cutover(
        &self,
        settings: &Settings,
        options: CutoverOptions,
        json: bool,
    ) -> Result<()> {
        let before = self.status().await?;
        if options.dry_run {
            print_report(
                &dry_run_plan(&before, &options),
                dry_run_json(&before, &options),
                json,
            );
            return Ok(());
        }

        // The mutable store first, and not for tidiness: `DomainBackfill::verify`
        // reads `lore_mutable` to prove no domain row leads its projection, and
        // that table is created by this store's own `ensure_schema`. Backfilling
        // first fails with a bare `db error` naming neither the table nor the
        // ordering.
        step("opening the cell's Postgres mutable and immutable stores");
        let mutable: Arc<dyn MutableStore> = Arc::new(
            connect_mutable_store(&self.plugin_config)
                .await
                .map_err(|error| anyhow!("Failed to open the cell's mutable store: {error}"))?,
        );
        let immutable_config = resolve_plugin_config_with_fallback(
            &settings.plugins,
            POSTGRES_MODE,
            "immutable_store",
        )
        .ok_or_else(|| {
            anyhow!(
                "No [plugins.postgres] configuration resolves for the immutable store; a \
                 cutover reads repository and branch names out of their metadata blobs and \
                 cannot run without it"
            )
        })?;
        let immutable: Arc<dyn ImmutableStore> = Arc::new(
            connect_immutable_store(&immutable_config, None, None)
                .await
                .map_err(|error| anyhow!("Failed to open the cell's immutable store: {error}"))?,
        );

        step("installing SCHEMA-117 lock objects if absent");
        self.lock_coordinator
            .bootstrap()
            .await
            .map_err(|error| anyhow!("Failed to install the SCHEMA-117 lock schema: {error}"))?;

        // Now, and not next to the lock backfill it guards.
        //
        // A reviewer ran this against a cell holding one legacy lock row and
        // found the refusal firing AFTER the domain cutover marker was set and
        // enforcement was enabled — leaving the cell enforcement-ON and
        // fencing-OFF, the exact half-armed state in which a released client's
        // governed push is refused UNIMPLEMENTED, under a message reading
        // "nothing was changed". `postgres-cell-a` is a cell that has served
        // locks, so it would have been the first thing this command did to it.
        //
        // It cannot move ahead of `bootstrap` either: before SCHEMA-117 is
        // installed `lore_locks` exists without `owner_issuer`, so the probe
        // would report no legacy rows at all and the refusal would be skipped —
        // the same bug by a different route. Everything above this line is
        // `CREATE TABLE IF NOT EXISTS`-shaped DDL that arms nothing, so a
        // refusal here still leaves no lifecycle state changed.
        self.refuse_uncovered_legacy_locks(&options).await?;

        let verification = if before.ready_for_enforcement() {
            step("domain backfill is already at cutover; skipping run/verify/complete");
            None
        } else {
            step("walking this cell's repositories for the domain backfill");
            let source = CellBackfillSource::new(self.pool.clone(), immutable, mutable);
            let backfill = DomainBackfill::for_store(&self.store, &source);
            // A cell already at VERIFIED skips `run`, and this is a recovery
            // path rather than an optimisation. `mark_running` refuses to start
            // from VERIFIED — correctly, since re-driving projection writes
            // against a verified cell is not what a restart wants — so calling
            // `run` here would hard-error with nothing able to advance the
            // state. `complete` is transactional as of this change, so nothing
            // new can reach VERIFIED-without-CUTOVER; a cell stranded there by
            // an older build still can, and this is what gets it out.
            if before.domain.backfill_state == schema::BACKFILL_VERIFIED {
                step(
                    "domain backfill is already VERIFIED; resuming at verify/complete without \
                     re-driving projection writes",
                );
            } else {
                let projected = backfill
                    .run()
                    .await
                    .map_err(|error| anyhow!("Domain backfill failed: {error}"))?;
                step(&format!(
                    "domain backfill pass complete: {projected} repository(ies) projected"
                ));
            }
            let report = backfill
                .verify()
                .await
                .map_err(|error| anyhow!("Domain backfill verification failed: {error}"))?;
            log_verification(&report);
            backfill
                .complete(&report)
                .await
                .map_err(|error| anyhow!("Domain backfill cutover refused: {error}"))?;
            step("domain cutover marker set");
            Some(report)
        };

        let lock_report = self.arm_fenced_locks(&before, &options).await?;

        // Enforcement goes on LAST, after fenced routing is armed, and the order
        // is a safety property rather than a preference.
        //
        // The uncovered-issuer refusal above cannot catch every reason a legacy
        // lock row quarantines: the other two — the lock's repository or branch
        // is missing or tombstoned, or its namespace row is absent — are only
        // decidable against domain rows the domain backfill itself creates, so
        // they cannot be pre-checked. When one of them fires, the lock backfill
        // fails here. With enforcement already on that failure left the cell
        // enforcement-ON and fencing-OFF, where a released client's governed
        // push is refused UNIMPLEMENTED. With enforcement last, the same failure
        // leaves it enforcement-OFF, which is simply the legacy path this cell
        // was already on.
        //
        // The intermediate state this creates is the tolerable one: a cell at
        // CUTOVER with fenced routing armed and enforcement off boots cleanly
        // (`resolve_enforcement` reads the flag and takes the legacy path) and
        // keeps serving. It is not literally unchanged: a fenced lock acquire
        // needs a `lore_domain_lock_namespaces` row, which is created from
        // `lore_domain_branches` — so a branch created in this window, on the
        // legacy path, has no namespace row and a lock on it is refused
        // NotReady until the next cutover pass backfills it. A narrow window
        // that the next run closes, against a state the reverse order made
        // permanent.
        if before.domain.enforcement_enabled {
            step("domain enforcement is already on");
        } else {
            self.store
                .enable_enforcement()
                .await
                .map_err(|error| anyhow!("Failed to enable domain enforcement: {error}"))?;
            step("domain enforcement enabled");
        }

        let after = self.status().await?;
        // Arming is a database fact; filing a receipt additionally needs a
        // verifier this command cannot install. Saying so here is the difference
        // between an operator knowing the cell is half-configured and reading a
        // clean success while pushes keep taking the legacy path.
        if let Some(reason) = after.not_ready_reason() {
            step(&format!(
                "WARNING: cutover completed, but this cell still files no attempt receipt: {reason}"
            ));
        }
        print_report(
            &cutover_summary(&after, verification.as_ref(), lock_report.as_ref()),
            cutover_json(&after, verification.as_ref(), lock_report.as_ref()),
            json,
        );
        Ok(())
    }

    /// Convert this cell's legacy lock rows and arm fenced routing.
    ///
    /// Returns the backfill report when a pass ran, `None` when the cell was
    /// already complete.
    async fn arm_fenced_locks(
        &self,
        before: &DomainStatusReport,
        options: &CutoverOptions,
    ) -> Result<Option<BackfillReport>> {
        // `refuse_uncovered_legacy_locks` already ran, at the top of `cutover`,
        // before anything was written. It is deliberately NOT repeated here: a
        // second call would re-run the `--force-release-legacy-locks` delete
        // against rows the first call already handled.
        let report = if before.lock.backfill_state
            == lore_postgres::domain::locks::schema::BACKFILL_COMPLETE
            && before.lock.unfenced_rows == 0
            && before.lock.quarantined_rows == 0
        {
            step("SCHEMA-117 lock backfill is already complete");
            None
        } else {
            step("converting this cell's legacy lock rows");
            let report = self
                .lock_coordinator
                .backfill(&options.issuers)
                .await
                .map_err(|error| anyhow!("Legacy lock backfill failed: {error}"))?;
            step(&format!(
                "legacy lock backfill pass complete: {} converted, {} quarantined, complete: {}",
                report.converted,
                report.quarantined,
                yes_no(report.complete)
            ));
            if !report.complete {
                return Err(anyhow!(
                    "Legacy lock backfill did not complete: {} row(s) quarantined. A quarantined \
                     row has no reviewed issuer for its subject, or its repository or branch is \
                     gone. Supply --legacy-lock-issuer for the subjects involved, or \
                     --force-release-legacy-locks to release them",
                    report.quarantined
                ));
            }
            Some(report)
        };

        if before.lock.fencing_enabled {
            step("fenced lock routing is already armed");
        } else {
            // Leases stay off: nothing on the wire renews one, so a finite
            // expiry would drop a lock a working client still believes it
            // holds. `resolve_lock_fencing` refuses readiness on an armed lease
            // for the same reason, so passing `true` here would brick the boot.
            self.lock_coordinator
                .enable_fencing(false)
                .await
                .map_err(|error| anyhow!("Failed to arm fenced lock routing: {error}"))?;
            step("fenced lock routing armed (leases off)");
        }
        Ok(report)
    }

    /// Refuse, or release, legacy lock rows no reviewed issuer covers.
    ///
    /// P-030-3's precondition. The lock backfill quarantines a row whose subject
    /// has no reviewed issuer instead of converting it, and a quarantined row
    /// stops the cutover — so the honest place to decide is here, before
    /// anything is written, with the count in the message.
    async fn refuse_uncovered_legacy_locks(&self, options: &CutoverOptions) -> Result<()> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|error| anyhow!("Failed to check out an operator connection: {error}"))?;
        let scope = legacy_lock_scope(&client).await?;
        if scope == LegacyLockScope::Absent {
            // No `lore_locks` table at all: this cell has never served a lock,
            // so there is nothing legacy to cover.
            return Ok(());
        }
        let Some(subjects) = uncovered_legacy_subjects(&client, &options.issuers).await? else {
            return Ok(());
        };
        if subjects.is_empty() {
            return Ok(());
        }
        if !options.force_release_legacy_locks {
            let named: Vec<&str> = subjects.iter().take(5).map(String::as_str).collect();
            return Err(anyhow!(
                "{} legacy lock subject(s) on this cell have no reviewed issuer (first: {}). \
                 The fenced store records ownership as an (issuer, subject) pair and a legacy \
                 row carries only the subject, so these rows can be converted with \
                 --legacy-lock-issuer SUBJECT=ISSUER, or released outright with \
                 --force-release-legacy-locks. Cutover refused before any lifecycle state \
                 changed: enforcement and fenced routing are exactly as they were, and only \
                 idempotent schema DDL ran",
                subjects.len(),
                named.join(", ")
            ));
        }
        // The quarantine rows go with the locks, in one statement, and the
        // second arm clears two kinds of row rather than one.
        //
        // A quarantine row is evidence that one specific lock row could not be
        // converted, and `enable_fencing` refuses while any exists. Two ways
        // that becomes unrecoverable, both found by running it:
        //
        // * Releasing the lock and leaving its quarantine row behind. The next
        //   pass finds zero unfenced rows, one quarantined row, and refuses
        //   forever with nothing left to act on.
        // * A **ghost**: a quarantine row whose lock was released through the
        //   ordinary legacy `Unlock` path between two cutover attempts. Nothing
        //   in the lock backfill ever revisits it, because that only clears the
        //   quarantine of a row it converts.
        //
        // The `NOT EXISTS` arm sees `lore_locks` as it was at statement start,
        // which is what makes the two arms disjoint rather than overlapping:
        // a row this statement releases is matched by the `IN` arm, and a ghost
        // by the `NOT EXISTS` arm.
        let row = client
            .query_one(
                &format!(
                    "WITH released AS ( \
                         DELETE FROM lore_locks \
                          WHERE {} AND owner <> ALL($1) \
                      RETURNING repository, branch, hash \
                     ), cleared AS ( \
                         DELETE FROM lore_domain_lock_backfill_quarantine AS quarantine \
                          WHERE (quarantine.repository_id, quarantine.branch_id, \
                                 quarantine.resource_hash) \
                                IN (SELECT repository, branch, hash FROM released) \
                             OR NOT EXISTS ( \
                                    SELECT 1 FROM lore_locks AS live \
                                     WHERE live.repository = quarantine.repository_id \
                                       AND live.branch = quarantine.branch_id \
                                       AND live.hash = quarantine.resource_hash) \
                      RETURNING 1 \
                     ) \
                     SELECT (SELECT count(*) FROM released)::bigint AS released, \
                            (SELECT count(*) FROM cleared)::bigint  AS cleared",
                    scope.legacy_predicate()
                ),
                &[&covered_subjects(&options.issuers)],
            )
            .await
            .map_err(|error| anyhow!("Failed to release legacy lock rows: {error}"))?;
        let released: i64 = row.get("released");
        let cleared: i64 = row.get("cleared");
        step(&format!(
            "WARNING: --force-release-legacy-locks released {released} legacy lock row(s) across \
             {} uncovered subject(s) and cleared {cleared} quarantine row(s); any client still \
             holding one of these locks no longer holds it",
            subjects.len()
        ));
        Ok(())
    }
}

/// What this cell's `lore_locks` relation can tell us about legacy rows.
///
/// Three states, not two, and the middle one is the whole point. The table is
/// created by the legacy lock store's own `ensure_schema`; SCHEMA-117 adds the
/// fenced-authority columns later. Probing only for the table would run a query
/// naming `owner_issuer` against a pre-SCHEMA-117 table and fail with an
/// undefined-column error that reads like a code fault. Probing only for the
/// column would report a cell that has served locks for years as having none —
/// which is exactly what `--dry-run` did before this: it runs before
/// `bootstrap`, so on an unmigrated cell it printed "no lore_locks relation"
/// while the real run refused on those very rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LegacyLockScope {
    /// No `lore_locks` relation at all. This cell has never served a lock.
    Absent,
    /// The relation predates SCHEMA-117, so **every** row is a legacy row.
    Unfenced,
    /// SCHEMA-117 is installed: a legacy row is one with a NULL `owner_issuer`.
    Fenced,
}

impl LegacyLockScope {
    /// The `WHERE` clause selecting legacy rows in this scope.
    fn legacy_predicate(self) -> &'static str {
        match self {
            // Every row, because none carries fenced authority yet.
            Self::Unfenced => "TRUE",
            Self::Fenced => "owner_issuer IS NULL",
            // Never reached: the caller returns before building a query.
            Self::Absent => "FALSE",
        }
    }
}

/// Which of the three states this cell is in.
async fn legacy_lock_scope(client: &lore_postgres::pool::Client) -> Result<LegacyLockScope> {
    let row = client
        .query_one(
            "SELECT to_regclass('lore_locks') IS NOT NULL AS table_present, \
                    EXISTS ( \
                        SELECT 1 FROM information_schema.columns \
                         WHERE table_name = 'lore_locks' \
                           AND column_name = 'owner_issuer' \
                           AND table_schema = ANY(current_schemas(false))) AS column_present",
            &[],
        )
        .await
        .map_err(|error| anyhow!("Failed to probe the lock relation: {error}"))?;
    Ok(
        match (row.get("table_present"), row.get("column_present")) {
            (false, _) => LegacyLockScope::Absent,
            (true, false) => LegacyLockScope::Unfenced,
            (true, true) => LegacyLockScope::Fenced,
        },
    )
}

/// Legacy lock subjects on this cell that `issuers` does not cover.
///
/// `None` when the cell has no `lore_locks` relation at all, which is a routing
/// answer rather than damage: a Postgres-mode cell whose lock store has never
/// been opened has no lock rows to convert.
async fn uncovered_legacy_subjects(
    client: &lore_postgres::pool::Client,
    issuers: &BackfillIssuerMap,
) -> Result<Option<Vec<String>>> {
    let scope = legacy_lock_scope(client).await?;
    if scope == LegacyLockScope::Absent {
        return Ok(None);
    }
    let rows = client
        .query(
            &format!(
                "SELECT DISTINCT owner FROM lore_locks WHERE {} ORDER BY owner",
                scope.legacy_predicate()
            ),
            &[],
        )
        .await
        .map_err(|error| anyhow!("Failed to read legacy lock subjects: {error}"))?;
    let covered: BTreeSet<&String> = issuers.keys().collect();
    Ok(Some(
        rows.into_iter()
            .map(|row| row.get::<_, String>("owner"))
            .filter(|subject| !covered.contains(subject))
            .collect(),
    ))
}

/// The subjects `--legacy-lock-issuer` covers, as a SQL array argument.
fn covered_subjects(issuers: &BackfillIssuerMap) -> Vec<String> {
    issuers.keys().cloned().collect()
}

/// Fenced and unfenced legacy lock row counts, or `None` when the relation is
/// absent.
async fn legacy_lock_counts(client: &lore_postgres::pool::Client) -> Result<Option<LockRowCounts>> {
    let scope = legacy_lock_scope(client).await?;
    if scope == LegacyLockScope::Absent {
        return Ok(None);
    }
    let row = client
        .query_one(
            &format!(
                "SELECT count(*)::bigint AS total, \
                        count(*) FILTER (WHERE {})::bigint AS unfenced \
                   FROM lore_locks",
                scope.legacy_predicate()
            ),
            &[],
        )
        .await
        .map_err(|error| anyhow!("Failed to count lock rows: {error}"))?;
    let total: i64 = row.get("total");
    let unfenced: i64 = row.get("unfenced");
    Ok(Some(LockRowCounts {
        total,
        unfenced,
        fenced: total - unfenced,
    }))
}

/// Live and tombstoned domain rows, plus the lock rows when they exist.
struct RowCounts {
    repositories_live: i64,
    repositories_tombstoned: i64,
    branches_live: i64,
    branches_tombstoned: i64,
    locks: Option<LockRowCounts>,
}

/// Lock rows, split by whether they carry fenced authority yet.
struct LockRowCounts {
    total: i64,
    fenced: i64,
    unfenced: i64,
}

/// Everything `status` reports.
struct DomainStatusReport {
    mutable_store_mode: String,
    immutable_store_mode: String,
    lock_store_mode: Option<String>,
    auth_enabled: bool,
    auth_url_present: bool,
    ready_for_enforcement: bool,
    domain: lore_postgres::domain::DomainSchemaState,
    lock: LockFencingReadiness,
    rows: RowCounts,
}

impl DomainStatusReport {
    /// Whether this cell governs a mutation at all.
    ///
    /// Both halves, because either alone is a cell that cannot serve a governed
    /// push from a released client.
    fn armed(&self) -> bool {
        self.domain.enforcement_enabled && self.lock.fencing_enabled
    }

    /// Whether a released client's mutation on this cell actually files an
    /// attempt receipt.
    ///
    /// Reported separately from [`armed`](Self::armed), and this distinction is
    /// the whole reason WP-120's live proof failed the way it did. Arming is a
    /// database fact; reaching the receipt rail is additionally a configuration
    /// fact. `internal_admission_reason` returns `Ok(None)` — silently, and
    /// correctly — when this cell has no operation verifier, so a cell that is
    /// fully armed but carries no `[environment.endpoint] auth_url` keeps taking
    /// the legacy path and files nothing, with no error anywhere to say so.
    fn governed_mutation_ready(&self) -> bool {
        self.armed() && self.auth_enabled && self.auth_url_present
    }

    /// The one-line reason `governed_mutation_ready` is false, if it is.
    fn not_ready_reason(&self) -> Option<&'static str> {
        if !self.domain.enforcement_enabled {
            return Some(
                "domain enforcement is off: every mutation takes the legacy path. Run \
                 `loreserver domain cutover`",
            );
        }
        if !self.lock.fencing_enabled {
            return Some(
                "fenced lock routing is off: a governed branch push is refused UNIMPLEMENTED. \
                 Run `loreserver domain cutover`",
            );
        }
        if !self.auth_enabled {
            return Some(
                "JWT authentication is off: an internal admission needs a verified principal, \
                 so no receipt is filed. Configure [server.auth]",
            );
        }
        if !self.auth_url_present {
            return Some(
                "[environment.endpoint] auth_url is unset: with no operation verifier this cell \
                 admits nothing internally and files no receipt, silently. Set auth_url",
            );
        }
        None
    }

    fn ready_for_enforcement(&self) -> bool {
        self.ready_for_enforcement
    }

    fn render(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "cell armed:            {}\n\
             files attempt receipts: {}\n\
             mutable store mode:    {}\n\
             immutable store mode:  {}\n\
             lock store mode:       {}\n\
             jwt authentication:    {}\n\
             private auth_url:      {}\n",
            yes_no(self.armed()),
            yes_no(self.governed_mutation_ready()),
            self.mutable_store_mode,
            self.immutable_store_mode,
            self.lock_store_mode.as_deref().unwrap_or("<unset>"),
            yes_no(self.auth_enabled),
            yes_no(self.auth_url_present),
        ));
        match self.not_ready_reason() {
            Some(reason) => out.push_str(&format!("  why not: {reason}\n\n")),
            None => out.push('\n'),
        }
        out.push_str(&format!(
            "domain schema state (lore_domain_schema_state)\n\
             \x20 schema_version:      {}\n\
             \x20 backfill_version:    {}\n\
             \x20 backfill_state:      {} ({})\n\
             \x20 backfill_cursor:     {}\n\
             \x20 residue_classified:  {}\n\
             \x20 cutover_at:          {}\n\
             \x20 enforcement_enabled: {}\n\
             \x20 ready_for_enforcement: {}\n\
             \x20 database_identity:   {}\n\n",
            self.domain.schema_version,
            self.domain.backfill_version,
            self.domain.backfill_state,
            backfill_state_label(self.domain.backfill_state),
            self.domain
                .backfill_cursor
                .as_ref()
                .map_or_else(|| "<none>".to_owned(), hex::encode),
            yes_no(self.domain.residue_classified),
            self.domain
                .cutover_at
                .map_or_else(|| "<unset>".to_owned(), |_| "set".to_owned()),
            yes_no(self.domain.enforcement_enabled),
            yes_no(self.ready_for_enforcement),
            self.domain.database_identity,
        ));
        out.push_str(&format!(
            "lock fencing (SCHEMA-117)\n\
             \x20 provisioned:         {}\n\
             \x20 schema_version:      {} (compiled {})\n\
             \x20 backfill_state:      {} (complete is {})\n\
             \x20 fencing_enabled:     {}\n\
             \x20 lease_enabled:       {}\n\
             \x20 same_database:       {}\n\
             \x20 sequence_headroom:   {}\n\
             \x20 quarantined_rows:    {}\n\
             \x20 unfenced_rows:       {}\n\
             \x20 never_issued_token_rows: {}\n\n",
            yes_no(self.lock.provisioned),
            self.lock.schema_version,
            lore_postgres::domain::locks::schema::LOCK_SCHEMA_VERSION,
            self.lock.backfill_state,
            lore_postgres::domain::locks::schema::BACKFILL_COMPLETE,
            yes_no(self.lock.fencing_enabled),
            yes_no(self.lock.lease_enabled),
            yes_no(self.lock.same_database),
            yes_no(self.lock.sequence_headroom),
            self.lock.quarantined_rows,
            self.lock.unfenced_rows,
            self.lock.never_issued_token_rows,
        ));
        if self.lock.never_issued_token_rows > 0 {
            // CR-030 P-030-3. These rows are well formed and the cell is ready
            // with them present, so this is a note rather than a warning — but
            // an operator reading a lock count needs to know which of them
            // nobody can release except an administrator.
            // Scoped to the armed case on purpose. While fenced routing is off
            // the legacy store still serves every lock RPC and matches on the
            // row's plain owner text, so a converted row is releasable the
            // ordinary way in that window.
            out.push_str(&format!(
                "  note: {} converted lock row(s) record a never-issued ownership token. \
                 Once this cell is armed their owners cannot release them, and `ForceUnlock` \
                 by a principal holding the `owner` permission is the only way to clear one.\n\n",
                self.lock.never_issued_token_rows
            ));
        }
        out.push_str(&format!(
            "rows\n\
             \x20 domain repositories: {} live, {} tombstoned\n\
             \x20 domain branches:     {} live, {} tombstoned\n\
             \x20 lock rows:           {}\n",
            self.rows.repositories_live,
            self.rows.repositories_tombstoned,
            self.rows.branches_live,
            self.rows.branches_tombstoned,
            match &self.rows.locks {
                Some(locks) => format!(
                    "{} total, {} converted (fenced), {} legacy (unfenced)",
                    locks.total, locks.fenced, locks.unfenced
                ),
                None => "<no lore_locks relation on this cell>".to_owned(),
            },
        ));
        out
    }

    fn as_json(&self) -> Value {
        json!({
            "armed": self.armed(),
            "files_attempt_receipts": self.governed_mutation_ready(),
            "not_ready_reason": self.not_ready_reason(),
            "config": {
                "mutable_store_mode": self.mutable_store_mode,
                "immutable_store_mode": self.immutable_store_mode,
                "lock_store_mode": self.lock_store_mode,
                "jwt_authentication": self.auth_enabled,
                "auth_url_present": self.auth_url_present,
            },
            "domain": {
                "schema_version": self.domain.schema_version,
                "backfill_version": self.domain.backfill_version,
                "backfill_state": self.domain.backfill_state,
                "backfill_state_label": backfill_state_label(self.domain.backfill_state),
                "backfill_cursor": self.domain.backfill_cursor.as_ref().map(hex::encode),
                "residue_classified": self.domain.residue_classified,
                "cutover_at_set": self.domain.cutover_at.is_some(),
                "enforcement_enabled": self.domain.enforcement_enabled,
                "ready_for_enforcement": self.ready_for_enforcement,
                "database_identity": self.domain.database_identity,
            },
            "lock_fencing": {
                "provisioned": self.lock.provisioned,
                "schema_version": self.lock.schema_version,
                "compiled_schema_version":
                    lore_postgres::domain::locks::schema::LOCK_SCHEMA_VERSION,
                "backfill_state": self.lock.backfill_state,
                "fencing_enabled": self.lock.fencing_enabled,
                "lease_enabled": self.lock.lease_enabled,
                "same_database": self.lock.same_database,
                "sequence_headroom": self.lock.sequence_headroom,
                "quarantined_rows": self.lock.quarantined_rows,
                "unfenced_rows": self.lock.unfenced_rows,
                "never_issued_token_rows": self.lock.never_issued_token_rows,
            },
            "rows": {
                "domain_repositories_live": self.rows.repositories_live,
                "domain_repositories_tombstoned": self.rows.repositories_tombstoned,
                "domain_branches_live": self.rows.branches_live,
                "domain_branches_tombstoned": self.rows.branches_tombstoned,
                "lock_rows_total": self.rows.locks.as_ref().map(|locks| locks.total),
                "lock_rows_converted": self.rows.locks.as_ref().map(|locks| locks.fenced),
                "lock_rows_legacy": self.rows.locks.as_ref().map(|locks| locks.unfenced),
            },
        })
    }
}

/// The human-readable name of a `lore_domain_schema_state.backfill_state`.
fn backfill_state_label(state: i16) -> &'static str {
    match state {
        schema::BACKFILL_NOT_STARTED => "NOT_STARTED",
        schema::BACKFILL_RUNNING => "RUNNING",
        schema::BACKFILL_VERIFIED => "VERIFIED",
        schema::BACKFILL_CUTOVER => "CUTOVER",
        _ => "UNKNOWN",
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

/// What a real run would do, from the state a dry run just read.
fn dry_run_plan(before: &DomainStatusReport, options: &CutoverOptions) -> String {
    let mut out = before.render();
    out.push_str("\ndry run: no row was changed. A real run would:\n");
    if before.ready_for_enforcement() {
        out.push_str("  - skip the domain backfill (already at cutover)\n");
    } else {
        out.push_str(
            "  - run, verify and complete the domain backfill over this cell's real \
             repositories\n",
        );
    }
    if before.domain.enforcement_enabled {
        out.push_str("  - skip enabling enforcement (already on)\n");
    } else {
        out.push_str("  - enable domain enforcement\n");
    }
    match &before.rows.locks {
        Some(locks) if locks.unfenced > 0 => out.push_str(&format!(
            "  - convert {} legacy lock row(s); {} subject mapping(s) supplied, \
             --force-release-legacy-locks {}\n",
            locks.unfenced,
            options.issuers.len(),
            if options.force_release_legacy_locks {
                "given"
            } else {
                "not given"
            }
        )),
        _ => out.push_str("  - run the lock backfill over no legacy rows\n"),
    }
    if before.lock.fencing_enabled {
        out.push_str("  - skip arming fenced lock routing (already armed)\n");
    } else {
        out.push_str("  - arm fenced lock routing with leases off\n");
    }
    out
}

fn dry_run_json(before: &DomainStatusReport, options: &CutoverOptions) -> Value {
    json!({
        "dry_run": true,
        "status": before.as_json(),
        "would": {
            "run_domain_backfill": !before.ready_for_enforcement(),
            "enable_enforcement": !before.domain.enforcement_enabled,
            "legacy_lock_rows": before.rows.locks.as_ref().map(|locks| locks.unfenced),
            "issuer_mappings": options.issuers.len(),
            "force_release_legacy_locks": options.force_release_legacy_locks,
            "arm_fenced_lock_routing": !before.lock.fencing_enabled,
        },
    })
}

/// The report a completed `cutover` prints.
fn cutover_summary(
    after: &DomainStatusReport,
    verification: Option<&VerificationReport>,
    lock_report: Option<&BackfillReport>,
) -> String {
    let mut out = String::new();
    match verification {
        Some(report) => out.push_str(&format!(
            "domain backfill: {} repositories, {} branches projected; {} missing projection \
             rows; {} residue row(s); {} name-map mismatch(es)\n",
            report.repositories_projected,
            report.branches_projected,
            report.missing_projection_rows,
            report.residue.len(),
            report.name_map_mismatches.len(),
        )),
        None => out.push_str("domain backfill: already at cutover, no pass run\n"),
    }
    match lock_report {
        Some(report) => out.push_str(&format!(
            "lock backfill:   {} row(s) converted, {} quarantined, complete: {}\n\n",
            report.converted,
            report.quarantined,
            yes_no(report.complete)
        )),
        None => out.push_str("lock backfill:   already complete, no pass run\n\n"),
    }
    out.push_str(&after.render());
    // `compiled_features` runs once, when the gRPC endpoint is built. A cell
    // armed while it is running keeps advertising the capability set it booted
    // with, so a client asking `ServerInfo` still sees no
    // `domain_operation_receipt_v2` while receipts are already being filed —
    // the inverse of the mismatch this change fixed, and just as confusing.
    out.push_str(
        "\nRestart this cell to pick up the change: its ServerInfo capability list is built \
         once at boot, so domain_operation_receipt_v2 stays unadvertised until it is.\n",
    );
    out
}

fn cutover_json(
    after: &DomainStatusReport,
    verification: Option<&VerificationReport>,
    lock_report: Option<&BackfillReport>,
) -> Value {
    json!({
        "dry_run": false,
        "domain_backfill": verification.map(|report| json!({
            "repositories_projected": report.repositories_projected,
            "branches_projected": report.branches_projected,
            "missing_projection_rows": report.missing_projection_rows,
            "residue_rows": report.residue.len(),
            "delete_residue": residue_count(report, ResidueClass::DeleteResidue),
            "orphaned_branch_rows": residue_count(report, ResidueClass::OrphanedBranchRow),
            "foreign_domain_key_writes":
                residue_count(report, ResidueClass::ForeignDomainKeyWrite),
            "name_map_mismatches": report.name_map_mismatches.len(),
        })),
        "lock_backfill": lock_report.map(|report| json!({
            "converted": report.converted,
            "quarantined": report.quarantined,
            "complete": report.complete,
        })),
        "status": after.as_json(),
    })
}

fn residue_count(report: &VerificationReport, class: ResidueClass) -> usize {
    report
        .residue
        .iter()
        .filter(|(_, observed)| *observed == class)
        .count()
}

/// Log the verification report before the cutover marker is set.
///
/// Every class separately, because they mean different things: delete residue
/// and orphaned branch rows are expected on any cell that has served a delete,
/// while a foreign domain-key write is the one class `complete` refuses on, and
/// an operator reading a single total cannot tell which they have.
fn log_verification(report: &VerificationReport) {
    step(&format!(
        "domain backfill verification: {} repositories, {} branches, \
         {} missing projection rows, {} delete residue, {} orphaned branch rows, \
         {} foreign domain-key writes, {} name-map mismatches",
        report.repositories_projected,
        report.branches_projected,
        report.missing_projection_rows,
        residue_count(report, ResidueClass::DeleteResidue),
        residue_count(report, ResidueClass::OrphanedBranchRow),
        residue_count(report, ResidueClass::ForeignDomainKeyWrite),
        report.name_map_mismatches.len(),
    ));
    for repository_id in &report.name_map_mismatches {
        step(&format!(
            "WARNING: repository {}'s metadata name does not resolve through the cell's name \
             map; it is projected without a live domain name row",
            hex::encode(repository_id)
        ));
    }
}

/// Print to stdout in exactly one shape.
///
/// Maintenance CLI contract: with `--json` stdout holds one JSON object and
/// nothing else, so a deployment script can parse it without depending on the
/// tracing format.
fn print_report(text: &str, value: Value, json: bool) {
    if json {
        println!("{value}");
    } else {
        println!("{text}");
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn a_backfill_fingerprint_is_thirty_two_deterministic_bytes() {
        let first = backfill_repository_fingerprint(&[1u8; 16], "alpha", &[2u8; 32], &[3u8; 16]);
        let second = backfill_repository_fingerprint(&[1u8; 16], "alpha", &[2u8; 32], &[3u8; 16]);
        assert_eq!(first.len(), 32);
        assert_eq!(first, second);
    }

    /// Every component must move the digest. A component absorbed into the
    /// preimage but not actually varied by the caller would look identical to
    /// one that is not absorbed at all.
    #[test]
    fn every_repository_component_changes_the_fingerprint() {
        let base = backfill_repository_fingerprint(&[1u8; 16], "alpha", &[2u8; 32], &[3u8; 16]);
        for (label, other) in [
            (
                "repository id",
                backfill_repository_fingerprint(&[9u8; 16], "alpha", &[2u8; 32], &[3u8; 16]),
            ),
            (
                "name",
                backfill_repository_fingerprint(&[1u8; 16], "beta", &[2u8; 32], &[3u8; 16]),
            ),
            (
                "metadata hash",
                backfill_repository_fingerprint(&[1u8; 16], "alpha", &[9u8; 32], &[3u8; 16]),
            ),
            (
                "default branch",
                backfill_repository_fingerprint(&[1u8; 16], "alpha", &[2u8; 32], &[9u8; 16]),
            ),
        ] {
            assert_ne!(base, other, "{label} must change the fingerprint");
        }
    }

    #[test]
    fn every_branch_component_changes_the_fingerprint() {
        let base = backfill_branch_fingerprint(&[1u8; 16], &[2u8; 16], "main", &[3u8; 32]);
        for (label, other) in [
            (
                "repository id",
                backfill_branch_fingerprint(&[9u8; 16], &[2u8; 16], "main", &[3u8; 32]),
            ),
            (
                "branch id",
                backfill_branch_fingerprint(&[1u8; 16], &[9u8; 16], "main", &[3u8; 32]),
            ),
            (
                "name",
                backfill_branch_fingerprint(&[1u8; 16], &[2u8; 16], "trunk", &[3u8; 32]),
            ),
            (
                "metadata hash",
                backfill_branch_fingerprint(&[1u8; 16], &[2u8; 16], "main", &[9u8; 32]),
            ),
        ] {
            assert_ne!(base, other, "{label} must change the fingerprint");
        }
    }

    /// Length prefixing, measured rather than asserted: two different splits of
    /// the same concatenated bytes must not collide. A naive implementation that
    /// simply concatenated its components would pass every test above and fail
    /// this one.
    #[test]
    fn a_component_boundary_cannot_be_moved_without_changing_the_digest() {
        let left = backfill_repository_fingerprint(&[1u8; 16], "ab", &[2u8; 32], &[3u8; 16]);
        let right = backfill_repository_fingerprint(&[1u8; 16], "a", &[2u8; 32], &[3u8; 16]);
        assert_ne!(left, right);

        let branch_left = backfill_branch_fingerprint(&[1u8; 16], &[2u8; 16], "ab", &[3u8; 32]);
        let branch_right = backfill_branch_fingerprint(&[1u8; 16], &[2u8; 16], "a", &[3u8; 32]);
        assert_ne!(branch_left, branch_right);
    }

    /// The two families must not share a preimage space.
    #[test]
    fn repository_and_branch_fingerprints_are_domain_separated() {
        let repository = backfill_repository_fingerprint(&[1u8; 16], "x", &[2u8; 32], &[3u8; 16]);
        let branch = backfill_branch_fingerprint(&[1u8; 16], &[3u8; 16], "x", &[2u8; 32]);
        assert_ne!(repository, branch);
    }

    /// A backfilled row must never be able to satisfy a governed create's
    /// exact-retry comparison, which checks the digest AND the version.
    #[test]
    fn the_backfill_fingerprint_version_is_not_the_governed_create_version() {
        // The schema's own `creation_fingerprint_version >= 1` CHECK is enforced
        // by Postgres and exercised by the live tier; asserting it against a
        // constant here would be an assertion that cannot fail. What this test
        // owns is the one thing no CHECK can express: that the version differs
        // from the governed create's.
        assert_ne!(
            BACKFILL_FINGERPRINT_VERSION, 1,
            "version 1 is the governed create's canonical-intent digest, and the coordinator's \
             exact-retry check compares digest AND version — a backfilled row sharing the \
             version could be matched by a create that never happened"
        );
    }

    #[test]
    fn an_issuer_mapping_splits_on_the_first_equals_only() {
        let parsed = parse_legacy_lock_issuers(&["sub=https://issuer/?a=b".to_owned()])
            .expect("an issuer containing '=' is well formed");
        assert_eq!(
            parsed.get("sub").map(String::as_str),
            Some("https://issuer/?a=b")
        );
    }

    #[test]
    fn each_malformed_issuer_mapping_names_the_offending_value() {
        for value in ["nosign", "=issuer", "subject="] {
            let error = parse_legacy_lock_issuers(&[value.to_owned()])
                .expect_err("a malformed mapping must be refused");
            assert!(
                error.to_string().contains(value),
                "the refusal must name '{value}', got: {error}"
            );
        }
    }

    #[test]
    fn one_subject_cannot_be_mapped_to_two_issuers() {
        let error = parse_legacy_lock_issuers(&["a=one".to_owned(), "a=two".to_owned()])
            .expect_err("a conflicting mapping must be refused");
        assert!(error.to_string().contains("one"), "got: {error}");
        let repeated = parse_legacy_lock_issuers(&["a=one".to_owned(), "a=one".to_owned()])
            .expect("an identical repeat is not a conflict");
        assert_eq!(repeated.len(), 1);
    }

    #[test]
    fn several_mappings_collect() {
        let parsed = parse_legacy_lock_issuers(&["a=one".to_owned(), "b=two".to_owned()])
            .expect("two distinct mappings are well formed");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed.get("b").map(String::as_str), Some("two"));
    }

    #[test]
    fn every_backfill_state_has_its_own_label() {
        let labels = [
            (schema::BACKFILL_NOT_STARTED, "NOT_STARTED"),
            (schema::BACKFILL_RUNNING, "RUNNING"),
            (schema::BACKFILL_VERIFIED, "VERIFIED"),
            (schema::BACKFILL_CUTOVER, "CUTOVER"),
        ];
        let mut seen = BTreeSet::new();
        for (state, expected) in labels {
            assert_eq!(backfill_state_label(state), expected);
            assert!(seen.insert(expected), "labels must be distinct: {expected}");
        }
        assert_eq!(backfill_state_label(99), "UNKNOWN");
    }

    /// A fully armed, fully configured cell.
    fn ready_report() -> DomainStatusReport {
        DomainStatusReport {
            mutable_store_mode: POSTGRES_MODE.to_owned(),
            immutable_store_mode: POSTGRES_MODE.to_owned(),
            lock_store_mode: Some(POSTGRES_MODE.to_owned()),
            auth_enabled: true,
            auth_url_present: true,
            ready_for_enforcement: true,
            domain: lore_postgres::domain::DomainSchemaState {
                schema_version: 1,
                backfill_version: 1,
                backfill_state: schema::BACKFILL_CUTOVER,
                backfill_cursor: None,
                residue_classified: true,
                cutover_at: Some(std::time::SystemTime::UNIX_EPOCH),
                enforcement_enabled: true,
                database_identity: "identity".to_owned(),
            },
            lock: LockFencingReadiness {
                provisioned: true,
                schema_version: lore_postgres::domain::locks::schema::LOCK_SCHEMA_VERSION,
                backfill_state: lore_postgres::domain::locks::schema::BACKFILL_COMPLETE,
                fencing_enabled: true,
                lease_enabled: false,
                same_database: true,
                sequence_headroom: true,
                quarantined_rows: 0,
                unfenced_rows: 0,
                never_issued_token_rows: 0,
            },
            rows: RowCounts {
                repositories_live: 1,
                repositories_tombstoned: 0,
                branches_live: 1,
                branches_tombstoned: 0,
                locks: None,
            },
        }
    }

    /// WP-120's actual failure: the dev cell would have reported "armed" while
    /// filing no receipt at all, because `[environment.endpoint] auth_url` was
    /// unset and `internal_admission_reason` answers `Ok(None)` for that
    /// silently. Each missing piece must name itself.
    #[test]
    fn each_missing_piece_of_the_receipt_path_names_itself() {
        let ready = ready_report();
        assert!(ready.armed());
        assert!(ready.governed_mutation_ready());
        assert_eq!(ready.not_ready_reason(), None);

        let mut no_enforcement = ready_report();
        no_enforcement.domain.enforcement_enabled = false;
        assert!(!no_enforcement.armed());
        assert!(
            no_enforcement
                .not_ready_reason()
                .is_some_and(|reason| reason.contains("enforcement is off")),
            "got {:?}",
            no_enforcement.not_ready_reason()
        );

        let mut no_fencing = ready_report();
        no_fencing.lock.fencing_enabled = false;
        assert!(!no_fencing.armed());
        assert!(
            no_fencing
                .not_ready_reason()
                .is_some_and(|reason| reason.contains("fenced lock routing is off")),
            "got {:?}",
            no_fencing.not_ready_reason()
        );

        let mut no_auth = ready_report();
        no_auth.auth_enabled = false;
        assert!(
            no_auth.armed(),
            "the database facts are unchanged, so the cell is still armed"
        );
        assert!(!no_auth.governed_mutation_ready());
        assert!(
            no_auth
                .not_ready_reason()
                .is_some_and(|reason| reason.contains("JWT authentication is off")),
            "got {:?}",
            no_auth.not_ready_reason()
        );

        let mut no_auth_url = ready_report();
        no_auth_url.auth_url_present = false;
        assert!(
            no_auth_url.armed(),
            "an armed cell with no verifier still reads as armed; that is the trap"
        );
        assert!(!no_auth_url.governed_mutation_ready());
        assert!(
            no_auth_url
                .not_ready_reason()
                .is_some_and(|reason| reason.contains("auth_url is unset")),
            "got {:?}",
            no_auth_url.not_ready_reason()
        );
    }

    /// The rendered report must carry both verdicts and the reason, so an
    /// operator reading stdout sees what the JSON carries.
    #[test]
    fn the_rendered_report_separates_armed_from_files_receipts() {
        let mut report = ready_report();
        report.auth_url_present = false;
        let rendered = report.render();
        assert!(rendered.contains("cell armed:            yes"));
        assert!(rendered.contains("files attempt receipts: no"));
        assert!(rendered.contains("auth_url is unset"));

        let json = report.as_json();
        assert_eq!(json["armed"], serde_json::Value::Bool(true));
        assert_eq!(
            json["files_attempt_receipts"],
            serde_json::Value::Bool(false)
        );
        assert!(json["not_ready_reason"].is_string());
    }

    #[test]
    fn covered_subjects_are_the_mapped_ones() {
        let map = BTreeMap::from([
            ("a".to_owned(), "one".to_owned()),
            ("b".to_owned(), "two".to_owned()),
        ]);
        assert_eq!(covered_subjects(&map), vec!["a".to_owned(), "b".to_owned()]);
        assert!(covered_subjects(&BackfillIssuerMap::new()).is_empty());
    }
}

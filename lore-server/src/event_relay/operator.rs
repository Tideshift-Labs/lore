// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-032's operator command surface (WP-119 Phase 8).
//!
//! `loreserver outbox <status|inspect|replay|requeue-dead-letter|obsolete>`.
//! Each subcommand loads the same settings a serving `loreserver` would, proves
//! the same Postgres-mode and cell preconditions, runs exactly one bounded
//! operation against `lore_postgres`'s [`operator`] module, prints, and exits.
//! No endpoint is bound, no relay worker starts, and nothing is published.
//!
//! # Why a subcommand rather than another `--flag`
//!
//! The existing maintenance precedent on this binary is
//! `--rebuild-postgres-metering`, a bare boolean on [`crate::server::Cli`]. It
//! is one operation with no arguments, so a flag carries it. This surface is
//! five operations with their own required arguments, several of which
//! (`--actor`, `--reason`, `--limit`) mean different things per operation, and
//! flattening them onto the root `Cli` would make every one of them optional
//! and every combination parseable. A `clap` subcommand makes the
//! actor-and-reason requirement on a disposition a parse error instead of a
//! runtime check, which is the difference between an operator being told what
//! they forgot before anything runs and after.
//!
//! The root `Cli`'s existing shape is unchanged and the subcommand is optional,
//! so `loreserver` with no arguments still starts a server exactly as before.
//!
//! # Every command is scoped to the configured cell
//!
//! CR-032: "Replay and recovery are scoped to the configured cell and
//! repository range. No command accepts an arbitrary subject or cross-cell
//! destination." There is deliberately **no `--cell` flag**. The cell comes
//! from `[plugins.remote].cell_id`, the same value the producers derive an
//! idempotency key under and the relay publishes under, so an operator cannot
//! point a command at another cell even by mistake — and the store-side
//! functions require the identity as an argument they have no default for.
//!
//! # What `status` reports, and what it deliberately cannot
//!
//! `lore_postgres`'s [`operator::status`] returns backlog, schema state,
//! membership, and what the checkpoint vector proves. It holds no thresholds.
//! This module applies the cell's configured [`EventRelayConfig`] bounds to
//! those facts.
//!
//! The result is the **backlog-derived half** of the relay's readiness facets,
//! and it is not the same answer `/event_readiness` gives. It cannot be. The
//! live facets in [`super::readiness`] also depend on `loop_running` and on
//! whether the last backlog observation has gone stale, and both of those are
//! properties of a **running worker in another process** that this command has
//! no way to observe. A cell whose relay loop is dead reports every backlog
//! bound satisfied here, because a dead loop stops adding to the backlog.
//!
//! So this output is labelled `backlog facets` rather than `readiness`, and the
//! live answer is `/event_readiness` on the running process. Reporting these as
//! readiness would be the same false green the relay's own
//! fail-closed-on-silence rule exists to prevent — a reviewer caught exactly
//! that claim in an earlier draft of this file.

use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use anyhow::Context as _;
use anyhow::Result;
use anyhow::anyhow;
use clap::Args;
use clap::Subcommand;
use lore_postgres::domain::outbox::EvaluationBlock;
use lore_postgres::domain::outbox::operator;
use lore_postgres::domain::outbox::relay::DeadLetterOutcome;
use lore_postgres::domain::outbox::relay::OutboxRow;
use lore_postgres::pool::Pool;
use serde_json::Value;
use serde_json::json;
use uuid::Uuid;

use crate::event_relay::config::EventRelayConfig;
use crate::event_relay::evaluator_task::block_label;
use crate::plugins::remote_notification::RemoteNotificationConfig;
use crate::settings::Settings;

/// The `remote` plugin table's registry name, which is also the `[notification]
/// mode` the relay requires.
const REMOTE_NOTIFICATION_MODE: &str = "remote";

/// The backlog-derived half of the relay's facets: what this command can decide
/// from the store's facts plus this cell's configured bounds, and nothing more.
///
/// Two things the live facets have are absent here, and their absence is the
/// whole reason this type is not called `Readiness`:
///
/// * **`loop_running` and observation staleness.** Properties of a worker in
///   another process. A dead loop satisfies every bound below, because a dead
///   loop stops adding to the backlog.
/// * **The durable-receiver facet.** The running receiver's own liveness, which
///   a separate process cannot observe without asserting something it has not
///   checked.
///
/// `PartialEq` so a test can assert one against
/// [`super::readiness::ReadinessSnapshot`]'s corresponding fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Facets {
    /// Oldest-unpublished age is inside `max_oldest_unpublished`.
    relay_ready: bool,
    /// No dead letter awaits an operator disposition.
    ///
    /// Matches [`super::readiness`]'s own rule, which depends on the dead-letter
    /// count alone and **not** on the relay facet: a dead letter is an
    /// unresolved correctness incident whether or not the backlog is healthy.
    /// An earlier draft here `&&`-ed it with `relay_ready` and so reported a
    /// different verdict than the live surface for the same cell.
    event_ready: bool,
    /// Every admission limit is satisfied.
    admission_open: bool,
}

/// Connections one operator command needs.
///
/// One. Every command is a single bounded operation on one client, and the
/// process exits when it finishes. Sized apart from the serving relay's own
/// pool on purpose: this binary invocation is not a relay and must not look
/// like one to the cell's connection budget.
const OPERATOR_POOL_MAX: u32 = 1;

/// The default inspection and replay row bound.
///
/// CR-032's maximum, because an operator who did not name a bound wants the
/// whole bounded page rather than an arbitrary fraction of it, and the bound is
/// what makes the page safe.
const DEFAULT_ROW_LIMIT: i64 = operator::MAX_INSPECT_ROWS;

/// The default replay window, in hours. CR-032's maximum, same reasoning.
const DEFAULT_REPLAY_WINDOW_HOURS: u64 = 24;

/// A maintenance operation that runs instead of serving.
#[derive(Debug, Subcommand)]
pub enum MaintenanceCommand {
    /// Inspect and recover this cell's CR-032 transactional event outbox.
    Outbox {
        /// The operation to run.
        #[command(subcommand)]
        command: OutboxCommand,
    },
}

/// The bounded operator recovery surface CR-032 specifies.
#[derive(Debug, Subcommand)]
pub enum OutboxCommand {
    /// Report backlog, schema state, membership, and the backlog-derived
    /// facets. A running relay's live readiness is on its /event_readiness.
    Status {
        /// Print one JSON object instead of the human-readable report.
        #[arg(long)]
        json: bool,
    },
    /// List outbox rows for one repository, one event, or the parked
    /// dead-letter queue.
    Inspect {
        #[command(flatten)]
        target: InspectTarget,
        /// Maximum rows to list. CR-032 caps this at 1,000.
        #[arg(long, default_value_t = DEFAULT_ROW_LIMIT)]
        limit: i64,
        /// Print JSON instead of the human-readable listing.
        #[arg(long)]
        json: bool,
    },
    /// Return broker-accepted rows to pending with their original keys.
    Replay {
        /// Only this repository, as 32 hex characters.
        #[arg(long, value_name = "HEX")]
        repository: Option<String>,
        /// How far back to reach. CR-032 caps this at 24 hours.
        #[arg(long, default_value_t = DEFAULT_REPLAY_WINDOW_HOURS)]
        window_hours: u64,
        /// Maximum rows. CR-032 caps this at 1,000; a larger range paginates
        /// by running the command again.
        #[arg(long, default_value_t = DEFAULT_ROW_LIMIT)]
        limit: i64,
        /// Who is ordering this replay. Recorded on every row it moves.
        #[arg(long)]
        actor: String,
        /// Why. Recorded on every row it moves.
        #[arg(long)]
        reason: String,
        /// Print JSON instead of the human-readable summary.
        #[arg(long)]
        json: bool,
    },
    /// Return one parked dead letter to pending.
    RequeueDeadLetter {
        /// The dead letter's event ID.
        #[arg(long, value_name = "UUID")]
        event: Uuid,
        /// Who is ordering the requeue.
        #[arg(long)]
        actor: String,
        /// Why.
        #[arg(long)]
        reason: String,
    },
    /// Mark one parked dead letter obsolete, with proof of the authoritative
    /// state that makes it obsolete. The evidence row is never deleted.
    Obsolete {
        /// The dead letter's event ID.
        #[arg(long, value_name = "UUID")]
        event: Uuid,
        /// Who is ordering the disposition.
        #[arg(long)]
        actor: String,
        /// Why.
        #[arg(long)]
        reason: String,
        /// The authoritative state checked, in the operator's own words.
        /// CR-032 requires this alongside the reason, so it is required here.
        #[arg(long)]
        proof: String,
    },
}

/// What `inspect` is pointed at. Exactly one, enforced by `clap` at parse time
/// rather than by a runtime check that could be forgotten.
#[derive(Debug, Args)]
#[group(required = true, multiple = false)]
pub struct InspectTarget {
    /// One repository, as 32 hex characters.
    #[arg(long, value_name = "HEX")]
    pub repository: Option<String>,
    /// One event ID. Reports the live row, the terminal evidence row, or both.
    #[arg(long, value_name = "UUID")]
    pub event: Option<Uuid>,
    /// This cell's parked dead-letter queue, oldest failure first.
    #[arg(long)]
    pub dead_letters: bool,
}

/// Run one maintenance command against the configured cell.
///
/// # Errors
/// A configuration refusal (not Postgres mode, no `[plugins.remote]`), a
/// database failure, or a bound this crate refuses rather than clamps.
pub async fn run(command: &MaintenanceCommand, settings: &Settings) -> Result<()> {
    let MaintenanceCommand::Outbox { command } = command;
    let context = OperatorContext::open(settings)?;
    context.run(command).await
}

/// The cell identity, pool, and thresholds every command shares.
struct OperatorContext {
    cell_id: String,
    pool: Pool,
    config: EventRelayConfig,
}

impl OperatorContext {
    /// Resolve the configured cell and open one connection to its database.
    ///
    /// Deliberately **not** gated on `[outbox_relay] enabled`. A disabled relay
    /// is precisely the state an operator is investigating when a cell stops
    /// publishing, and refusing to report on it would make the surface useless
    /// at the moment it is most needed. What is required is a cell that has an
    /// outbox at all: Postgres mode, and a `[plugins.remote]` table whose
    /// `cell_id` is present and grammar-checked by its own parser.
    fn open(settings: &Settings) -> Result<Self> {
        if settings.mutable_store.mode != "postgres" {
            return Err(anyhow!(
                "`loreserver outbox` requires mutable_store.mode = postgres; effective mode is \
                 '{}'",
                settings.mutable_store.mode
            ));
        }
        let table = settings
            .plugins
            .get(REMOTE_NOTIFICATION_MODE)
            .ok_or_else(|| {
                anyhow!(
                    "`loreserver outbox` needs the [plugins.remote] section for this cell's \
                     identity; it is absent"
                )
            })?;
        let remote = RemoteNotificationConfig::parse(table)
            .map_err(|error| anyhow!("Invalid [plugins.remote] configuration: {error}"))?;

        // The relay's own validated bounds when the section is present, its
        // reviewed defaults otherwise. Either way the thresholds this command
        // reports against are the ones a serving process would use, never a
        // second set invented here.
        let config =
            EventRelayConfig::from_settings(&settings.outbox_relay.clone().unwrap_or_default())
                .map_err(|error| anyhow!("Invalid [outbox_relay] configuration: {error}"))?;

        let pool = crate::event_relay::wiring::build_operator_pool(settings, OPERATOR_POOL_MAX)?;

        Ok(Self {
            cell_id: remote.cell_id,
            pool,
            config,
        })
    }

    async fn run(&self, command: &OutboxCommand) -> Result<()> {
        match command {
            OutboxCommand::Status { json } => self.status(*json).await,
            OutboxCommand::Inspect {
                target,
                limit,
                json,
            } => self.inspect(target, *limit, *json).await,
            OutboxCommand::Replay {
                repository,
                window_hours,
                limit,
                actor,
                reason,
                json,
            } => {
                self.replay(
                    repository.as_deref(),
                    *window_hours,
                    *limit,
                    actor,
                    reason,
                    *json,
                )
                .await
            }
            OutboxCommand::RequeueDeadLetter {
                event,
                actor,
                reason,
            } => self.requeue_dead_letter(*event, actor, reason).await,
            OutboxCommand::Obsolete {
                event,
                actor,
                reason,
                proof,
            } => self.mark_obsolete(*event, actor, reason, proof).await,
        }
    }

    async fn client(&self) -> Result<lore_postgres::pool::Client> {
        self.pool
            .get()
            .await
            .context("could not take a connection to the cell database")
    }

    // -----------------------------------------------------------------------
    // status
    // -----------------------------------------------------------------------

    async fn status(&self, as_json: bool) -> Result<()> {
        let mut client = self.client().await?;
        let status = operator::status(&mut client, &self.cell_id).await?;
        let backlog = &status.backlog;

        // The two facets this command can answer for itself, applying the
        // cell's configured bounds to the facts the store returned. The
        // durable-receiver facet is deliberately absent: it is the running
        // receiver's own liveness, and a separate process cannot observe it
        // without asserting something it has not checked.
        // A cell with no outbox schema has no facts to decide a facet on, and
        // reporting "ready" from an all-zero backlog it never probed would be
        // the same false green a serving relay's fail-closed-on-silence rule
        // exists to prevent. `None` here prints and serialises as unknown.
        let facets = status.schema_state.as_ref().map(|_| {
            let oldest_age = backlog.oldest_pending_age.unwrap_or(Duration::ZERO);
            let relay_ready = oldest_age <= self.config.max_oldest_unpublished;
            Facets {
                relay_ready,
                // The cell-wide count, matching `readiness`'s own rule rather
                // than the cell-scoped queue printed separately below.
                event_ready: backlog.dead_letter_count == 0,
                admission_open: oldest_age <= self.config.admission.max_oldest_pending_age
                    && backlog.pending_count <= self.config.admission.max_pending_rows
                    && backlog.pending_bytes <= self.config.admission.max_pending_bytes,
            }
        });

        if as_json {
            print_json(&json!({
                "cell_id": status.cell_id,
                "backlog": {
                    "pending_count": backlog.pending_count,
                    "pending_bytes": backlog.pending_bytes,
                    "oldest_pending_age_seconds": backlog
                        .oldest_pending_age
                        .map(|age| age.as_secs_f64()),
                    "claimed_count": backlog.claimed_count,
                    "dead_letter_count": backlog.dead_letter_count,
                    "saturated": backlog.saturated(),
                },
                "parked_dead_letters": status.parked_dead_letters,
                "backlog_facets": facets.map(|facets| json!({
                    "relay_ready": facets.relay_ready,
                    "event_ready": facets.event_ready,
                    "admission_open": facets.admission_open,
                })),
                "schema_state": status.schema_state.as_ref().map(|state| json!({
                    "migration_version": state.migration_version,
                    "relay_compat_floor": state.relay_compat_floor,
                    "producer_compat_floor": state.producer_compat_floor,
                    "consumer_compat_floor": state.consumer_compat_floor,
                    "cutover_at": state.cutover_at.map(epoch_seconds),
                })),
                "safe_vector": status.safe_vector.as_ref().map(|vector| json!({
                    "membership_version": vector.membership_version,
                    "stream_identity": vector.stream_identity,
                    "stream_epoch": vector.stream_epoch,
                    "safe_sequence": vector.safe_sequence,
                    "required_members": vector.required_members,
                })),
                "evaluation_block": status.evaluation_block.as_ref().map(block_label),
                "membership": status.membership.as_ref().map(|membership| json!({
                    "membership_version": membership.membership_version,
                    "reset_in_progress": membership.reset_in_progress,
                    "reset_generation": membership.reset_generation,
                    "current_stream_identity": membership.current_stream_identity,
                    "current_stream_epoch": membership.current_stream_epoch,
                    "required_members": membership
                        .required_members
                        .iter()
                        .map(|member| json!({
                            "receiver_identity": member.receiver_identity,
                            "membership_generation": member.membership_generation,
                            "state": member.state,
                            "ready": member.ready_at.is_some(),
                            "baselined": member.baseline_at.is_some(),
                        }))
                        .collect::<Vec<Value>>(),
                })),
            }));
            return Ok(());
        }

        println!("cell {}", status.cell_id);
        match status.schema_state.as_ref() {
            None => println!("  schema        absent (this database has no outbox)"),
            Some(state) => println!(
                "  schema        migration {} relay-floor {} cutover {}",
                state.migration_version,
                state.relay_compat_floor,
                match state.cutover_at {
                    Some(_) => "complete",
                    None => "INCOMPLETE",
                }
            ),
        }
        println!(
            "  backlog       {} pending, {} bytes, {} claimed{}",
            backlog.pending_count,
            backlog.pending_bytes,
            backlog.claimed_count,
            if backlog.saturated() {
                " (at the probe ceiling; the real totals are larger)"
            } else {
                ""
            }
        );
        println!(
            "  oldest        {}",
            match backlog.oldest_pending_age {
                None => "none pending".to_owned(),
                Some(age) => format!("{:.1}s", age.as_secs_f64()),
            }
        );
        println!(
            "  dead letters  {} parked in this cell ({} cell-wide)",
            status.parked_dead_letters, backlog.dead_letter_count
        );
        match facets {
            None => println!("  facets        unknown (no outbox schema to decide on)"),
            Some(facets) => {
                println!(
                    "  facets        relay {} / event {} / admission {}",
                    yes_no(facets.relay_ready),
                    yes_no(facets.event_ready),
                    if facets.admission_open {
                        "open"
                    } else {
                        "CLOSED"
                    }
                );
                println!(
                    "                backlog-derived only; a running relay's live facets are on \
                     its /event_readiness"
                );
            }
        }
        match (
            status.safe_vector.as_ref(),
            status.evaluation_block.as_ref(),
        ) {
            (Some(vector), _) => println!(
                "  safe vector   {}@{} sequence {} over {} required receiver(s)",
                vector.stream_identity,
                vector.stream_epoch,
                vector.safe_sequence,
                vector.required_members
            ),
            (None, Some(block)) => println!("  safe vector   blocked: {}", describe_block(block)),
            (None, None) => println!("  safe vector   unknown"),
        }
        if let Some(membership) = status.membership.as_ref() {
            println!(
                "  membership    version {} reset-generation {}{}",
                membership.membership_version,
                membership.reset_generation,
                if membership.reset_in_progress {
                    " FENCE STANDING"
                } else {
                    ""
                }
            );
            for member in &membership.required_members {
                println!(
                    "    - {} generation {} {}{}",
                    member.receiver_identity,
                    member.membership_generation,
                    member.state,
                    if member.ready_at.is_some() {
                        ""
                    } else {
                        " (not ready)"
                    }
                );
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // inspect
    // -----------------------------------------------------------------------

    async fn inspect(&self, target: &InspectTarget, limit: i64, as_json: bool) -> Result<()> {
        let client = self.client().await?;

        if let Some(event_id) = target.event {
            let found = operator::inspect_event(&client, &self.cell_id, event_id).await?;
            if as_json {
                print_json(&json!({
                    "cell_id": self.cell_id,
                    "event_id": event_id.to_string(),
                    "live": found.live.as_ref().map(row_json),
                    "dead_letter": found.dead_letter.as_ref().map(|dead| json!({
                        "event_id": dead.event.event_id.to_string(),
                        "event_kind": dead.event.event_kind,
                        "repository_id": hex::encode(&dead.event.repository_id),
                        "attempt_count": dead.attempt_count,
                        "terminal_class": dead.terminal_class,
                        "first_failed_at": epoch_seconds(dead.first_failed_at),
                        "last_failed_at": epoch_seconds(dead.last_failed_at),
                        "disposition": dead.disposition,
                        "disposition_reason": dead.disposition_reason,
                        "disposition_actor": dead.disposition_actor,
                        "disposition_at": dead.disposition_at.map(epoch_seconds),
                    })),
                }));
                return Ok(());
            }
            if found.is_empty() {
                println!("no event {event_id} in cell {}", self.cell_id);
                return Ok(());
            }
            if let Some(row) = found.live.as_ref() {
                println!("live row:");
                print_row(row);
            }
            if let Some(dead) = found.dead_letter.as_ref() {
                println!(
                    "dead letter:  class {} disposition {} after {} attempt(s)",
                    dead.terminal_class, dead.disposition, dead.attempt_count
                );
                if let Some(reason) = dead.disposition_reason.as_deref() {
                    println!(
                        "              by {} — {reason}",
                        dead.disposition_actor.as_deref().unwrap_or("(unrecorded)")
                    );
                }
            }
            return Ok(());
        }

        if target.dead_letters {
            let rows = operator::inspect_dead_letters(&client, &self.cell_id, limit).await?;
            if as_json {
                print_json(&json!({
                    "cell_id": self.cell_id,
                    "parked": rows.iter().map(|dead| json!({
                        "event_id": dead.event.event_id.to_string(),
                        "event_kind": dead.event.event_kind,
                        "repository_id": hex::encode(&dead.event.repository_id),
                        "terminal_class": dead.terminal_class,
                        "attempt_count": dead.attempt_count,
                        "last_failed_at": epoch_seconds(dead.last_failed_at),
                    })).collect::<Vec<Value>>(),
                }));
                return Ok(());
            }
            println!(
                "{} parked dead letter(s) in cell {} (bound {limit})",
                rows.len(),
                self.cell_id
            );
            for dead in &rows {
                println!(
                    "  {} {} class {} after {} attempt(s) repo {}",
                    dead.event.event_id,
                    dead.event.event_kind,
                    dead.terminal_class,
                    dead.attempt_count,
                    hex::encode(&dead.event.repository_id)
                );
            }
            return Ok(());
        }

        // `clap`'s `required = true, multiple = false` group makes this the only
        // remaining arm, so the `else` below is unreachable through the CLI. It
        // is an error rather than an `expect` because this function is also
        // callable from a test that built the struct directly.
        let repository = target.repository.as_deref().ok_or_else(|| {
            anyhow!("`loreserver outbox inspect` needs --repository, --event, or --dead-letters")
        })?;
        let repository_id = decode_repository(repository)?;
        let rows =
            operator::inspect_repository(&client, &self.cell_id, &repository_id, limit).await?;
        if as_json {
            print_json(&json!({
                "cell_id": self.cell_id,
                "repository_id": repository,
                "rows": rows.iter().map(row_json).collect::<Vec<Value>>(),
            }));
            return Ok(());
        }
        println!(
            "{} row(s) for repository {repository} in cell {} (bound {limit})",
            rows.len(),
            self.cell_id
        );
        for row in &rows {
            print_row(row);
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // replay
    // -----------------------------------------------------------------------

    async fn replay(
        &self,
        repository: Option<&str>,
        window_hours: u64,
        limit: i64,
        actor: &str,
        reason: &str,
        as_json: bool,
    ) -> Result<()> {
        let repository_id = repository.map(decode_repository).transpose()?;
        // Checked-multiplied rather than `hours * 3600`: an operator typing a
        // very large number would otherwise wrap to a small window and get a
        // successful-looking replay over the wrong range. Overflow is refused
        // here; the store refuses anything past 24 hours regardless.
        let window = window_hours
            .checked_mul(3_600)
            .map(Duration::from_secs)
            .ok_or_else(|| {
                anyhow!("--window-hours {window_hours} is not a representable window")
            })?;

        let mut client = self.client().await?;
        let outcome = operator::replay(
            &mut client,
            &self.cell_id,
            repository_id.as_deref(),
            window,
            limit,
            actor,
            reason,
        )
        .await?;

        if as_json {
            print_json(&json!({
                "cell_id": self.cell_id,
                "replayed": outcome.replayed,
                "window_seconds": outcome.window.as_secs(),
                "limit": outcome.limit,
                "repository_id": repository,
                "paginated": outcome.replayed as i64 == outcome.limit,
            }));
            return Ok(());
        }
        println!(
            "replayed {} row(s) in cell {} over the last {}h{}",
            outcome.replayed,
            self.cell_id,
            window_hours,
            match repository {
                Some(repository) => format!(" for repository {repository}"),
                None => String::new(),
            }
        );
        if outcome.replayed as i64 == outcome.limit {
            println!(
                "the row bound was reached; run the command again to continue — CR-032 requires a \
                 larger range to paginate explicitly"
            );
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // dispositions
    // -----------------------------------------------------------------------

    async fn requeue_dead_letter(&self, event: Uuid, actor: &str, reason: &str) -> Result<()> {
        let mut client = self.client().await?;
        let outcome =
            operator::requeue_dead_letter(&mut client, &self.cell_id, event, actor, reason).await?;
        report_disposition("requeue", event, &outcome)
    }

    async fn mark_obsolete(
        &self,
        event: Uuid,
        actor: &str,
        reason: &str,
        proof: &str,
    ) -> Result<()> {
        let client = self.client().await?;
        let outcome =
            operator::mark_obsolete(&client, &self.cell_id, event, actor, reason, proof).await?;
        report_disposition("obsolete", event, &outcome)
    }
}

/// Print one disposition outcome, and fail the process on anything but
/// `Applied`.
///
/// A refused disposition exits non-zero on purpose: these commands are run from
/// incident runbooks and wrapper scripts, and a `NotParked` that printed a line
/// and exited zero would let a script move on believing it had acted.
fn report_disposition(operation: &str, event: Uuid, outcome: &DeadLetterOutcome) -> Result<()> {
    match outcome {
        DeadLetterOutcome::Applied => {
            println!("{operation} applied to {event}");
            Ok(())
        }
        DeadLetterOutcome::NotFound => Err(anyhow!(
            "no parked dead letter {event} in this cell; check the event ID, and that it has not \
             already been disposed of"
        )),
        DeadLetterOutcome::NotParked { disposition } => Err(anyhow!(
            "dead letter {event} already carries the disposition '{disposition}'; a decision is \
             recorded once and is not overwritten"
        )),
        DeadLetterOutcome::EventStillPresent => Err(anyhow!(
            "a live outbox row with {event}'s stable keys already exists, so requeueing it would \
             duplicate the event; nothing was changed"
        )),
        DeadLetterOutcome::RelayIncompatible { relay_compat_floor } => Err(anyhow!(
            "this binary's relay contract is below the cell's floor of {relay_compat_floor}, so it \
             may not requeue work it cannot publish; upgrade the cell's loreserver first"
        )),
    }
}

/// Render one live row for the human listing.
fn print_row(row: &OutboxRow) {
    println!(
        "  {} {} {} repo {} attempt {}{}",
        row.event.event_id,
        row.state,
        row.event.event_kind,
        hex::encode(&row.event.repository_id),
        row.attempt_count,
        match row.last_error_class.as_deref() {
            Some(class) => format!(" last-error {class}"),
            None => String::new(),
        }
    );
    if let Some(acceptance) = row.acceptance.as_ref() {
        println!(
            "      accepted on {}@{} sequence {}",
            acceptance.stream_identity, acceptance.stream_epoch, acceptance.broker_sequence
        );
    }
    if let Some(replay) = row.replay.as_ref() {
        println!(
            "      replayed {}x, last by {} — {}",
            row.replay_count, replay.actor, replay.reason
        );
    }
}

/// The JSON projection of one live row.
fn row_json(row: &OutboxRow) -> Value {
    json!({
        "event_id": row.event.event_id.to_string(),
        "state": row.state,
        "event_kind": row.event.event_kind,
        "aggregate_kind": row.event.aggregate_kind,
        "repository_id": hex::encode(&row.event.repository_id),
        "repository_generation": row.event.repository_generation,
        "created_at": epoch_seconds(row.event.created_at),
        "available_at": epoch_seconds(row.available_at),
        "claim_generation": row.claim_generation,
        "claim_owner": row.claim_owner,
        "attempt_count": row.attempt_count,
        "last_error_class": row.last_error_class,
        "acceptance": row.acceptance.as_ref().map(|acceptance| json!({
            "stream_identity": acceptance.stream_identity,
            "stream_epoch": acceptance.stream_epoch,
            "broker_sequence": acceptance.broker_sequence,
            "gateway_response_id": acceptance.gateway_response_id,
            "publisher_contract_version": acceptance.publisher_contract_version,
        })),
        "broker_accepted_at": row.broker_accepted_at.map(epoch_seconds),
        "replay_count": row.replay_count,
        "replay": row.replay.as_ref().map(|replay| json!({
            "actor": replay.actor,
            "reason": replay.reason,
            "at": epoch_seconds(replay.at),
        })),
    })
}

/// One operator-readable sentence per evaluation block.
///
/// Deliberately not [`block_label`]: that is the bounded **metric** label set,
/// and CR-032 prohibits identities as metric labels — so it must drop the
/// receiver identity a blocked cell's operator most needs. Here there is no
/// cardinality budget and the identity is the whole answer.
fn describe_block(block: &EvaluationBlock) -> String {
    match block {
        EvaluationBlock::MissingCheckpoint {
            receiver_identity,
            membership_generation,
        } => format!(
            "{receiver_identity} generation {membership_generation} has no checkpoint at the \
             current placement"
        ),
        other => block_label(other).to_owned(),
    }
}

/// Decode a repository ID from the 32 hex characters an operator reads off a
/// listing or a log line.
fn decode_repository(hex_id: &str) -> Result<Vec<u8>> {
    let bytes = hex::decode(hex_id)
        .map_err(|error| anyhow!("repository ID must be 32 hex characters: {error}"))?;
    if bytes.len() != 16 {
        return Err(anyhow!(
            "repository ID must be 16 bytes (32 hex characters), got {}",
            bytes.len()
        ));
    }
    Ok(bytes)
}

/// Seconds since the Unix epoch, for the JSON projection.
///
/// A timestamp before the epoch is not representable and cannot occur — every
/// one of these is written by `clock_timestamp()` on a live database — so it
/// renders as zero rather than propagating an error through a print path.
fn epoch_seconds(at: SystemTime) -> f64 {
    at.duration_since(UNIX_EPOCH)
        .map_or(0.0, |since| since.as_secs_f64())
}

fn yes_no(value: bool) -> &'static str {
    if value { "ready" } else { "NOT READY" }
}

/// Maintenance CLI contract, matching `--rebuild-postgres-metering`: stdout
/// carries only the machine-readable value, so a deployment script can parse it
/// without depending on the tracing format.
fn print_json(value: &Value) {
    println!("{value}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_repository_id_round_trips_through_hex() {
        let id = [0xab_u8; 16];
        let encoded = hex::encode(id);
        assert_eq!(encoded.len(), 32);
        assert_eq!(decode_repository(&encoded).expect("valid hex"), id.to_vec());
    }

    #[test]
    fn a_short_or_unparsable_repository_id_is_refused() {
        assert!(decode_repository("").is_err());
        assert!(decode_repository("ab").is_err());
        assert!(decode_repository(&"ab".repeat(17)).is_err());
        assert!(decode_repository("zz".repeat(16).as_str()).is_err());
    }

    /// The defaults are CR-032's own maxima, so an operator who names no bound
    /// still runs inside the reviewed limits.
    #[test]
    fn the_defaults_are_the_reviewed_bounds() {
        assert_eq!(DEFAULT_ROW_LIMIT, operator::MAX_INSPECT_ROWS);
        assert_eq!(DEFAULT_ROW_LIMIT, operator::MAX_REPLAY_ROWS);
        assert_eq!(
            Duration::from_secs(DEFAULT_REPLAY_WINDOW_HOURS * 3_600),
            operator::MAX_REPLAY_WINDOW
        );
    }

    /// Every refusal exits non-zero, so a runbook script cannot mistake a
    /// refused disposition for an applied one.
    #[test]
    fn only_an_applied_disposition_succeeds() {
        let event = Uuid::nil();
        assert!(report_disposition("requeue", event, &DeadLetterOutcome::Applied).is_ok());
        for refused in [
            DeadLetterOutcome::NotFound,
            DeadLetterOutcome::NotParked {
                disposition: "obsolete".to_owned(),
            },
            DeadLetterOutcome::EventStillPresent,
            DeadLetterOutcome::RelayIncompatible {
                relay_compat_floor: 9,
            },
        ] {
            assert!(
                report_disposition("requeue", event, &refused).is_err(),
                "{refused:?} must exit non-zero"
            );
        }
    }

    /// The blocked-vector sentence carries the receiver identity the metric
    /// label is required to drop.
    #[test]
    fn a_missing_checkpoint_names_the_receiver_the_metric_label_cannot() {
        let block = EvaluationBlock::MissingCheckpoint {
            receiver_identity: "loreserver-sfo3-cell-a-1".to_owned(),
            membership_generation: 4,
        };
        let described = describe_block(&block);
        assert!(described.contains("loreserver-sfo3-cell-a-1"));
        assert!(described.contains('4'));
        assert!(
            !block_label(&block).contains("loreserver"),
            "the metric label must stay identity-free"
        );
    }

    /// A window an operator could type must not wrap into a small one.
    #[test]
    fn an_unrepresentable_window_is_refused_rather_than_wrapped() {
        assert!(u64::MAX.checked_mul(3_600).is_none());
    }
}

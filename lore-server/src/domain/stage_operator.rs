// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! `loreserver stage resolve-lost <list|apply|status>`: operator loss rulings
//! for staged fragments the guarded drain keeps `Staged` forever.
//!
//! The drain guard never reads a missing staged file as absent unless the
//! drain process confirmed the file's stager in its own stage directory (see
//! `crate::stage_liveness`, "Drain guard"). A file whose stager left before
//! that, or that has no recorded stager, is retried on every pass and a GET
//! of it answers `SlowDown`. This command is the way out:
//!
//! - `list` is read-only. It prints those files (at least an hour old, by the
//!   database clock) and a confirm token bound to that exact set.
//! - `apply --confirm <token>` selects the set again as of the token's issue
//!   time, refuses if it changed or the token is older than 15 minutes, and
//!   records one ruling row per file. `--actor` and `--reason` are required at
//!   parse time.
//! - `status` prints the rulings and their outcomes.
//!
//! The command never reads the stage and never touches the lifecycle. The
//! running drain carries a ruling out, with its own pinned read, its own guard
//! and its own evidence check (`lore_postgres`'s `stage_loss` module).
//!
//! # Authority
//!
//! The cell database credential plus shell access, as for `outbox`. There is
//! no `--cell` flag: the cell comes from the write-behind configuration. There
//! is no HTTP or gRPC surface: a demote-to-`Missing` lever does not belong on
//! a serving port.
//!
//! # Tenant rule
//!
//! Fragments are content-addressed and shared by every repository that holds
//! them. `--repository` only selects; it never limits the effect. Lore has no
//! org concept, so a file associated with more than one repository needs
//! `--multi-repository`, which is recorded.

use std::time::Duration;

use anyhow::Result;
use anyhow::anyhow;
use clap::Args;
use clap::Subcommand;
use lore_postgres::domain::fragments::stage_loss;
use lore_postgres::domain::fragments::stage_loss::LossApply;
use lore_postgres::domain::fragments::stage_loss::LossApplyOutcome;
use lore_postgres::domain::fragments::stage_loss::LossApplyRefusal;
use lore_postgres::domain::fragments::stage_loss::LossFilter;
use lore_postgres::domain::fragments::stage_loss::LostStagedFile;
use serde_json::Value;
use serde_json::json;

use crate::settings::Settings;

/// One connection: every command is one bounded operation.
const OPERATOR_POOL_MAX: u32 = 1;

/// The least `--min-age-minutes`: one hour. A floor the flag cannot lower.
#[lore_macro::test_pub]
const MIN_AGE_MINUTES: u64 = 60;

/// The default and largest `--limit`.
#[lore_macro::test_pub]
const MAX_ROWS: i64 = stage_loss::MAX_LOSS_RULING_ROWS;

/// The default `status --limit`.
const STATUS_ROWS: i64 = 100;

/// A maintenance operation on this cell's write-behind stage.
#[derive(Debug, Subcommand)]
pub enum StageCommand {
    /// Resolve staged fragments the drain keeps because it cannot prove the
    /// file gone: list them, record an operator loss ruling, or show rulings.
    ResolveLost {
        #[command(subcommand)]
        command: ResolveLostCommand,
    },
}

/// `stage resolve-lost`.
#[derive(Debug, Subcommand)]
pub enum ResolveLostCommand {
    /// List the kept staged files and print a confirm token for that exact
    /// set. Read-only.
    List {
        #[command(flatten)]
        selection: SelectionArgs,
        /// Print one JSON object instead of the human-readable listing.
        #[arg(long)]
        json: bool,
    },
    /// Record one loss ruling per file of the confirmed set. The running drain
    /// carries each out: only with a healthy guard, a fresh miss in its own
    /// stage, and echo evidence or the attestation.
    Apply {
        #[command(flatten)]
        selection: SelectionArgs,
        /// The token `list` printed for the same filters. Valid 15 minutes.
        #[arg(long, value_name = "TOKEN")]
        confirm: String,
        /// Who orders the ruling. Recorded.
        #[arg(long)]
        actor: String,
        /// Why. Recorded.
        #[arg(long)]
        reason: String,
        /// The stage mount was checked on every web host and the drain host.
        /// Required for a file with no recorded stager, and for any file whose
        /// stager left no echo file in the drain's stage. Recorded.
        #[arg(long)]
        attest_mounts_checked: bool,
        /// Allow files associated with more than one repository. Recorded.
        #[arg(long)]
        multi_repository: bool,
        /// Print one JSON object instead of the human-readable summary.
        #[arg(long)]
        json: bool,
    },
    /// Show loss rulings, newest first, with each outcome.
    Status {
        /// Only this fragment hash, as 64 hex characters.
        #[arg(long, value_name = "HEX")]
        hash: Option<String>,
        /// Only rulings the drain can still carry out: undecided and not past
        /// their expiry.
        #[arg(long)]
        open: bool,
        /// Maximum rows, 1 to 1,000.
        #[arg(long, default_value_t = STATUS_ROWS,
              value_parser = clap::value_parser!(i64).range(1..=MAX_ROWS))]
        limit: i64,
        /// Print one JSON object instead of the human-readable listing.
        #[arg(long)]
        json: bool,
    },
}

/// The selection `list` and `apply` share. `apply` must repeat the filters
/// `list` was given: the token binds them.
#[derive(Debug, Clone, Args)]
pub struct SelectionArgs {
    /// Only this fragment hash, as 64 hex characters.
    #[arg(long, value_name = "HEX")]
    pub hash: Option<String>,
    /// Only files staged by this web replica id.
    #[arg(long, value_name = "REPLICA_ID")]
    pub stager: Option<String>,
    /// Only files associated with this repository, as 32 hex characters.
    /// Selects only: a ruling acts on the fragment for every repository.
    #[arg(long, value_name = "HEX")]
    pub repository: Option<String>,
    /// Least age of the staged representation, by the database clock. At
    /// least 60.
    #[arg(long, default_value_t = MIN_AGE_MINUTES,
          value_parser = clap::value_parser!(u64).range(MIN_AGE_MINUTES..=525_600))]
    pub min_age_minutes: u64,
    /// Maximum files, 1 to 1,000.
    #[arg(long, default_value_t = MAX_ROWS,
          value_parser = clap::value_parser!(i64).range(1..=MAX_ROWS))]
    pub limit: i64,
}

impl SelectionArgs {
    /// The store-side filter. Bounds are refused, never clamped.
    #[lore_macro::test_pub]
    fn filter(&self) -> Result<LossFilter> {
        let filter = LossFilter {
            hash: self
                .hash
                .as_deref()
                .map(|hash| decode_hex("--hash", hash, 32))
                .transpose()?,
            stager: self.stager.clone(),
            repository: self
                .repository
                .as_deref()
                .map(|repository| decode_hex("--repository", repository, 16))
                .transpose()?,
            min_age: Duration::from_secs(self.min_age_minutes.saturating_mul(60)),
            limit: self.limit,
        };
        filter.validate()?;
        Ok(filter)
    }
}

/// Decode `value` as exactly `bytes` bytes of hex.
#[lore_macro::test_pub]
fn decode_hex(flag: &str, value: &str, bytes: usize) -> Result<Vec<u8>> {
    let decoded = hex::decode(value)
        .map_err(|error| anyhow!("{flag} must be {} hex characters: {error}", bytes * 2))?;
    if decoded.len() != bytes {
        return Err(anyhow!(
            "{flag} must be {} hex characters, got {}",
            bytes * 2,
            value.len()
        ));
    }
    Ok(decoded)
}

/// Run one `stage` maintenance command against the configured cell.
///
/// # Errors
/// Not a Postgres cell, write-behind not configured, a missing relation, a
/// database failure, or any `apply` refusal (which writes nothing).
pub async fn run(command: &StageCommand, settings: &Settings) -> Result<()> {
    let StageCommand::ResolveLost { command } = command;
    let cell_id = crate::server::postgres_write_behind_settings(settings)?
        .map(|composition| composition.cell_id)
        .ok_or_else(|| {
            anyhow!(
                "`loreserver stage resolve-lost` needs this cell's write-behind configuration \
                 (immutable_store.mode = postgres with write_behind enabled)"
            )
        })?;
    let pool = crate::event_relay::wiring::build_operator_pool(
        settings,
        OPERATOR_POOL_MAX,
        "loreserver stage resolve-lost",
    )?;
    let mut client = pool
        .get()
        .await
        .map_err(|error| anyhow!("could not take a connection to the cell database: {error}"))?;
    let fresh = crate::stage_liveness::SHARE_PEER_FRESH;
    match command {
        ResolveLostCommand::List { selection, json } => {
            let filter = selection.filter()?;
            let listing =
                stage_loss::list_lost_staged(&***client, &cell_id, fresh, &filter, None).await?;
            let token =
                stage_loss::confirm_token(listing.as_of_ms, &cell_id, &filter, &listing.files);
            print_listing(&cell_id, &listing.files, &token, *json);
            Ok(())
        }
        ResolveLostCommand::Apply {
            selection,
            confirm,
            actor,
            reason,
            attest_mounts_checked,
            multi_repository,
            json,
        } => {
            let filter = selection.filter()?;
            let outcome = stage_loss::apply_loss_rulings(
                &mut client,
                &cell_id,
                fresh,
                &filter,
                &LossApply {
                    actor,
                    reason,
                    attested: *attest_mounts_checked,
                    multi_repository: *multi_repository,
                    token: confirm,
                },
            )
            .await?;
            report_apply(&cell_id, &outcome, *json)
        }
        ResolveLostCommand::Status {
            hash,
            open,
            limit,
            json,
        } => {
            let hash = hash
                .as_deref()
                .map(|hash| decode_hex("--hash", hash, 32))
                .transpose()?;
            let rulings =
                stage_loss::loss_rulings(&***client, hash.as_deref(), *open, *limit).await?;
            print_status(&cell_id, &rulings, *json);
            Ok(())
        }
    }
}

fn stager_label(file: &LostStagedFile) -> String {
    match file.stager.as_ref() {
        Some(stager) => format!("{}/{}", stager.replica_id, stager.incarnation),
        None => "none".to_owned(),
    }
}

/// The JSON projection of one listed file.
#[lore_macro::test_pub]
fn file_json(file: &LostStagedFile) -> Value {
    json!({
        "hash": hex::encode(&file.hash),
        "epoch": file.epoch,
        "manifest_id": hex::encode(&file.manifest_id),
        "selection": file.selection().as_str(),
        "stager": file.stager.as_ref().map(|stager| json!({
            "replica_id": stager.replica_id,
            "incarnation": stager.incarnation,
        })),
        "age_seconds": file.age.as_secs(),
        "repositories": file.repositories,
        "open_ruling": file.open_ruling,
    })
}

fn print_listing(cell_id: &str, files: &[LostStagedFile], token: &str, as_json: bool) {
    if as_json {
        println!(
            "{}",
            json!({
                "cell_id": cell_id,
                "files": files.iter().map(file_json).collect::<Vec<Value>>(),
                "confirm_token": token,
                "confirm_token_valid_seconds": stage_loss::LOSS_CONFIRM_TOKEN_TTL.as_secs(),
            })
        );
        return;
    }
    println!(
        "{} kept staged file(s) in cell {cell_id} (dry run; nothing changed)",
        files.len()
    );
    for file in files {
        println!(
            "  {} epoch {} stager {} age {}m repos {}{}",
            hex::encode(&file.hash),
            file.epoch,
            stager_label(file),
            file.age.as_secs() / 60,
            file.repositories,
            match file.open_ruling {
                Some(id) => format!(" (open ruling {id})"),
                None => String::new(),
            }
        );
    }
    println!("confirm token (15 minutes, same filters): {token}");
    println!(
        "check the stage mount on the drain host and on every web host before apply; a file \
         with stager none, or whose stager left no echo file, needs --attest-mounts-checked"
    );
}

/// Print one `apply` outcome; every refusal exits non-zero and wrote nothing.
#[lore_macro::test_pub]
fn report_apply(cell_id: &str, outcome: &LossApplyOutcome, as_json: bool) -> Result<()> {
    match outcome {
        LossApplyOutcome::Applied {
            rulings,
            already_open,
        } => {
            if as_json {
                println!(
                    "{}",
                    json!({
                        "cell_id": cell_id,
                        "rulings": rulings.iter().map(|ruling| json!({
                            "ruling_id": ruling.ruling_id,
                            "hash": hex::encode(&ruling.hash),
                            "epoch": ruling.epoch,
                        })).collect::<Vec<Value>>(),
                        "already_open": already_open.iter().map(|(hash, epoch)| json!({
                            "hash": hex::encode(hash),
                            "epoch": epoch,
                        })).collect::<Vec<Value>>(),
                    })
                );
            } else {
                println!(
                    "recorded {} loss ruling(s) in cell {cell_id}; {} already had an open ruling",
                    rulings.len(),
                    already_open.len()
                );
                for ruling in rulings {
                    println!(
                        "  ruling {} {} epoch {}",
                        ruling.ruling_id,
                        hex::encode(&ruling.hash),
                        ruling.epoch
                    );
                }
                println!(
                    "the running drain carries them out on its next passes; see `stage \
                     resolve-lost status`"
                );
            }
            Ok(())
        }
        LossApplyOutcome::Refused(refusal) => Err(anyhow!(
            "refused; nothing was written: {}",
            describe_refusal(refusal)
        )),
    }
}

/// One sentence per refusal, naming the hashes where it has them.
#[lore_macro::test_pub]
fn describe_refusal(refusal: &LossApplyRefusal) -> String {
    let hashes = |hashes: &[Vec<u8>]| {
        hashes
            .iter()
            .map(hex::encode)
            .collect::<Vec<_>>()
            .join(", ")
    };
    match refusal {
        LossApplyRefusal::Token(refusal) => refusal.describe().to_owned(),
        LossApplyRefusal::Empty => "the selection is empty".to_owned(),
        LossApplyRefusal::NeedsAttestation(list) => format!(
            "these files have no recorded stager, so no evidence is possible; check the stage \
             mount on every host and rerun with --attest-mounts-checked: {}",
            hashes(list)
        ),
        LossApplyRefusal::NeedsMultiRepository(list) => format!(
            "these files are associated with more than one repository; rerun with \
             --multi-repository if the loss is accepted for all of them: {}",
            hashes(list)
        ),
        LossApplyRefusal::Contended => "a drain refresh or another apply changed the same \
             ruling at the same time (serialization failure or deadlock); the transaction \
             rolled back and this attempt did not use the confirm token, so the token is still \
             valid until it expires unless another apply used it; run the same apply again (it \
             re-checks the token and the set)"
            .to_owned(),
    }
}

/// A ruling's state for `status`: its outcome, `open`, or, for an undecided
/// ruling past its expiry that no drain will carry out,
/// `expired (pending drain)`.
#[lore_macro::test_pub]
fn ruling_state(ruling: &stage_loss::LossRulingRecord) -> &str {
    match ruling.outcome.as_deref() {
        Some(outcome) => outcome,
        None if ruling.expired_pending => "expired (pending drain)",
        None => "open",
    }
}

fn print_status(cell_id: &str, rulings: &[stage_loss::LossRulingRecord], as_json: bool) {
    if as_json {
        println!(
            "{}",
            json!({
                "cell_id": cell_id,
                "rulings": rulings.iter().map(|ruling| json!({
                    "ruling_id": ruling.ruling_id,
                    "hash": hex::encode(&ruling.hash),
                    "epoch": ruling.epoch,
                    "selection": ruling.selection,
                    "stager": ruling.stager.as_ref().map(|stager| json!({
                        "replica_id": stager.replica_id,
                        "incarnation": stager.incarnation,
                    })),
                    "actor": ruling.actor,
                    "reason": ruling.reason,
                    "attested": ruling.attested,
                    "multi_repository": ruling.multi_repository,
                    "repositories": ruling.repositories,
                    "created_ms": ruling.created_ms,
                    "expires_ms": ruling.expires_ms,
                    "outcome": ruling.outcome,
                    "evidence": ruling.evidence,
                    "decided_ms": ruling.decided_ms,
                    "drain_replica_id": ruling.drain_replica_id,
                    "state": ruling_state(ruling),
                })).collect::<Vec<Value>>(),
            })
        );
        return;
    }
    println!("{} loss ruling(s) in cell {cell_id}", rulings.len());
    for ruling in rulings {
        println!(
            "  ruling {} {} epoch {} {}{} by {}: {}",
            ruling.ruling_id,
            hex::encode(&ruling.hash),
            ruling.epoch,
            ruling_state(ruling),
            ruling
                .evidence
                .as_deref()
                .map_or_default(|evidence| format!(" (evidence {evidence})")),
            ruling.actor,
            ruling.reason
        );
    }
}

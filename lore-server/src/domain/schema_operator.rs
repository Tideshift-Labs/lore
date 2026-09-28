// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-FileCopyrightText: 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! `loreserver schema validate-constraints` — prove the cell's `NOT VALID`
//! constraints against the rows that predate them.
//!
//! The boot path adds constraints on populated tables as `NOT VALID` so it
//! never scans a table inside its 250 ms statement timeout. They bind every
//! new write from that moment, but PostgreSQL has not proved the old rows. This
//! command runs `VALIDATE CONSTRAINT` for each one, one statement at a time,
//! under a generous lock and statement timeout, and reports each result. The
//! store half is `lore_postgres::domain::constraint_validation`.
//!
//! Safe against a serving cell: a CHECK validation takes SHARE UPDATE
//! EXCLUSIVE, which blocks neither reads nor writes. Idempotent: the work list
//! comes from the catalog each run, so a rerun retries only what is left.

use std::time::Duration;

use anyhow::Result;
use anyhow::anyhow;
use clap::Subcommand;
use lore_postgres::domain::constraint_validation::ConstraintValidation;
use lore_postgres::domain::constraint_validation::ConstraintValidationError;
use lore_postgres::domain::constraint_validation::ValidationOutcome;
use lore_postgres::domain::constraint_validation::ValidationTimeouts;
use lore_postgres::domain::constraint_validation::list_not_valid_constraints;
use lore_postgres::domain::constraint_validation::validate_not_valid_constraints;
use serde_json::json;

use crate::settings::Settings;

/// Default wait for one table's lock, in milliseconds.
const DEFAULT_LOCK_TIMEOUT_MS: u64 = 10_000;

/// Default bound on one validation scan, in milliseconds: one hour.
const DEFAULT_STATEMENT_TIMEOUT_MS: u64 = 3_600_000;

/// A maintenance operation on this cell's schema.
#[derive(Debug, Subcommand)]
pub enum SchemaCommand {
    /// Validate every NOT VALID constraint on this cell's `lore_` tables, one
    /// at a time. Safe while the cell serves; rerun to retry what is left.
    ///
    /// Exits non-zero when any constraint stays NOT VALID. A `violated` result
    /// names a constraint an existing row breaks: repair the row, then rerun.
    /// A `lock_timeout` or `statement_timeout` result is safe to rerun as is.
    ValidateConstraints {
        /// How long to wait for each table's lock, in milliseconds.
        #[arg(long, default_value_t = DEFAULT_LOCK_TIMEOUT_MS,
              value_parser = clap::value_parser!(u64).range(1..))]
        lock_timeout_ms: u64,
        /// How long one validation scan may run, in milliseconds.
        #[arg(long, default_value_t = DEFAULT_STATEMENT_TIMEOUT_MS,
              value_parser = clap::value_parser!(u64).range(1..))]
        statement_timeout_ms: u64,
        /// List the NOT VALID constraints and change nothing.
        #[arg(long)]
        dry_run: bool,
        /// Print one JSON object instead of the human-readable report.
        #[arg(long)]
        json: bool,
    },
}

/// Run one schema maintenance command against the configured cell.
///
/// # Errors
/// A configuration refusal (not Postgres mode, no `[plugins.postgres]`), a
/// database failure, or any constraint left NOT VALID.
pub async fn run(command: &SchemaCommand, settings: &Settings) -> Result<()> {
    match command {
        SchemaCommand::ValidateConstraints {
            lock_timeout_ms,
            statement_timeout_ms,
            dry_run,
            json,
        } => {
            let pool = crate::event_relay::wiring::build_operator_pool(
                settings,
                1,
                "loreserver schema validate-constraints",
            )?;
            let client = pool
                .get()
                .await
                .map_err(|error| anyhow!("Failed to check out an operator connection: {error}"))?;
            // The pooled client reaches `tokio_postgres::Client` through two
            // `Deref` hops, and a generic `GenericClient` bound will not walk
            // them; this crate does not name `tokio_postgres` outside tests.
            let client = &**client;
            if *dry_run {
                let pending = list_not_valid_constraints(client)
                    .await
                    .map_err(|error| anyhow!("Failed to list NOT VALID constraints: {error}"))?;
                print_dry_run(&pending, *json);
                return Ok(());
            }
            let results = match validate_not_valid_constraints(
                client,
                ValidationTimeouts {
                    lock_timeout: Duration::from_millis(*lock_timeout_ms),
                    statement_timeout: Duration::from_millis(*statement_timeout_ms),
                },
            )
            .await
            {
                Ok(results) => results,
                // The scan ran to completion and every result below is real;
                // only the post-scan session-timeout reset failed. Report the
                // results rather than discarding them for a cleanup error.
                Err(ConstraintValidationError::ResetFailed { results, error }) => {
                    print_results(&results, *json);
                    return Err(anyhow!(
                        "constraint validation ran and is reported above, but resetting the \
                         session's timeouts afterward failed: {error}"
                    ));
                }
                Err(error @ ConstraintValidationError::Setup(_)) => {
                    return Err(anyhow!("Constraint validation did not run: {error}"));
                }
            };
            print_results(&results, *json);
            let left = results
                .iter()
                .filter(|result| result.outcome != ValidationOutcome::Validated)
                .count();
            if left > 0 {
                return Err(anyhow!(
                    "{left} of {} constraint(s) remain NOT VALID; see the report above",
                    results.len()
                ));
            }
            Ok(())
        }
    }
}

fn print_dry_run(pending: &[(String, String)], json: bool) {
    if json {
        let rows: Vec<_> = pending
            .iter()
            .map(|(relation, constraint)| json!({ "relation": relation, "constraint": constraint }))
            .collect();
        println!("{}", json!({ "dry_run": true, "not_valid": rows }));
        return;
    }
    if pending.is_empty() {
        println!("no NOT VALID constraints on this cell's lore_ tables");
        return;
    }
    println!(
        "dry run: {} NOT VALID constraint(s); nothing changed",
        pending.len()
    );
    for (relation, constraint) in pending {
        println!("  {relation}.{constraint}");
    }
}

fn print_results(results: &[ConstraintValidation], json: bool) {
    if json {
        let rows: Vec<_> = results
            .iter()
            .map(|result| {
                json!({
                    "relation": result.relation,
                    "constraint": result.constraint,
                    "outcome": result.outcome.label(),
                    "detail": result.outcome.detail(),
                    "elapsed_ms": u64::try_from(result.elapsed.as_millis()).unwrap_or(u64::MAX),
                })
            })
            .collect();
        println!("{}", json!({ "results": rows }));
        return;
    }
    if results.is_empty() {
        println!("no NOT VALID constraints on this cell's lore_ tables; nothing to do");
        return;
    }
    for result in results {
        let detail = result
            .outcome
            .detail()
            .map(|detail| format!(": {detail}"))
            .unwrap_or_default();
        println!(
            "{:<17} {}.{} ({} ms){detail}",
            result.outcome.label(),
            result.relation,
            result.constraint,
            result.elapsed.as_millis()
        );
    }
    let validated = results
        .iter()
        .filter(|result| result.outcome == ValidationOutcome::Validated)
        .count();
    println!("{validated} of {} constraint(s) validated", results.len());
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Debug, Parser)]
    struct Harness {
        #[command(subcommand)]
        command: SchemaCommand,
    }

    #[test]
    fn validate_constraints_parses_with_generous_defaults() {
        let parsed = Harness::try_parse_from(["loreserver", "validate-constraints"])
            .expect("parse with defaults");
        let SchemaCommand::ValidateConstraints {
            lock_timeout_ms,
            statement_timeout_ms,
            dry_run,
            json,
        } = parsed.command;
        assert_eq!(lock_timeout_ms, DEFAULT_LOCK_TIMEOUT_MS);
        assert_eq!(statement_timeout_ms, DEFAULT_STATEMENT_TIMEOUT_MS);
        assert!(!dry_run);
        assert!(!json);
    }

    #[test]
    fn validate_constraints_refuses_a_zero_timeout() {
        for flag in ["--lock-timeout-ms", "--statement-timeout-ms"] {
            assert!(
                Harness::try_parse_from(["loreserver", "validate-constraints", flag, "0"]).is_err(),
                "{flag} 0 means no timeout to PostgreSQL and must be refused"
            );
        }
    }
}

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use clap::Parser;
use lore_server::domain::schema_operator::*;

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

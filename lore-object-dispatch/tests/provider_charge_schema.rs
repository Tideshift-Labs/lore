// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! WP-114 CD-4's durable shared cell-local limiter schema.

use std::time::Duration;

use lore_object_dispatch::PostgresProviderChargeConfig;
use lore_object_dispatch::ProviderChargeError;
use lore_object_dispatch::classify_provider_charge_commit;

const MIGRATION: &str =
    include_str!("../migrations/0021_object_store_dispatch_budget_limiter_schema.sql");
const PROVISIONING: &str =
    include_str!("../migrations/0022_object_store_dispatch_budget_limiter_provisioning.sql");

#[test]
fn unresolved_commit_is_always_an_ambiguous_nonrefundable_charge() {
    let result: Result<(), ProviderChargeError> =
        classify_provider_charge_commit::<(), _>(Err("connection lost after COMMIT"));

    assert_eq!(result, Err(ProviderChargeError::AmbiguousCommit));
}

#[test]
fn postgres_charge_timeouts_are_positive_whole_milliseconds() {
    let valid = PostgresProviderChargeConfig {
        statement_timeout: Duration::from_millis(1),
        lock_timeout: Duration::from_millis(2),
    };
    assert_eq!(valid.validate(), Ok(valid));

    for invalid in [
        PostgresProviderChargeConfig {
            statement_timeout: Duration::ZERO,
            lock_timeout: Duration::from_millis(1),
        },
        PostgresProviderChargeConfig {
            statement_timeout: Duration::from_nanos(1),
            lock_timeout: Duration::from_millis(1),
        },
        PostgresProviderChargeConfig {
            statement_timeout: Duration::from_millis(1),
            lock_timeout: Duration::from_micros(1_001),
        },
    ] {
        assert_eq!(
            invalid.validate(),
            Err(ProviderChargeError::ConfigurationUnresolved)
        );
    }
}

#[test]
fn limiter_schema_declares_one_configuration_cap_state_and_grant_family() {
    for relation in [
        "object_dispatch_budget_configurations",
        "object_dispatch_current_budget_configuration",
        "object_dispatch_budget_dimensions",
        "object_dispatch_budget_caps",
        "object_dispatch_budget_bucket_state",
        "object_dispatch_provider_charge_grants",
    ] {
        assert_eq!(
            MIGRATION
                .matches(&format!("CREATE TABLE object_store_retention.{relation}"))
                .count(),
            1,
            "{relation} must be declared exactly once"
        );
    }
}

#[test]
fn every_bucket_state_is_bound_to_one_exact_budget_configuration_and_cap() {
    let state = table_body("object_dispatch_budget_bucket_state");

    assert!(state.contains(
        "PRIMARY KEY (provider_boundary_id, allocation_revision, allocation_fence, cap_class)"
    ));
    assert!(state.contains(
        "FOREIGN KEY (provider_boundary_id, allocation_revision, allocation_fence, cap_class)"
    ));
    assert!(state.contains("REFERENCES object_store_retention.object_dispatch_budget_caps"));
}

#[test]
fn current_configuration_binds_the_revision_and_fence_as_one_foreign_key() {
    let current = table_body("object_dispatch_current_budget_configuration");

    assert!(current.contains("provider_boundary_id text PRIMARY KEY"));
    assert!(
        current
            .contains("FOREIGN KEY (provider_boundary_id, allocation_revision, allocation_fence)")
    );
    assert!(
        current.contains("REFERENCES object_store_retention.object_dispatch_budget_configurations")
    );
}

#[test]
fn durable_grant_identity_cannot_be_reused_for_a_second_charge() {
    let grants = table_body("object_dispatch_provider_charge_grants");

    assert!(grants.contains("grant_id uuid NOT NULL CHECK"));
    assert!(grants.contains("PRIMARY KEY (grant_id)"));
    assert!(grants.contains("CONSTRAINT object_dispatch_provider_charge_attempt_key"));
    assert!(grants.contains(
        "UNIQUE (provider_boundary_id, logical_request_id, attempt_id, attempt_ordinal)"
    ));
    assert!(grants.contains(
        "charged_units object_store_retention.uint64 NOT NULL CHECK (charged_units = 1)"
    ));
}

#[test]
fn migration_is_one_owner_scoped_forward_transaction() {
    assert!(
        MIGRATION
            .starts_with("-- Copyright 2026 Tideshift Labs\n-- SPDX-License-Identifier: MIT\n")
    );
    assert_eq!(MIGRATION.matches("BEGIN;").count(), 1);
    assert_eq!(MIGRATION.matches("COMMIT;").count(), 1);
    assert!(MIGRATION.contains("SET LOCAL ROLE object_dispatch_retention_owner;"));
    assert!(!MIGRATION.contains("DROP TABLE"));
    assert!(!MIGRATION.contains("TRUNCATE"));
    assert!(!MIGRATION.contains("INSERT INTO"));
}

#[test]
fn frozen_revision_grammar_is_byte_based_and_has_the_exact_ascii_alphabet() {
    let validator = function_body("assert_dispatch_budget_revision_v1");
    let byte_zero_start = validator
        .find("IF index = 0 THEN")
        .expect("byte-zero branch must be explicit");
    let byte_zero_end = validator[byte_zero_start..]
        .find("ELSIF NOT (")
        .map(|offset| byte_zero_start + offset)
        .expect("later-byte branch must be distinct");
    let byte_zero = &validator[byte_zero_start..byte_zero_end];

    assert!(validator.contains("convert_to(revision, 'UTF8')"));
    assert!(validator.contains("octet_length(encoded) NOT BETWEEN 1 AND 128"));
    assert!(validator.contains("value BETWEEN 48 AND 57"));
    assert!(validator.contains("value BETWEEN 65 AND 90"));
    assert!(validator.contains("value BETWEEN 97 AND 122"));
    assert!(validator.contains("value IN (45, 46, 95)"));
    assert!(!byte_zero.contains("value IN (45, 46, 95)"));
    assert!(validator.contains("ELSIF NOT ("));
    assert!(!validator.contains("lower("));
    assert!(!validator.contains("normalize("));
}

#[test]
fn publication_pins_first_fence_exact_successor_and_idempotent_same_pair() {
    let publication = function_body("object_store_dispatch_publish_budget_configuration_v1");

    assert!(publication.contains("RETURN ROW('REPLAY', allocation_revision, allocation_fence)"));
    assert!(publication.contains("prior.allocation_fence = 18446744073709551615"));
    assert!(publication.contains("allocation_fence IS DISTINCT FROM prior.allocation_fence + 1"));
    assert!(publication.contains("allocation_revision = prior.allocation_revision"));
    assert!(publication.contains("IF allocation_fence <> 1"));
}

#[test]
fn publication_restates_the_cell_scoped_schema_headroom_cache_and_digest_invariants() {
    let publication = function_body("object_store_dispatch_publish_budget_configuration_v1");
    let json_validator = function_body("assert_dispatch_budget_json_v1");

    assert!(
        publication.contains("core_target_revision IS DISTINCT FROM disposition_target_revision")
    );
    assert!(publication.contains("core_target_revision IS DISTINCT FROM envelope_target_revision"));
    assert!(publication.contains("target_kind IS DISTINCT FROM disposition_target_kind"));
    assert!(publication.contains("target_kind IS DISTINCT FROM envelope_target_kind"));
    assert!(publication.contains("target_id IS DISTINCT FROM disposition_target_id"));
    assert!(publication.contains("target_id IS DISTINCT FROM envelope_target_id"));
    assert!(publication.contains("disposition_core_digest IS DISTINCT FROM core_record_digest"));
    assert!(
        publication
            .contains("envelope_disposition_digest IS DISTINCT FROM disposition_record_digest")
    );
    assert!(json_validator.contains("DISPATCH_BUDGET_HEADROOM_IDENTITY_INVALID"));
    assert!(json_validator.contains("DISPATCH_BUDGET_NOT_REQUIRED_CACHE_FIELDS_PRESENT"));
    assert!(json_validator.contains("DISPATCH_BUDGET_REQUIRED_CACHE_FIELDS_INCOMPLETE"));
}

#[test]
fn charge_uses_only_the_database_clock_and_checked_scaled_integer_arithmetic() {
    let charge = function_body("object_store_dispatch_charge_provider_attempt_v1");

    assert_eq!(charge.matches("clock_unix_ms_v1()").count(), 1);
    assert!(!charge.contains("CURRENT_TIMESTAMP"));
    assert!(!charge.contains("statement_timestamp"));
    assert!(!charge.contains("transaction_timestamp"));
    assert!(charge.contains("database_now >= deadline_unix_ms"));
    assert!(charge.contains("elapsed_ms * bucket.refill_units > 18446744073709551615"));
    assert!(charge.contains("capacity_scaled > 18446744073709551615"));
    assert!(charge.contains("attempt_units * bucket.refill_interval_ms > 18446744073709551615"));
}

#[test]
fn charge_locks_and_checks_every_cap_before_inserting_or_debiting() {
    let charge = function_body("object_store_dispatch_charge_provider_attempt_v1");
    let validation = charge
        .find("FOR UPDATE OF state")
        .expect("cap rows must be locked");
    let grant = charge
        .find("INSERT INTO object_store_retention.object_dispatch_provider_charge_grants")
        .expect("durable grant insert must exist");
    let debit = charge
        .find("UPDATE object_store_retention.object_dispatch_budget_bucket_state AS state SET")
        .expect("bucket debit must exist");

    assert!(validation < grant);
    assert!(grant < debit);
    assert!(charge.contains("expected_caps := ARRAY[1::smallint, (traffic_class + 1)::smallint]"));
    assert!(charge.contains("expected_caps := expected_caps || 7::smallint"));
}

fn table_body(name: &str) -> &str {
    let marker = format!("CREATE TABLE object_store_retention.{name} (");
    let start = MIGRATION
        .find(&marker)
        .unwrap_or_else(|| panic!("missing table {name}"));
    let rest = &MIGRATION[start + marker.len()..];
    let end = rest
        .find("\n);\n")
        .unwrap_or_else(|| panic!("unterminated table {name}"));
    &rest[..end]
}

fn function_body(name: &str) -> &str {
    let marker = format!("CREATE FUNCTION object_store_retention.{name}(");
    let start = PROVISIONING
        .find(&marker)
        .unwrap_or_else(|| panic!("missing function {name}"));
    let rest = &PROVISIONING[start + marker.len()..];
    let end = rest
        .find("\n$$;")
        .unwrap_or_else(|| panic!("unterminated function {name}"));
    &rest[..end]
}

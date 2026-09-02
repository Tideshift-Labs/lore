// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Deployment-config guards for WP-118 Phase 5's opt-in fragment provider.

use lore_server::plugins::ImmutableStorePluginFactory;
use lore_server::plugins::postgres::FragmentProviderConfig;
use lore_server::plugins::postgres::PostgresImmutableStorePluginFactory;

const REQUIRED_ENABLED_FIELDS: [&str; 12] = [
    "dispatch_postgres_url",
    "dispatch_ca_cert_path",
    "dispatch_pool_max",
    "dispatch_connect_timeout_millis",
    "dispatch_acquire_timeout_millis",
    "dispatch_statement_timeout_millis",
    "dispatch_lock_timeout_millis",
    "provider_boundary_id",
    "endpoint_host",
    "region",
    "budget_revision",
    "budget_fence",
];

fn base_config(fragment_provider: &str) -> toml::Value {
    let text = format!(
        r#"
url = "postgresql://store.example/cell?sslmode=verify-full"

[object_store]
bucket = "fragment-bucket"
endpoint_url = "https://objects.example.com"
region = "us-test-1"

{fragment_provider}
"#
    );
    toml::from_str(&text).unwrap_or_else(|error| panic!("fixture must parse: {error}"))
}

fn enabled_block() -> String {
    r#"[fragment_provider]
enabled = true
dispatch_postgres_url = "postgresql://dispatcher:dispatch-secret@dispatch.example:5432/cell?sslmode=require"
dispatch_ca_cert_path = "C:/secrets/dispatch-ca.pem"
dispatch_pool_max = 2
dispatch_connect_timeout_millis = 1000
dispatch_acquire_timeout_millis = 1000
dispatch_statement_timeout_millis = 2000
dispatch_lock_timeout_millis = 3000
provider_boundary_id = "cell.primary"
endpoint_host = "objects.example.com"
region = "us-test-1"
budget_revision = "budget-v1"
budget_fence = 1"#
        .to_owned()
}

fn validate(config: &toml::Value) -> Result<(), String> {
    PostgresImmutableStorePluginFactory
        .validate_config(config)
        .map_err(|error| error.to_string())
}

fn without_field(block: &str, field: &str) -> String {
    block
        .lines()
        .filter(|line| !line.starts_with(&format!("{field} =")))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn absent_and_explicitly_disabled_blocks_keep_the_legacy_route_valid() {
    assert!(validate(&base_config("")).is_ok());
    assert!(validate(&base_config("[fragment_provider]\nenabled = false")).is_ok());
    assert!(
        validate(&base_config(
            "[fragment_provider]\nenabled = false\nprovider_boundary_id = \"ignored.partial\"",
        ))
        .is_ok(),
        "a disabled partial block must not become an accidental activation"
    );
}

#[test]
fn every_enabled_field_is_independently_required_and_named() {
    let complete = enabled_block();
    assert!(validate(&base_config(&complete)).is_ok());

    let mut without_object_store = base_config(&complete);
    without_object_store
        .as_table_mut()
        .expect("root config table")
        .remove("object_store");
    let error = validate(&without_object_store)
        .expect_err("enabled fragment_provider without object_store must be refused");
    assert!(error.contains("object_store"), "got {error}");

    for field in REQUIRED_ENABLED_FIELDS {
        let error = validate(&base_config(&without_field(&complete, field)))
            .expect_err("an enabled partial block must be refused");
        assert!(
            error.contains(field),
            "missing {field} must be named without leaking another field: {error}"
        );
    }
}

#[test]
fn enabled_string_fields_must_be_non_empty() {
    let complete = enabled_block();
    for field in [
        "dispatch_postgres_url",
        "dispatch_ca_cert_path",
        "provider_boundary_id",
        "endpoint_host",
        "region",
        "budget_revision",
    ] {
        let line = complete
            .lines()
            .find(|line| line.starts_with(&format!("{field} =")))
            .expect("required string fixture");
        let invalid = complete.replace(line, &format!("{field} = \"\""));
        let error =
            validate(&base_config(&invalid)).expect_err("an enabled empty string must be refused");
        assert!(
            error.contains(field),
            "empty {field} must be named: {error}"
        );
    }
}

#[test]
fn numeric_identity_target_and_budget_values_fail_closed() {
    let complete = enabled_block();
    let invalid = [
        (
            "dispatch_pool_max = 2",
            "dispatch_pool_max = 0",
            "dispatch_pool_max",
        ),
        (
            "dispatch_pool_max = 2",
            "dispatch_pool_max = 6",
            "dispatch_pool_max",
        ),
        (
            "dispatch_connect_timeout_millis = 1000",
            "dispatch_connect_timeout_millis = 0",
            "dispatch_connect_timeout_millis",
        ),
        (
            "dispatch_acquire_timeout_millis = 1000",
            "dispatch_acquire_timeout_millis = 2147483648",
            "dispatch_acquire_timeout_millis",
        ),
        (
            "dispatch_statement_timeout_millis = 2000",
            "dispatch_statement_timeout_millis = 0",
            "dispatch_statement_timeout_millis",
        ),
        (
            "dispatch_lock_timeout_millis = 3000",
            "dispatch_lock_timeout_millis = 2147483648",
            "dispatch_lock_timeout_millis",
        ),
        (
            "provider_boundary_id = \"cell.primary\"",
            "provider_boundary_id = \"bad boundary\"",
            "provider boundary",
        ),
        (
            "endpoint_host = \"objects.example.com\"",
            "endpoint_host = \"https://objects.example.com/path\"",
            "provider boundary",
        ),
        (
            "region = \"us-test-1\"",
            "region = \"bad region\"",
            "provider boundary",
        ),
        (
            "budget_revision = \"budget-v1\"",
            "budget_revision = \".bad\"",
            "budget pin",
        ),
        ("budget_fence = 1", "budget_fence = 0", "budget pin"),
    ];

    for (from, to, expected) in invalid {
        let error = validate(&base_config(&complete.replace(from, to)))
            .expect_err("invalid enabled config must be refused");
        assert!(
            error.contains(expected),
            "{to} must fail as {expected:?}, got {error}"
        );
    }
}

#[test]
fn fragment_provider_rejects_unknown_and_retired_spool_vocabulary() {
    for field in [
        "unknown_field",
        "spool_root",
        "write_behind",
        "reserve_put",
        "put_spool_ready",
    ] {
        let config = format!("{}\n{field} = \"forbidden\"", enabled_block());
        let error = validate(&base_config(&config)).expect_err("unknown field must be refused");
        assert!(
            error.contains(field),
            "unknown field must be named: {error}"
        );
    }
}

#[test]
fn fragment_provider_debug_and_validation_errors_redact_secrets() {
    let secret_url =
        "postgresql://dispatcher:dispatch-secret@dispatch.example:5432/cell?sslmode=require";
    let secret_ca = "C:/secrets/dispatch-ca.pem";
    let secret_boundary = "cell.primary";
    let secret_host = "objects.example.com";
    let secret_region = "us-test-1";
    let secret_revision = "budget-v1";
    let config = base_config(&enabled_block());
    let raw: FragmentProviderConfig = config
        .get("fragment_provider")
        .cloned()
        .expect("fragment_provider table")
        .try_into()
        .expect("typed fragment_provider");
    let debug = format!("{raw:?}");

    for secret in [
        secret_url,
        secret_ca,
        secret_boundary,
        secret_host,
        secret_region,
        secret_revision,
    ] {
        assert!(!debug.contains(secret), "Debug leaked {secret:?}: {debug}");
    }
    assert!(debug.matches("[REDACTED]").count() >= 6);

    let invalid = enabled_block().replace("budget_fence = 1", "budget_fence = 0");
    let error = validate(&base_config(&invalid)).expect_err("invalid pin must fail");
    assert!(!error.contains(secret_url));
    assert!(!error.contains("dispatch-secret"));
    assert!(!error.contains(secret_ca));
}

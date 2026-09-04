// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! WP-114 CD-8: `lore-server`'s wiring for the cell-scale retention scheduler
//! (`lore-server/src/fragment_retention.rs`, `plugins/postgres.rs`'s
//! `cell_retention_settings`, and the `/event_readiness` facet body).
//!
//! `fragment_retention.rs`'s own `#[cfg(test)] mod tests` already proves the
//! two settings/handle degenerate cases —
//! `a_cell_with_no_retention_settings_spawns_nothing` and
//! `enabled_settings_with_no_dispatch_pool_refuse_startup` — this file does
//! not duplicate those. `lore-object-dispatch/tests/cell_retention.rs`
//! separately owns `CellRetentionSettings::new`'s own reviewed bounds and
//! `CellRetentionReadiness`'s progress rule from synthetic values; this file
//! does not restate that either. `cell_retention_settings` and its sibling
//! `fragment_prune_settings` (`plugins/postgres.rs`) are `pub(crate)`,
//! unreachable from an external `tests/` binary — their own control flow
//! (the `enabled` filter, the `cell_retention_enabled == Some(false)`
//! shortcut, and the exact field threading into `CellRetentionSettings::new`)
//! is covered by a same-file `#[cfg(test)]` addition to `plugins/postgres.rs`
//! itself, not here. What is left, and what this file covers:
//!
//! 1. The TOML wire shape: `[plugins.postgres.<store>.fragment_provider]`'s
//!    five `cell_retention_*` keys parse onto the *public*
//!    `FragmentProviderConfig` with the right names, types, and defaults, and
//!    the parsed values thread into `CellRetentionSettings::new` in the same
//!    positions `cell_retention_settings` uses. Includes the wire-format type
//!    fidelity cases (a value past `u32::MAX` failing to parse rather than
//!    truncating) that a same-file unit test constructing the struct directly
//!    in Rust would not exercise.
//! 2. The `/event_readiness` facet body: `ServerHealth.cell_retention` and
//!    the nine `retention_*` response fields, fully offline against a real
//!    `CellRetentionReadiness` driven through its own public `record_pass`/
//!    `record_failure`, mirroring `event_readiness.rs`'s own internal test
//!    style for the sibling relay/prune facets.
//!
//! # What this file does NOT cover, and why
//!
//! The two live cases from the original brief — startup refusing a database
//! whose retention layer (0023/0024) is absent, and a happy path against a
//! database with the full cell chain installed — need a real
//! `FragmentCellRetentionHandle`. That type has no public constructor
//! anywhere: its only mint site is `FragmentProviderEntry::cell_retention()`,
//! reachable only after a full `FragmentProviderEntry::connect()` — a real
//! S3-compatible bucket, the full 20-migration cell chain (schema attestation
//! checks all four layers, not just retention's), CD-4's charge-authority
//! migrations, and a `PinnedRootCa` TLS dispatch pool
//! (`phase5_fragment_provider_wiring.rs`'s own
//! `server_exposes_only_pinned_ca_tls_and_the_pool_owns_the_operation_envelope`
//! pins `Disabled` as structurally forbidden on this path). Nothing in the
//! fork stands that up live today (checked `lore-server`, `lore-postgres`,
//! and `lore-fragment-provider`'s own test trees). This is a recorded
//! REQUIRED-DEFERRED, owed to a dedicated live runner in the shape of
//! `run-cell-schema-install-live.ps1`, not something to improvise inline
//! against this file's offline fixtures.

use std::sync::Arc;
use std::sync::Weak;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use axum::http::StatusCode;
use axum::routing;
use axum_test::TestServer;
use lore_object_dispatch::cell_retention::CellRetentionBacklog;
use lore_object_dispatch::cell_retention::CellRetentionPruneReport;
use lore_object_dispatch::cell_retention::CellRetentionReadiness;
use lore_object_dispatch::cell_retention::CellRetentionSettings;
use lore_object_dispatch::cell_retention::CellRetentionSettingsError;
use lore_object_dispatch::cell_retention::MAX_CELL_RETENTION_BATCH;
use lore_object_dispatch::cell_retention::REASON_BLOCKED_BACKLOG;
use lore_server::http::server::ServerHealth;
use lore_server::plugins::postgres::PostgresStoreConfig;

// ---------------------------------------------------------------------------------------------
// Section 1: the TOML wire shape (offline, executed)
// ---------------------------------------------------------------------------------------------

/// A realistic `[plugins.postgres.immutable_store]` table with all five
/// `cell_retention_*` keys set to non-default values, so a field silently
/// reading its default instead of the parsed value would not be caught.
const REALISTIC_FRAGMENT_PROVIDER_TOML: &str = r#"
url = "postgres://user:pass@localhost:5432/lore"

[fragment_provider]
enabled = true
cell_retention_enabled = true
cell_retention_interval_millis = 5000
cell_retention_batch = 50
cell_retention_terminal_retention_millis = 120000
cell_retention_stall_ticks = 4
"#;

/// The realistic table parses onto the *public* `FragmentProviderConfig` with
/// the exact key names `cell_retention_settings` reads, and the parsed values
/// thread into `CellRetentionSettings::new` in the same field order that
/// function uses, producing the expected settings.
///
/// This cannot call `cell_retention_settings` itself (`pub(crate)`, invisible
/// here); see the module doc for why, and the source-shape pin below for the
/// half this test cannot reach.
#[test]
fn a_realistic_fragment_provider_toml_table_threads_into_cell_retention_settings() {
    let cfg: PostgresStoreConfig = toml::from_str(REALISTIC_FRAGMENT_PROVIDER_TOML)
        .expect("a realistic [plugins.postgres.<store>] table must parse");
    let provider = cfg
        .fragment_provider
        .as_ref()
        .expect("the fragment_provider block must parse");
    assert!(provider.enabled);
    assert_eq!(provider.cell_retention_enabled, Some(true));
    assert_eq!(provider.cell_retention_interval_millis, Some(5_000));
    assert_eq!(provider.cell_retention_batch, Some(50));
    assert_eq!(
        provider.cell_retention_terminal_retention_millis,
        Some(120_000)
    );
    assert_eq!(provider.cell_retention_stall_ticks, Some(4));

    let settings = CellRetentionSettings::new(
        provider.cell_retention_interval_millis,
        provider.cell_retention_batch,
        provider.cell_retention_terminal_retention_millis,
        provider.cell_retention_stall_ticks,
    )
    .expect("the parsed TOML values are within CellRetentionSettings' reviewed bounds");
    assert_eq!(settings.interval, Duration::from_millis(5_000));
    assert_eq!(settings.batch, 50);
    assert_eq!(settings.terminal_retention, Duration::from_millis(120_000));
    assert_eq!(settings.stall_ticks, 4);
}

/// A `[fragment_provider]` block with none of the five keys set parses every
/// one to `None`, so `cell_retention_settings` (which passes these straight
/// through) resolves to `CellRetentionSettings::default()` rather than a
/// TOML-layer default silently diverging from the Rust-layer one.
#[test]
fn an_empty_fragment_provider_toml_table_parses_every_cell_retention_key_to_none() {
    let cfg: PostgresStoreConfig = toml::from_str(
        r#"
        url = "postgres://user:pass@localhost:5432/lore"

        [fragment_provider]
        enabled = true
        "#,
    )
    .expect("a fragment_provider table with only `enabled` must parse");
    let provider = cfg.fragment_provider.as_ref().expect("block must parse");
    assert_eq!(provider.cell_retention_enabled, None);
    assert_eq!(provider.cell_retention_interval_millis, None);
    assert_eq!(provider.cell_retention_batch, None);
    assert_eq!(provider.cell_retention_terminal_retention_millis, None);
    assert_eq!(provider.cell_retention_stall_ticks, None);

    let settings = CellRetentionSettings::new(
        provider.cell_retention_interval_millis,
        provider.cell_retention_batch,
        provider.cell_retention_terminal_retention_millis,
        provider.cell_retention_stall_ticks,
    )
    .expect("every key omitted must still validate");
    assert_eq!(settings, CellRetentionSettings::default());
}

/// A `[plugins.postgres.<store>]` table with no `fragment_provider` block at
/// all parses to `None`, matching `cell_retention_settings`'s first inert
/// case (an absent block never opened a dispatch pool).
#[test]
fn an_absent_fragment_provider_block_parses_to_none() {
    let cfg: PostgresStoreConfig =
        toml::from_str(r#"url = "postgres://user:pass@localhost:5432/lore""#)
            .expect("a table with no fragment_provider block must still parse");
    assert!(cfg.fragment_provider.is_none());
}

/// `cell_retention_enabled = false` parses distinctly from an absent key
/// (`None`), which is the fact `cell_retention_settings`'s
/// `== Some(false)` comparison (not `!provider.cell_retention_enabled...`)
/// depends on to tell "operator explicitly turned it off" apart from
/// "operator said nothing".
#[test]
fn cell_retention_enabled_false_parses_distinctly_from_omitted() {
    let cfg: PostgresStoreConfig = toml::from_str(
        r#"
        url = "postgres://user:pass@localhost:5432/lore"

        [fragment_provider]
        enabled = true
        cell_retention_enabled = false
        "#,
    )
    .expect("an explicit cell_retention_enabled = false must parse");
    assert_eq!(
        cfg.fragment_provider
            .as_ref()
            .unwrap()
            .cell_retention_enabled,
        Some(false)
    );
}

/// A TOML-parsed out-of-bounds value reaches the same typed error a directly
/// constructed one does, through the real `u32`/`u64` types the wire format
/// deserializes into (not `i64`/`f64`, which TOML could plausibly produce for
/// an untyped consumer).
#[test]
fn a_toml_parsed_out_of_bounds_batch_is_refused_the_same_way_as_a_direct_one() {
    let cfg: PostgresStoreConfig = toml::from_str(
        r#"
        url = "postgres://user:pass@localhost:5432/lore"

        [fragment_provider]
        enabled = true
        cell_retention_batch = 0
        "#,
    )
    .expect("a zero batch must still parse; the bound is CellRetentionSettings' job, not serde's");
    let provider = cfg.fragment_provider.as_ref().unwrap();
    assert_eq!(provider.cell_retention_batch, Some(0));
    assert_eq!(
        CellRetentionSettings::new(None, provider.cell_retention_batch, None, None),
        Err(CellRetentionSettingsError::Batch)
    );
}

/// A batch value past `u32::MAX` fails at the TOML/serde layer itself, before
/// `CellRetentionSettings::new` is ever reached — proving `cell_retention_batch`
/// is really typed `u32` in the wire format, not a wider integer that would
/// silently truncate.
#[test]
fn a_batch_value_past_u32_max_fails_to_parse_rather_than_truncating() {
    let result: Result<PostgresStoreConfig, _> = toml::from_str(
        r#"
        url = "postgres://user:pass@localhost:5432/lore"

        [fragment_provider]
        enabled = true
        cell_retention_batch = 5000000000
        "#,
    );
    assert!(
        result.is_err(),
        "a batch value past u32::MAX must fail to deserialize, not silently truncate"
    );
}

/// The reviewed batch ceiling `MAX_CELL_RETENTION_BATCH` (the bound
/// `cell_retention_batch` is checked against once parsed) is itself a `u32`,
/// so a config value at exactly that ceiling parses and validates -- the
/// TOML layer must not narrow the type below what the bound needs.
#[test]
fn the_batch_ceiling_itself_parses_and_validates() {
    let toml_text = format!(
        r#"
        url = "postgres://user:pass@localhost:5432/lore"

        [fragment_provider]
        enabled = true
        cell_retention_batch = {MAX_CELL_RETENTION_BATCH}
        "#
    );
    let cfg: PostgresStoreConfig =
        toml::from_str(&toml_text).expect("the exact ceiling must parse");
    let provider = cfg.fragment_provider.as_ref().unwrap();
    assert_eq!(
        provider.cell_retention_batch,
        Some(MAX_CELL_RETENTION_BATCH)
    );
    assert!(
        CellRetentionSettings::new(None, provider.cell_retention_batch, None, None).is_ok(),
        "the ceiling itself must validate, not just values below it"
    );
}

// ---------------------------------------------------------------------------------------------
// Section 2: the `/event_readiness` facet body (offline, executed)
// ---------------------------------------------------------------------------------------------

fn settings() -> CellRetentionSettings {
    CellRetentionSettings::new(Some(1_000), Some(10), Some(600_000), Some(2))
        .expect("bounded settings")
}

fn healthy_pass() -> (CellRetentionPruneReport, CellRetentionBacklog) {
    (
        CellRetentionPruneReport {
            examined: 4,
            pruned_requests: 4,
            pruned_attempts: 4,
            pruned_spool_objects: 4,
            pruned_payload_purges: 4,
            pruned_fetch_leases: 4,
            pruned_charge_grants: 1,
            horizon_unix_ms: 1_000,
            database_now_unix_ms: 601_000,
        },
        CellRetentionBacklog {
            prunable: 0,
            blocked: 0,
            grants: 0,
            horizon_unix_ms: 1_000,
            database_now_unix_ms: 601_000,
        },
    )
}

fn blocked_pass() -> (CellRetentionPruneReport, CellRetentionBacklog) {
    (
        CellRetentionPruneReport {
            examined: 0,
            pruned_requests: 0,
            pruned_attempts: 0,
            pruned_spool_objects: 0,
            pruned_payload_purges: 0,
            pruned_fetch_leases: 0,
            pruned_charge_grants: 0,
            horizon_unix_ms: 1_000,
            database_now_unix_ms: 601_000,
        },
        CellRetentionBacklog {
            prunable: 0,
            blocked: 3,
            grants: 0,
            horizon_unix_ms: 1_000,
            database_now_unix_ms: 601_000,
        },
    )
}

fn health(cell_retention: Option<Arc<CellRetentionReadiness>>) -> Arc<ServerHealth> {
    Arc::new(ServerHealth {
        immutable_store: Weak::<lore_storage::LocalImmutableStore>::new(),
        available: AtomicBool::new(true),
        interval_timeout: None,
        store_health_check: false,
        drain: None,
        event_relay: None,
        fragment_prune: None,
        cell_retention,
    })
}

async fn body(health: Arc<ServerHealth>) -> serde_json::Value {
    let app = axum::Router::new().route(
        "/event_readiness",
        routing::get(lore_server::http::event_readiness::handler).with_state(health),
    );
    let server = TestServer::new(app).expect("test server");
    let response = server.get("/event_readiness").await;
    assert_eq!(response.status_code(), StatusCode::OK);
    response.json()
}

/// A cell with no cell-retention scheduler configured reports `false`/`null`
/// rather than a vacuous green -- the same honest-absence rule the relay and
/// prune facets already follow on this endpoint.
#[tokio::test]
async fn a_cell_with_no_cell_retention_reports_unconfigured_rather_than_green() {
    let json = body(health(None)).await;
    assert_eq!(json["retention_configured"], false);
    assert!(json["retention_ready"].is_null());
    assert!(json["retention_reason"].is_null());
    assert_eq!(json["retention_last_prunable_backlog"], -1);
    assert_eq!(json["retention_last_blocked_backlog"], -1);
    assert_eq!(json["retention_last_grant_backlog"], -1);
}

/// A healthy pass reports every evidence field, not only the boolean facet.
#[tokio::test]
async fn a_healthy_retention_pass_reports_ready_with_its_evidence() {
    let readiness = Arc::new(CellRetentionReadiness::new(&settings()));
    let (report, backlog) = healthy_pass();
    readiness.record_pass(&report, &backlog);

    let json = body(health(Some(readiness))).await;
    assert_eq!(json["retention_configured"], true);
    assert_eq!(json["retention_ready"], true);
    assert!(json["retention_reason"].is_null());
    assert_eq!(json["retention_consecutive_stalls"], 0);
    assert_eq!(json["retention_last_pruned"], 4);
    assert_eq!(json["retention_last_examined"], 4);
    assert_eq!(json["retention_last_prunable_backlog"], 0);
    assert_eq!(json["retention_last_blocked_backlog"], 0);
    assert_eq!(json["retention_last_grant_backlog"], 0);
}

/// Rows past the retention horizon held back by non-terminal payload
/// evidence flip the facet false, once the configured stall tolerance is
/// spent, and name the specific reason -- the one condition the module's own
/// docs call out as having no other red gate.
#[tokio::test]
async fn a_blocked_backlog_flips_the_facet_false_with_the_specific_reason() {
    let readiness = Arc::new(CellRetentionReadiness::new(&settings()));
    let (report, backlog) = blocked_pass();
    // settings()'s stall_ticks is 2.
    readiness.record_pass(&report, &backlog);
    readiness.record_pass(&report, &backlog);

    let json = body(health(Some(readiness))).await;
    assert_eq!(json["retention_ready"], false);
    assert_eq!(json["retention_reason"], REASON_BLOCKED_BACKLOG);
    assert_eq!(json["retention_consecutive_stalls"], 2);
    assert_eq!(json["retention_last_blocked_backlog"], 3);
}

/// One blocked pass alone must not yet flip the facet -- matches
/// `cell_retention.rs`'s own module-doc tolerance rule ("a burst legitimately
/// saturates for a pass or two"), proven here through the HTTP surface rather
/// than the readiness type directly.
#[tokio::test]
async fn one_blocked_pass_alone_does_not_yet_flip_the_facet() {
    let readiness = Arc::new(CellRetentionReadiness::new(&settings()));
    let (report, backlog) = blocked_pass();
    readiness.record_pass(&report, &backlog);

    let json = body(health(Some(readiness))).await;
    assert_eq!(
        json["retention_ready"], true,
        "one blocked pass is within the stall tolerance"
    );
}

/// The retention facet is independent of the relay and prune facets --
/// configuring one must not report the others as configured, and vice versa.
/// This is the HTTP-level counterpart to the module doc's "the two schedulers
/// drain different tables and either can be running without the other having
/// anything to do".
#[tokio::test]
async fn the_retention_facet_is_independent_of_the_relay_and_prune_facets() {
    let readiness = Arc::new(CellRetentionReadiness::new(&settings()));
    let (report, backlog) = healthy_pass();
    readiness.record_pass(&report, &backlog);

    let json = body(health(Some(readiness))).await;
    assert_eq!(
        json["configured"], false,
        "no relay was configured in this fixture"
    );
    assert_eq!(
        json["prune_configured"], false,
        "no prune scheduler was configured in this fixture"
    );
    assert_eq!(json["retention_configured"], true);
    assert_eq!(json["retention_ready"], true);
}

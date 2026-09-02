// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Source-shape controls for WP-118's deployment-only composition seams.
//!
//! The relevant constructors are intentionally private and require live Postgres,
//! S3, and lifecycle state. These controls pin the ordering and capability shape
//! that cannot be injected through the public plugin factory.

use lore_postgres::domain::fragments::FragmentProcessPoolInventory;

const POSTGRES_PLUGIN: &str = include_str!("../src/plugins/postgres.rs");
const SERVER: &str = include_str!("../src/server.rs");
const FRAGMENT_SEAM: &str = include_str!("../../lore-fragment-provider/src/lib.rs");
const DISPATCH_POOL: &str = include_str!("../../lore-object-dispatch/src/dispatch_pool.rs");
const IMMUTABLE_STORE: &str = include_str!("../../lore-postgres/src/store/immutable_store.rs");

fn between<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start = source.find(start).expect("fixture start must exist");
    let remainder = &source[start..];
    let end = remainder.find(end).expect("fixture end must exist");
    &remainder[..end]
}

fn assert_precedes(source: &str, first: &str, second: &str) {
    let first = source.find(first).expect("first marker must exist");
    let second = source.find(second).expect("second marker must exist");
    assert!(first < second, "first marker must precede second marker");
}

#[test]
fn disabled_or_absent_config_returns_before_dispatch_composition() {
    let enabled_conversion = between(
        POSTGRES_PLUGIN,
        "fn enabled_fragment_provider_config(",
        "fn parse_config(",
    );
    assert!(enabled_conversion.contains(".filter(|fragment_provider| fragment_provider.enabled)"));
    assert!(enabled_conversion.contains("return Ok(None);"));

    let connect = between(
        POSTGRES_PLUGIN,
        "pub(crate) async fn connect_immutable_store(",
        "/// Build the CR-029 domain coordinator",
    );
    assert_precedes(
        connect,
        "let fragment_activation = match fragment_provider",
        "let tls = build_tls",
    );
    assert_precedes(
        connect,
        "let Some((fragment_provider, activation, expected_database_identity)) = fragment_activation",
        "std::fs::read_to_string",
    );
    assert_precedes(
        connect,
        "return Ok(store);",
        "FragmentDispatchRuntimeConfig",
    );
    assert_precedes(connect, "return Ok(store);", ".with_fragment_provider(");
}

#[test]
fn lifecycle_is_composed_and_proven_ready_before_provider_activation() {
    let startup = between(
        SERVER,
        "let fragment_process_pool_inventory = postgres_fragment_process_pool_inventory",
        "let mutable_context = MutableStorePluginContext",
    );
    let enabled = between(startup, "if let Some(process_pool_inventory)", "} else {");
    assert_precedes(
        enabled,
        "configure_domain_context(&settings).await?",
        "configure_immutable_store_via_plugin(",
    );
    assert!(enabled.contains("FragmentProviderActivation::new("));
    for field in [
        "coordinator",
        "process_pool_inventory",
        "expected_database_identity",
    ] {
        assert!(enabled.contains(field), "activation omitted {field}");
    }
    assert!(enabled.contains(
        "FragmentProviderActivation::new(\n                coordinator,\n                process_pool_inventory,\n                expected_database_identity,\n            )"
    ));

    let legacy = between(
        startup,
        "} else {",
        "(immutable_store, configured_domain)\n        };",
    );
    assert_precedes(
        legacy,
        "configure_immutable_store_via_plugin(",
        "configure_domain_context(&settings).await?",
    );
    assert!(
        startup
            .contains("configured_domain\n            .fragment_coordinator\n            .clone()")
    );

    let connect = between(
        POSTGRES_PLUGIN,
        "pub(crate) async fn connect_immutable_store(",
        "/// Build the CR-029 domain coordinator",
    );
    assert_precedes(
        connect,
        "let FragmentProviderActivation",
        "coordinator.readiness().await",
    );
    assert_precedes(
        connect,
        "if !readiness.lifecycle_enabled",
        "std::fs::read_to_string",
    );
    assert_precedes(
        connect,
        "if !readiness.ready_for_lifecycle()",
        ".with_fragment_provider(",
    );
    assert_eq!(connect.matches(".with_fragment_provider(").count(), 1);
}

#[test]
fn whole_server_validates_the_exact_five_pool_inventory_before_any_boot_io() {
    let startup = between(
        SERVER,
        "let fragment_process_pool_inventory = postgres_fragment_process_pool_inventory",
        "let mutable_context = MutableStorePluginContext",
    );
    for marker in [
        ".map(lore_postgres::domain::fragments::FragmentProcessPoolInventory::validate)",
        ".transpose()",
        "Invalid Postgres process pool inventory",
    ] {
        assert!(
            startup.contains(marker),
            "missing preflight marker {marker}"
        );
        assert_precedes(
            startup,
            marker,
            "configure_domain_context(&settings).await?",
        );
        assert_precedes(startup, marker, "configure_immutable_store_via_plugin(");
    }
    assert_precedes(
        startup,
        "Invalid Postgres process pool inventory",
        "if let Some(process_pool_inventory)",
    );
    assert_eq!(
        startup
            .matches("FragmentProcessPoolInventory::validate")
            .count(),
        1,
        "server must use the seam-owned canonical validation exactly once"
    );

    let valid = |values: [u32; 5]| {
        let [immutable, mutable, lock, domain, dispatch] = values;
        FragmentProcessPoolInventory {
            immutable_pool_max: immutable,
            mutable_pool_max: mutable,
            lock_pool_max: lock,
            domain_pool_max: domain,
            dispatch_pool_max: dispatch,
        }
        .validate()
    };
    assert!(valid([1, 2, 3, 4, 5]).is_ok(), "total 15 must pass");
    assert!(valid([2, 3, 4, 5, 6]).is_ok(), "exact total 20 must pass");
    for invalid in [
        [0, 1, 1, 1, 1],
        [1, 0, 1, 1, 1],
        [1, 1, 0, 1, 1],
        [1, 1, 1, 0, 1],
        [1, 1, 1, 1, 0],
        [u32::MAX, 1, 1, 1, 1],
        [4, 4, 4, 4, 5],
    ] {
        assert!(
            valid(invalid).is_err(),
            "whole-server inventory {invalid:?} must fail before boot I/O"
        );
    }
}

#[test]
fn enabled_none_refuses_before_tls_s3_or_store_connection() {
    let connect = between(
        POSTGRES_PLUGIN,
        "pub(crate) async fn connect_immutable_store(",
        "/// Build the CR-029 domain coordinator",
    );
    let refusal = "enabled fragment_provider requires the lifecycle coordinator and exact process pool inventory";
    assert!(!connect.contains("fragment_activation.is_none()"));
    assert_precedes(connect, refusal, "let tls = build_tls");
    assert_precedes(connect, refusal, "let object = cfg.object_store");
    assert_precedes(connect, refusal, "PostgresImmutableStore::connect(");
}

#[test]
fn actual_five_pool_maxima_flow_from_their_own_resolved_configs() {
    let inventory = between(
        POSTGRES_PLUGIN,
        "pub(crate) fn fragment_process_pool_inventory(",
        "/// Build the Postgres TLS settings",
    );
    for required in [
        "let immutable = parse_config(PLUGIN_NAME, immutable_config)?",
        "let mutable = parse_config(PLUGIN_NAME, mutable_config)?",
        "let lock = parse_config(PLUGIN_NAME, lock_config)?",
        "immutable_pool_max: immutable.pool_max",
        "mutable_pool_max: mutable.pool_max",
        "lock_pool_max: lock.pool_max",
        "domain_pool_max: mutable.domain_pool_max",
        "dispatch_pool_max: fragment_provider.dispatch_pool_max",
    ] {
        assert!(
            inventory.contains(required),
            "missing exact inventory mapping {required}"
        );
    }

    let server_inventory = between(
        SERVER,
        "fn postgres_fragment_process_pool_inventory(",
        "async fn configure_mutable_store_via_plugin(",
    );
    assert!(server_inventory.contains("settings.mutable_store.mode != \"postgres\""));
    assert!(server_inventory.contains("Some(\"postgres\")"));
    for store_type in ["immutable_store", "mutable_store", "lock_store"] {
        assert!(server_inventory.contains(store_type));
    }
    assert!(server_inventory.contains("fragment_process_pool_inventory("));
}

#[test]
fn one_arc_dispatch_pool_serves_attestation_and_charge_authority() {
    let connect = between(
        FRAGMENT_SEAM,
        "    pub async fn connect<P>(",
        "    pub fn boundary(&self)",
    );
    assert_eq!(connect.matches("DispatchRuntimePool::new(").count(), 1);
    assert_eq!(connect.matches("Arc::new(").count(), 1);
    assert!(connect.contains("DispatchRuntimeClient::new(pool.clone())"));
    assert!(connect.contains("attest_cell_schema(&dispatch, boundary)"));
    assert!(connect.contains("PostgresProviderChargeAuthority::new(pool)"));
    assert_precedes(
        connect,
        "let ValidatedFragmentProcessPoolInventory { inventory, budget }",
        "DispatchRuntimePool::new(",
    );
    for field in ["pool_max: inventory.dispatch_pool_max", "budget,"] {
        assert!(connect.contains(field), "budget omitted {field}");
    }
    assert_precedes(connect, "DispatchRuntimeClient::new", "attest_cell_schema(");
    assert_precedes(
        connect,
        "attest_cell_schema(",
        "PostgresProviderChargeAuthority::new",
    );
    assert_precedes(
        connect,
        "PostgresProviderChargeAuthority::new",
        "with_transport_port(",
    );
}

#[test]
fn server_exposes_only_pinned_ca_tls_and_the_pool_owns_the_operation_envelope() {
    let connect = between(
        POSTGRES_PLUGIN,
        "pub(crate) async fn connect_immutable_store(",
        "/// Build the CR-029 domain coordinator",
    );
    assert!(connect.contains("FragmentDispatchTls::PinnedRootCa(dispatch_ca)"));
    assert!(!connect.contains("FragmentDispatchTls::Disabled"));
    assert_precedes(
        connect,
        "std::fs::read_to_string",
        "FragmentDispatchRuntimeConfig",
    );
    assert_precedes(
        connect,
        "dispatch_ca.trim().is_empty()",
        "FragmentDispatchRuntimeConfig",
    );

    let pool_new = between(
        DISPATCH_POOL,
        "    pub fn new(config: DispatchPoolConfig)",
        "    /// The identity this pool connects as.",
    );
    assert!(pool_new.contains(".statement_timeout"));
    assert!(pool_new.contains(".checked_add(config.lock_timeout)"));
    assert!(DISPATCH_POOL.contains("pinned root CA requires sslmode=require"));
}

#[test]
fn boundary_and_physical_sdk_target_are_attested_before_gateway_construction() {
    let enabled_conversion = between(
        POSTGRES_PLUGIN,
        "fn enabled_fragment_provider_config(",
        "fn parse_config(",
    );
    assert!(enabled_conversion.contains("&object_store.bucket"));
    assert!(enabled_conversion.contains("&region"));
    assert!(enabled_conversion.contains("&endpoint_host"));

    let attach = between(
        IMMUTABLE_STORE,
        "    pub async fn with_fragment_provider(",
        "    fn hash_key(hash: Hash)",
    );
    assert_precedes(
        attach,
        "target.bucket != self.bucket",
        "FragmentProviderEntry::connect(",
    );
    assert_precedes(
        attach,
        ".resolved_endpoint_url()",
        "FragmentProviderEntry::connect(",
    );
    assert!(attach.contains(".s3\n            .sdk_client()\n            .config()"));
    assert!(attach.contains("PostgresFragmentS3Transport::new("));
    assert_precedes(
        attach,
        "PostgresFragmentS3Transport::new(",
        "FragmentProviderEntry::connect(",
    );
}

#[test]
fn physical_database_identity_is_bound_before_schema_charge_or_gateway_construction() {
    let connect = between(
        FRAGMENT_SEAM,
        "    pub async fn connect<P>(",
        "    pub fn boundary(&self)",
    );
    assert_precedes(
        connect,
        "attest_database_identity(config.expected_database_identity.0)",
        "attest_cell_schema(&dispatch, boundary)",
    );
    assert_precedes(
        connect,
        "attest_database_identity(config.expected_database_identity.0)",
        "PostgresProviderChargeAuthority::new(pool)",
    );
    assert_precedes(
        connect,
        "attest_database_identity(config.expected_database_identity.0)",
        "FragmentProviderGateway::with_transport_port(",
    );

    let activation = between(
        POSTGRES_PLUGIN,
        "pub(crate) struct FragmentProviderActivation",
        "const MAX_DISPATCH_POOL_MAX",
    );
    assert!(activation.contains("expected_database_identity: DatabaseIdentity"));
    let plugin_connect = between(
        POSTGRES_PLUGIN,
        "pub(crate) async fn connect_immutable_store(",
        "/// Build the CR-029 domain coordinator",
    );
    assert!(plugin_connect.contains("activation.expected_database_identity.system_identifier"));
    assert!(plugin_connect.contains("activation.expected_database_identity.database_oid"));
    assert!(!plugin_connect.contains("activation.expected_database_identity.database_name"));
}

#[test]
fn get_remains_unmetered_and_phase5_config_has_no_spool_route() {
    let gateway = between(
        FRAGMENT_SEAM,
        "impl FragmentProviderGateway {",
        "impl std::fmt::Debug for FragmentProviderGateway",
    );
    let get = between(
        gateway,
        "    pub async fn get(\n",
        "    /// Runs every local Phase 4 check",
    );
    assert!(get.contains("ProviderGetAttemptRequest"));
    assert!(get.contains(".issue_get(&request, operation)"));
    for forbidden in [
        "ProviderAttemptLedger",
        "BudgetPin",
        "charge_authority",
        "deadline",
        "admit_operation",
    ] {
        assert!(!get.contains(forbidden), "GET widened through {forbidden}");
    }

    let raw_config = between(
        POSTGRES_PLUGIN,
        "pub struct FragmentProviderConfig",
        "impl fmt::Debug for FragmentProviderConfig",
    );
    for forbidden in ["spool", "write_behind", "ReservePut", "PutSpoolReady"] {
        assert!(
            !raw_config.contains(forbidden),
            "Phase 5 config exposed retired vocabulary {forbidden}"
        );
    }
    assert!(raw_config.contains("dispatch_postgres_url"));
    assert!(raw_config.contains("provider_boundary_id"));
}

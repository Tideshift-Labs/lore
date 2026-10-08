// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! The two budget provenance types: record validation, cell-binding checks and the refusals that
//! must precede any database connection. Database-backed publication of both types is covered in
//! `budget_configure_live.rs`.

use lore_object_dispatch::DispatchTlsMode;
use lore_object_dispatch::budget_provenance::DOCUMENTED_PROVIDER_BUDGET_PROVENANCE;
use lore_object_dispatch::budget_provenance::DOCUMENTED_PROVIDER_BUDGET_REVISION;
use lore_object_dispatch::budget_provenance::DOCUMENTED_PROVIDER_ENDPOINT;
use lore_object_dispatch::budget_provenance::DOCUMENTED_PROVIDER_ENDPOINT_HOST;
use lore_object_dispatch::budget_provenance::DOCUMENTED_PROVIDER_MAX_WINDOW_MS;
use lore_object_dispatch::budget_provenance::LOCAL_BUDGET_PROVENANCE;
use lore_object_dispatch::budget_provenance::LOCAL_MAX_WINDOW_MS;
use lore_object_dispatch::budget_provenance::documented_provider_revision;
use lore_object_dispatch::cell_budget_configure::BudgetAction;
use lore_object_dispatch::cell_budget_configure::BudgetConfigureError;
use lore_object_dispatch::cell_budget_configure::CellConfigBinding;
use lore_object_dispatch::cell_budget_configure::LEGACY_LOCAL_BUDGET_REVISION;
use lore_object_dispatch::cell_budget_configure::LOCAL_BUDGET_REVISION;
use lore_object_dispatch::cell_budget_configure::LocalBudgetConfiguration;
use lore_object_dispatch::cell_budget_configure::configure_budget;
use lore_object_dispatch::cell_budget_configure::configure_budget_for_cell;

#[path = "common/budget_configuration.rs"]
mod configuration;

const NOW: i64 = 1_000_000;
const TENANT_HOST: &str = "nyc3.digitaloceanspaces.com";

fn documented() -> LocalBudgetConfiguration {
    configuration::documented_config(1, 1, NOW)
}

fn local() -> LocalBudgetConfiguration {
    configuration::config(1, 1, NOW)
}

/// Move the hard expiry to `issued + window_ms` and keep the derived revision exact, so a window
/// case isolates the window rule alone.
fn documented_with_window(window_ms: i64) -> LocalBudgetConfiguration {
    let mut config = documented();
    config.hard_expires_at_unix_ms = config.issued_at_unix_ms + window_ms;
    config.allocation_revision =
        documented_provider_revision(config.allocation_fence, config.hard_expires_at_unix_ms);
    config
}

fn invalid(config: &LocalBudgetConfiguration) -> bool {
    config.validate() == Err(BudgetConfigureError::InvalidConfiguration)
}

#[test]
fn a_valid_documented_record_passes_and_roundtrips_with_its_extra_fields() {
    let config = documented();
    config.validate().unwrap();
    assert!(config.is_documented_provider());
    let json = serde_json::to_vec(&config).unwrap();
    let text = String::from_utf8(json.clone()).unwrap();
    assert!(text.contains("\"providerRegion\":\"do.sfo3\""), "{text}");
    assert!(
        text.contains("\"rulingReference\":\"object-store-budget-v1#owner-decision-2026-08-31\""),
        "{text}"
    );
    let parsed = LocalBudgetConfiguration::from_json(&json).unwrap();
    assert_eq!(serde_json::to_vec(&parsed).unwrap(), json);
    assert_eq!(
        config.allocation_revision,
        format!("owner-decision-f1-x{}", config.hard_expires_at_unix_ms)
    );
}

#[test]
fn local_canonical_json_omits_the_documented_only_fields() {
    let json = serde_json::to_string(&local()).unwrap();
    assert!(!json.contains("providerRegion"), "{json}");
    assert!(!json.contains("rulingReference"), "{json}");
    local().validate().unwrap();
}

#[test]
fn documented_record_refuses_each_off_contract_field() {
    type Mutate = fn(&mut LocalBudgetConfiguration);
    let cases: Vec<(&str, Mutate)> = vec![
        ("http endpoint", |c| {
            c.provider_endpoint = "http://sfo3.digitaloceanspaces.com".into();
        }),
        ("local http endpoint", |c| {
            c.provider_endpoint = "http://minio:9000".into();
        }),
        ("other https host (nyc3)", |c| {
            c.provider_endpoint = format!("https://{TENANT_HOST}");
        }),
        ("trailing slash", |c| {
            c.provider_endpoint = format!("{DOCUMENTED_PROVIDER_ENDPOINT}/");
        }),
        ("port", |c| {
            c.provider_endpoint = format!("{DOCUMENTED_PROVIDER_ENDPOINT}:443");
        }),
        ("region nyc3", |c| {
            c.provider_region = Some("do.nyc3".into());
        }),
        ("region absent", |c| c.provider_region = None),
        ("ruling absent", |c| c.ruling_reference = None),
        ("ruling different", |c| {
            c.ruling_reference = Some("object-store-budget-v1#owner-decision-2026-09-01".into());
        }),
        ("ruling empty", |c| c.ruling_reference = Some(String::new())),
        ("local schema with documented provenance", |c| {
            c.schema_revision = LOCAL_BUDGET_REVISION.into();
        }),
        ("legacy local schema with documented provenance", |c| {
            c.schema_revision = LEGACY_LOCAL_BUDGET_REVISION.into();
        }),
        ("documented schema with local provenance", |c| {
            c.provenance = LOCAL_BUDGET_PROVENANCE.into();
        }),
        ("unknown provenance", |c| {
            c.provenance = "measured-production".into();
        }),
        ("rate 801 ops/s (shared 801 at 1000 ms)", |c| {
            c.shared_units = 801;
        }),
        ("rate 81 per 100 ms", |c| {
            c.refill_interval_ms = 100;
            c.shared_units = 81;
            c.class_units = 64;
            c.list_units = 16;
        }),
        ("refill 1001 ms", |c| {
            c.refill_interval_ms = 1001;
        }),
        ("allocation revision with the wrong fence", |c| {
            c.allocation_revision = documented_provider_revision(2, c.hard_expires_at_unix_ms);
        }),
        ("allocation revision with the wrong expiry", |c| {
            c.allocation_revision =
                documented_provider_revision(c.allocation_fence, c.hard_expires_at_unix_ms + 1);
        }),
        ("allocation revision arbitrary", |c| {
            c.allocation_revision = "budget-v1".into();
        }),
        ("allocation revision with a suffix", |c| {
            c.allocation_revision = format!("{}-extra", c.allocation_revision);
        }),
        ("allocation revision with a non-canonical fence", |c| {
            c.allocation_revision = format!("owner-decision-f01-x{}", c.hard_expires_at_unix_ms);
        }),
    ];
    for (name, mutate) in cases {
        let mut config = documented();
        mutate(&mut config);
        assert_eq!(
            config.validate(),
            Err(BudgetConfigureError::InvalidConfiguration),
            "{name}"
        );
        // The JSON entry point refuses the same record.
        assert_eq!(
            LocalBudgetConfiguration::from_json(&serde_json::to_vec(&config).unwrap()).unwrap_err(),
            BudgetConfigureError::InvalidConfiguration,
            "{name} via from_json"
        );
    }
}

#[test]
fn documented_rate_ceiling_is_800_per_second_and_inclusive() {
    // 800 per 1000 ms is the ceiling itself.
    documented().validate().unwrap();
    // 80 per 100 ms is also exactly 800 per second.
    let mut tenth = documented();
    tenth.refill_interval_ms = 100;
    tenth.shared_units = 80;
    tenth.class_units = 64;
    tenth.list_units = 16;
    tenth.validate().unwrap();
    // A slower refill with fewer units stays under the ceiling.
    let mut slow = documented();
    slow.shared_units = 100;
    slow.class_units = 80;
    slow.list_units = 20;
    slow.validate().unwrap();
}

#[test]
fn documented_window_is_sixty_seconds_to_seven_days_inclusive() {
    documented_with_window(60_000).validate().unwrap();
    documented_with_window(DOCUMENTED_PROVIDER_MAX_WINDOW_MS)
        .validate()
        .unwrap();
    assert_eq!(DOCUMENTED_PROVIDER_MAX_WINDOW_MS, 7 * 86_400_000);
    for window in [DOCUMENTED_PROVIDER_MAX_WINDOW_MS + 1, 59_999, 0, -1] {
        assert!(invalid(&documented_with_window(window)), "{window}");
    }
}

#[test]
fn local_window_is_sixty_seconds_to_twenty_four_hours_inclusive() {
    let with_window = |window: i64| {
        let mut config = local();
        config.hard_expires_at_unix_ms = config.issued_at_unix_ms + window;
        config
    };
    with_window(LOCAL_MAX_WINDOW_MS).validate().unwrap();
    with_window(60_000).validate().unwrap();
    assert_eq!(LOCAL_MAX_WINDOW_MS, 86_400_000);
    for window in [LOCAL_MAX_WINDOW_MS + 1, 59_999] {
        assert!(invalid(&with_window(window)), "{window}");
    }
    // The local cap does not widen to the documented seven days.
    assert!(invalid(&with_window(DOCUMENTED_PROVIDER_MAX_WINDOW_MS)));
}

#[test]
fn local_record_refuses_documented_only_fields_revision_tag_and_https() {
    type Mutate = fn(&mut LocalBudgetConfiguration);
    let cases: Vec<(&str, Mutate)> = vec![
        ("providerRegion", |c| {
            c.provider_region = Some("do.sfo3".into());
        }),
        ("rulingReference", |c| {
            c.ruling_reference = Some("object-store-budget-v1#owner-decision-2026-08-31".into());
        }),
        ("owner-decision revision tag", |c| {
            c.allocation_revision = "owner-decision-f1-x121000".into();
        }),
        ("bare owner-decision prefix", |c| {
            c.allocation_revision = "owner-decision-anything".into();
        }),
        ("https endpoint", |c| {
            c.provider_endpoint = "https://minio:9000".into();
        }),
        ("the documented endpoint", |c| {
            c.provider_endpoint = DOCUMENTED_PROVIDER_ENDPOINT.into();
        }),
        ("documented schema", |c| {
            c.schema_revision = DOCUMENTED_PROVIDER_BUDGET_REVISION.into();
        }),
        ("unknown provenance", |c| {
            c.provenance = "measured-production".into();
        }),
        ("documented provenance on a local schema", |c| {
            c.provenance = DOCUMENTED_PROVIDER_BUDGET_PROVENANCE.into();
        }),
    ];
    for (name, mutate) in cases {
        let mut config = local();
        mutate(&mut config);
        assert_eq!(
            config.validate(),
            Err(BudgetConfigureError::InvalidConfiguration),
            "{name}"
        );
    }
    // A revision that merely resembles the tag stays a valid local token.
    let mut similar = local();
    similar.allocation_revision = "owner-decisionx".into();
    similar.validate().unwrap();
}

#[test]
fn record_whose_provenance_matches_neither_arm_does_not_fall_through() {
    let mut config = documented();
    config.provenance = format!("{DOCUMENTED_PROVIDER_BUDGET_PROVENANCE}x");
    assert!(!config.is_documented_provider());
    assert!(invalid(&config));
}

// ---- cell binding ----------------------------------------------------------------------------

fn matching_binding(config: &LocalBudgetConfiguration) -> CellConfigBinding {
    CellConfigBinding {
        bucket: Some(config.provider_bucket.clone()),
        endpoint_url: Some(config.provider_endpoint.clone()),
        provider_boundary_id: Some(config.provider_boundary_id.clone()),
        endpoint_host: Some(DOCUMENTED_PROVIDER_ENDPOINT_HOST.into()),
    }
}

#[test]
fn a_matching_binding_passes_for_both_provenance_types() {
    let documented = documented();
    documented
        .check_cell_binding(&matching_binding(&documented))
        .unwrap();
    let local = local();
    local.check_cell_binding(&matching_binding(&local)).unwrap();
    // The boundary id and endpoint host are checked only where the layers set them.
    let mut sparse = matching_binding(&documented);
    sparse.provider_boundary_id = None;
    sparse.endpoint_host = None;
    documented.check_cell_binding(&sparse).unwrap();
}

#[test]
fn a_mismatched_or_missing_binding_refuses_for_both_provenance_types() {
    type Mutate = fn(&mut CellConfigBinding);
    let cases: Vec<(&str, Mutate)> = vec![
        ("bucket mismatch", |b| {
            b.bucket = Some("other-bucket".into());
        }),
        ("bucket missing", |b| b.bucket = None),
        ("endpoint_url mismatch", |b| {
            b.endpoint_url = Some(format!("https://{TENANT_HOST}"));
        }),
        ("endpoint_url trailing slash", |b| {
            b.endpoint_url = b.endpoint_url.take().map(|url| format!("{url}/"));
        }),
        ("endpoint_url missing", |b| b.endpoint_url = None),
        ("boundary mismatch", |b| {
            b.provider_boundary_id = Some("other-boundary".into());
        }),
    ];
    for (name, mutate) in cases {
        for config in [documented(), local()] {
            let mut binding = matching_binding(&config);
            mutate(&mut binding);
            assert_eq!(
                config.check_cell_binding(&binding),
                Err(BudgetConfigureError::CellBindingMismatch),
                "{name} ({})",
                config.provenance
            );
        }
    }
    let documented = documented();
    let mut host = matching_binding(&documented);
    host.endpoint_host = Some(TENANT_HOST.into());
    assert_eq!(
        documented.check_cell_binding(&host),
        Err(BudgetConfigureError::CellBindingMismatch),
        "documented endpoint_host mismatch"
    );
    assert_eq!(
        documented.check_cell_binding(&CellConfigBinding::default()),
        Err(BudgetConfigureError::CellBindingMismatch),
        "an empty binding binds nothing"
    );
}

const LAYER: &str = r#"
[plugins.postgres.immutable_store.object_store]
bucket = "test-fragments"
endpoint_url = "https://sfo3.digitaloceanspaces.com"

[plugins.postgres.immutable_store.fragment_provider]
provider_boundary_id = "test-cell-provider"
endpoint_host = "sfo3.digitaloceanspaces.com"
"#;

#[test]
fn toml_layers_read_the_four_bound_keys() {
    let binding = CellConfigBinding::from_toml_layers(&[LAYER]).unwrap();
    assert_eq!(
        binding,
        CellConfigBinding {
            bucket: Some("test-fragments".into()),
            endpoint_url: Some(DOCUMENTED_PROVIDER_ENDPOINT.into()),
            provider_boundary_id: Some("test-cell-provider".into()),
            endpoint_host: Some(DOCUMENTED_PROVIDER_ENDPOINT_HOST.into()),
        }
    );
    documented().check_cell_binding(&binding).unwrap();
}

#[test]
fn dotted_keys_and_inline_tables_read_the_same_binding() {
    let expected = CellConfigBinding::from_toml_layers(&[LAYER]).unwrap();
    let dotted = r#"
plugins.postgres.immutable_store.object_store.bucket = "test-fragments"
plugins.postgres.immutable_store.object_store.endpoint_url = "https://sfo3.digitaloceanspaces.com"
plugins.postgres.immutable_store.fragment_provider.provider_boundary_id = "test-cell-provider"
plugins.postgres.immutable_store.fragment_provider.endpoint_host = "sfo3.digitaloceanspaces.com"
"#;
    let inline = r#"
plugins = { postgres = { immutable_store = { object_store = { bucket = "test-fragments", endpoint_url = "https://sfo3.digitaloceanspaces.com" }, fragment_provider = { provider_boundary_id = "test-cell-provider", endpoint_host = "sfo3.digitaloceanspaces.com" } } } }
"#;
    let mixed = r#"
[plugins.postgres.immutable_store]
object_store = { bucket = "test-fragments", endpoint_url = "https://sfo3.digitaloceanspaces.com" }
fragment_provider.provider_boundary_id = "test-cell-provider"
fragment_provider.endpoint_host = "sfo3.digitaloceanspaces.com"
"#;
    for (name, layer) in [("dotted", dotted), ("inline", inline), ("mixed", mixed)] {
        assert_eq!(
            CellConfigBinding::from_toml_layers(&[layer]).unwrap(),
            expected,
            "{name}"
        );
    }
    let single = "plugins.postgres.immutable_store.object_store.bucket = \"x\"\n";
    assert_eq!(
        CellConfigBinding::from_toml_layers(&[single]).unwrap(),
        CellConfigBinding {
            bucket: Some("x".into()),
            ..CellConfigBinding::default()
        }
    );
}

#[test]
fn absent_keys_and_no_layers_read_as_none() {
    assert_eq!(
        CellConfigBinding::from_toml_layers::<&str>(&[]).unwrap(),
        CellConfigBinding::default()
    );
    assert_eq!(
        CellConfigBinding::from_toml_layers(&["[server]\nname = \"x\"\n"]).unwrap(),
        CellConfigBinding::default()
    );
    let only_bucket = "[plugins.postgres.immutable_store.object_store]\nbucket = \"b\"\n";
    assert_eq!(
        CellConfigBinding::from_toml_layers(&[only_bucket]).unwrap(),
        CellConfigBinding {
            bucket: Some("b".into()),
            ..CellConfigBinding::default()
        }
    );
}

#[test]
fn a_later_layer_overrides_an_earlier_one_key_by_key() {
    let later = "[plugins.postgres.immutable_store.object_store]\nbucket = \"later-bucket\"\n";
    let binding = CellConfigBinding::from_toml_layers(&[LAYER, later]).unwrap();
    assert_eq!(binding.bucket.as_deref(), Some("later-bucket"));
    // Keys the later layer does not set keep the earlier value.
    assert_eq!(
        binding.endpoint_url.as_deref(),
        Some(DOCUMENTED_PROVIDER_ENDPOINT)
    );
    assert_eq!(
        binding.provider_boundary_id.as_deref(),
        Some("test-cell-provider")
    );
    // Order matters: the reverse load order yields the earlier layer's bucket.
    let reversed = CellConfigBinding::from_toml_layers(&[later, LAYER]).unwrap();
    assert_eq!(reversed.bucket.as_deref(), Some("test-fragments"));
}

#[test]
fn a_non_string_value_or_non_toml_layer_refuses() {
    for layer in [
        "[plugins.postgres.immutable_store.object_store]\nbucket = 5\n",
        "[plugins.postgres.immutable_store.object_store]\nendpoint_url = [\"a\"]\n",
        "[plugins.postgres.immutable_store.fragment_provider]\nprovider_boundary_id = true\n",
        "[plugins.postgres.immutable_store.fragment_provider]\nendpoint_host = 1.5\n",
        "this is = = not toml",
        "{\"json\": true}",
    ] {
        assert_eq!(
            CellConfigBinding::from_toml_layers(&[layer]).unwrap_err(),
            BudgetConfigureError::CellBindingMismatch,
            "{layer}"
        );
    }
    // A bad later layer refuses even when an earlier layer was good.
    assert_eq!(
        CellConfigBinding::from_toml_layers(&[LAYER, "bucket = 5 5"]).unwrap_err(),
        BudgetConfigureError::CellBindingMismatch
    );
}

// ---- refusal precedes any connection ---------------------------------------------------------

const DUMMY_PEM: &str = "-----BEGIN CERTIFICATE-----\ndummy\n-----END CERTIFICATE-----\n";

fn listener_url(listener: &std::net::TcpListener) -> String {
    format!(
        "postgresql://object_dispatch_retention_maintenance@{}/test?sslmode=require",
        listener.local_addr().unwrap()
    )
}

fn assert_no_connection(listener: &std::net::TcpListener) {
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock,
        "a refusal must precede any connection attempt"
    );
}

#[tokio::test]
async fn configure_budget_refuses_a_documented_record_before_connecting() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = listener_url(&listener);
    for action in [
        BudgetAction::Publish,
        BudgetAction::Verify,
        BudgetAction::Reconcile,
    ] {
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            configure_budget(
                &documented(),
                &url,
                DispatchTlsMode::PinnedRootCa(DUMMY_PEM.into()),
                action,
            ),
        )
        .await
        .expect("must be refused before any connection attempt");
        assert_eq!(
            result.unwrap_err(),
            BudgetConfigureError::CellBindingMismatch
        );
        assert_no_connection(&listener);
    }
}

#[tokio::test]
async fn configure_budget_for_cell_refuses_a_mismatched_binding_before_connecting() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = listener_url(&listener);
    for config in [documented(), local()] {
        let mut wrong = matching_binding(&config);
        wrong.bucket = Some("other-bucket".into());
        for action in [
            BudgetAction::Publish,
            BudgetAction::Verify,
            BudgetAction::Reconcile,
        ] {
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                configure_budget_for_cell(
                    &config,
                    &wrong,
                    &url,
                    DispatchTlsMode::PinnedRootCa(DUMMY_PEM.into()),
                    action,
                ),
            )
            .await
            .expect("must be refused before any connection attempt");
            assert_eq!(
                result.unwrap_err(),
                BudgetConfigureError::CellBindingMismatch
            );
            assert_no_connection(&listener);
        }
    }
}

#[tokio::test]
async fn a_matching_binding_passes_the_check_and_reaches_the_connection_stage() {
    // Control for the two tests above: with the binding right, the refusal moves on to the
    // connection, so those tests prove the binding check ran first and not that everything fails.
    let unreachable =
        "postgresql://object_dispatch_retention_maintenance@127.0.0.1:1/test?sslmode=require";
    let config = documented();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        configure_budget_for_cell(
            &config,
            &matching_binding(&config),
            unreachable,
            DispatchTlsMode::PinnedRootCa(DUMMY_PEM.into()),
            BudgetAction::Verify,
        ),
    )
    .await
    .expect("connection stage must resolve");
    let error = result.unwrap_err();
    assert_ne!(error, BudgetConfigureError::CellBindingMismatch);
    assert_eq!(error, BudgetConfigureError::ConnectionRefused);
}

#[tokio::test]
async fn a_missing_pinned_ca_is_still_refused_first() {
    // The existing pinned-CA check precedes the binding check, as documented.
    let result = configure_budget(
        &documented(),
        "postgresql://u@127.0.0.1:1/test",
        DispatchTlsMode::Disabled,
        BudgetAction::Publish,
    )
    .await;
    assert_eq!(result.unwrap_err(), BudgetConfigureError::ConnectionRefused);
}

// ---- operator binary -------------------------------------------------------------------------

fn run_operator(
    record: &LocalBudgetConfiguration,
    extra: &[&std::path::Path],
    layers: bool,
    listener: &std::net::TcpListener,
) -> std::process::Output {
    let dir = std::env::temp_dir();
    let record_path = dir.join(format!("budget-prov-record-{}.json", uuid::Uuid::now_v7()));
    std::fs::write(&record_path, serde_json::to_vec(record).unwrap()).unwrap();
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_cell-budget-configure"));
    command.arg("verify").arg(&record_path);
    for layer in extra {
        if layers {
            command.arg("--cell-config");
        }
        command.arg(layer);
    }
    let output = command
        .env("LORE_CELL_BUDGET_MAINTENANCE_URL", listener_url(listener))
        .env("LORE_CELL_BUDGET_CA_PEM", DUMMY_PEM)
        .output()
        .unwrap();
    std::fs::remove_file(record_path).unwrap();
    output
}

fn write_layer(text: &str) -> std::path::PathBuf {
    let path =
        std::env::temp_dir().join(format!("budget-prov-layer-{}.toml", uuid::Uuid::now_v7()));
    std::fs::write(&path, text).unwrap();
    path
}

#[test]
fn operator_binary_requires_a_matching_cell_config_for_a_documented_record() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    // No layers at all.
    let none = run_operator(&documented(), &[], true, &listener);
    // A layer whose bucket differs.
    let wrong_layer = write_layer(&LAYER.replace("test-fragments", "other-bucket"));
    let wrong = run_operator(&documented(), &[wrong_layer.as_path()], true, &listener);
    // A non-TOML layer.
    let junk_layer = write_layer("= = =");
    let junk = run_operator(&documented(), &[junk_layer.as_path()], true, &listener);
    // A layer path without its flag is a usage error.
    let good_layer = write_layer(LAYER);
    let bare = run_operator(&documented(), &[good_layer.as_path()], false, &listener);
    for path in [&wrong_layer, &junk_layer, &good_layer] {
        std::fs::remove_file(path).unwrap();
    }
    for (name, output) in [("none", &none), ("wrong", &wrong), ("junk", &junk)] {
        assert!(!output.status.success(), "{name}");
        assert!(output.stdout.is_empty(), "{name}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("does not match the cell configuration"),
            "{name}: {stderr}"
        );
    }
    assert!(!bare.status.success());
    assert!(String::from_utf8_lossy(&bare.stderr).contains("usage:"));
    assert_no_connection(&listener);
}

#[test]
fn operator_binary_with_a_matching_cell_config_reaches_the_connection() {
    // Control: the binding passes, so the failure is the (refused) connection, not the binding.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let layer = write_layer(LAYER);
    let output = run_operator(&documented(), &[layer.as_path()], true, &listener);
    std::fs::remove_file(layer).unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("does not match the cell configuration"),
        "{stderr}"
    );
    assert!(
        stderr.contains("connection or identity was refused"),
        "{stderr}"
    );
}

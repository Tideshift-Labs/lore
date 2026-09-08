// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_object_dispatch::cell_budget_configure::BudgetConfigureError;
use lore_object_dispatch::cell_budget_configure::BudgetPredecessor;
use lore_object_dispatch::cell_budget_configure::LocalBudgetConfiguration;

#[path = "common/budget_configuration.rs"]
mod configuration;

#[test]
fn valid_local_policy_roundtrips_with_explicit_provenance() {
    let config = configuration::config(1, 1, 1000);
    config.validate().unwrap();
    let json = serde_json::to_vec(&config).unwrap();
    let parsed = LocalBudgetConfiguration::from_json(&json).unwrap();
    assert_eq!(serde_json::to_vec(&parsed).unwrap(), json);
}

#[test]
fn malformed_unknown_duplicate_and_oversized_json_refuse() {
    for bytes in [b"{}".to_vec(), b"null".to_vec(), vec![b' '; 16_385]] {
        assert_eq!(
            LocalBudgetConfiguration::from_json(&bytes).unwrap_err(),
            BudgetConfigureError::InvalidConfiguration
        );
    }
    let json = serde_json::to_string(&configuration::config(1, 1, 1000)).unwrap();
    for field in ["\"unknown\":1", "\"cellId\":\"duplicate\""] {
        let changed = format!("{{{field},{}", &json[1..]);
        assert_eq!(
            LocalBudgetConfiguration::from_json(changed.as_bytes()).unwrap_err(),
            BudgetConfigureError::InvalidConfiguration
        );
    }
}

#[test]
fn invalid_policy_bounds_and_binding_fields_refuse() {
    let base = serde_json::to_value(configuration::config(1, 1, 1000)).unwrap();
    for (key, invalid) in [
        ("schemaRevision", serde_json::json!("unknown")),
        ("provenance", serde_json::json!("measured-production")),
        ("cellId", serde_json::json!("../escape")),
        ("providerBoundaryId", serde_json::json!("")),
        ("providerBucket", serde_json::json!("with space")),
        (
            "providerEndpoint",
            serde_json::json!("http://user:secret@host"),
        ),
        ("providerEndpoint", serde_json::json!("http://host?secret")),
        ("systemIdentifier", serde_json::json!("0")),
        ("databaseOid", serde_json::json!(0)),
        ("allocationFence", serde_json::json!(0)),
        ("sharedUnits", serde_json::json!(1_000_001)),
        ("classUnits", serde_json::json!(100)),
        ("listUnits", serde_json::json!(0)),
        ("refillIntervalMs", serde_json::json!(99)),
        ("refillIntervalMs", serde_json::json!(60_001)),
        ("hardExpiresAtUnixMs", serde_json::json!(60_999)),
        ("hardExpiresAtUnixMs", serde_json::json!(86_401_001)),
    ] {
        let mut value = base.clone();
        value[key] = invalid;
        assert_eq!(
            LocalBudgetConfiguration::from_json(&serde_json::to_vec(&value).unwrap()).unwrap_err(),
            BudgetConfigureError::InvalidConfiguration,
            "{key}"
        );
    }
}

#[test]
fn successor_requires_exact_predecessor_shape() {
    let mut config = configuration::config(1, 1, 1000);
    config.allocation_fence = 2;
    assert_eq!(
        config.validate(),
        Err(BudgetConfigureError::InvalidConfiguration)
    );
    config.predecessor = Some(BudgetPredecessor {
        allocation_fence: 1,
        disposition_id: uuid::Uuid::nil().to_string(),
        disposition_digest: "ab".repeat(32),
        envelope_digest: "cd".repeat(32),
    });
    config.validate().unwrap();
    config.predecessor.as_mut().unwrap().disposition_digest = "zz".repeat(32);
    assert_eq!(
        config.validate(),
        Err(BudgetConfigureError::InvalidConfiguration)
    );
}

#[test]
fn operator_binary_refuses_invalid_inputs_without_echoing_secrets() {
    let path = std::env::temp_dir().join(format!(
        "budget-operator-test-{}.json",
        uuid::Uuid::now_v7()
    ));
    std::fs::write(
        &path,
        serde_json::to_vec(&configuration::config(1, 1, 1000)).unwrap(),
    )
    .unwrap();
    let result = std::process::Command::new(env!("CARGO_BIN_EXE_cell-budget-configure"))
        .arg("verify")
        .arg(&path)
        .env(
            "LORE_CELL_BUDGET_MAINTENANCE_URL",
            "postgresql://wrong:secret-password@localhost/test?sslmode=require",
        )
        .env("LORE_CELL_BUDGET_CA_PEM", "invalid-nonempty-ca-secret")
        .output()
        .unwrap();
    std::fs::remove_file(path).unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    let stderr = String::from_utf8(result.stderr).unwrap();
    assert!(stderr.contains("connection or identity was refused"));
    assert!(!stderr.contains("secret-password"));
    assert!(!stderr.contains("postgresql://"));
}

#[tokio::test]
async fn operator_refuses_plaintext_before_opening_a_connection() {
    use lore_object_dispatch::DispatchTlsMode;
    use lore_object_dispatch::cell_budget_configure::BudgetAction;
    use lore_object_dispatch::cell_budget_configure::configure_budget;
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!(
        "postgresql://object_dispatch_retention_maintenance@{}/test?sslmode=disable",
        listener.local_addr().unwrap()
    );
    for action in [
        BudgetAction::Publish,
        BudgetAction::Verify,
        BudgetAction::Reconcile,
    ] {
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            configure_budget(
                &configuration::config(1, 1, 1000),
                &url,
                DispatchTlsMode::Disabled,
                action,
            ),
        )
        .await
        .expect("plaintext must be rejected before any connection attempt");
        assert_eq!(result.unwrap_err(), BudgetConfigureError::ConnectionRefused);
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
}

#[test]
fn operator_binary_requires_nonempty_ca_with_exact_maintenance_role() {
    let path = std::env::temp_dir().join(format!("budget-ca-test-{}.json", uuid::Uuid::now_v7()));
    std::fs::write(
        &path,
        serde_json::to_vec(&configuration::config(1, 1, 1000)).unwrap(),
    )
    .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    for ca in [None, Some(""), Some(" \t\r\n")] {
        for action in ["publish", "verify", "reconcile"] {
            let mut command =
                std::process::Command::new(env!("CARGO_BIN_EXE_cell-budget-configure"));
            command.arg(action).arg(&path).env("LORE_CELL_BUDGET_MAINTENANCE_URL", format!("postgresql://object_dispatch_retention_maintenance:secret-password@{}/test?sslmode=disable", listener.local_addr().unwrap()));
            if let Some(ca) = ca {
                command.env("LORE_CELL_BUDGET_CA_PEM", ca);
            } else {
                command.env_remove("LORE_CELL_BUDGET_CA_PEM");
            }
            let result = command.output().unwrap();
            assert!(!result.status.success());
            assert!(result.stdout.is_empty());
            assert_eq!(
                String::from_utf8(result.stderr).unwrap().trim(),
                "cell-budget-configure: LORE_CELL_BUDGET_CA_PEM is required and must be nonempty"
            );
            assert_eq!(
                listener.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        }
    }
    std::fs::remove_file(path).unwrap();
}

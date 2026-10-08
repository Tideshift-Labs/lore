// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::path::PathBuf;

use lore_server::plugins::remote_notification::config::*;
use lore_server::plugins::remote_notification::error::RemoteNotificationError;
use lore_server::plugins::remote_notification::wire::TRANSPORT_VERSION;

fn table(toml_text: &str) -> toml::Value {
    toml::from_str(toml_text).expect("test config parses as TOML")
}

const MINIMAL: &str = r#"
    gateway_uri = "https://gateway.internal:8443"
    cell_id = "sfo3-cell-a"
    placement_epoch = 12
    producer_instance_id = "loreserver-sfo3-cell-a-2"
    client_cert_path = "/secrets/tls.crt"
    client_key_path = "/secrets/tls.key"
    trust_roots_path = "/secrets/ca.crt"
"#;

#[test]
fn a_minimal_config_parses_with_bounded_defaults() {
    let cfg = RemoteNotificationConfig::parse(&table(MINIMAL)).expect("valid");
    assert_eq!(cfg.queue_capacity, QUEUE_CAPACITY_DEFAULT);
    assert_eq!(cfg.retry.limit, RETRY_LIMIT_DEFAULT);
    assert_eq!(cfg.contract.private_transport_version, TRANSPORT_VERSION);
    assert!(cfg.receiver.is_none());
    assert!(cfg.mtls.is_some());
}

#[test]
fn an_insecure_endpoint_is_rejected_without_the_explicit_test_escape() {
    let cfg = table(
        r#"
        gateway_uri = "http://gateway.internal:8080"
        cell_id = "sfo3-cell-a"
        placement_epoch = 12
        producer_instance_id = "p"
        client_cert_path = "/secrets/tls.crt"
        client_key_path = "/secrets/tls.key"
        trust_roots_path = "/secrets/ca.crt"
    "#,
    );
    let err = RemoteNotificationConfig::parse(&cfg).expect_err("insecure endpoint");
    assert!(matches!(
        err,
        RemoteNotificationError::ConfigField {
            field: "gateway_uri",
            ..
        }
    ));
}

#[test]
fn missing_mtls_material_is_rejected() {
    let cfg = table(
        r#"
        gateway_uri = "https://gateway.internal:8443"
        cell_id = "sfo3-cell-a"
        placement_epoch = 12
        producer_instance_id = "p"
    "#,
    );
    let err = RemoteNotificationConfig::parse(&cfg).expect_err("no mTLS");
    assert!(matches!(
        err,
        RemoteNotificationError::ConfigField {
            field: "client_cert_path",
            ..
        }
    ));
}

#[test]
fn partial_mtls_material_is_rejected_even_in_the_insecure_test_mode() {
    let cfg = table(
        r#"
        gateway_uri = "http://127.0.0.1:1"
        cell_id = "sfo3-cell-a"
        placement_epoch = 12
        producer_instance_id = "p"
        allow_insecure_transport_for_test = true
        client_cert_path = "/secrets/tls.crt"
    "#,
    );
    let err = RemoteNotificationConfig::parse(&cfg).expect_err("partial mTLS");
    assert!(matches!(
        err,
        RemoteNotificationError::ConfigField {
            field: "client_key_path",
            ..
        }
    ));
}

#[test]
fn local_shadow_remote_is_rejected_rather_than_silently_downgraded() {
    let cfg = table(&format!("mode = \"local-shadow-remote\"\n{MINIMAL}"));
    let err = RemoteNotificationConfig::parse(&cfg).expect_err("shadow composition");
    let RemoteNotificationError::ConfigField { field, reason } = err else {
        panic!("expected a field error");
    };
    assert_eq!(field, "mode");
    assert!(reason.contains("server-level composition"));
}

#[test]
fn an_unknown_mode_is_rejected() {
    let cfg = table(&format!("mode = \"nats\"\n{MINIMAL}"));
    assert!(RemoteNotificationConfig::parse(&cfg).is_err());
}

#[test]
fn an_incompatible_transport_version_is_rejected_at_startup() {
    let cfg = table(&format!(
        "{MINIMAL}\n[contract]\nprivate_transport_version = 2\n"
    ));
    let err = RemoteNotificationConfig::parse(&cfg).expect_err("transport version");
    assert!(matches!(
        err,
        RemoteNotificationError::IncompatibleTransportVersion {
            configured: 2,
            supported: 1
        }
    ));
}

#[test]
fn a_durable_payload_range_excluding_this_build_is_rejected_at_startup() {
    let cfg = table(&format!(
        "{MINIMAL}\n[contract]\ndurable_payload_version_min = 2\ndurable_payload_version_max = 3\n"
    ));
    let err = RemoteNotificationConfig::parse(&cfg).expect_err("payload range");
    assert!(matches!(
        err,
        RemoteNotificationError::IncompatibleDurablePayloadVersion {
            min: 2,
            max: 3,
            supported: 1
        }
    ));
}

#[test]
fn an_unbounded_queue_cannot_be_configured() {
    let cfg = table(&format!("{MINIMAL}\nqueue_capacity = 0\n"));
    assert!(RemoteNotificationConfig::parse(&cfg).is_err());
    let cfg = table(&format!("{MINIMAL}\nqueue_capacity = 99999999\n"));
    assert!(RemoteNotificationConfig::parse(&cfg).is_err());
}

#[test]
fn an_unknown_config_key_is_rejected_rather_than_ignored() {
    let cfg = table(&format!("{MINIMAL}\nnats_url = \"nats://broker:4222\"\n"));
    let err = RemoteNotificationConfig::parse(&cfg).expect_err("unknown key");
    assert!(matches!(err, RemoteNotificationError::ConfigParse(_)));
}

#[test]
fn cell_id_grammar_matches_the_contract() {
    assert!(cell_id_is_valid("sfo3-cell-a"));
    assert!(cell_id_is_valid("a"));
    assert!(cell_id_is_valid("a1"));
    assert!(!cell_id_is_valid(""));
    assert!(!cell_id_is_valid("sfo3_cell_a"));
    assert!(!cell_id_is_valid("-sfo3"));
    assert!(!cell_id_is_valid("sfo3-"));
    assert!(!cell_id_is_valid("SFO3"));
    assert!(!cell_id_is_valid(&"a".repeat(CELL_ID_MAX_BYTES + 1)));
    assert!(cell_id_is_valid(&"a".repeat(CELL_ID_MAX_BYTES)));
}

#[test]
fn a_zero_placement_epoch_is_rejected() {
    let cfg = table(&MINIMAL.replace("placement_epoch = 12", "placement_epoch = 0"));
    let err = RemoteNotificationConfig::parse(&cfg).expect_err("zero placement epoch");
    assert!(matches!(
        err,
        RemoteNotificationError::ConfigField {
            field: "placement_epoch",
            ..
        }
    ));
}

#[test]
fn a_zero_receiver_generation_is_rejected() {
    let cfg = table(&format!(
        "{MINIMAL}\n[receiver]\nmembership_identity = \"r\"\nlifecycle_generation = 0\nlag_readiness_threshold = 10\n"
    ));
    assert!(RemoteNotificationConfig::parse(&cfg).is_err());
}

// -- the receiver's own role credential --------------------------------

/// The production shape: two least-privilege leaves, one shared trust
/// anchor. The trust roots are inherited rather than repeated, because they
/// authenticate the gateway rather than this cell.
#[test]
fn a_receiver_credential_is_accepted_and_inherits_the_plugins_trust_roots() {
    let cfg = RemoteNotificationConfig::parse(&table(&format!(
        "{MINIMAL}\n[receiver]\nmembership_identity = \"r\"\nlifecycle_generation = 1\n\
         lag_readiness_threshold = 10\nclient_cert_path = \"/secrets/recv.crt\"\n\
         client_key_path = \"/secrets/recv.key\"\n"
    )))
    .expect("a receiver with its own credential is valid");
    let receiver = cfg.receiver.expect("the receiver section parsed");
    let mtls = receiver
        .mtls
        .expect("the receiver carries its own material");
    assert_eq!(mtls.client_cert_path, PathBuf::from("/secrets/recv.crt"));
    assert_eq!(mtls.client_key_path, PathBuf::from("/secrets/recv.key"));
    assert_eq!(mtls.trust_roots_path, PathBuf::from("/secrets/ca.crt"));
    assert_ne!(
        mtls.client_cert_path,
        cfg.mtls
            .expect("the plugin carries material")
            .client_cert_path,
        "the two roles must not share one leaf; a SPIFFE SAN names exactly one role"
    );
}

/// A receiver on an mTLS cell with no credential of its own is REFUSED at
/// parse time.
///
/// It cannot be allowed to fall back on the plugin's: `Consume` requires
/// the `receiver` role and refuses a `relay` credential as
/// `UNAUTHORIZED_RECEIVER_ROLE_V1` on every attempt. That produces no boot
/// failure and no self-healing state — just a receiver that loops and a
/// facet that never goes true, reported as a stream problem.
#[test]
fn a_receiver_without_its_own_credential_is_rejected_on_an_mtls_cell() {
    let err = RemoteNotificationConfig::parse(&table(&format!(
        "{MINIMAL}\n[receiver]\nmembership_identity = \"r\"\nlifecycle_generation = 1\n\
         lag_readiness_threshold = 10\n"
    )))
    .expect_err("a receiver with no role credential must be refused");
    assert!(
        matches!(
            err,
            RemoteNotificationError::ConfigField {
                field: "receiver.client_cert_path",
                ..
            }
        ),
        "got {err:?}"
    );
}

/// Reusing the relay's own leaf for the receiver is refused. It is the one
/// misconfiguration that looks right, parses, boots, and then refuses every
/// `Consume` forever with nothing in the boot log.
#[test]
fn the_receiver_may_not_reuse_the_plugins_own_credential() {
    let err = RemoteNotificationConfig::parse(&table(&format!(
        "{MINIMAL}\n[receiver]\nmembership_identity = \"r\"\nlifecycle_generation = 1\n\
         lag_readiness_threshold = 10\nclient_cert_path = \"/secrets/tls.crt\"\n\
         client_key_path = \"/secrets/tls.key\"\n"
    )))
    .expect_err("the relay's own leaf must be refused for the receiver");
    assert!(
        matches!(
            err,
            RemoteNotificationError::ConfigField {
                field: "receiver.client_cert_path",
                ..
            }
        ),
        "got {err:?}"
    );
}

/// A half-configured receiver credential is a fault, not a fallback.
#[test]
fn a_partial_receiver_credential_names_the_missing_field() {
    let err = RemoteNotificationConfig::parse(&table(&format!(
        "{MINIMAL}\n[receiver]\nmembership_identity = \"r\"\nlifecycle_generation = 1\n\
         lag_readiness_threshold = 10\nclient_cert_path = \"/secrets/recv.crt\"\n"
    )))
    .expect_err("a half-configured receiver credential must be refused");
    assert!(
        matches!(
            err,
            RemoteNotificationError::ConfigField {
                field: "receiver.client_key_path",
                ..
            }
        ),
        "got {err:?}"
    );
}

/// The insecure test transport presents no client identity at all, so there
/// is no role to separate and no credential to demand.
#[test]
fn an_insecure_test_cell_may_declare_a_receiver_with_no_credential() {
    let cfg = RemoteNotificationConfig::parse(&table(
        r#"
        gateway_uri = "http://127.0.0.1:1"
        cell_id = "sfo3-cell-a"
        placement_epoch = 12
        producer_instance_id = "loreserver-sfo3-cell-a-2"
        allow_insecure_transport_for_test = true

        [receiver]
        membership_identity = "r"
        lifecycle_generation = 1
        lag_readiness_threshold = 10
        "#,
    ))
    .expect("an insecure test cell may declare a receiver");
    assert!(cfg.mtls.is_none());
    assert!(
        cfg.receiver
            .expect("the receiver section parsed")
            .mtls
            .is_none()
    );
}

#[test]
fn diagnostics_never_expose_credential_paths_or_material() {
    let cfg = RemoteNotificationConfig::parse(&table(MINIMAL)).expect("valid");
    let rendered = format!("{:?}", cfg.diagnostics());
    assert!(!rendered.contains("/secrets/"));
    assert!(!rendered.contains("tls.key"));
    assert!(rendered.contains("mtls_configured"));
}

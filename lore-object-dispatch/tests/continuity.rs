// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use std::time::Duration;

use lore_object_dispatch::continuity::ContinuityError;
use lore_object_dispatch::continuity::ContinuityTlsConfig;
use rcgen::BasicConstraints;
use rcgen::CertificateParams;
use rcgen::IsCa;
use rcgen::Issuer;
use rcgen::KeyPair;
use rcgen::KeyUsagePurpose;

struct TestIdentity {
    ca_pem: String,
    client_certificate_pem: String,
    client_private_key_pem: String,
}

fn test_identity() -> TestIdentity {
    let ca_key = KeyPair::generate().expect("test CA key generation must succeed");
    let mut ca_params =
        CertificateParams::new(Vec::<String>::new()).expect("test CA parameters must be valid");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_certificate = ca_params
        .self_signed(&ca_key)
        .expect("test CA certificate generation must succeed");
    let ca_pem = ca_certificate.pem();
    let issuer = Issuer::new(ca_params, ca_key);

    let client_key = KeyPair::generate().expect("test client key generation must succeed");
    let client_params = CertificateParams::new(vec!["continuity-client".to_string()])
        .expect("test client parameters must be valid");
    let client_certificate = client_params
        .signed_by(&client_key, &issuer)
        .expect("test client certificate generation must succeed");

    TestIdentity {
        ca_pem,
        client_certificate_pem: client_certificate.pem(),
        client_private_key_pem: client_key.serialize_pem(),
    }
}

fn valid_config() -> ContinuityTlsConfig {
    let identity = test_identity();
    ContinuityTlsConfig {
        postgres_url:
            "postgresql://odc_boundary:password@continuity.internal:5432/continuity?sslmode=require"
                .to_string(),
        root_ca_pem: identity.ca_pem,
        client_certificate_chain_pem: identity.client_certificate_pem,
        private_key_pem: identity.client_private_key_pem,
        connect_timeout: Duration::from_secs(5),
    }
}

fn assert_invalid_configuration(config: &ContinuityTlsConfig, expected: &'static str) {
    let error = config
        .validate()
        .expect_err("invalid connection configuration must fail closed");
    assert!(
        matches!(error, ContinuityError::InvalidConfiguration(message) if message == expected),
        "unexpected error: {error}"
    );
}

fn assert_invalid_tls(config: &ContinuityTlsConfig, expected: &'static str) {
    let error = config
        .validate()
        .expect_err("invalid TLS material must fail closed");
    assert!(
        matches!(error, ContinuityError::InvalidTlsMaterial(message) if message == expected),
        "unexpected error: {error}"
    );
}

#[test]
fn validate_accepts_one_dns_host_with_require_and_explicit_mtls_identity() {
    valid_config()
        .validate()
        .expect("complete fail-closed TLS material must validate");
}

#[test]
fn validate_rejects_zero_connect_timeout() {
    let mut config = valid_config();
    config.connect_timeout = Duration::ZERO;

    assert_invalid_configuration(&config, "connect timeout must be positive");
}

#[test]
fn validate_rejects_opportunistic_and_plaintext_ssl_modes() {
    for url in [
        "postgresql://user@continuity.internal/database",
        "postgresql://user@continuity.internal/database?sslmode=prefer",
        "postgresql://user@continuity.internal/database?sslmode=disable",
    ] {
        let mut config = valid_config();
        config.postgres_url = url.to_string();

        assert_invalid_configuration(&config, "continuity PostgreSQL requires sslmode=require");
    }
}

#[test]
fn validate_rejects_multiple_hosts() {
    let mut config = valid_config();
    config.postgres_url =
        "postgresql://user@primary.internal:5432,standby.internal:5432/database?sslmode=require"
            .to_string();

    assert_invalid_configuration(
        &config,
        "continuity PostgreSQL requires exactly one TCP DNS host",
    );
}

#[test]
fn validate_rejects_unix_socket_hosts() {
    let mut config = valid_config();
    config.postgres_url =
        "host=/var/run/postgresql user=odc_boundary dbname=continuity sslmode=require".to_string();

    assert_invalid_configuration(&config, "continuity PostgreSQL host must be a DNS name");
}

#[test]
fn validate_rejects_ip_hosts_so_rustls_must_verify_a_dns_name() {
    let mut config = valid_config();
    config.postgres_url = "postgresql://user@127.0.0.1:5432/database?sslmode=require".to_string();

    assert_invalid_configuration(&config, "continuity PostgreSQL host must be a DNS name");
}

#[test]
fn validate_requires_user_and_database() {
    for url in [
        "postgresql://continuity.internal/database?sslmode=require",
        "postgresql://user@continuity.internal?sslmode=require",
    ] {
        let mut config = valid_config();
        config.postgres_url = url.to_string();

        assert_invalid_configuration(
            &config,
            "continuity PostgreSQL URL requires user and database",
        );
    }
}

#[test]
fn validate_rejects_empty_and_malformed_root_ca_bundles() {
    for root_ca_pem in ["", "-----BEGIN CERTIFICATE-----\nnot-base64\n"] {
        let mut config = valid_config();
        config.root_ca_pem = root_ca_pem.to_string();

        let error = config
            .validate()
            .expect_err("missing or malformed roots must fail closed");
        assert!(
            matches!(error, ContinuityError::InvalidTlsMaterial(_)),
            "unexpected error: {error}"
        );
    }
}

#[test]
fn validate_rejects_empty_and_malformed_client_certificate_chains() {
    for certificate_pem in ["", "-----BEGIN CERTIFICATE-----\nnot-base64\n"] {
        let mut config = valid_config();
        config.client_certificate_chain_pem = certificate_pem.to_string();

        let error = config
            .validate()
            .expect_err("missing or malformed client certificates must fail closed");
        assert!(
            matches!(error, ContinuityError::InvalidTlsMaterial(_)),
            "unexpected error: {error}"
        );
    }
}

#[test]
fn validate_rejects_empty_and_malformed_client_private_keys() {
    for private_key_pem in ["", "-----BEGIN PRIVATE KEY-----\nnot-base64\n"] {
        let mut config = valid_config();
        config.private_key_pem = private_key_pem.to_string();

        let error = config
            .validate()
            .expect_err("missing or malformed client keys must fail closed");
        assert!(
            matches!(error, ContinuityError::InvalidTlsMaterial(_)),
            "unexpected error: {error}"
        );
    }
}

#[test]
fn validate_rejects_a_client_certificate_and_private_key_mismatch() {
    let other_identity = test_identity();
    let mut config = valid_config();
    config.private_key_pem = other_identity.client_private_key_pem;

    assert_invalid_tls(&config, "client certificate and key do not match");
}

#[test]
fn debug_and_validation_errors_redact_connection_and_pem_secrets() {
    const URL_SECRET: &str = "url-password-secret";
    const ROOT_SECRET: &str = "root-pem-secret";
    const CERTIFICATE_SECRET: &str = "certificate-pem-secret";
    const KEY_SECRET: &str = "private-key-secret";
    let config = ContinuityTlsConfig {
        postgres_url: format!(
            "postgresql://odc_boundary:{URL_SECRET}@continuity.internal/continuity?sslmode=broken"
        ),
        root_ca_pem: ROOT_SECRET.to_string(),
        client_certificate_chain_pem: CERTIFICATE_SECRET.to_string(),
        private_key_pem: KEY_SECRET.to_string(),
        connect_timeout: Duration::from_secs(5),
    };

    let debug = format!("{config:?}");
    let error = config
        .validate()
        .expect_err("an invalid sslmode must be rejected");
    let rendered_error = format!("{error:?} {error}");
    for secret in [URL_SECRET, ROOT_SECRET, CERTIFICATE_SECRET, KEY_SECRET] {
        assert!(!debug.contains(secret), "Debug leaked {secret}");
        assert!(!rendered_error.contains(secret), "error leaked {secret}");
    }
}

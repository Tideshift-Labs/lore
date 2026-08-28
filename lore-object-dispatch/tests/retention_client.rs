// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use std::time::Duration;

use lore_object_dispatch::RetentionError;
use lore_object_dispatch::RetentionTlsConfig;
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
    let client_params = CertificateParams::new(vec!["retention-client".to_string()])
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

fn valid_config() -> RetentionTlsConfig {
    let identity = test_identity();
    RetentionTlsConfig {
        postgres_url: "postgresql://object_dispatch_retention_maintenance:secret@retention.internal:5432/retention?sslmode=require".to_string(),
        root_ca_pem: identity.ca_pem,
        client_certificate_chain_pem: identity.client_certificate_pem,
        private_key_pem: identity.client_private_key_pem,
        connect_timeout: Duration::from_secs(5),
        statement_timeout: Duration::from_secs(2),
        lock_timeout: Duration::from_secs(1),
        max_retry_attempts: 3,
    }
}

fn source_section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let tail = source.split_once(start).expect("source section start").1;
    tail.split_once(end).expect("source section end").0
}

fn assert_invalid_configuration(config: &RetentionTlsConfig, expected: &'static str) {
    let error = config
        .validate()
        .expect_err("invalid retention connection configuration must fail closed");
    assert!(
        matches!(error, RetentionError::InvalidConfiguration(message) if message == expected),
        "unexpected error: {error}"
    );
}

#[test]
fn validate_accepts_one_dns_host_with_require_and_explicit_mtls_identity() {
    valid_config()
        .validate()
        .expect("complete fail-closed retention TLS material must validate");
}

#[test]
fn validate_rejects_nonpositive_fractional_and_oversized_timeouts() {
    for (field, expected) in [
        (
            "statement",
            "statement timeout must be a positive whole-millisecond value",
        ),
        (
            "lock",
            "lock timeout must be a positive whole-millisecond value",
        ),
    ] {
        for timeout in [
            Duration::ZERO,
            Duration::from_nanos(1),
            Duration::from_millis(1) + Duration::from_nanos(1),
            Duration::MAX,
        ] {
            let mut config = valid_config();
            if field == "statement" {
                config.statement_timeout = timeout;
            } else {
                config.lock_timeout = timeout;
            }
            assert_invalid_configuration(&config, expected);
        }
    }
    let mut config = valid_config();
    config.connect_timeout = Duration::ZERO;
    assert_invalid_configuration(&config, "connect timeout must be positive");
}

#[test]
fn validate_requires_exactly_three_retry_attempts() {
    for attempts in [0, 1, 2, 4, u8::MAX] {
        let mut config = valid_config();
        config.max_retry_attempts = attempts;
        assert_invalid_configuration(
            &config,
            "retention mutation retry attempts must equal three",
        );
    }
}

#[test]
fn validate_requires_the_exact_maintenance_session_identity() {
    let mut config = valid_config();
    config.postgres_url =
        "postgresql://other_user@retention.internal/retention?sslmode=require".to_string();
    assert_invalid_configuration(
        &config,
        "retention PostgreSQL user must be the exact maintenance identity",
    );
}

#[test]
fn validate_rejects_plaintext_opportunistic_multiple_socket_and_ip_hosts() {
    for (url, expected) in [
        (
            "postgresql://user@retention.internal/database",
            "retention PostgreSQL requires sslmode=require",
        ),
        (
            "postgresql://user@retention.internal/database?sslmode=prefer",
            "retention PostgreSQL requires sslmode=require",
        ),
        (
            "postgresql://user@primary.internal:5432,standby.internal:5432/database?sslmode=require",
            "retention PostgreSQL requires exactly one TCP DNS host",
        ),
        (
            "host=/var/run/postgresql user=maintenance dbname=retention sslmode=require",
            "retention PostgreSQL host must be a DNS name",
        ),
        (
            "postgresql://user@127.0.0.1:5432/database?sslmode=require",
            "retention PostgreSQL host must be a DNS name",
        ),
    ] {
        let mut config = valid_config();
        config.postgres_url = url.to_string();
        assert_invalid_configuration(&config, expected);
    }
}

#[test]
fn validate_requires_user_database_ca_certificate_and_matching_key() {
    for url in [
        "postgresql://retention.internal/database?sslmode=require",
        "postgresql://user@retention.internal?sslmode=require",
    ] {
        let mut config = valid_config();
        config.postgres_url = url.to_string();
        assert_invalid_configuration(
            &config,
            "retention PostgreSQL URL requires user and database",
        );
    }

    for field in ["root", "certificate", "key"] {
        let mut config = valid_config();
        match field {
            "root" => config.root_ca_pem.clear(),
            "certificate" => config.client_certificate_chain_pem.clear(),
            "key" => config.private_key_pem.clear(),
            _ => unreachable!(),
        }
        assert!(matches!(
            config.validate(),
            Err(RetentionError::InvalidTlsMaterial(_))
        ));
    }

    let mut config = valid_config();
    config.private_key_pem = test_identity().client_private_key_pem;
    assert!(matches!(
        config.validate(),
        Err(RetentionError::InvalidTlsMaterial(
            "client certificate and key do not match"
        ))
    ));
}

#[test]
fn debug_and_errors_redact_connection_and_pem_secrets() {
    const URL_SECRET: &str = "url-password-secret";
    const ROOT_SECRET: &str = "root-pem-secret";
    const CERTIFICATE_SECRET: &str = "certificate-pem-secret";
    const KEY_SECRET: &str = "private-key-secret";
    let config = RetentionTlsConfig {
        postgres_url: format!(
            "postgresql://maintenance:{URL_SECRET}@retention.internal/retention?sslmode=broken"
        ),
        root_ca_pem: ROOT_SECRET.to_string(),
        client_certificate_chain_pem: CERTIFICATE_SECRET.to_string(),
        private_key_pem: KEY_SECRET.to_string(),
        connect_timeout: Duration::from_secs(5),
        statement_timeout: Duration::from_secs(2),
        lock_timeout: Duration::from_secs(1),
        max_retry_attempts: 3,
    };
    let debug = format!("{config:?}");
    let error = config.validate().expect_err("invalid sslmode must reject");
    let rendered_error = format!("{error:?} {error}");
    for secret in [URL_SECRET, ROOT_SECRET, CERTIFICATE_SECRET, KEY_SECRET] {
        assert!(!debug.contains(secret), "Debug leaked {secret}");
        assert!(!rendered_error.contains(secret), "error leaked {secret}");
    }
}

#[test]
fn client_sql_is_closed_to_v1_transfer_and_append_only_v2_prune() {
    let source = include_str!("../src/retention_client.rs");
    for required in [
        "object_store_retention_read_transfer_v1",
        "object_store_retention_apply_transfer_v1",
        "object_store_retention_read_prune_v2",
        "object_store_retention_apply_prune_v2",
        "$2::text::object_store_retention.uint64",
        "$13::text::object_store_retention.uint64",
    ] {
        assert!(
            source.contains(required),
            "missing closed SQL seam: {required}"
        );
    }
    for forbidden in [
        "object_store_retention_read_prune_v1",
        "object_store_retention_apply_prune_v1",
        "::bigint",
    ] {
        assert!(
            !source.contains(forbidden),
            "unsafe client SQL seam: {forbidden}"
        );
    }
}

#[test]
fn client_sql_projects_every_authoritative_child_and_uses_canonical_uint64_text() {
    let source = include_str!("../src/retention_client.rs");
    let read_transfer = source_section(source, "const READ_TRANSFER_SQL", "const READ_PRUNE_SQL");
    let read_prune = source_section(source, "const READ_PRUNE_SQL", "const APPLY_TRANSFER_SQL");
    let apply_transfer =
        source_section(source, "const APPLY_TRANSFER_SQL", "const APPLY_PRUNE_SQL");
    let apply_prune = source_section(source, "const APPLY_PRUNE_SQL", "#[derive(Clone)]");

    for (name, sql) in [
        ("read transfer", read_transfer),
        ("read prune", read_prune),
        ("apply transfer", apply_transfer),
        ("apply prune", apply_prune),
    ] {
        assert!(!sql.contains("SELECT *"), "{name} has an open projection");
        for required in [
            ".scope_kind",
            ".scope_id",
            ".full_record_rows::text",
            ".full_record_bytes::text",
            ".compact_rows::text",
            ".compact_bytes::text",
            ".counter_revision::text",
        ] {
            assert!(sql.contains(required), "{name} omitted {required}");
        }
    }
    for required in [
        ".compact_sequence::text",
        ".source_authority_blake3",
        ".compact_receipt_bytes",
        ".compact_blake3",
        ".compaction_fingerprint",
        ".transfer_fingerprint",
        ".compacted_at_unix_ms",
        ".compact_prune_after_unix_ms",
    ] {
        assert!(read_transfer.contains(required));
        assert!(read_prune.contains(required));
    }
    for required in [
        ".prune_fingerprint",
        ".backup_revision",
        ".backup_manifest_blake3",
        ".durable_covered_through_compact_sequence::text",
        ".restore_verified_through_compact_sequence::text",
        ".backup_observed_at_unix_ms",
        ".pruned_at_unix_ms",
    ] {
        assert!(
            read_prune.contains(required),
            "read prune omitted {required}"
        );
        assert!(
            apply_prune.contains(required),
            "apply prune omitted {required}"
        );
    }
    for required in [
        ".post_watermark",
        ".post_global_counter",
        ".post_cell_counter",
        ".post_tenant_counter",
    ] {
        assert!(
            apply_prune.contains(required),
            "apply prune omitted {required}"
        );
    }
    assert!(read_prune.contains("$2::text::object_store_retention.uint64"));
    for parameter in ["$8", "$9", "$10", "$11", "$12", "$13"] {
        assert!(
            apply_transfer.contains(&format!("{parameter}::text::object_store_retention.uint64"))
        );
    }
    for parameter in ["$2", "$5", "$6", "$7", "$8", "$11", "$12"] {
        assert!(apply_prune.contains(&format!("{parameter}::text::object_store_retention.uint64")));
    }
    assert!(!apply_transfer.contains("$20"));
    assert!(!apply_prune.contains("$14"));
}

#[test]
fn decoding_closes_states_presence_scopes_digests_and_canonical_numbers() {
    let source = include_str!("../src/retention_client.rs");
    for required in [
        "parsed.to_string() != value",
        "bytes.len() <= 32",
        "let (preimage, trailing) = bytes.split_at(bytes.len() - 32)",
        "trailing == digest && blake3::hash(preimage).as_bytes() == digest",
        "\"FULL_OWNED\" => RetentionTransferState::FullOwned",
        "\"COMPACT_INSTALLED\" => RetentionTransferState::CompactInstalled",
        "\"ABSENT\" => RetentionTransferState::Absent",
        "\"CONFLICT\" => RetentionTransferState::Conflict",
        "\"PRUNED\" => RetentionPruneState::Pruned",
        "\"ABSENT_UNPROVEN\" => RetentionPruneState::AbsentUnproven",
        "_ => return Err(RetentionError::InvalidResponse(\"transfer state\"))",
        "_ => return Err(RetentionError::InvalidResponse(\"prune state\"))",
        "ObjectStoreFullToCompactScope::Global",
        "ObjectStoreFullToCompactScope::Cell",
        "ObjectStoreFullToCompactScope::Tenant",
        "let valid_shape = match state",
        "RetentionTransferState::Conflict =>",
        "RetentionPruneState::Pruned =>",
        "RetentionPruneState::AbsentUnproven =>",
        "validate_full_projection(&full)?",
        "validate_compact_projection(&compact)?",
        "validate_watermark_projection(&watermark)?",
        "validate_counter_projection(&counter)?",
        "validate_prune_receipt_projection(receipt)?",
        "ownership.rows != 1",
        "ownership.concurrency != 0",
        "value.compact_sequence == 0",
        "value.compact_rows != 1",
        "value.compact_concurrency != 0",
        "value.watermark_revision == 0",
        "value.counter_revision == 0",
        "value.scope_id != OBJECT_STORE_FULL_TO_COMPACT_GLOBAL_SCOPE_ID",
        "child.full_record_rows > global.full_record_rows",
        "child.compact_bytes > global.compact_bytes",
        "value.post_watermark.last_prune_fingerprint != Some(value.prune_fingerprint)",
        "value.post_watermark.last_backup_manifest_blake3",
    ] {
        assert!(
            source.contains(required),
            "open response decoder: {required}"
        );
    }
}

#[test]
fn client_is_unreachable_from_process_composition_and_the_cell_authority_config() {
    // CR-033's revised specification (D1/D6/P2) removes the separate-process service shell
    // (`service.rs`, `server.rs`, `main.rs`) entirely: the crate has no `[[bin]]` target and no
    // process-composition surface left to escape into. Assert that structurally rather than by
    // grepping deleted files, then keep the one remaining forbidden-substring check against the
    // cell authority's own configuration surface.
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for removed in ["src/service.rs", "src/server.rs", "src/main.rs"] {
        assert!(
            !manifest.join(removed).exists(),
            "process-composition surface must stay removed: {removed}"
        );
    }
    let config_source = include_str!("../src/config.rs");
    for forbidden in [
        "RetentionMaintenanceClient",
        "RetentionTlsConfig",
        "retention_client",
        "object_store_retention_read_",
        "object_store_retention_apply_",
    ] {
        assert!(
            !config_source.contains(forbidden),
            "source-dark retention client escaped into config: {forbidden}"
        );
    }
}

#[test]
fn production_source_pins_canonical_decoding_retry_and_commit_ambiguity_rules() {
    let source = include_str!("../src/retention_client.rs");
    for required in [
        "FIRST_MUTATION_RETRY_DELAY: Duration = Duration::from_millis(25)",
        "SECOND_MUTATION_RETRY_DELAY: Duration = Duration::from_millis(100)",
        "MUTATION_ISOLATION_LEVEL: IsolationLevel = IsolationLevel::Serializable",
        "matches!(database_error.code().code(), \"40001\" | \"40P01\")",
        "RetentionError::AmbiguousCommit",
        "RetentionError::OperationTimeout",
        "tokio::time::timeout(",
        "self.operation_timeout",
        "if self.reconnect().await.is_err()",
        "ObjectStoreFullToCompactDecision",
        "ObjectStoreCompactPruneDecision",
        "CanonicalObjectStoreCompactReceipt",
        "ObjectStoreCompactPruneBackupCoverage",
        "blake3::hash(preimage)",
        "parsed.to_string() != value",
    ] {
        assert!(
            source.contains(required),
            "missing client invariant: {required}"
        );
    }
    for forbidden in [
        "tokio::spawn",
        "native_tls",
        "dangerous()",
        "NoCertificateVerification",
    ] {
        assert!(
            !source.contains(forbidden),
            "unsafe client primitive: {forbidden}"
        );
    }
}

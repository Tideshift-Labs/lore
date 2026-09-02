// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Offline controls for the dispatch pool's physical PostgreSQL identity attestation.

use lore_object_dispatch::DispatchDatabaseIdentity;
use lore_object_dispatch::DispatchDatabaseIdentityError;

const CLIENT_SOURCE: &str = include_str!("../src/dispatch_client.rs");
const POOL_SOURCE: &str = include_str!("../src/dispatch_pool.rs");

fn section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let start = source.find(start).expect("section start must exist");
    let remainder = &source[start..];
    let end = remainder.find(end).expect("section end must exist");
    &remainder[..end]
}

#[test]
fn exact_identity_matches_while_either_physical_component_differs() {
    let expected = DispatchDatabaseIdentity::new(7_260_001, 16_384).expect("expected identity");
    let same = DispatchDatabaseIdentity::new(7_260_001, 16_384).expect("same identity");
    let other_database =
        DispatchDatabaseIdentity::new(7_260_001, 16_385).expect("other database identity");
    let other_system =
        DispatchDatabaseIdentity::new(7_260_002, 16_384).expect("other system identity");

    assert_eq!(same, expected);
    assert_ne!(other_database, expected);
    assert_ne!(other_system, expected);
}

#[test]
fn zero_identity_components_are_unrepresentable_and_errors_carry_no_values() {
    for result in [
        DispatchDatabaseIdentity::new(0, 16_384),
        DispatchDatabaseIdentity::new(7_260_001, 0),
    ] {
        let error = result.expect_err("zero identity component must be refused");
        assert_eq!(error, DispatchDatabaseIdentityError::Malformed);
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("7260001"));
        assert!(!rendered.contains("16384"));
    }
}

#[test]
fn database_identity_debug_redacts_both_physical_components() {
    let identity = DispatchDatabaseIdentity::new(7_260_001, 16_384).expect("identity");
    let rendered = format!("{identity:?}");
    assert!(
        !rendered.contains("7260001"),
        "Debug leaked the system identifier"
    );
    assert!(!rendered.contains("16384"), "Debug leaked the database OID");
    assert!(rendered.matches("[REDACTED]").count() >= 2);
}

#[test]
fn identity_readback_is_fixed_to_system_identifier_and_database_oid() {
    let sql = section(
        CLIENT_SOURCE,
        "const DATABASE_IDENTITY_SQL: &str = \"",
        "\";\n\n/// Why a cell-authority call refused",
    );
    assert!(sql.contains("system_identifier::text FROM pg_control_system()"));
    assert!(sql.contains("oid FROM pg_database WHERE datname = current_database()"));
    for forbidden in [
        "current_user",
        "session_user",
        "inet_server_addr",
        "current_setting",
    ] {
        assert!(
            !sql.contains(forbidden),
            "identity query widened through {forbidden}"
        );
    }
}

#[test]
fn malformed_null_and_wrong_shape_rows_fail_through_typed_decode_before_comparison() {
    let decode = section(
        CLIENT_SOURCE,
        "fn decode_database_identity(",
        "/// The maintenance-identity client",
    );
    assert!(decode.contains("try_get::<_, String>(\"system_identifier\")"));
    assert!(decode.contains("try_get::<_, u32>(\"database_oid\")"));
    assert_eq!(
        decode
            .matches("map_err(|_| DispatchDatabaseIdentityError::Malformed)")
            .count(),
        3,
    );
    assert!(decode.contains("parsed_system_identifier.to_string() != system_identifier"));
    assert!(
        decode.contains("DispatchDatabaseIdentity::new(parsed_system_identifier, database_oid)")
    );

    let attest = section(
        CLIENT_SOURCE,
        "    pub async fn attest_database_identity(",
        "    /// 0019: read every installed layer's identity tuple.",
    );
    assert!(attest.contains("let actual = decode_database_identity(&row)?;"));
    assert!(attest.contains("if actual != expected"));
    assert!(attest.contains("DispatchDatabaseIdentityError::Mismatch"));
}

#[test]
fn database_identity_errors_and_debug_have_no_identity_or_connection_payload_fields() {
    let error = section(
        CLIENT_SOURCE,
        "pub enum DispatchDatabaseIdentityError",
        "/// How an accepted call reached its result.",
    );
    for forbidden in [
        "system_identifier:",
        "database_oid:",
        "postgres_url:",
        "ca_cert:",
    ] {
        assert!(
            !error.contains(forbidden),
            "identity error carries {forbidden}"
        );
    }
    assert!(error.contains("Malformed"));
    assert!(error.contains("Mismatch"));
}

#[test]
fn every_new_pool_connection_attests_its_own_client_before_session_admission() {
    let connect = section(
        POOL_SOURCE,
        "    async fn connect(&self) -> Result<DispatchSession, DispatchPoolError> {",
        "    async fn release(&self, session: DispatchSession)",
    );
    let opened = connect
        .find("let (client, connection) = postgres")
        .expect("connect must bind the newly opened client");
    let attested = connect
        .find("attest_open_connection_database_identity(\n                &client,")
        .expect("that exact newly opened client must be physically attested");
    let admitted = connect
        .find("Ok(DispatchSession {")
        .expect("the attested client may then become a pool session");
    assert!(opened < attested, "attestation must follow physical open");
    assert!(
        attested < admitted,
        "an unattested physical connection must never enter the pool"
    );
    assert_eq!(
        connect
            .matches("attest_open_connection_database_identity(")
            .count(),
        1,
        "each connect invocation needs exactly one load-bearing attestation"
    );

    let attestation = section(
        POOL_SOURCE,
        "async fn attest_open_connection_database_identity(",
        "/// A borrowed pool connection.",
    );
    assert!(attestation.contains("client\n        .query_one(DATABASE_IDENTITY_SQL, &[])"));
    assert!(attestation.contains("if actual != expected"));
    assert!(!attestation.contains("postgres_url"));
}

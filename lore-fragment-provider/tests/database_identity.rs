// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Public seam controls for binding the domain database identity into provider activation.

use std::time::Duration;

use lore_fragment_provider::FragmentDatabaseIdentity;
use lore_fragment_provider::FragmentDatabaseIdentityError;
use lore_fragment_provider::FragmentDispatchRuntimeConfig;
use lore_fragment_provider::FragmentDispatchTls;
use lore_fragment_provider::FragmentProcessPoolInventory;
use lore_fragment_provider::FragmentProviderActivationError;
use lore_fragment_provider::FragmentSchemaAttestationError;
use lore_object_dispatch::DispatchDatabaseIdentityError;
use lore_object_dispatch::cell_schema_install::CellSchemaLayerId;

#[test]
fn canonical_system_identifier_and_nonzero_database_oid_are_required() {
    assert!(FragmentDatabaseIdentity::new("7260001", 16_384).is_ok());
    for value in ["", "0", "07260001", "+7260001", "7260001 ", "not-a-number"] {
        assert_eq!(
            FragmentDatabaseIdentity::new(value, 16_384),
            Err(FragmentDatabaseIdentityError::InvalidSystemIdentifier),
            "system identifier {value:?} must be refused",
        );
    }
    assert_eq!(
        FragmentDatabaseIdentity::new("7260001", 0),
        Err(FragmentDatabaseIdentityError::InvalidDatabaseOid),
    );
}

#[test]
fn schema_mismatch_remains_a_typed_activation_source() {
    let error = FragmentProviderActivationError::Schema(FragmentSchemaAttestationError::Mismatch {
        layer: CellSchemaLayerId::Retention,
    });
    assert!(matches!(
        error,
        FragmentProviderActivationError::Schema(FragmentSchemaAttestationError::Mismatch {
            layer: CellSchemaLayerId::Retention,
        })
    ));
    assert!(format!("{error}").contains("Retention"));
}

#[test]
fn database_identity_refusal_remains_a_typed_activation_source() {
    let error =
        FragmentProviderActivationError::DatabaseIdentity(DispatchDatabaseIdentityError::Malformed);
    assert!(matches!(
        error,
        FragmentProviderActivationError::DatabaseIdentity(DispatchDatabaseIdentityError::Malformed)
    ));
    assert!(std::error::Error::source(&error).is_some());
}

#[test]
fn dispatch_config_debug_redacts_url_ca_and_physical_identity() {
    let identity = FragmentDatabaseIdentity::new("7260001", 16_384).expect("identity");
    let config = FragmentDispatchRuntimeConfig {
        postgres_url: "postgresql://runtime:password@secret.invalid/cell".into(),
        expected_database_identity: identity,
        process_pool_inventory: FragmentProcessPoolInventory {
            immutable_pool_max: 1,
            mutable_pool_max: 1,
            lock_pool_max: 1,
            domain_pool_max: 1,
            dispatch_pool_max: 1,
        }
        .validate()
        .expect("valid five-pool inventory"),
        connect_timeout: Duration::from_secs(1),
        acquire_timeout: Duration::from_secs(1),
        statement_timeout: Duration::from_secs(1),
        lock_timeout: Duration::from_secs(1),
        tls: FragmentDispatchTls::PinnedRootCa("secret-ca-material".into()),
    };
    let rendered = format!("{config:?}");
    for secret in [
        "runtime:password",
        "secret.invalid",
        "secret-ca-material",
        "7260001",
        "16384",
    ] {
        assert!(
            !rendered.contains(secret),
            "Debug leaked {secret}: {rendered}"
        );
    }
    assert!(rendered.contains("[REDACTED]"));
}

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use super::*;

const LEGACY_JSON: &str = r#"{"schemaRevision":"local-cell-budget-policy-v1","provenance":"operator-selected-local-development-limit-v1","cellId":"test-cell","providerBoundaryId":"test-cell-provider","providerEndpoint":"http://minio:9000","providerBucket":"test-fragments","evidenceReference":"owned TLS operator test fixture","systemIdentifier":"1","databaseOid":1,"allocationRevision":"budget-v1","allocationFence":1,"issuedAtUnixMs":1000,"hardExpiresAtUnixMs":121000,"sharedUnits":100,"classUnits":80,"listUnits":20,"refillIntervalMs":60000,"predecessor":null}"#;

fn config(revision: &str, issued: i64) -> LocalBudgetConfiguration {
    let mut config = LocalBudgetConfiguration::from_json(LEGACY_JSON.as_bytes()).unwrap();
    config.schema_revision = revision.into();
    config.issued_at_unix_ms = issued;
    config.hard_expires_at_unix_ms = issued + 120_000;
    config
}

#[test]
fn legacy_identity_preserves_literal_json_digest_chain_and_non_v7_uuid() {
    let config = config(LEGACY_LOCAL_BUDGET_REVISION, 1000);
    let canonical = serde_json::to_vec(&config).unwrap();
    assert_eq!(canonical, LEGACY_JSON.as_bytes());
    // Independently computed with Python blake3's derive_key_context API.
    let core = digest("Commit0 local development budget core v1", &canonical);
    assert_eq!(
        core.to_hex().as_str(),
        "6b311b6aa3a4958750cce831f0dc65257b052861f3964dc152c8250eda4678d0"
    );
    let disposition = digest(
        "Commit0 local development no-cache disposition v1",
        core.as_bytes(),
    );
    assert_eq!(
        disposition.to_hex().as_str(),
        "c25044f084a68a867f45af04697d922bce21a414b3fe669f5d4730a524857739"
    );
    assert_eq!(
        local_disposition_id(&config, &disposition).to_string(),
        "c25044f0-84a6-8a86-7f45-af04697d922b"
    );
    assert_eq!(
        digest(
            "Commit0 local development budget envelope v1",
            disposition.as_bytes()
        )
        .to_hex()
        .as_str(),
        "ce9fb71ea9b567180af0c1fd7d85fd4a26f3818ecb104b7a08edf4b9cafb4144"
    );
}

#[test]
fn v2_uuid_has_issued_timestamp_rfc_variant_and_stable_digest_bits() {
    assert_eq!(LOCAL_BUDGET_REVISION, "local-cell-budget-policy-v2");
    let config = config(LOCAL_BUDGET_REVISION, 0x0123_4567_89ab);
    let disposition = blake3::Hash::from([0xff; 32]);
    let id = local_disposition_id(&config, &disposition);
    assert_eq!(id.to_string(), "01234567-89ab-7fff-bfff-ffffffffffff");
    assert_eq!(id.get_version_num(), 7);
    assert_eq!(id.get_variant(), uuid::Variant::RFC4122);
    assert_eq!(local_disposition_id(&config, &disposition), id);
    let mut different_digest = [0xff; 32];
    different_digest[15] = 0xfe;
    assert_ne!(
        local_disposition_id(&config, &blake3::Hash::from(different_digest)),
        id
    );
}

#[test]
fn v2_timestamp_bounds_do_not_reject_legacy_reconciliation_inputs() {
    for issued in [0, 1, 0xffff_ffff_ffff] {
        let config = config(LOCAL_BUDGET_REVISION, issued);
        config.validate().unwrap();
        let id = local_disposition_id(&config, &blake3::Hash::from([0; 32]));
        assert_eq!(&id.as_bytes()[..6], &issued.to_be_bytes()[2..]);
        assert_eq!(id.get_version_num(), 7);
        assert_eq!(id.get_variant(), uuid::Variant::RFC4122);
    }
    assert_eq!(
        config(LOCAL_BUDGET_REVISION, 0x1_0000_0000_0000).validate(),
        Err(BudgetConfigureError::InvalidConfiguration)
    );
    config(LEGACY_LOCAL_BUDGET_REVISION, 0x1_0000_0000_0000)
        .validate()
        .unwrap();
    for revision in [LOCAL_BUDGET_REVISION, LEGACY_LOCAL_BUDGET_REVISION] {
        assert_eq!(
            config(revision, -1).validate(),
            Err(BudgetConfigureError::InvalidConfiguration)
        );
    }
}

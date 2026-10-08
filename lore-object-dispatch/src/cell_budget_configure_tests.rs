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

fn documented_config() -> LocalBudgetConfiguration {
    let mut config = config(LOCAL_BUDGET_REVISION, 1000);
    config.provenance = DOCUMENTED_PROVIDER_BUDGET_PROVENANCE.into();
    config.schema_revision = DOCUMENTED_PROVIDER_BUDGET_REVISION.into();
    config.provider_endpoint = DOCUMENTED_PROVIDER_ENDPOINT.into();
    config.provider_region = Some(DOCUMENTED_PROVIDER_REGION.into());
    config.ruling_reference = Some(DOCUMENTED_PROVIDER_RULING_REFERENCE.into());
    config.allocation_revision = documented_provider_revision(1, config.hard_expires_at_unix_ms);
    config.shared_units = 800;
    config.class_units = 640;
    config.list_units = 160;
    config.refill_interval_ms = 1000;
    config
}

#[test]
fn documented_and_local_digest_domains_and_dimension_never_coincide() {
    let local = config(LOCAL_BUDGET_REVISION, 1000).domains();
    let documented_config = documented_config();
    documented_config.validate().unwrap();
    let documented = documented_config.domains();
    // The local labels are the retained literals; they must not move.
    assert_eq!(local.core, "Commit0 local development budget core v1");
    assert_eq!(
        local.disposition,
        "Commit0 local development no-cache disposition v1"
    );
    assert_eq!(
        local.envelope,
        "Commit0 local development budget envelope v1"
    );
    assert_eq!(local.vector, "Commit0 local development budget vector v1");
    assert_eq!(local.dimension, "local-policy-requests");
    assert_eq!(
        documented.core,
        "Commit0 documented provider budget core v1"
    );
    assert_eq!(
        documented.disposition,
        "Commit0 documented provider no-cache disposition v1"
    );
    assert_eq!(
        documented.envelope,
        "Commit0 documented provider budget envelope v1"
    );
    assert_eq!(
        documented.vector,
        "Commit0 documented provider budget vector v1"
    );
    assert_eq!(documented.dimension, "documented-provider-operations");
    let all = [
        local.core,
        local.disposition,
        local.envelope,
        local.vector,
        documented.core,
        documented.disposition,
        documented.envelope,
        documented.vector,
    ];
    for (index, left) in all.iter().enumerate() {
        for right in &all[index + 1..] {
            assert_ne!(left, right);
        }
    }
    // The same bytes hash differently under the two core domains, so no documented record can
    // share a digest with a local one.
    let canonical = serde_json::to_vec(&documented_config).unwrap();
    assert_ne!(
        digest(local.core, &canonical),
        digest(documented.core, &canonical)
    );
    // And the documented digest is the plain keyed derivation under its own label.
    assert_eq!(
        digest(documented.core, &canonical),
        blake3::Hash::from(blake3::derive_key(
            "Commit0 documented provider budget core v1",
            &canonical
        ))
    );
}

#[test]
fn local_records_stay_on_the_local_domains_whatever_their_schema() {
    for revision in [LEGACY_LOCAL_BUDGET_REVISION, LOCAL_BUDGET_REVISION] {
        let domains = config(revision, 1000).domains();
        assert_eq!(domains.core, "Commit0 local development budget core v1");
        assert_eq!(domains.dimension, "local-policy-requests");
    }
}

// Retained fixture: lorehub/docs/execution/wp115-local-20260920-checkpoint/local-v2-bridge-r1/
// (budget.json and publish.json), copied byte for byte. A published local record must keep its
// digests and identity whatever later changes to the record type or its provenance handling.
const RETAINED_V2_BUDGET_JSON: &str = r#"{
  "schemaRevision": "local-cell-budget-policy-v2",
  "provenance": "operator-selected-local-development-limit-v1",
  "cellId": "local",
  "providerBoundaryId": "local.minio",
  "providerEndpoint": "http://minio:9000",
  "providerBucket": "urc-fragments",
  "evidenceReference": "Bounded local development policy; not provider capacity evidence",
  "systemIdentifier": "7687737303001485354",
  "databaseOid": 16384,
  "allocationRevision": "wp115-local-bridge-2",
  "allocationFence": 2,
  "issuedAtUnixMs": 1789949079367,
  "hardExpiresAtUnixMs": 1789992279367,
  "sharedUnits": 1000,
  "classUnits": 900,
  "listUnits": 100,
  "refillIntervalMs": 1000,
  "predecessor": {
    "allocationFence": 1,
    "dispositionId": "7af83236-8a94-2ded-3ca8-b90b13117bad",
    "dispositionDigest": "7af832368a942ded3ca8b90b13117bad0513258bff46f3546bb2729e5ec46e0b",
    "envelopeDigest": "f67b189a1782932dc4c3bfdf47e3c320f41bb40b17ede14309d96a1c19fbdde5"
  }
}
"#;

const RETAINED_V2_PUBLISH_RECEIPT_JSON: &str = r#"{
  "result": "PUBLISHED",
  "expired": false,
  "allocationRevision": "wp115-local-bridge-2",
  "allocationFence": 2,
  "hardExpiresAtUnixMs": 1789992279367,
  "dispositionId": "01a0c147-6f47-705e-b348-94df7fa8a61d",
  "dispositionDigest": "4175ce0d446ac05e334894df7fa8a61dc079f721099ae4af635598b1d5c6db42",
  "envelopeDigest": "1c5ad59e0acc738b1afa046ef5c9982108d190a2e87e2101cc8a31010aebce08"
}
"#;

#[test]
fn retained_local_v2_digests_and_disposition_id_stay_byte_identical() {
    let config = LocalBudgetConfiguration::from_json(RETAINED_V2_BUDGET_JSON.as_bytes()).unwrap();
    assert_eq!(config.schema_revision, LOCAL_BUDGET_REVISION);
    assert_eq!(config.provenance, LOCAL_BUDGET_PROVENANCE);
    assert!(config.provider_region.is_none() && config.ruling_reference.is_none());
    // The canonical bytes carry no documented-provider keys, so the hash input is unchanged.
    let canonical = serde_json::to_vec(&config).unwrap();
    let text = std::str::from_utf8(&canonical).unwrap();
    assert!(!text.contains("providerRegion") && !text.contains("rulingReference"));
    let domains = config.domains();
    let core = digest(domains.core, &canonical);
    let disposition = digest(domains.disposition, core.as_bytes());
    let envelope = digest(domains.envelope, disposition.as_bytes());
    assert_eq!(
        disposition.to_hex().as_str(),
        "4175ce0d446ac05e334894df7fa8a61dc079f721099ae4af635598b1d5c6db42"
    );
    assert_eq!(
        envelope.to_hex().as_str(),
        "1c5ad59e0acc738b1afa046ef5c9982108d190a2e87e2101cc8a31010aebce08"
    );
    assert_eq!(
        local_disposition_id(&config, &disposition).to_string(),
        "01a0c147-6f47-705e-b348-94df7fa8a61d"
    );
    // The retained publish receipt names the same values.
    let receipt: BudgetReceipt = serde_json::from_str(RETAINED_V2_PUBLISH_RECEIPT_JSON).unwrap();
    assert_eq!(receipt.disposition_digest, disposition.to_hex().as_str());
    assert_eq!(receipt.envelope_digest, envelope.to_hex().as_str());
    assert_eq!(
        receipt.disposition_id,
        local_disposition_id(&config, &disposition).to_string()
    );
    assert_eq!(receipt.allocation_revision, config.allocation_revision);
    assert_eq!(receipt.allocation_fence, config.allocation_fence);
    assert_eq!(
        receipt.hard_expires_at_unix_ms,
        config.hard_expires_at_unix_ms
    );
}

#[test]
fn receipt_retained_before_the_provenance_field_reads_as_local() {
    let receipt: BudgetReceipt = serde_json::from_str(RETAINED_V2_PUBLISH_RECEIPT_JSON).unwrap();
    assert!(!RETAINED_V2_PUBLISH_RECEIPT_JSON.contains("provenance"));
    assert_eq!(receipt.provenance, LOCAL_BUDGET_PROVENANCE);
    assert_eq!(
        receipt.provenance,
        "operator-selected-local-development-limit-v1"
    );
    assert_eq!(receipt.result, "PUBLISHED");
    // An explicit provenance still wins over the default.
    let explicit = RETAINED_V2_PUBLISH_RECEIPT_JSON.replacen(
        "\"expired\"",
        "\"provenance\": \"owner-decision-documented-provider-limit-v1\", \"expired\"",
        1,
    );
    let explicit: BudgetReceipt = serde_json::from_str(&explicit).unwrap();
    assert_eq!(explicit.provenance, DOCUMENTED_PROVIDER_BUDGET_PROVENANCE);
}

#[test]
fn receipt_with_an_unknown_key_is_still_refused() {
    let with_extra = RETAINED_V2_PUBLISH_RECEIPT_JSON.replacen(
        "\"expired\"",
        "\"unexpected\": true, \"expired\"",
        1,
    );
    assert!(with_extra.contains("unexpected"));
    assert!(serde_json::from_str::<BudgetReceipt>(&with_extra).is_err());
}

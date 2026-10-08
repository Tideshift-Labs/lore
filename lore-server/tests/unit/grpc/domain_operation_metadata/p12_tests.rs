// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use tonic::metadata::BinaryMetadataValue;
use uuid::Uuid;

use super::*;

const ORG_UUID: [u8; 16] = [
    0x01, 0x91, 0x23, 0x45, 0x67, 0x89, 0x7a, 0xbc, 0x8d, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
];
const PRINCIPAL_UUID: &str = "01912345-6789-7abc-8def-0123456789ac";

fn insert(metadata: &mut MetadataMap, key: &'static str, bytes: &[u8]) {
    metadata.insert_bin(key, BinaryMetadataValue::from_bytes(bytes));
}

fn original_carriage() -> MetadataMap {
    let mut metadata = MetadataMap::new();
    insert(&mut metadata, OPERATION_ID_KEY, Uuid::now_v7().as_bytes());
    let mut fingerprint = vec![FINGERPRINT_VERSION_V1];
    fingerprint.extend(std::iter::repeat_n(0x42, FINGERPRINT_V1_LEN));
    insert(&mut metadata, FINGERPRINT_KEY, &fingerprint);
    insert(&mut metadata, PREPARE_TOKEN_KEY, &[0x53; PREPARE_TOKEN_LEN]);
    metadata
}

fn mediated_scope_bytes() -> Vec<u8> {
    let mut bytes = Vec::with_capacity(MEDIATED_SCOPE_V1_LEN);
    bytes.push(1);
    bytes.extend_from_slice(&ORG_UUID);
    bytes.extend_from_slice(b"principal-v1\0");
    bytes.extend_from_slice(PRINCIPAL_UUID.as_bytes());
    assert_eq!(bytes.len(), MEDIATED_SCOPE_V1_LEN);
    bytes
}

fn mediated_carriage() -> MetadataMap {
    let mut metadata = original_carriage();
    insert(&mut metadata, MEDIATED_SCOPE_KEY, &mediated_scope_bytes());
    metadata
}

#[test]
fn exact_literal_mediated_scope_decodes_without_normalization() {
    let parsed = require(&mediated_carriage()).expect("exact v1 carriage must decode");
    let scope = parsed
        .mediated_scope
        .expect("the fourth header must produce mediated scope");

    assert_eq!(scope.org_uuid, ORG_UUID);
    assert_eq!(
        scope.initiating_principal_namespace,
        *b"principal-v1\x0001912345-6789-7abc-8def-0123456789ac"
    );
}

#[test]
fn original_three_header_carriage_remains_parseable_without_mediated_scope() {
    let parsed = require(&original_carriage()).expect("direct carriage must remain valid");
    assert_eq!(parsed.mediated_scope, None);
}

#[test]
fn mediated_scope_rejects_every_wrong_width() {
    for len in [0, 1, MEDIATED_SCOPE_V1_LEN - 1, MEDIATED_SCOPE_V1_LEN + 1] {
        let mut metadata = original_carriage();
        insert(&mut metadata, MEDIATED_SCOPE_KEY, &vec![0x01; len]);
        assert!(require(&metadata).is_err(), "width {len} must be refused");
    }
}

#[test]
fn mediated_scope_rejects_unknown_versions() {
    for version in [0, 2, 255] {
        let mut bytes = mediated_scope_bytes();
        bytes[0] = version;
        let mut metadata = original_carriage();
        insert(&mut metadata, MEDIATED_SCOPE_KEY, &bytes);
        assert!(
            require(&metadata).is_err(),
            "version {version} must be refused"
        );
    }
}

#[test]
fn mediated_scope_rejects_noncanonical_principal_namespaces() {
    let mut cases = Vec::new();

    let mut uppercase_uuid = mediated_scope_bytes();
    let uuid_offset = 1 + ORG_UUID.len() + b"principal-v1\0".len();
    uppercase_uuid[uuid_offset + 10] = b'A';
    cases.push(uppercase_uuid);

    let mut wrong_tag = mediated_scope_bytes();
    wrong_tag[1 + ORG_UUID.len()] = b'P';
    cases.push(wrong_tag);

    let mut non_uuid = mediated_scope_bytes();
    *non_uuid.last_mut().expect("scope is nonempty") = b'g';
    cases.push(non_uuid);

    for bytes in cases {
        let mut metadata = original_carriage();
        insert(&mut metadata, MEDIATED_SCOPE_KEY, &bytes);
        assert!(require(&metadata).is_err());
    }
}

#[test]
fn divergent_mediated_scope_duplicate_is_refused_but_identical_is_accepted() {
    let bytes = mediated_scope_bytes();
    let mut identical = mediated_carriage();
    identical.append_bin(MEDIATED_SCOPE_KEY, BinaryMetadataValue::from_bytes(&bytes));
    assert!(require(&identical).is_ok());

    let mut divergent = mediated_carriage();
    let mut changed = bytes;
    changed[1] ^= 0x01;
    divergent.append_bin(
        MEDIATED_SCOPE_KEY,
        BinaryMetadataValue::from_bytes(&changed),
    );
    assert!(require(&divergent).is_err());
}

#[test]
fn mediated_scope_without_complete_original_carriage_is_never_treated_as_absent() {
    let mut metadata = MetadataMap::new();
    insert(&mut metadata, MEDIATED_SCOPE_KEY, &mediated_scope_bytes());
    assert!(extract(&metadata).is_err());

    insert(&mut metadata, OPERATION_ID_KEY, Uuid::now_v7().as_bytes());
    assert!(extract(&metadata).is_err());
}

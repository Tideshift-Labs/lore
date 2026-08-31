// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use tonic::Code;
use tonic::metadata::BinaryMetadataValue;
use uuid::Uuid;

use super::test_support::context;
use super::*;
use crate::grpc::domain_operation_metadata::FINGERPRINT_KEY;
use crate::grpc::domain_operation_metadata::FINGERPRINT_V1_LEN;
use crate::grpc::domain_operation_metadata::FINGERPRINT_VERSION_V1;
use crate::grpc::domain_operation_metadata::MEDIATED_SCOPE_KEY;
use crate::grpc::domain_operation_metadata::MEDIATED_SCOPE_V1_LEN;
use crate::grpc::domain_operation_metadata::OPERATION_ID_KEY;
use crate::grpc::domain_operation_metadata::PREPARE_TOKEN_KEY;
use crate::grpc::domain_operation_metadata::PREPARE_TOKEN_LEN;
use crate::grpc::domain_operation_metadata::scope_key_mediated_namespace;

const ORG_UUID: [u8; 16] = [
    0x01, 0x91, 0x23, 0x45, 0x67, 0x89, 0x7a, 0xbc, 0x8d, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
];
const PRINCIPAL_NAMESPACE: [u8; 49] = *b"principal-v1\x0001912345-6789-7abc-8def-0123456789ac";

fn token(subject: &str, is_service_account: Option<bool>) -> AuthorizationToken {
    AuthorizationToken {
        issuer: "https://issuer.example".to_string(),
        user_id: subject.to_string(),
        is_service_account,
        ..Default::default()
    }
}

fn carriage(include_mediated_scope: bool) -> MetadataMap {
    let mut metadata = MetadataMap::new();
    metadata.insert_bin(
        OPERATION_ID_KEY,
        BinaryMetadataValue::from_bytes(Uuid::now_v7().as_bytes()),
    );
    let mut fingerprint = vec![FINGERPRINT_VERSION_V1];
    fingerprint.extend(std::iter::repeat_n(0x42, FINGERPRINT_V1_LEN));
    metadata.insert_bin(
        FINGERPRINT_KEY,
        BinaryMetadataValue::from_bytes(&fingerprint),
    );
    metadata.insert_bin(
        PREPARE_TOKEN_KEY,
        BinaryMetadataValue::from_bytes(&[0x53; PREPARE_TOKEN_LEN]),
    );
    if include_mediated_scope {
        let mut scope = Vec::with_capacity(MEDIATED_SCOPE_V1_LEN);
        scope.push(1);
        scope.extend_from_slice(&ORG_UUID);
        scope.extend_from_slice(&PRINCIPAL_NAMESPACE);
        metadata.insert_bin(MEDIATED_SCOPE_KEY, BinaryMetadataValue::from_bytes(&scope));
    }
    metadata
}

fn direct_scope() -> GovernedScope<'static> {
    GovernedScope::TargetRepository {
        repository_id: &[0x77; 16],
    }
}

#[test]
fn exact_control_plane_service_uses_only_the_carried_mediated_scope() {
    let admitted = context(true)
        .admit(
            &carriage(true),
            Some(&token("lorehub-control-plane", Some(true))),
            direct_scope(),
        )
        .expect("exact service carriage must admit")
        .expect("enforced carriage must be governed");

    assert_eq!(
        admitted.key.tenant_scope_key,
        scope_key_mediated_namespace(&ORG_UUID, &PRINCIPAL_NAMESPACE)
            .expect("frozen mediated tuple must be canonical")
    );
}

#[test]
fn exact_control_plane_service_without_mediated_scope_fails_closed() {
    let error = context(true)
        .admit(
            &carriage(false),
            Some(&token("lorehub-control-plane", Some(true))),
            direct_scope(),
        )
        .expect_err("exact service absence must fail");
    assert_eq!(error.code(), Code::InvalidArgument);
}

#[test]
fn mediated_scope_is_refused_for_every_non_service_identity_shape() {
    let identities = [
        token("human-user", Some(false)),
        token("human-user", None),
        token("human-user", Some(true)),
        token("lorehub-control-plane", Some(false)),
        token("lorehub-control-plane", None),
    ];
    for identity in identities {
        let error = context(true)
            .admit(&carriage(true), Some(&identity), direct_scope())
            .expect_err("platform-only carriage must reject non-service identity");
        assert_eq!(error.code(), Code::InvalidArgument);
    }
}

#[test]
fn exact_org_and_principal_bytes_are_both_receipt_key_inputs() {
    let identity = token("lorehub-control-plane", Some(true));
    let expected = context(true)
        .admit(&carriage(true), Some(&identity), direct_scope())
        .expect("exact carriage must parse")
        .expect("exact carriage must govern")
        .key
        .tenant_scope_key;

    let mut changed_org = ORG_UUID;
    changed_org[0] ^= 0x01;
    assert_ne!(
        scope_key_mediated_namespace(&changed_org, &PRINCIPAL_NAMESPACE)
            .expect("changed org remains structurally valid"),
        expected
    );

    let mut changed_principal = PRINCIPAL_NAMESPACE;
    *changed_principal.last_mut().expect("namespace is nonempty") = b'd';
    assert_ne!(
        scope_key_mediated_namespace(&ORG_UUID, &changed_principal)
            .expect("changed principal remains structurally valid"),
        expected
    );
}

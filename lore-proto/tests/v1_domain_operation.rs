// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Drift guards for CR-029's private `lore.domain.v1` receipt rail.

use lore_proto::lore::domain::v1::DomainOperationClockGetRequest;
use lore_proto::lore::domain::v1::DomainOperationClockGetResponse;
use lore_proto::lore::domain::v1::DomainOperationOutcome;
use lore_proto::lore::domain::v1::DomainOperationPrepareRequest;
use lore_proto::lore::domain::v1::DomainOperationPrepareResponse;
use lore_proto::lore::domain::v1::DomainOperationPrepareStatus;
use lore_proto::lore::domain::v1::DomainOperationReceiptGetRequest;
use lore_proto::lore::domain::v1::DomainOperationReceiptGetResponse;
use lore_proto::lore::domain::v1::DomainOperationReceiptStatus;
use lore_proto::lore::domain::v1::domain_operation_service_client::DomainOperationServiceClient;
use lore_proto::lore::domain::v1::domain_operation_service_server::DomainOperationServiceServer;
use prost::Message;

const PROTO: &str = include_str!("../proto/lore/domain/v1/domain_operation.proto");
const GENERATED: &str = include_str!("../src/grpc/lore.domain.v1.rs");

#[test]
fn request_and_response_field_shapes_are_frozen() {
    let DomainOperationClockGetRequest {} = DomainOperationClockGetRequest::default();
    let DomainOperationClockGetResponse {
        lore_clock_unix_millis: _,
        sample_nonce: _,
    } = DomainOperationClockGetResponse::default();

    let DomainOperationPrepareRequest {
        org_uuid: _,
        initiating_principal_namespace: _,
        operation_id: _,
        method: _,
        scope: _,
        fingerprint_version: _,
        fingerprint: _,
        canonical_intent_digest: _,
        authorization_id: _,
        authorization_revision: _,
        preclaim_ticket: _,
    } = DomainOperationPrepareRequest::default();
    let DomainOperationPrepareResponse {
        status: _,
        consume_token: _,
        hard_expires_at_unix_millis: _,
        outcome: _,
        reason_version: _,
        reason: _,
        verification_nonce: _,
        bound_fields_digest: _,
        consumed_ticket_sha256: _,
        authorization_revision: _,
    } = DomainOperationPrepareResponse::default();

    let DomainOperationReceiptGetRequest {
        org_uuid: _,
        initiating_principal_namespace: _,
        operation_id: _,
        method: _,
        scope: _,
        fingerprint_version: _,
        fingerprint: _,
        canonical_intent_digest: _,
        authorization_id: _,
        authorization_revision: _,
        consumed_ticket_sha256: _,
    } = DomainOperationReceiptGetRequest::default();
    let DomainOperationReceiptGetResponse {
        status: _,
        outcome: _,
        reason_version: _,
        reason: _,
        from_future_marker: _,
        prepared_at_unix_millis: _,
        hard_expires_at_unix_millis: _,
        verification_nonce: _,
        bound_fields_digest: _,
        consumed_ticket_sha256: _,
        authorization_revision: _,
    } = DomainOperationReceiptGetResponse::default();
}

#[test]
fn enum_discriminants_are_frozen() {
    assert_eq!(DomainOperationPrepareStatus::Prepared as i32, 1);
    assert_eq!(DomainOperationPrepareStatus::Committed as i32, 2);
    assert_eq!(DomainOperationPrepareStatus::ExpiredOrUnknown as i32, 3);
    assert_eq!(DomainOperationPrepareStatus::Mismatch as i32, 4);
    assert_eq!(DomainOperationPrepareStatus::CapacityExhausted as i32, 5);

    assert_eq!(DomainOperationOutcome::Applied as i32, 1);
    assert_eq!(DomainOperationOutcome::NotApplied as i32, 2);

    assert_eq!(DomainOperationReceiptStatus::Prepared as i32, 1);
    assert_eq!(DomainOperationReceiptStatus::Committed as i32, 2);
    assert_eq!(DomainOperationReceiptStatus::Mismatch as i32, 3);
    assert_eq!(DomainOperationReceiptStatus::Expired as i32, 4);
    assert_eq!(DomainOperationReceiptStatus::ExpiredOrUnknown as i32, 5);
    assert_eq!(DomainOperationReceiptStatus::NotFound as i32, 6);
}

#[test]
fn optional_zero_values_retain_wire_presence() {
    let prepare = DomainOperationPrepareResponse {
        hard_expires_at_unix_millis: Some(0),
        reason_version: Some(0),
        ..Default::default()
    };
    assert_eq!(prepare.encode_to_vec(), [0x18, 0x00, 0x28, 0x00]);

    let receipt = DomainOperationReceiptGetResponse {
        reason_version: Some(0),
        prepared_at_unix_millis: Some(0),
        hard_expires_at_unix_millis: Some(0),
        ..Default::default()
    };
    assert_eq!(
        receipt.encode_to_vec(),
        [0x18, 0x00, 0x30, 0x00, 0x38, 0x00]
    );
}

#[test]
fn private_service_declares_only_the_coherent_three_rpc_slice() {
    let expected = [
        "rpc DomainOperationClockGet",
        "rpc DomainOperationPrepare",
        "rpc DomainOperationReceiptGet",
    ];
    assert_eq!(PROTO.matches("rpc DomainOperation").count(), expected.len());
    for declaration in expected {
        assert!(PROTO.contains(declaration), "missing {declaration}");
    }
    for deferred in [
        "DomainOperationVerifiedStaleFinalize",
        "DomainOperationTerminalStatusAttach",
        "DomainOperationProofNamespaceMaterialize",
        "DomainOperationProofNamespaceRetire",
    ] {
        assert!(!PROTO.contains(&format!("rpc {deferred}")));
    }
}

#[test]
fn generated_client_server_and_exact_method_paths_exist() {
    let _ = std::mem::size_of::<DomainOperationServiceClient<tonic::transport::Channel>>();
    let _ = std::mem::size_of::<DomainOperationServiceServer<UnimplementedService>>();
    for method in [
        "/lore.domain.v1.DomainOperationService/DomainOperationClockGet",
        "/lore.domain.v1.DomainOperationService/DomainOperationPrepare",
        "/lore.domain.v1.DomainOperationService/DomainOperationReceiptGet",
    ] {
        assert!(
            GENERATED.contains(method),
            "missing generated path {method}"
        );
    }
}

#[derive(Debug)]
struct UnimplementedService;

#[tonic::async_trait]
impl lore_proto::lore::domain::v1::domain_operation_service_server::DomainOperationService
    for UnimplementedService
{
    async fn domain_operation_clock_get(
        &self,
        _request: tonic::Request<DomainOperationClockGetRequest>,
    ) -> Result<tonic::Response<DomainOperationClockGetResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("test-only"))
    }

    async fn domain_operation_prepare(
        &self,
        _request: tonic::Request<DomainOperationPrepareRequest>,
    ) -> Result<tonic::Response<DomainOperationPrepareResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("test-only"))
    }

    async fn domain_operation_receipt_get(
        &self,
        _request: tonic::Request<DomainOperationReceiptGetRequest>,
    ) -> Result<tonic::Response<DomainOperationReceiptGetResponse>, tonic::Status> {
        Err(tonic::Status::unimplemented("test-only"))
    }
}

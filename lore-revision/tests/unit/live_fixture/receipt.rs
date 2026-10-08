// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Moved from `src/live_fixture/receipt.rs` when the crate's lib test harness was turned off.
use std::sync::Arc;

use lore_proto::lore::domain::v1::domain_operation_service_server::DomainOperationService;
use lore_proto::lore::domain::v1::*;
use lore_revision::live_fixture::receipt::ReceiptProbe;
use lore_revision::live_fixture::receipt::ReceiptService;
use tonic::Request;

fn bound_namespace_request() -> DomainOperationProofNamespaceStateGetRequestV1 {
    DomainOperationProofNamespaceStateGetRequestV1 {
        protocol_revision: 2,
        org_uuid: vec![0x11; 16].into(),
        initiating_principal_namespace: b"principal-v1\0aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
            .as_slice()
            .into(),
        namespace_epoch: vec![0x22; 16].into(),
        namespace_claim_revision: 7,
        namespace_claim_nonce: vec![0x33; 32].into(),
    }
}

#[tokio::test]
async fn namespace_snapshot_is_absent_without_touching_receipt_probe() {
    let probe = Arc::new(ReceiptProbe::default());
    let service = ReceiptService(probe.clone());
    let response = service
        .domain_operation_proof_namespace_state_get(Request::new(bound_namespace_request()))
        .await
        .expect("fixture supports namespace snapshot reads")
        .into_inner();

    assert_eq!(
        response,
        DomainOperationProofNamespaceStateGetResponseV1 {
            status: ProofNamespaceStateStatus::Absent as i32,
            quota_revision: None,
            final_high_water: None,
            final_range_set_digest: None,
        }
    );
    assert!(probe.calls().is_empty());
    assert!(probe.expected.lock().is_none());
}

#[tokio::test]
async fn namespace_snapshot_rejects_other_protocols_without_receipt_probe_activity() {
    let probe = Arc::new(ReceiptProbe::default());
    let service = ReceiptService(probe.clone());
    for protocol_revision in [0, 1, 3, u32::MAX] {
        let mut request = bound_namespace_request();
        request.protocol_revision = protocol_revision;
        let error = service
            .domain_operation_proof_namespace_state_get(Request::new(request))
            .await
            .expect_err("only receipt protocol v2 is supported");
        assert_eq!(
            error.code(),
            tonic::Code::InvalidArgument,
            "protocol {protocol_revision}"
        );
    }
    assert!(probe.calls().is_empty());
    assert!(probe.expected.lock().is_none());
}

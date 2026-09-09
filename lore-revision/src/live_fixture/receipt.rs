// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! Test-only receipt authority. JWT signature verification belongs to live auth tests.
use std::sync::Arc;

use lore_base::types::RepositoryId;
use lore_proto::lore::domain::v1::domain_operation_service_server::DomainOperationService;
use lore_proto::lore::domain::v1::domain_operation_service_server::DomainOperationServiceServer;
use lore_proto::lore::domain::v1::*;
use parking_lot::Mutex;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use uuid::Uuid;

#[derive(Default)]
pub struct ReceiptProbe {
    expected: Mutex<Option<(RepositoryId, Uuid)>>,
    calls: Mutex<Vec<(Vec<u8>, Vec<u8>)>>,
}
impl ReceiptProbe {
    pub fn allow(&self, repository: RepositoryId, attempt: Uuid) {
        *self.expected.lock() = Some((repository, attempt));
    }
    pub fn calls(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.calls.lock().clone()
    }
}
pub struct ReceiptService(Arc<ReceiptProbe>);
pub(super) fn service(probe: Arc<ReceiptProbe>) -> DomainOperationServiceServer<ReceiptService> {
    DomainOperationServiceServer::new(ReceiptService(probe))
}
#[tonic::async_trait]
impl DomainOperationService for ReceiptService {
    async fn domain_operation_attempt_receipt_get(
        &self,
        request: Request<DomainOperationAttemptReceiptGetRequest>,
    ) -> Result<Response<DomainOperationAttemptReceiptGetResponse>, Status> {
        let repository = request
            .metadata()
            .get_bin("urc-repository-id-bin")
            .and_then(|v| v.to_bytes().ok())
            .ok_or_else(|| Status::invalid_argument("repository missing"))?;
        let attempt = request.into_inner().client_attempt_id;
        self.0
            .calls
            .lock()
            .push((repository.to_vec(), attempt.to_vec()));
        let expected = *self.0.expected.lock();
        let Some((expected_repo, expected_attempt)) = expected else {
            return Err(Status::permission_denied(
                "no receipt authority in root repository",
            ));
        };
        if repository.as_ref() != <[u8; 16]>::from(expected_repo).as_slice()
            || attempt.as_ref() != expected_attempt.as_bytes()
        {
            return Err(Status::permission_denied(
                "wrong receipt namespace or attempt",
            ));
        }
        Ok(Response::new(DomainOperationAttemptReceiptGetResponse {
            status: DomainOperationReceiptStatus::Committed as i32,
            outcome: DomainOperationOutcome::Applied as i32,
            method: "branch.push".into(),
            ..Default::default()
        }))
    }
    async fn domain_operation_clock_get(
        &self,
        _: Request<DomainOperationClockGetRequest>,
    ) -> Result<Response<DomainOperationClockGetResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn domain_operation_prepare(
        &self,
        _: Request<DomainOperationPrepareRequest>,
    ) -> Result<Response<DomainOperationPrepareResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn domain_operation_receipt_get(
        &self,
        _: Request<DomainOperationReceiptGetRequest>,
    ) -> Result<Response<DomainOperationReceiptGetResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn domain_operation_verified_stale_finalize(
        &self,
        _: Request<DomainOperationVerifiedStaleFinalizeRequest>,
    ) -> Result<Response<DomainOperationVerifiedStaleFinalizeResponse>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn domain_operation_terminal_status_attach(
        &self,
        _: Request<DomainOperationTerminalStatusAttachRequest>,
    ) -> Result<Response<DomainOperationTerminalStatusAttachmentAckV1>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn domain_operation_proof_namespace_materialize(
        &self,
        _: Request<DomainOperationProofNamespaceMaterializeRequestV1>,
    ) -> Result<Response<DomainOperationProofNamespaceMaterializeReceiptV1>, Status> {
        Err(Status::unimplemented("unused"))
    }
    async fn domain_operation_proof_namespace_retire(
        &self,
        _: Request<DomainOperationProofNamespaceRetireRequestV1>,
    ) -> Result<Response<DomainOperationProofNamespaceRetireAckV1>, Status> {
        Err(Status::unimplemented("unused"))
    }
}

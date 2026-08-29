// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_base::lore_spawn_net;
use lore_proto::RebacApiClient as RebacApiGrpcClient;
use lore_proto::rebac::CreateResourceRequest;
use lore_proto::rebac::CreateResourceResponse;
use lore_proto::rebac::DeleteResourceRequest;
use lore_proto::rebac::DeleteResourceResponse;
use lore_proto::rebac::DomainOperationMaintenanceVerificationRequest;
use lore_proto::rebac::DomainOperationMaintenanceVerificationResponse;
use lore_proto::rebac::VerifyRepositoryOperationAuthorizationRequest;
use lore_proto::rebac::VerifyRepositoryOperationAuthorizationResponse;
use lore_telemetry::InstrumentProvider;
use lore_telemetry::LabelArray;
use lore_telemetry::METRICS_OPERATION_LATENCY_METRIC_NAME;
use lore_telemetry::timed;
use lore_telemetry::timer::TimedResult;
use lore_transport::grpc::CorrelationInterceptor;
use opentelemetry::KeyValue;
use smallvec::SmallVec;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::codegen::InterceptedService;
use tonic::transport::ClientTlsConfig;

use crate::grpc::ServerResultExt;

pub type RebacApiResult<T> = Result<Response<T>, Status>;

#[async_trait::async_trait]
pub trait RebacApiClient {
    async fn create_resource(
        &mut self,
        request: Request<CreateResourceRequest>,
    ) -> RebacApiResult<CreateResourceResponse>;

    async fn delete_resource(
        &mut self,
        request: Request<DeleteResourceRequest>,
    ) -> RebacApiResult<DeleteResourceResponse>;
}

/// Private CR-029 verifier used by the domain prepare/receipt service.
///
/// Kept separate from [`RebacApiClient`] so repository-handler test doubles do
/// not gain an unrelated method and the private rail can inject a focused fake
/// without opening a network connection.
#[async_trait::async_trait]
pub trait RepositoryOperationAuthorizationVerifier: Send + Sync {
    /// Consume an ISSUED preclaim ticket or exact-load an already verified
    /// authorization, returning its immutable witness and exact binding echo.
    async fn verify_repository_operation_authorization(
        &self,
        request: Request<VerifyRepositoryOperationAuthorizationRequest>,
    ) -> Result<VerifyRepositoryOperationAuthorizationResponse, Status>;

    /// Atomically claim the current stale-finalize permit for this exact
    /// strict-codec-approved request. A stale, revoked, or mismatched permit is
    /// a gRPC error and no Lore transaction may start.
    async fn claim_repository_operation_stale_finalize_permit(
        &self,
        request: Request<DomainOperationMaintenanceVerificationRequest>,
    ) -> Result<DomainOperationMaintenanceVerificationResponse, Status>;

    /// Verify the exact terminal-attachment phase/action and its platform
    /// claim, charge, and release-intent state before Lore mutation.
    async fn verify_repository_operation_terminal_status_attach(
        &self,
        request: Request<DomainOperationMaintenanceVerificationRequest>,
    ) -> Result<DomainOperationMaintenanceVerificationResponse, Status>;

    /// Verify the signed platform namespace claim and capacity binding before
    /// materializing a Lore-local epoch.
    async fn verify_repository_operation_proof_namespace_materialize(
        &self,
        request: Request<DomainOperationMaintenanceVerificationRequest>,
    ) -> Result<DomainOperationMaintenanceVerificationResponse, Status>;

    /// Verify and claim the current namespace-retirement permit before Lore
    /// takes the namespace lock.
    async fn verify_repository_operation_proof_namespace_retire(
        &self,
        request: Request<DomainOperationMaintenanceVerificationRequest>,
    ) -> Result<DomainOperationMaintenanceVerificationResponse, Status>;
}

/// Network implementation of the private CR-029 verifier.
pub struct GrpcRepositoryOperationAuthorizationVerifier {
    auth_url: String,
}

impl GrpcRepositoryOperationAuthorizationVerifier {
    /// Bind this verifier to the configured private auth-grpc endpoint.
    pub fn new(auth_url: String) -> Self {
        Self { auth_url }
    }
}

#[async_trait::async_trait]
impl RepositoryOperationAuthorizationVerifier for GrpcRepositoryOperationAuthorizationVerifier {
    async fn verify_repository_operation_authorization(
        &self,
        request: Request<VerifyRepositoryOperationAuthorizationRequest>,
    ) -> Result<VerifyRepositoryOperationAuthorizationResponse, Status> {
        let mut client = grpc_get_rebac_client(self.auth_url.clone())
            .await
            .map_err(|_| Status::unavailable("Repository operation verifier unavailable"))?;
        timed!(
            self.latency_histogram_ms(METRICS_OPERATION_LATENCY_METRIC_NAME),
            &self.get_labels_for_operation_context("verify_repository_operation_authorization"),
            client
                .client
                .verify_repository_operation_authorization(request)
                .await
        )
        .result
        .map(Response::into_inner)
    }

    async fn claim_repository_operation_stale_finalize_permit(
        &self,
        request: Request<DomainOperationMaintenanceVerificationRequest>,
    ) -> Result<DomainOperationMaintenanceVerificationResponse, Status> {
        let mut client = grpc_get_rebac_client(self.auth_url.clone())
            .await
            .map_err(|_| Status::unavailable("Repository operation verifier unavailable"))?;
        client
            .client
            .claim_repository_operation_stale_finalize_permit(request)
            .await
            .map(Response::into_inner)
    }

    async fn verify_repository_operation_terminal_status_attach(
        &self,
        request: Request<DomainOperationMaintenanceVerificationRequest>,
    ) -> Result<DomainOperationMaintenanceVerificationResponse, Status> {
        let mut client = grpc_get_rebac_client(self.auth_url.clone())
            .await
            .map_err(|_| Status::unavailable("Repository operation verifier unavailable"))?;
        client
            .client
            .verify_repository_operation_terminal_status_attach(request)
            .await
            .map(Response::into_inner)
    }

    async fn verify_repository_operation_proof_namespace_materialize(
        &self,
        request: Request<DomainOperationMaintenanceVerificationRequest>,
    ) -> Result<DomainOperationMaintenanceVerificationResponse, Status> {
        let mut client = grpc_get_rebac_client(self.auth_url.clone())
            .await
            .map_err(|_| Status::unavailable("Repository operation verifier unavailable"))?;
        client
            .client
            .verify_repository_operation_proof_namespace_materialize(request)
            .await
            .map(Response::into_inner)
    }

    async fn verify_repository_operation_proof_namespace_retire(
        &self,
        request: Request<DomainOperationMaintenanceVerificationRequest>,
    ) -> Result<DomainOperationMaintenanceVerificationResponse, Status> {
        let mut client = grpc_get_rebac_client(self.auth_url.clone())
            .await
            .map_err(|_| Status::unavailable("Repository operation verifier unavailable"))?;
        client
            .client
            .verify_repository_operation_proof_namespace_retire(request)
            .await
            .map(Response::into_inner)
    }
}

pub struct RebacClientHelper {
    client:
        RebacApiGrpcClient<InterceptedService<tonic::transport::Channel, CorrelationInterceptor>>,
}

impl RebacClientHelper {
    async fn new(auth_url: String) -> Result<RebacClientHelper, Status> {
        let mut endpoint = tonic::transport::Endpoint::from_shared(auth_url.clone())
            .warn_map_err(|_| Status::internal("Failed to create rebac endpoint"))?;
        if auth_url.starts_with("https://") {
            endpoint = endpoint
                .tls_config(
                    ClientTlsConfig::new()
                        .assume_http2(true)
                        .with_native_roots(),
                )
                .warn_map_err(|_| Status::internal("Failed to configure TLS for rebac"))?;
        }
        // Connect from net so the hyper/h2 driver tasks this spawns bind there
        // rather than to the core runtime the caller runs on.
        let channel = lore_spawn_net!(async move { endpoint.connect().await })
            .await
            .warn_map_err(|_| Status::internal("rebac connection task failed"))?
            .warn_map_err(|_| Status::internal("Failed to connect to rebac service"))?;
        let client = RebacApiGrpcClient::with_interceptor(channel, CorrelationInterceptor);
        Ok(RebacClientHelper { client })
    }
}

#[async_trait::async_trait]
impl RebacApiClient for RebacClientHelper {
    async fn create_resource(
        &mut self,
        request: Request<CreateResourceRequest>,
    ) -> RebacApiResult<CreateResourceResponse> {
        timed!(
            self.latency_histogram_ms(METRICS_OPERATION_LATENCY_METRIC_NAME),
            &self.get_labels_for_operation_context("create_resource"),
            self.client.create_resource(request).await
        )
        .result
    }

    async fn delete_resource(
        &mut self,
        request: Request<DeleteResourceRequest>,
    ) -> RebacApiResult<DeleteResourceResponse> {
        timed!(
            self.latency_histogram_ms(METRICS_OPERATION_LATENCY_METRIC_NAME),
            &self.get_labels_for_operation_context("delete_resource"),
            self.client.delete_resource(request).await
        )
        .result
    }
}

pub async fn grpc_get_rebac_client(auth_url: String) -> Result<RebacClientHelper, Status> {
    RebacClientHelper::new(auth_url).await
}

impl InstrumentProvider for RebacClientHelper {
    fn namespace(&self) -> &'static str {
        "urc.authnz.rebac"
    }
}

impl InstrumentProvider for GrpcRepositoryOperationAuthorizationVerifier {
    fn namespace(&self) -> &'static str {
        "urc.authnz.repository_operation"
    }
}

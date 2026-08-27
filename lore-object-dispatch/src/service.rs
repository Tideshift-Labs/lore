// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Fail-closed implementation of the frozen private service surface.

use std::pin::Pin;
use std::sync::Arc;

use lore_proto::lore::object_dispatch::v1::ObjectStoreRequestOutcomeV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreRequestQueryV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreRequestReceiptV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreRequestV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultAckReceiptV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultAckV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultChunkV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultDiscardReceiptV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultDiscardV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultFetchV1;
use lore_proto::lore::object_dispatch::v1::PutSpoolReadyV1;
use lore_proto::lore::object_dispatch::v1::ReservePutAckV1;
use lore_proto::lore::object_dispatch::v1::ReservePutRequestV1;
use lore_proto::lore::object_dispatch::v1::UploadPutChunkV1;
use lore_proto::lore::object_dispatch::v1::object_store_dispatch_service_server::ObjectStoreDispatchService;
use tokio_stream::Stream;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::Streaming;

use crate::DispatchMetricRecorder;
use crate::DispatchMetrics;
use crate::DispatchRpc;

pub const SOURCE_DARK_STATUS_MESSAGE: &str = "object-store dispatch authority is source-dark";

#[derive(Clone)]
pub struct SourceDarkObjectStoreDispatchService {
    metrics: Arc<dyn DispatchMetricRecorder>,
}

impl std::fmt::Debug for SourceDarkObjectStoreDispatchService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SourceDarkObjectStoreDispatchService")
            .finish_non_exhaustive()
    }
}

impl Default for SourceDarkObjectStoreDispatchService {
    fn default() -> Self {
        Self::new()
    }
}

impl SourceDarkObjectStoreDispatchService {
    pub fn new() -> Self {
        Self::with_metric_recorder(Arc::new(DispatchMetrics::new()))
    }

    pub fn with_metric_recorder(metrics: Arc<dyn DispatchMetricRecorder>) -> Self {
        Self { metrics }
    }

    fn unavailable<T>(&self, rpc: DispatchRpc) -> Result<Response<T>, Status> {
        self.metrics.record_source_dark_rejection(rpc);
        Err(Status::unavailable(SOURCE_DARK_STATUS_MESSAGE))
    }
}

#[tonic::async_trait]
impl ObjectStoreDispatchService for SourceDarkObjectStoreDispatchService {
    async fn reserve_put(
        &self,
        _request: Request<ReservePutRequestV1>,
    ) -> Result<Response<ReservePutAckV1>, Status> {
        self.unavailable(DispatchRpc::ReservePut)
    }

    async fn upload_put(
        &self,
        _request: Request<Streaming<UploadPutChunkV1>>,
    ) -> Result<Response<PutSpoolReadyV1>, Status> {
        self.unavailable(DispatchRpc::UploadPut)
    }

    async fn submit(
        &self,
        _request: Request<ObjectStoreRequestV1>,
    ) -> Result<Response<ObjectStoreRequestReceiptV1>, Status> {
        self.unavailable(DispatchRpc::Submit)
    }

    async fn get_request(
        &self,
        _request: Request<ObjectStoreRequestQueryV1>,
    ) -> Result<Response<ObjectStoreRequestOutcomeV1>, Status> {
        self.unavailable(DispatchRpc::GetRequest)
    }

    type FetchResultStream =
        Pin<Box<dyn Stream<Item = Result<ObjectStoreResultChunkV1, Status>> + Send + 'static>>;

    async fn fetch_result(
        &self,
        _request: Request<ObjectStoreResultFetchV1>,
    ) -> Result<Response<Self::FetchResultStream>, Status> {
        self.unavailable(DispatchRpc::FetchResult)
    }

    async fn acknowledge_result(
        &self,
        _request: Request<ObjectStoreResultAckV1>,
    ) -> Result<Response<ObjectStoreResultAckReceiptV1>, Status> {
        self.unavailable(DispatchRpc::AcknowledgeResult)
    }

    async fn discard_result(
        &self,
        _request: Request<ObjectStoreResultDiscardV1>,
    ) -> Result<Response<ObjectStoreResultDiscardReceiptV1>, Status> {
        self.unavailable(DispatchRpc::DiscardResult)
    }
}

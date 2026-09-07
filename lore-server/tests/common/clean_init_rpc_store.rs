// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Test-only ImmutableStore adapter: revision serialization sends actual authenticated storage RPCs.
use std::sync::Arc;

use bytes::Bytes;
use lore_proto::lore::storage::v1 as wire;
use lore_storage::immutable_store::StoreError;
use lore_storage::*;
use tonic::Request;
use wire::storage_service_client::StorageServiceClient;

pub(super) struct RpcStore {
    pub endpoint: String,
    pub token: String,
    pub uploads: std::sync::Mutex<Vec<(Address, Bytes)>>,
}
impl RpcStore {
    pub(super) async fn assert_absent_repository_put_refused(&self, partition: Partition) {
        let payload = Bytes::from_static(b"ordinary absent repository upload must remain refused");
        self.assert_put_refused(partition, payload).await;
    }
    pub(super) async fn assert_put_refused(&self, partition: Partition, payload: Bytes) {
        let address = Address {
            hash: hash_slice(&payload),
            context: Context::default(),
        };
        let fragment = Fragment {
            flags: 0,
            size_payload: payload.len() as u32,
            size_content: payload.len() as u64,
        };
        let request = self.request(
            tokio_stream::iter([wire::PutRequest {
                address: Some(address.into()),
                fragment: Some(fragment.into()),
                payload: Some(payload),
            }]),
            partition,
        );
        let mut stream = self.client().await.put(request).await.unwrap().into_inner();
        let result = stream
            .message()
            .await
            .unwrap()
            .expect("one refused PUT response");
        let status = result
            .status
            .expect("ordinary absent repository PUT is refused");
        assert_ne!(status.code, 0);

        assert!(stream.message().await.unwrap().is_none());
    }
    fn request<T>(&self, body: T, partition: Partition) -> Request<T> {
        let mut request = Request::new(body);
        request.metadata_mut().insert(
            "authorization",
            format!("Bearer {}", self.token).parse().unwrap(),
        );
        request.metadata_mut().insert_bin(
            "lore-partition-bin",
            tonic::metadata::BinaryMetadataValue::from_bytes(partition.data()),
        );
        request.metadata_mut().insert_bin(
            "urc-repository-id-bin",
            tonic::metadata::BinaryMetadataValue::from_bytes(partition.data()),
        );
        request
    }
    async fn client(&self) -> StorageServiceClient<tonic::transport::Channel> {
        StorageServiceClient::connect(self.endpoint.clone())
            .await
            .unwrap()
    }
    async fn read(&self, partition: Partition, address: Address, metadata: bool) -> StoreGetData {
        let request = self.request(
            tokio_stream::iter([lore_proto::lore::model::v1::Address::from(address)]),
            partition,
        );
        let mut client = self.client().await;
        let mut stream = if metadata {
            client.get_metadata(request).await
        } else {
            client.get(request).await
        }
        .unwrap()
        .into_inner();
        let result = stream
            .message()
            .await
            .unwrap()
            .expect("one storage response");
        assert_eq!(
            result.status.as_ref().map_or(0, |s| s.code),
            0,
            "storage GET: {:?}",
            result.status
        );
        assert_eq!(result.address, Some(address.into()));
        assert!(stream.message().await.unwrap().is_none());
        StoreGetData {
            fragment: result.fragment.unwrap().into(),
            match_made: StoreMatch::MatchFull,
            partition,
            payload: (!metadata).then_some(result.payload),
        }
    }
}
#[async_trait::async_trait]
impl ImmutableStore for RpcStore {
    async fn get(self: Arc<Self>, p: Partition, a: Address) -> Result<StoreGetData, StoreError> {
        Ok(self.read(p, a, false).await)
    }
    async fn get_metadata(
        self: Arc<Self>,
        p: Partition,
        a: Address,
    ) -> Result<StoreGetData, StoreError> {
        Ok(self.read(p, a, true).await)
    }
    async fn put(
        self: Arc<Self>,
        p: Partition,
        a: Address,
        f: Fragment,
        payload: Option<Bytes>,
        _force: bool,
    ) -> Result<(), StoreError> {
        let observed = payload.clone().expect("revision uploads carry bytes");
        let request = self.request(
            tokio_stream::iter([wire::PutRequest {
                address: Some(a.into()),
                fragment: Some(f.into()),
                payload,
            }]),
            p,
        );
        let mut stream = self.client().await.put(request).await.unwrap().into_inner();
        let result = stream.message().await.unwrap().expect("one PUT response");
        assert_eq!(result.address, Some(a.into()));
        assert_eq!(
            result.status.as_ref().map_or(0, |s| s.code),
            0,
            "storage PUT: {:?}",
            result.status
        );
        assert!(stream.message().await.unwrap().is_none());
        self.uploads.lock().unwrap().push((a, observed));
        Ok(())
    }
    async fn query(
        self: Arc<Self>,
        p: Partition,
        addresses: &[Address],
        results: &mut [StoreMatchResult],
    ) -> Result<(), StoreError> {
        let response = self
            .client()
            .await
            .query(self.request(
                wire::QueryRequest {
                    addresses: addresses.iter().map(Into::into).collect(),
                },
                p,
            ))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(response.results.len(), results.len());
        for ((result, state), address) in results.iter_mut().zip(response.results).zip(addresses) {
            let match_made = match state {
                0 => StoreMatch::MatchFull,
                1 => StoreMatch::MatchPartition,
                3 => StoreMatch::MatchNone,
                other => panic!("indeterminate query {other}"),
            };
            *result = StoreMatchResult {
                match_made,
                partition: p,
                context: address.context,
                stored_local: false,
                stored_durable: state == 0,
            };
        }
        Ok(())
    }
    async fn obliterate(
        self: Arc<Self>,
        _: Partition,
        _: Address,
        _: Arc<StoreObliterateStats>,
    ) -> Result<(), StoreError> {
        panic!("outside RPC fixture scope")
    }
    async fn evict(
        self: Arc<Self>,
        _: usize,
        _: bool,
        _: Option<lore_storage::gc_event::GcEventSinkRef>,
    ) -> Result<usize, StoreError> {
        panic!("outside RPC fixture scope")
    }
    async fn compact(
        self: Arc<Self>,
        _: usize,
        _: Option<usize>,
        _: bool,
        _: Option<lore_storage::gc_event::GcEventSinkRef>,
    ) -> Result<Option<usize>, StoreError> {
        panic!("outside RPC fixture scope")
    }
    async fn compact_resume_at(self: Arc<Self>) -> Option<usize> {
        None
    }
    async fn compact_stop(self: Arc<Self>) {}
    fn max_query_batch(&self) -> Option<usize> {
        None
    }
    async fn flush(self: Arc<Self>, _: bool) -> Result<(), StoreError> {
        Ok(())
    }
    async fn verify(self: Arc<Self>, _: bool) -> Result<(), StoreError> {
        panic!("outside RPC fixture scope")
    }
    async fn copy(
        self: Arc<Self>,
        _: Partition,
        _: Address,
        _: Partition,
        _: Context,
        _: bool,
    ) -> Result<(), StoreError> {
        panic!("outside RPC fixture scope")
    }
}

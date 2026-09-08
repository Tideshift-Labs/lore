// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

#[tokio::test]
async fn caller_required_revision_lists_preserve_history_without_mutable_backfill() {
    use crate::grpc::caller_capabilities::CallerCapabilityPolicy;
    use crate::grpc::caller_capabilities::tests::read_repairs::CountWritesMutableStore;
    use std::sync::atomic::{AtomicUsize, Ordering};
    for v1 in [false, true] {
        for required in [true, false] {
            let repository = random::<RepositoryId>();
            let (immutable, mutable, execution) = test_store_create().await.unwrap();
            Box::pin(LORE_CONTEXT.scope(execution, async move {
                let context = Arc::new(RepositoryContext::new_server_context(immutable.clone(), mutable.clone(), repository));
                let (branch_id, signatures) = create_branch_with_history(&context, 3).await;
                let writes = Arc::new(AtomicUsize::new(0));
                let spy: Arc<dyn lore_storage::MutableStore> = Arc::new(CountWritesMutableStore { inner: mutable, writes: writes.clone() });
                let policy = if required { CallerCapabilityPolicy::RequireOutcomeUnknownV1 } else { CallerCapabilityPolicy::CompatibleSingleReplica };
                if v1 {
                    let mut request = make_request_identifier(repository, branch_id, 2);
                    request.extensions_mut().insert(policy);
                    let response = handler(request, immutable, spy, 2, crate::grpc::server::RevisionListAcceleration { step_keys: true, list_cache: false }, &make_instruments()).await.unwrap().into_inner();
                    assert_eq!(response.items.len(), 2);
                    assert_eq!(Hash::from(response.items[0].signature.as_ref()), signatures[1]);
                } else {
                    let mut request = tonic::Request::new(lore_proto::RevisionListRequest { start: Some(lore_proto::revision_list_request::Start::Identifier(lore_proto::RevisionIdentifer { branch: branch_id.into(), number: 2 })) });
                    request.metadata_mut().insert_bin(REPOSITORY_ID_KEY, tonic::metadata::BinaryMetadataValue::from_bytes(repository.data()));
                    request.extensions_mut().insert(policy);
                    let provider = TestInstrumentProvider {};
                    let instruments = crate::grpc::revision_service::RevisionListInstruments {
                        resolve_start_duration: provider.latency_histogram_ms("caller-test.resolve"),
                        relative_age_seconds: provider.length_histogram("caller-test.age", vec![1.0,2.0]),
                        walk_duration: provider.latency_histogram_ms("caller-test.walk"),
                    };
                    let response = crate::grpc::handlers::revision_list::handler(request, immutable, spy, 2, crate::grpc::server::RevisionListAcceleration { step_keys: true, list_cache: false }, &instruments).await.unwrap().into_inner();
                    assert_eq!(response.items.len(), 2);
                }
                if required { assert_eq!(writes.load(Ordering::SeqCst), 0, "v1={v1}"); }
                else { assert!(writes.load(Ordering::SeqCst) > 0, "compatible positive control v1={v1}"); }
            })).await;
        }
    }
}

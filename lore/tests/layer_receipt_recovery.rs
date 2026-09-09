// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! [CLIENT] Retained layer receipts use the original repository on the real gRPC wire.
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::RepositoryId;
use lore_revision::live_fixture::LiveRepository;
use lore_revision::live_fixture::LockServer;
use lore_revision::live_fixture::fixture_execution_context;
use lore_revision::repository_fence::RepositoryMutationGuard;
use lore_transport::AttemptId;
use lore_transport::AttemptRecord;
use lore_transport::AttemptResolution;
use lore_transport::AttemptState;
use lore_transport::AttemptStore;
use lore_transport::DomainReceiptOutcome;
use lore_transport::DomainReceiptState;
use lore_transport::caller_operation::ManagedAttemptIntent;
use uuid::Uuid;

#[test]
fn recovery_reads_frozen_layer_receipt_even_when_root_scope_is_refused() {
    lore::runtime().block_on(LORE_CONTEXT.scope(fixture_execution_context(), async {
        let server = LockServer::start().await;
        let fixture = LiveRepository::create_managed(&format!("{}/", server.remote_url())).await;
        let connection = fixture.managed_connection().await;
        let root = fixture.repository_id;
        let layer = RepositoryId::from([0x71; 16]);
        assert_ne!(root, layer);
        let namespace =
            lore_transport::caller_operation::selected_caller_namespace(&connection, layer)
                .await
                .unwrap();
        let guard = RepositoryMutationGuard::acquire(&fixture.path)
            .await
            .unwrap();
        let parent = Uuid::now_v7();
        let attempt = AttemptId::new();
        let store = guard
            .begin(parent, "push-stage".into(), "layer dispatch".into())
            .await
            .unwrap();
        let rpc = "RevisionService.BranchPush".to_string();
        store
            .record_managed(
                &AttemptRecord {
                    attempt_id: attempt,
                    state: AttemptState::Unresolved,
                    operation: rpc.clone(),
                    repository: layer,
                    recorded_at_unix_millis: 1,
                    receipt: None,
                },
                &ManagedAttemptIntent {
                    version: 1,
                    parent_id: parent,
                    repository: layer,
                    rpc,
                    canonical_request: vec![8, 1],
                    endpoint: namespace.endpoint,
                    verified_issuer: namespace.verified_issuer,
                    authenticated_subject: namespace.authenticated_subject,
                    caller_capabilities: namespace.caller_capabilities,
                },
            )
            .await
            .unwrap();
        store.complete_parent_body(parent).await.unwrap();
        drop(store);
        drop(guard);
        server.receipts.allow(layer, attempt.as_uuid());
        let root_client = connection.domain_operations(root).await.unwrap();
        assert!(root_client.attempt_receipt_get(&attempt).await.is_err());
        let recovery = RepositoryMutationGuard::recover(&fixture.path)
            .await
            .unwrap();
        let retained = recovery.store();
        let receipt = lore::recovery::receipt_get(&retained, &attempt)
            .await
            .unwrap();
        assert!(matches!(
            receipt.state,
            DomainReceiptState::Committed {
                outcome: DomainReceiptOutcome::Applied,
                ..
            }
        ));
        assert_eq!(receipt.method, "branch.push");
        assert_eq!(
            server.receipts.calls(),
            vec![
                (
                    <[u8; 16]>::from(root).to_vec(),
                    attempt.as_uuid().as_bytes().to_vec()
                ),
                (
                    <[u8; 16]>::from(layer).to_vec(),
                    attempt.as_uuid().as_bytes().to_vec()
                )
            ]
        );
        // A caller cannot reuse this frozen layer binding with a root-scoped client.
        let binding = retained.recovery_context(&attempt).await.unwrap();
        assert!(
            lore_transport::with_caller_recovery(
                binding,
                root_client.attempt_receipt_get(&attempt)
            )
            .await
            .is_err()
        );
        assert_eq!(
            server.receipts.calls().len(),
            2,
            "mismatch must refuse before wire dispatch"
        );
        assert_eq!(
            retained.unresolved().await.unwrap()[0].attempt_id,
            attempt,
            "lookup alone never settles the child"
        );
        retained
            .resolve(&attempt, AttemptResolution::Applied)
            .await
            .unwrap();
        retained.reconcile_parent(parent).await.unwrap();
    }));
}

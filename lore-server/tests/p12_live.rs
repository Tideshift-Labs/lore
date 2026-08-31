// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use std::sync::Arc;

use lore_postgres::domain::DomainOutcome;
use lore_postgres::domain::coordinator::ADMISSION_REJECTED_V1;
use lore_postgres::domain::coordinator::DomainTransactionStore;
use lore_postgres::domain::coordinator::GovernedOperation;
use lore_postgres::domain::coordinator::RepositoryCreateInput;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptKey;
use lore_postgres::domain::receipts::ReceiptLookup;
use lore_postgres::domain::store::PostgresDomainStore;
use lore_postgres::pool::TlsConfig;
use lore_server::auth::jwt::AuthorizationToken;
use lore_server::domain::DomainContext;
use lore_server::domain::GovernedScope;
use lore_server::domain_intent::CanonicalIntent;
use lore_server::domain_intent::canonical_intent_digest;
use lore_server::grpc::domain_operation_metadata::FINGERPRINT_KEY;
use lore_server::grpc::domain_operation_metadata::FINGERPRINT_V1_LEN;
use lore_server::grpc::domain_operation_metadata::FINGERPRINT_VERSION_V1;
use lore_server::grpc::domain_operation_metadata::MEDIATED_SCOPE_KEY;
use lore_server::grpc::domain_operation_metadata::OPERATION_ID_KEY;
use lore_server::grpc::domain_operation_metadata::PREPARE_TOKEN_KEY;
use lore_server::grpc::domain_operation_metadata::scope_key_mediated_namespace;
use tonic::metadata::BinaryMetadataValue;
use tonic::metadata::MetadataMap;
use uuid::Uuid;

fn service_token() -> AuthorizationToken {
    AuthorizationToken {
        issuer: "https://issuer.example/p12".to_string(),
        user_id: "lorehub-control-plane".to_string(),
        is_service_account: Some(true),
        ..Default::default()
    }
}

fn principal_namespace(user_id: Uuid) -> Vec<u8> {
    format!("principal-v1\0{user_id}").into_bytes()
}

fn mediated_key(operation_id: Uuid, org_uuid: &[u8; 16], principal: &[u8]) -> ReceiptKey {
    let token = service_token();
    ReceiptKey {
        verified_issuer: token.issuer,
        authenticated_subject: token.user_id,
        tenant_scope_key: scope_key_mediated_namespace(org_uuid, principal)
            .expect("fixture mediated namespace must be canonical"),
        operation_id,
    }
}

fn carriage(
    operation_id: Uuid,
    prepare_token: &[u8; 32],
    fingerprint: &[u8; 32],
    org_uuid: &[u8; 16],
    principal: &[u8],
) -> MetadataMap {
    let mut metadata = MetadataMap::new();
    metadata.insert_bin(
        OPERATION_ID_KEY,
        BinaryMetadataValue::from_bytes(operation_id.as_bytes()),
    );
    let mut fingerprint_header = vec![FINGERPRINT_VERSION_V1];
    fingerprint_header.extend_from_slice(fingerprint);
    assert_eq!(fingerprint.len(), FINGERPRINT_V1_LEN);
    metadata.insert_bin(
        FINGERPRINT_KEY,
        BinaryMetadataValue::from_bytes(&fingerprint_header),
    );
    metadata.insert_bin(
        PREPARE_TOKEN_KEY,
        BinaryMetadataValue::from_bytes(prepare_token),
    );
    let mut mediated = Vec::with_capacity(66);
    mediated.push(1);
    mediated.extend_from_slice(org_uuid);
    mediated.extend_from_slice(principal);
    metadata.insert_bin(
        MEDIATED_SCOPE_KEY,
        BinaryMetadataValue::from_bytes(&mediated),
    );
    metadata
}

async fn create_repository(
    store: &Arc<dyn DomainTransactionStore>,
    repository_id: &[u8; 16],
    org_uuid: &[u8; 16],
    principal: &[u8],
) {
    let operation_id = Uuid::now_v7();
    let key = mediated_key(operation_id, org_uuid, principal);
    let fingerprint = rand::random::<[u8; 32]>().to_vec();
    let digest = canonical_intent_digest(&CanonicalIntent::RepositoryCreate {
        repository_id,
        name: "p12-live",
        description: "",
        default_branch_id: Uuid::new_v4().as_bytes(),
        default_branch_name: "main",
        creator: None,
        caller_created: None,
    })
    .expect("fixture create intent must hash");
    let binding = OperationBinding {
        method: "repository_create".to_string(),
        scope: key.tenant_scope_key.clone(),
        fingerprint_version: 1,
        fingerprint: fingerprint.clone(),
        canonical_intent_digest: digest,
    };
    let prepared = store
        .domain_operation_prepare(&key, &binding, None)
        .await
        .expect("fixture prepare must succeed");
    let PrepareResult::Prepared { token, .. } = prepared else {
        panic!("fixture create must prepare, got {prepared:?}");
    };
    let operation = GovernedOperation {
        key,
        binding,
        prepare_token: token,
    };
    let input = RepositoryCreateInput {
        repository_id: repository_id.to_vec(),
        name: format!("p12-live-{operation_id}"),
        metadata_hash: rand::random::<[u8; 32]>().to_vec(),
        default_branch_id: Uuid::new_v4().as_bytes().to_vec(),
        default_branch_name: "main".to_string(),
        default_branch_metadata_hash: rand::random::<[u8; 32]>().to_vec(),
        default_branch_latest_hash: vec![0; 32],
        creation_fingerprint: fingerprint,
        creation_fingerprint_version: 1,
        projection: Vec::new(),
        event: None,
    };
    let result = store
        .repository_create(&operation, &input)
        .await
        .expect("fixture repository create must execute");
    assert_eq!(result.outcome, DomainOutcome::Applied);
}

#[tokio::test]
#[ignore = "needs disposable live Postgres via LORE_TEST_PG_URL; run with -- --ignored --test-threads=1"]
async fn exact_mediated_obliterate_consumes_while_tuple_tamper_preserves_prepared() {
    let url = std::env::var("LORE_TEST_PG_URL")
        .expect("LORE_TEST_PG_URL must be set; an unconfigured live case is NOT RUN");
    let store = Arc::new(
        PostgresDomainStore::connect(&url, 4, &TlsConfig::default())
            .await
            .expect("real Postgres domain store must connect"),
    );
    let context = DomainContext::new(store, true);
    let store = context.store().clone();

    for tamper in [None, Some("org"), Some("principal")] {
        let repository_id = *Uuid::new_v4().as_bytes();
        let org_uuid = *Uuid::new_v4().as_bytes();
        let principal = principal_namespace(Uuid::new_v4());
        create_repository(&store, &repository_id, &org_uuid, &principal).await;
        let before = store
            .repository_snapshot(&repository_id)
            .await
            .expect("repository snapshot must read")
            .expect("fixture repository must exist");

        let operation_id = Uuid::now_v7();
        let fingerprint = rand::random::<[u8; 32]>();
        let address_hash = rand::random::<[u8; 32]>();
        let address_context = rand::random::<[u8; 16]>();
        let digest = canonical_intent_digest(&CanonicalIntent::Obliterate {
            repository_id: &repository_id,
            address_hash: &address_hash,
            address_context: &address_context,
        })
        .expect("obliterate intent must hash");
        let key = mediated_key(operation_id, &org_uuid, &principal);
        let binding = OperationBinding {
            method: "begin_obliterate".to_string(),
            scope: key.tenant_scope_key.clone(),
            fingerprint_version: 1,
            fingerprint: fingerprint.to_vec(),
            canonical_intent_digest: digest.clone(),
        };
        let prepared = store
            .domain_operation_prepare(&key, &binding, None)
            .await
            .expect("obliterate prepare must succeed");
        let PrepareResult::Prepared { token, .. } = prepared else {
            panic!("obliterate must prepare, got {prepared:?}");
        };

        let mut carried_org = org_uuid;
        let mut carried_principal = principal.clone();
        if tamper == Some("org") {
            carried_org[0] ^= 0x01;
        } else if tamper == Some("principal") {
            carried_principal = principal_namespace(Uuid::new_v4());
        }
        let metadata = carriage(
            operation_id,
            &token,
            &fingerprint,
            &carried_org,
            &carried_principal,
        );
        let admitted = context
            .admit(
                &metadata,
                Some(&service_token()),
                GovernedScope::TargetRepository {
                    repository_id: &repository_id,
                },
            )
            .expect("canonical carriage must pass the entry gate")
            .expect("enforced carriage must govern");
        let operation = admitted.into_governed("begin_obliterate", digest);
        let result = store
            .begin_obliterate(&operation, &repository_id)
            .await
            .expect("obliterate coordinator call must return decisively");

        if tamper.is_none() {
            assert_eq!(result.outcome, DomainOutcome::Applied);
            assert!(matches!(
                store
                    .domain_operation_receipt_get(&key, &binding)
                    .await
                    .expect("committed receipt must read"),
                ReceiptLookup::Committed { .. }
            ));
        } else {
            assert!(matches!(
                result.outcome,
                DomainOutcome::NotApplied { ref reason, .. } if reason == ADMISSION_REJECTED_V1
            ));
            let after = store
                .repository_snapshot(&repository_id)
                .await
                .expect("repository snapshot must read")
                .expect("tamper must not remove the repository");
            assert_eq!(after.generation, before.generation);
            assert!(matches!(
                store
                    .domain_operation_receipt_get(&key, &binding)
                    .await
                    .expect("prepared receipt must read"),
                ReceiptLookup::Prepared { .. }
            ));
        }
    }
}

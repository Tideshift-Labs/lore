// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The same governed create intent on v0 and v1; v0 binds caller time explicitly.
use lore_postgres::domain::coordinator::DomainTransactionStore;
use lore_postgres::domain::receipts::OperationBinding;
use lore_postgres::domain::receipts::PrepareResult;
use lore_postgres::domain::receipts::ReceiptKey;

use super::*;
pub(super) async fn prepare(
    backend: &backend::SharedBackend,
    issuer: &str,
    writer: &str,
    repository: &[u8; 16],
    branch: &[u8; 16],
    v0: bool,
) -> carriage::Carriage {
    let scope =
        lore_server::grpc::domain_operation_metadata::scope_key_repository_create(repository)
            .unwrap();
    let digest = lore_server::domain_intent::canonical_intent_digest(
        &lore_server::domain_intent::CanonicalIntent::RepositoryCreate {
            repository_id: repository,
            name: "single-rpc",
            description: "WP118",
            default_branch_id: branch,
            default_branch_name: "main",
            creator: Some("fixture"),
            caller_created: v0.then_some(1_700_000_000_000),
        },
    )
    .unwrap();
    let elapsed = backend
        .domain
        .domain_operation_clock_get()
        .await
        .unwrap()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let operation_id = uuid::Uuid::new_v7(uuid::Timestamp::from_unix(
        uuid::NoContext,
        elapsed.as_secs(),
        elapsed.subsec_nanos(),
    ));
    let fingerprint = [0x11; 32];
    let key = ReceiptKey {
        verified_issuer: issuer.into(),
        authenticated_subject: writer.into(),
        tenant_scope_key: scope.clone(),
        operation_id,
    };
    let binding = OperationBinding {
        method: lore_server::domain::PLATFORM_METHOD_REPOSITORY_CREATE.into(),
        scope,
        fingerprint_version: 1,
        fingerprint: fingerprint.to_vec(),
        canonical_intent_digest: digest,
    };
    let PrepareResult::Prepared { token, .. } = backend
        .domain
        .domain_operation_prepare(&key, &binding, None, None)
        .await
        .unwrap()
    else {
        panic!("fresh create must prepare")
    };
    carriage::Carriage {
        operation_id,
        fingerprint,
        prepare_token: token,
    }
}
pub(super) async fn send(
    endpoint: &str,
    token: &str,
    repository: &[u8; 16],
    branch: &[u8; 16],
    prepared: &carriage::Carriage,
    v0: bool,
) -> Vec<u8> {
    send_result(endpoint, token, repository, branch, prepared, v0)
        .await
        .unwrap()
}
pub(super) async fn send_result(
    endpoint: &str,
    token: &str,
    repository: &[u8; 16],
    branch: &[u8; 16],
    prepared: &carriage::Carriage,
    v0: bool,
) -> Result<Vec<u8>, tonic::Status> {
    let request = carriage::create_request(
        token,
        repository,
        "single-rpc",
        "WP118",
        branch,
        "main",
        Some("fixture"),
        prepared,
    );
    if v0 {
        let (metadata, extensions, body) = request.into_parts();
        let request = tonic::Request::from_parts(
            metadata,
            extensions,
            lore_proto::RepositoryCreateRequest {
                id: body.id,
                name: body.name,
                description: body.description,
                default_branch_id: body.default_branch_id,
                default_branch_name: body.default_branch_name,
                creator: body.creator.unwrap(),
                created: 1_700_000_000_000,
            },
        );
        Ok(
            lore_server::legacy::rpc::repository_service_client::RepositoryServiceClient::connect(
                endpoint.to_owned(),
            )
            .await
            .unwrap()
            .repository_create(request)
            .await?
            .into_inner()
            .repository
            .unwrap()
            .metadata
            .to_vec(),
        )
    } else {
        Ok(carriage::repository_create(endpoint.to_owned(), request)
            .await?
            .repository
            .unwrap()
            .metadata
            .to_vec())
    }
}

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! FORK-LOCAL (Tideshift, D-SC2): QUIC v4 under `AuthClient`. An identity
//! token (no `resources` claim) may start a session and read once the auth
//! service answers, but a `Put` stays refused by the fork write gate, even
//! when the auth service grants `write`.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use lore_base::runtime::LORE_CONTEXT;
use lore_revision::fragment;
use lore_revision::lore::RepositoryId;
use lore_server::authnz::repository_authorizer::AuthClientAuthorizer;
use lore_server::protocol::attribute_map::AttributeMap;
use lore_server::protocol::storage::messages::MessageHandleError;
use lore_server::protocol::storage::put::Put;
use lore_server::quic::QuicService;
use lore_server::quic::storage_service_v4::ParsedStorageRequestV4;
use lore_server::quic::storage_service_v4::StorageServiceV4;
use lore_telemetry::user_agent_filter::UserAgentFilter;
use lore_transport::quic::storage_service::Command;
use rand::random;
use zerocopy::IntoBytes;

use crate::authnz::auth_client_fixture::start_stub;
use crate::authnz::auth_client_fixture::token;
use crate::authnz::auth_client_fixture::urc;
use crate::authnz::auth_client_fixture::verifier;
use crate::store::test_support::test_store_create;

async fn start_session(service: &StorageServiceV4, repository: RepositoryId, token: &str) -> u32 {
    let response = service
        .run_request_handler(
            AttributeMap::default().into(),
            ParsedStorageRequestV4::AuthorizeStart {
                repository,
                correlation_id: "corr".to_string(),
                auth_token: token.as_bytes().to_vec(),
            },
        )
        .await
        .expect("the session must start");
    u32::from_le_bytes(response[0][..4].try_into().unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_identity_token_reads_but_cannot_put() {
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");
    LORE_CONTEXT
        .scope(execution, async move {
            let repository = random::<RepositoryId>();
            let (stored, stored_address, stored_payload) = fragment::generate_random();
            immutable_store
                .clone()
                .put(
                    repository,
                    stored_address,
                    stored,
                    Some(stored_payload),
                    false,
                )
                .await
                .expect("seed the repository");
            let (url, calls) =
                start_stub(vec![(urc(repository), vec!["read", "write", "owner"])]).await;
            let service = StorageServiceV4::new(
                Arc::new(Some(verifier())),
                Arc::new(AuthClientAuthorizer::new(url)),
                immutable_store.clone(),
                immutable_store,
                mutable_store,
                true,
                Arc::new(UserAgentFilter::default()),
            );
            let session_id = start_session(&service, repository, &token(None)).await;
            assert!(
                calls.load(Ordering::SeqCst) >= 1,
                "an identity token must be answered by CheckUserPermission"
            );

            service
                .run_request_handler(
                    AttributeMap::default().into(),
                    ParsedStorageRequestV4::StorageCommand {
                        session_id,
                        opcode: Command::Get as u8,
                        payload: bytes::Bytes::copy_from_slice(stored_address.as_bytes()),
                    },
                )
                .await
                .expect("the session may read");

            let (fragment, address, payload) = fragment::generate_random();
            let put = Put {
                address,
                fragment,
                payload: Some(payload),
            };
            let err = service
                .run_request_handler(
                    AttributeMap::default().into(),
                    ParsedStorageRequestV4::StorageCommand {
                        session_id,
                        opcode: Command::Put as u8,
                        payload: put.to_bytes(),
                    },
                )
                .await
                .expect_err("a Put must be refused");
            assert!(
                matches!(&err, MessageHandleError::AuthorizationFailure(message)
                    if message.contains("write permission required for Put")),
                "{err:?}"
            );
        })
        .await;
}

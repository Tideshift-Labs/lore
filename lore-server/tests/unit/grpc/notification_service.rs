// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use lore_base::types::Context;
use lore_notification::NotificationService as _;
use lore_proto::lore::notification::SubscribeRequest;
use lore_revision::lore::RepositoryId;
use lore_server::auth::jwt::AuthorizationToken;
use lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
use lore_server::authnz::repository_authorizer::RawToken;
use lore_server::authnz::repository_authorizer::RepositoryAuthorizer;
use lore_server::authnz::repository_authorizer::VerifiedToken;
use lore_server::grpc::authorization_timeout_status;
use lore_server::grpc::notification_service::*;
use lore_transport::grpc::PARTITION_ID_KEY;
use tonic::Code;
use tonic::Request;
use tonic::Status;

/// Denies everything and records which partition it was asked about.
struct DenyingAuthorizer {
    asked: Mutex<Vec<RepositoryId>>,
}

#[async_trait]
impl RepositoryAuthorizer for DenyingAuthorizer {
    async fn check_repository_access(
        &self,
        _token: Option<&VerifiedToken<'_>>,
        repository_id: RepositoryId,
        _action: Option<&str>,
    ) -> Result<(), Status> {
        self.asked.lock().unwrap().push(repository_id);
        Err(Status::permission_denied("no grant"))
    }
}

fn repository(id: u8) -> RepositoryId {
    let mut data = [0u8; 16];
    data[15] = id;
    Context::from(data).into()
}

/// A subscribe whose *metadata* names one partition and whose *body*
/// names another: only the body value — the one the stream registers
/// on — may decide, so the check must be asked about it.
#[tokio::test]
async fn subscribe_is_decided_by_the_body_partition_not_the_metadata() {
    let authorizer = Arc::new(DenyingAuthorizer {
        asked: Mutex::new(Vec::new()),
    });
    let service = NotificationService::new(
        Arc::new(lore_server::notification::local::NotificationSender::default()),
        authorizer.clone(),
        Duration::from_secs(5),
    );

    let body_partition = repository(1);
    let metadata_partition = repository(2);
    let mut request = Request::new(SubscribeRequest {
        repository: Context::from(body_partition).into(),
    });
    request.metadata_mut().insert_bin(
        PARTITION_ID_KEY,
        tonic::metadata::BinaryMetadataValue::from_bytes(metadata_partition.data()),
    );
    request
        .extensions_mut()
        .insert(AuthorizationToken::default());
    request.extensions_mut().insert(RawToken("raw.jwt".into()));

    let denied = match service.subscribe(request).await {
        Err(status) => status,
        Ok(_) => panic!("an ungranted subscribe must be denied"),
    };

    assert_eq!(denied.code(), Code::PermissionDenied);
    assert_eq!(*authorizer.asked.lock().unwrap(), vec![body_partition]);
}

/// A stalled authorizer cannot park a subscriber: the check elapses under
/// its own bound, and answers with the authorization timeout's status
/// rather than a denial or the handler timeout's.
#[tokio::test]
async fn a_stalled_authorizer_times_out_the_subscribe_check() {
    struct StalledAuthorizer;

    #[async_trait]
    impl RepositoryAuthorizer for StalledAuthorizer {
        async fn check_repository_access(
            &self,
            _token: Option<&VerifiedToken<'_>>,
            _repository_id: RepositoryId,
            _action: Option<&str>,
        ) -> Result<(), Status> {
            std::future::pending().await
        }
    }

    let service = NotificationService::new(
        Arc::new(lore_server::notification::local::NotificationSender::default()),
        Arc::new(StalledAuthorizer),
        Duration::from_millis(50),
    );

    let mut request = Request::new(SubscribeRequest {
        repository: Context::from(repository(1)).into(),
    });
    request
        .extensions_mut()
        .insert(AuthorizationToken::default());
    request.extensions_mut().insert(RawToken("raw.jwt".into()));

    let status = match service.subscribe(request).await {
        Err(status) => status,
        Ok(_) => panic!("a stalled authorization check must not admit a subscriber"),
    };

    assert_eq!(status.code(), Code::Cancelled);
    assert_eq!(status.message(), authorization_timeout_status().message());
}

/// A no-auth configuration selects `AllowAllRepositoryAuthorizer`, under
/// which subscribe stays open.
#[tokio::test]
async fn subscribe_stays_open_under_the_allow_all_authorizer() {
    let service = NotificationService::new(
        Arc::new(lore_server::notification::local::NotificationSender::default()),
        Arc::new(AllowAllRepositoryAuthorizer),
        Duration::from_secs(5),
    );
    let request = Request::new(SubscribeRequest {
        repository: Context::from(repository(1)).into(),
    });

    service
        .subscribe(request)
        .await
        .expect("a no-auth server's subscribe is open");
}

/// FORK-LOCAL (Tideshift, CR-010): the body-repository re-check, pinned against
/// the claim-reading authorizer Lorehub cells select (`ResourceGrants` with the
/// default `urc-{id}` / `urc-*` shape; `AuthClient` answers a claim-carrying
/// token the same way). Ported from the pre-v0.10.0 `verify_authorization`
/// tests; the denial message is now the uniform `Unauthorized`.
mod fork_tests {
    use std::time::Duration;

    use bytes::Bytes;
    use lore_notification::NotificationService as _;
    use lore_proto::lore::notification::event::Event as EventPayload;
    use lore_revision::lore::BranchId;
    use lore_revision::lore::RepositoryId;
    use lore_revision::notification::NotificationSender as _;
    use lore_server::auth::jwt::AuthorizationToken;
    use lore_server::auth::jwt::ResourcePermission;
    use lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
    use lore_server::authnz::repository_authorizer::RawToken;
    use lore_server::authnz::resource_grants_authorizer::ResourceGrantsAuthorizer;
    use lore_server::notification::local::NotificationSender;
    use rand::random;
    use tokio_stream::StreamExt;
    use tonic::Code;
    use tonic::Request;

    use super::*;

    fn claim_service(sender: Arc<NotificationSender>) -> NotificationService {
        NotificationService::new(
            sender,
            Arc::new(ResourceGrantsAuthorizer::new(
                "resources".to_string(),
                "resource_id".to_string(),
                None,
                "urc-{id}".to_string(),
                "urc-*".to_string(),
            )),
            Duration::from_secs(5),
        )
    }

    fn token_with_resources(resources: Vec<ResourcePermission>) -> AuthorizationToken {
        AuthorizationToken {
            resources: Some(resources),
            ..AuthorizationToken::default()
        }
    }

    fn resource_for(repository: RepositoryId) -> ResourcePermission {
        ResourcePermission {
            resource_id: format!("urc-{repository}"),
            permission: vec![],
        }
    }

    fn wildcard_resource() -> ResourcePermission {
        ResourcePermission {
            resource_id: "urc-*".to_string(),
            permission: vec![],
        }
    }

    fn subscribe_request(
        repository: RepositoryId,
    ) -> Request<lore_proto::lore::notification::SubscribeRequest> {
        Request::new(lore_proto::lore::notification::SubscribeRequest {
            repository: Bytes::from(repository),
        })
    }

    /// Inserts both verified halves, as the interceptor does.
    fn with_token<T>(mut request: Request<T>, token: AuthorizationToken) -> Request<T> {
        request.extensions_mut().insert(token);
        request.extensions_mut().insert(RawToken("raw.jwt".into()));
        request
    }

    #[tokio::test]
    async fn subscribe_denies_body_repository_not_covered_by_token() {
        let authorized_repository = random::<RepositoryId>();
        let requested_repository = random::<RepositoryId>();

        let service = claim_service(Arc::new(NotificationSender::default()));

        let request = with_token(
            subscribe_request(requested_repository),
            token_with_resources(vec![resource_for(authorized_repository)]),
        );

        let error = service
            .subscribe(request)
            .await
            .err()
            .expect("subscribe should be denied for an unauthorized body repository");

        assert_eq!(error.code(), Code::PermissionDenied);
        assert_eq!(error.message(), "Unauthorized");
    }

    #[tokio::test]
    async fn subscribe_denies_token_with_no_granted_resources() {
        let repository = random::<RepositoryId>();

        let service = claim_service(Arc::new(NotificationSender::default()));

        let request = with_token(subscribe_request(repository), AuthorizationToken::default());

        let error = service
            .subscribe(request)
            .await
            .err()
            .expect("subscribe should be denied for a token with no granted resources");

        assert_eq!(error.code(), Code::PermissionDenied);
        assert_eq!(error.message(), "Unauthorized");
    }

    #[tokio::test]
    async fn subscribe_accepts_exact_repository_match_and_streams_events() {
        let repository = random::<RepositoryId>();

        let sender = Arc::new(NotificationSender::default());
        let service = claim_service(sender.clone());

        let request = with_token(
            subscribe_request(repository),
            token_with_resources(vec![resource_for(repository)]),
        );

        let response = service
            .subscribe(request)
            .await
            .expect("subscribe should be allowed for an exact repository match");
        let mut stream = response.into_inner();

        let branch = random::<BranchId>();
        sender.branch_created(repository, branch).await;

        let event = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("timed out waiting for the event to arrive on the stream")
            .expect("stream ended before an event was received")
            .expect("event should not be an error");

        match event.event {
            Some(EventPayload::BranchCreated(data)) => {
                assert_eq!(data.branch, Bytes::from(branch));
            }
            other => panic!("expected a BranchCreated event, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn subscribe_accepts_wildcard_token_for_any_repository() {
        let repository = random::<RepositoryId>();

        let service = claim_service(Arc::new(NotificationSender::default()));

        let request = with_token(
            subscribe_request(repository),
            token_with_resources(vec![wildcard_resource()]),
        );

        service
            .subscribe(request)
            .await
            .expect("a wildcard token should authorize any repository");
    }

    /// Auth OFF selects `AllowAllRepositoryAuthorizer` and inserts no token.
    #[tokio::test]
    async fn subscribe_unaffected_when_auth_is_off() {
        let repository = random::<RepositoryId>();

        let service = NotificationService::new(
            Arc::new(NotificationSender::default()),
            Arc::new(AllowAllRepositoryAuthorizer),
            Duration::from_secs(5),
        );

        service
            .subscribe(subscribe_request(repository))
            .await
            .expect("subscribe should succeed unchanged when auth is off");
    }

    #[tokio::test]
    async fn subscribe_rejects_zero_repository_with_token() {
        let service = claim_service(Arc::new(NotificationSender::default()));

        let request = with_token(
            subscribe_request(RepositoryId::default()),
            token_with_resources(vec![wildcard_resource()]),
        );

        let error = service
            .subscribe(request)
            .await
            .err()
            .expect("a zero repository should be rejected even with an authorizing token");

        assert_eq!(error.code(), Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn subscribe_rejects_zero_repository_without_token() {
        let service = NotificationService::new(
            Arc::new(NotificationSender::default()),
            Arc::new(AllowAllRepositoryAuthorizer),
            Duration::from_secs(5),
        );

        let error = service
            .subscribe(subscribe_request(RepositoryId::default()))
            .await
            .err()
            .expect("a zero repository should be rejected");

        assert_eq!(error.code(), Code::FailedPrecondition);
    }
}

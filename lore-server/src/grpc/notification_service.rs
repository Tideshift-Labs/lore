// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::pin::Pin;
use std::sync::Arc;

use async_trait::async_trait;
use lore_base::types::Context;
use lore_proto::lore::notification::PublishRequest;
use lore_revision::lore::RepositoryId;
use lore_telemetry::tracing::fields::REPOSITORY_ID;
use lore_telemetry::tracing::fields::USER_ID;
use tokio_stream::Stream;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::debug;
use tracing::instrument;

use crate::auth::jwt::AuthorizationToken;
use crate::auth::jwt::verify_authorization;
use crate::grpc::get_user_id;

#[derive(Clone)]
pub struct NotificationService {
    sender: Arc<crate::notification::local::NotificationSender>,
}

impl NotificationService {
    pub fn new(sender: Arc<crate::notification::local::NotificationSender>) -> Self {
        Self { sender }
    }
}

type SubscribeResponseStream =
    Pin<Box<dyn Stream<Item = Result<lore_proto::lore::notification::Event, Status>> + Send>>;

#[async_trait]
impl lore_notification::NotificationService for NotificationService {
    type SubscribeStream = SubscribeResponseStream;

    #[instrument(name = "NotificationService::Subscribe", skip_all)]
    async fn subscribe(
        &self,
        request: Request<lore_proto::lore::notification::SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let (_, extensions, subscribe_request) = request.into_parts();
        let user_id = get_user_id(&extensions);
        let repository: RepositoryId = Context::from(subscribe_request.repository).into();

        if repository.is_zero() {
            return Err(Status::failed_precondition("invalid stream"));
        }

        // The JWT interceptor authorizes the repository named in the request
        // metadata, but the subscription targets the repository named in the
        // request body — re-check the token against the body repository so a
        // token for one repository cannot stream another repository's events.
        // No token in extensions means auth is OFF (the service is registered
        // without the interceptor), where there is nothing to enforce.
        if let Some(authorization) = extensions.get::<AuthorizationToken>() {
            verify_authorization(authorization, repository).map_err(|_err| {
                Status::permission_denied("Not authorized to subscribe to this repository")
            })?;
        }

        let rx = self.sender.register(repository);

        debug!(
            { REPOSITORY_ID } = %repository,
            { USER_ID } = user_id,
            "User subscribed to notifications"
        );

        let stream = BroadcastStream::new(rx).filter_map(|res| {
            match res {
                Ok(item) => Some(Ok(item)),
                // Ignore if client is lagging behind, just drop the event
                Err(BroadcastStreamRecvError::Lagged(_)) => None,
            }
        });

        Ok(Response::new(Box::pin(stream) as Self::SubscribeStream))
    }

    async fn publish(&self, _request: Request<PublishRequest>) -> Result<Response<()>, Status> {
        Err(Status::permission_denied(
            "Publish is not supported by the local notification service",
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;
    use lore_notification::NotificationService as _;
    use lore_proto::lore::notification::event::Event as EventPayload;
    use lore_revision::lore::BranchId;
    use lore_revision::lore::RepositoryId;
    use lore_revision::notification::NotificationSender as _;
    use rand::random;
    use tokio_stream::StreamExt;
    use tonic::Code;
    use tonic::Request;

    use super::*;
    use crate::auth::jwt::ResourcePermission;
    use crate::notification::local::NotificationSender;

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

    #[tokio::test]
    async fn subscribe_denies_body_repository_not_covered_by_token() {
        let authorized_repository = random::<RepositoryId>();
        let requested_repository = random::<RepositoryId>();

        let sender = Arc::new(NotificationSender::default());
        let service = NotificationService::new(sender);

        let mut request = subscribe_request(requested_repository);
        request
            .extensions_mut()
            .insert(token_with_resources(vec![resource_for(
                authorized_repository,
            )]));

        let error = service
            .subscribe(request)
            .await
            .err()
            .expect("subscribe should be denied for an unauthorized body repository");

        assert_eq!(error.code(), Code::PermissionDenied);
        assert_eq!(
            error.message(),
            "Not authorized to subscribe to this repository"
        );
    }

    #[tokio::test]
    async fn subscribe_denies_token_with_no_granted_resources() {
        let repository = random::<RepositoryId>();

        let sender = Arc::new(NotificationSender::default());
        let service = NotificationService::new(sender);

        let mut request = subscribe_request(repository);
        request
            .extensions_mut()
            .insert(AuthorizationToken::default());

        let error = service
            .subscribe(request)
            .await
            .err()
            .expect("subscribe should be denied for a token with no granted resources");

        assert_eq!(error.code(), Code::PermissionDenied);
        assert_eq!(
            error.message(),
            "Not authorized to subscribe to this repository"
        );
    }

    #[tokio::test]
    async fn subscribe_accepts_exact_repository_match_and_streams_events() {
        let repository = random::<RepositoryId>();

        let sender = Arc::new(NotificationSender::default());
        let service = NotificationService::new(sender.clone());

        let mut request = subscribe_request(repository);
        request
            .extensions_mut()
            .insert(token_with_resources(vec![resource_for(repository)]));

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

        let sender = Arc::new(NotificationSender::default());
        let service = NotificationService::new(sender);

        let mut request = subscribe_request(repository);
        request
            .extensions_mut()
            .insert(token_with_resources(vec![wildcard_resource()]));

        service
            .subscribe(request)
            .await
            .expect("a wildcard token should authorize any repository");
    }

    #[tokio::test]
    async fn subscribe_unaffected_when_auth_is_off() {
        let repository = random::<RepositoryId>();

        let sender = Arc::new(NotificationSender::default());
        let service = NotificationService::new(sender);

        // No AuthorizationToken extension is inserted, matching the auth-OFF
        // registration path where no interceptor runs.
        let request = subscribe_request(repository);

        service
            .subscribe(request)
            .await
            .expect("subscribe should succeed unchanged when auth is off");
    }

    #[tokio::test]
    async fn subscribe_rejects_zero_repository_with_token() {
        let sender = Arc::new(NotificationSender::default());
        let service = NotificationService::new(sender);

        let mut request = subscribe_request(RepositoryId::default());
        request
            .extensions_mut()
            .insert(token_with_resources(vec![wildcard_resource()]));

        let error = service
            .subscribe(request)
            .await
            .err()
            .expect("a zero repository should be rejected even with an authorizing token");

        assert_eq!(error.code(), Code::FailedPrecondition);
    }

    #[tokio::test]
    async fn subscribe_rejects_zero_repository_without_token() {
        let sender = Arc::new(NotificationSender::default());
        let service = NotificationService::new(sender);

        let request = subscribe_request(RepositoryId::default());

        let error = service
            .subscribe(request)
            .await
            .err()
            .expect("a zero repository should be rejected");

        assert_eq!(error.code(), Code::FailedPrecondition);
    }
}

// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use async_trait::async_trait;
use lore_base::lore_spawn_net;
use lore_base::types::Hash;
use lore_error_set::prelude::*;
use lore_proto::lore::notification;
use lore_proto::lore::notification::event::Event::BranchCreated;
use lore_proto::lore::notification::event::Event::BranchDeleted;
use lore_proto::lore::notification::event::Event::BranchPushed;
use lore_proto::lore::notification::event::Event::ResourceLocked;
use lore_proto::lore::notification::event::Event::ResourceUnlocked;
use lore_proto::lore::notification::notification_service_client;
use lore_proto::lore::notification::notification_service_client::NotificationServiceClient;
use lore_revision::interface::LoreArray;
use lore_revision::interface::LoreEvent;
use lore_revision::interface::LoreString;
use lore_revision::lore::BranchId;
use lore_revision::lore::RepositoryId;
use lore_revision::lore::execution_context;
use lore_revision::lore_debug;
use lore_revision::notification::LoreNotificationBranchCreatedEventData;
use lore_revision::notification::LoreNotificationBranchDeletedEventData;
use lore_revision::notification::LoreNotificationBranchPushedEventData;
use lore_revision::notification::LoreNotificationResourceLockedEventData;
use lore_revision::notification::LoreNotificationResourceUnlockedEventData;
use lore_revision::notification::LoreNotificationSubscribedEventData;
use lore_revision::notification::LoreNotificationUnsubscribedEventData;
use lore_revision::notification::NotificationError;
use lore_revision::notification::NotificationRoute;
use lore_revision::notification::NotificationStreamClose;
use lore_revision::notification::NotificationSubscription;
use lore_revision::util;
use lore_transport::Connection;
use lore_transport::grpc;
use lore_transport::grpc::AuthzInterceptor;
use lore_transport::grpc::Channel;
use tokio_util::sync::CancellationToken;
use tonic::Streaming;
use tonic::codegen::InterceptedService;

pub(crate) struct NotificationService;

#[async_trait]
impl lore_revision::notification::NotificationService for NotificationService {
    async fn create_client(
        &self,
        remote: Arc<Connection>,
        endpoint: &str,
    ) -> Result<Arc<dyn lore_revision::notification::NotificationClient>, NotificationError> {
        Ok(Arc::new(NotificationClient::new(
            remote,
            endpoint.to_string(),
        )))
    }
}

struct NotificationClient {
    remote: Arc<Connection>,
    endpoint: String,
}

impl NotificationClient {
    fn new(remote: Arc<Connection>, endpoint: String) -> Self {
        Self { remote, endpoint }
    }
}

const RETRY_START_DURATION: u64 = 100;
const RETRY_MAX_DURATION: u64 = 1_000;
const RETRY_MAX_ATTEMPTS: usize = 10;

impl NotificationClient {
    async fn connect(
        &self,
        repository: RepositoryId,
    ) -> Result<
        NotificationServiceClient<InterceptedService<Channel, AuthzInterceptor>>,
        NotificationError,
    > {
        let mut retry_attempt = 1;
        let mut retry =
            util::time::retry(RETRY_START_DURATION, RETRY_MAX_DURATION, RETRY_MAX_ATTEMPTS);

        let endpoint = self.endpoint.as_str();

        let auth_url = self.remote.auth_url.as_str();
        // Fall back to the identity the connection authenticated as when the
        // context carries none, so authorization never has to guess one.
        let context_identity = execution_context().user_id().await;
        let identity = if context_identity.is_empty() {
            self.remote.identity().to_string()
        } else {
            context_identity
        };

        loop {
            lore_debug!(
                "Connecting to notification endpoint {endpoint}{}",
                if retry_attempt > 1 {
                    format!(" (attempt {retry_attempt})")
                } else {
                    String::default()
                }
            );
            match grpc::connect(Arc::downgrade(&self.remote), endpoint, true).await {
                Ok(connection) => {
                    let auth = connection
                        .repository_authz(
                            auth_url,
                            &identity,
                            repository,
                            self.remote.credentials(),
                        )
                        .await;
                    let client =
                        notification_service_client::NotificationServiceClient::with_interceptor(
                            connection.channel(),
                            AuthzInterceptor { repository, auth },
                        );
                    return Ok(client);
                }
                Err(err) => {
                    if !retry.wait().await {
                        return Err(err).forward_any("connecting to notification service");
                    }
                    retry_attempt += 1;
                }
            }
        }
    }

    async fn subscribe(
        &self,
        client: NotificationServiceClient<InterceptedService<Channel, AuthzInterceptor>>,
        repository: RepositoryId,
        metadata: &[(String, String)],
    ) -> Result<Streaming<notification::Event>, NotificationError> {
        let mut retry_attempt = 1;
        let mut retry =
            util::time::retry(RETRY_START_DURATION, RETRY_MAX_DURATION, RETRY_MAX_ATTEMPTS);

        loop {
            lore_debug!("Attempt {retry_attempt} to subscribe to repository stream {repository}",);
            let mut request = tonic::Request::new(notification::SubscribeRequest {
                repository: repository.into(),
            });
            // Additive only. The interceptor injects authorization, the repository
            // and the correlation id AFTER this, so a routed key can never displace
            // one of them; an unparseable key or value is dropped rather than
            // failing a subscription over a value the server may not even read.
            for (key, value) in metadata {
                match (
                    tonic::metadata::MetadataKey::from_bytes(key.as_bytes()),
                    value.parse::<tonic::metadata::MetadataValue<tonic::metadata::Ascii>>(),
                ) {
                    (Ok(key), Ok(value)) => {
                        request.metadata_mut().insert(key, value);
                    }
                    _ => lore_debug!("Dropping unrepresentable notification metadata key {key}"),
                }
            }

            let mut client = client.clone();
            let result = lore_spawn_net!(async move { client.subscribe(request).await })
                .await
                .internal("subscribing to notification stream")?;
            match result {
                Ok(response) => {
                    lore_debug!("Subscription to stream successful");
                    return Ok(response.into_inner());
                }
                Err(err) => {
                    lore_debug!("Subscription to stream failure: {err:?}");
                    if err.code() == tonic::Code::Unauthenticated {
                        return Err(err).internal("not authorized for notifications")?;
                    }
                    if !retry.wait().await {
                        return Err(NotificationError::internal("subscribing to stream"));
                    }
                    retry_attempt += 1;
                }
            }
        }
    }
}

#[async_trait]
impl lore_revision::notification::NotificationClient for NotificationClient {
    async fn subscribe_repository(
        self: Arc<Self>,
        repository: RepositoryId,
        route: NotificationRoute,
    ) -> Result<NotificationSubscription, NotificationError> {
        let client = self.connect(repository).await?;

        let stream = self
            .subscribe(client.clone(), repository, &route.metadata)
            .await?;

        let cancellation_token = CancellationToken::new();

        let stop = cancellation_token.clone();
        let client_ref = client;
        let event_sender = execution_context().dispatcher.sender();
        let task = lore_spawn_net!(async move {
            LoreEvent::NotificationSubscribed(LoreNotificationSubscribedEventData { repository })
                .send();

            let close = event_loop(repository, stream, stop.clone()).await;

            // The loop may have exited on its own, for example because the
            // stream broke. Cancel so the subscription reads as inactive.
            //
            // BEFORE the router callback, deliberately. `shutdown()` waits on this
            // task, so a router that blocks would otherwise hold the subscription
            // in a state that still reads as active, and a router that panics would
            // skip the cancel entirely and leave a dead stream reporting itself
            // alive forever. Cancelling first makes the callback unable to damage
            // the subscription's own bookkeeping, whatever it does.
            stop.cancel();

            // Whatever the server said on the way out, delivered exactly once and
            // BEFORE the unsubscribed event, so a router that stores a resume
            // position has it recorded by the time the embedder reacts to the end
            // of the stream. An empty close means the server said nothing, not that
            // it retracted something.
            if let Some(router) = lore_revision::notification::notification_router() {
                router.on_stream_close(repository, close);
            }

            LoreEvent::NotificationUnsubscribed(LoreNotificationUnsubscribedEventData {
                repository,
            })
            .send();

            drop(event_sender);
            drop(client_ref);
        });

        Ok(NotificationSubscription::new(task, cancellation_token))
    }
}

/// Drive one subscription's stream to its end, returning what the server said on
/// the way out.
///
/// Trailers reach a client two different ways and both are read here: a stream
/// that ends cleanly carries them on the response itself
/// ([`Streaming::trailers`]), while a stream the server terminates with a non-OK
/// status carries them on that [`tonic::Status`]. A server that closes every
/// stream with a status uses only the second, so reading just the first would
/// return nothing on exactly the paths that have something to say.
///
/// A cancelled subscription returns an empty close: the stream is still open, so
/// there is nothing to read, and that is not the same as the server saying
/// nothing.
async fn event_loop(
    repository: RepositoryId,
    stream: Streaming<notification::Event>,
    stop: CancellationToken,
) -> NotificationStreamClose {
    lore_debug!("Entering notification event loop for {repository}");

    let mut stream = stream;
    let mut close = NotificationStreamClose::default();
    loop {
        tokio::select! {
            _ = stop.cancelled() => break,
            message = stream.message() => {
                match message {
                    Ok(Some(event)) => {
                        lore_debug!("Processing notification event {event:?}");
                        let _ = handle_event(&event);
                    }
                    Ok(None) => {
                        lore_debug!("Notification stream closed for {repository}");
                        if let Ok(Some(map)) = stream.trailers().await {
                            close.trailers = ascii_pairs(&map);
                        }
                        break;
                    }
                    Err(status) => {
                        lore_debug!("Failed to receive notification event: {status:?}");
                        close.status_code = Some(status.code().into());
                        close.message = status.message().to_string();
                        close.trailers = ascii_pairs(status.metadata());
                        break;
                    }
                }
            }
        }
    }

    lore_debug!("Exiting notification event loop for {repository}");
    close
}

/// The status keys the transport carries in the trailer frame, which a caller must
/// never see as trailers.
///
/// A stream that ends cleanly hands back the RAW trailer map, which still contains
/// these; a stream the server terminates with a status hands back a map tonic has
/// already stripped them from. Removing them here makes the two paths deliver the
/// same shape, so a caller cannot come to depend on a key that is present only on
/// one of them. The status itself already reaches the caller as
/// `NotificationStreamClose`'s own fields.
const TRANSPORT_STATUS_KEYS: [&str; 2] = ["grpc-status", "grpc-message"];

/// The printable-ASCII entries of a metadata map, lowercase keys.
///
/// Binary (`-bin`) keys are skipped rather than decoded: their bytes are not text,
/// and handing a caller a lossy string of them invites it to be compared or logged
/// as though it were the value.
fn ascii_pairs(map: &tonic::metadata::MetadataMap) -> Vec<(String, String)> {
    map.iter()
        .filter_map(|entry| match entry {
            tonic::metadata::KeyAndValueRef::Ascii(key, value) => {
                let key = key.as_str();
                if TRANSPORT_STATUS_KEYS.contains(&key) {
                    return None;
                }
                value
                    .to_str()
                    .ok()
                    .map(|value| (key.to_string(), value.to_string()))
            }
            tonic::metadata::KeyAndValueRef::Binary(_, _) => None,
        })
        .collect()
}

fn handle_event(event: &notification::Event) -> Result<(), NotificationError> {
    match &event.event {
        Some(BranchCreated(data)) => {
            LoreEvent::NotificationBranchCreated(LoreNotificationBranchCreatedEventData {
                branch: BranchId::from(&data.branch),
            })
            .send();
        }
        Some(BranchDeleted(data)) => {
            LoreEvent::NotificationBranchDeleted(LoreNotificationBranchDeletedEventData {
                branch: BranchId::from(&data.branch),
            })
            .send();
        }
        Some(BranchPushed(data)) => {
            let revision = Hash::from(data.revision.clone());
            let branch = BranchId::from(data.branch.clone());
            LoreEvent::NotificationBranchPushed(LoreNotificationBranchPushedEventData {
                revision,
                revision_number: data.revision_number,
                branch,
                user_id: LoreString::from(&data.user_id),
            })
            .send();
        }
        Some(ResourceLocked(data)) => {
            let branch = branch_from_resources(&data.resources);
            let paths = paths_from_resources(&data.resources);
            LoreEvent::NotificationResourceLocked(LoreNotificationResourceLockedEventData {
                user_id: LoreString::from(&data.user_id),
                branch,
                paths,
            })
            .send();
        }
        Some(ResourceUnlocked(data)) => {
            let branch = branch_from_resources(&data.resources);
            let paths = paths_from_resources(&data.resources);
            LoreEvent::NotificationResourceUnlocked(LoreNotificationResourceUnlockedEventData {
                user_id: LoreString::from(&data.user_id),
                branch,
                paths,
            })
            .send();
        }
        _ => {}
    }

    Ok(())
}

fn branch_from_resources(resources: &[lore_proto::lock::Resource]) -> BranchId {
    if resources.is_empty() {
        BranchId::default()
    } else {
        BranchId::from(resources[0].branch.clone())
    }
}

fn paths_from_resources(resources: &[lore_proto::lock::Resource]) -> LoreArray<LoreString> {
    let mut paths = vec![];
    for resource in resources {
        paths.push(LoreString::from(&resource.description));
    }
    LoreArray::from_vec(paths)
}

#[cfg(test)]
mod tests {
    use tonic::metadata::MetadataMap;
    use tonic::metadata::MetadataValue;

    use super::*;

    // ── ascii_pairs: trailer exposure (A-29's `lorehub-live-resume` cursor rides
    // this path) ────────────────────────────────────────────────────────────

    #[test]
    fn ascii_pairs_is_empty_for_an_empty_map() {
        let map = MetadataMap::new();
        assert!(ascii_pairs(&map).is_empty());
    }

    #[test]
    fn ascii_pairs_surfaces_a_printable_ascii_entry() {
        let mut map = MetadataMap::new();
        map.insert(
            "lorehub-live-resume",
            MetadataValue::from_static("lhrc1.deadbeef.cell-a.1.1234.cafebabe"),
        );

        let pairs = ascii_pairs(&map);

        assert_eq!(
            pairs,
            vec![(
                "lorehub-live-resume".to_string(),
                "lhrc1.deadbeef.cell-a.1.1234.cafebabe".to_string()
            )]
        );
    }

    #[test]
    fn ascii_pairs_drops_binary_bin_suffixed_keys_rather_than_lossily_decoding_them() {
        let mut map = MetadataMap::new();
        map.insert(
            "lorehub-live-resume",
            MetadataValue::from_static("lhrc1.deadbeef.cell-a.1.1234.cafebabe"),
        );
        map.insert_bin(
            "some-trailer-bin",
            MetadataValue::from_bytes(&[0xff, 0x00, 0xfe]),
        );

        let pairs = ascii_pairs(&map);

        // Only the printable-ASCII entry survives; the binary one is dropped, not
        // decoded lossily as though its bytes were text.
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, "lorehub-live-resume");
    }

    /// A clean end of stream hands back the RAW trailer frame, which still carries
    /// the transport's own status keys; a server-terminated stream hands back a map
    /// tonic has already stripped them from. Both paths must deliver the same shape,
    /// or a caller comes to depend on a key present on only one of them.
    #[test]
    fn ascii_pairs_strips_the_transport_status_keys_so_both_close_paths_agree() {
        let mut map = MetadataMap::new();
        map.insert("grpc-status", MetadataValue::from_static("14"));
        map.insert("grpc-message", MetadataValue::from_static("lag"));
        map.insert(
            "lorehub-live-resume",
            MetadataValue::from_static("lhrc1.deadbeef.cell-a.1.1234.cafebabe"),
        );

        let pairs = ascii_pairs(&map);

        assert_eq!(
            pairs,
            vec![(
                "lorehub-live-resume".to_string(),
                "lhrc1.deadbeef.cell-a.1.1234.cafebabe".to_string()
            )],
            "the status reaches the caller as NotificationStreamClose's own fields"
        );
    }

    #[test]
    fn ascii_pairs_preserves_multiple_entries() {
        let mut map = MetadataMap::new();
        map.insert(
            "lorehub-live-resume",
            MetadataValue::from_static("cursor-1"),
        );
        map.insert("x-other-trailer", MetadataValue::from_static("value-2"));

        let mut pairs = ascii_pairs(&map);
        pairs.sort();

        assert_eq!(
            pairs,
            vec![
                ("lorehub-live-resume".to_string(), "cursor-1".to_string()),
                ("x-other-trailer".to_string(), "value-2".to_string()),
            ]
        );
    }

    // ── subscribe: additive metadata never displaces the interceptor's own keys
    // (a routed value colliding with `authorization`/`repository` must not
    // reach `request.metadata_mut()` under that name, since the interceptor
    // injects those AFTER — proven here at the level the merge itself runs:
    // an unparseable key/value is dropped, never panics, never short-circuits
    // the rest of the metadata list) ────────────────────────────────────────

    #[test]
    fn metadata_key_from_bytes_rejects_an_unrepresentable_key_without_panicking() {
        // Mirrors the `match` arm in `subscribe()`: an invalid key must be
        // droppable, not a hard error — a routed value the server doesn't
        // recognize must never fail the whole subscription attempt.
        let key = tonic::metadata::MetadataKey::<tonic::metadata::Ascii>::from_bytes(
            b"not a valid header key",
        );
        assert!(key.is_err());
    }

    #[test]
    fn metadata_value_parse_rejects_a_control_character_without_panicking() {
        // A byte string HTTP's header-value grammar actually forbids: obs-text
        // (0x80-0xFF, e.g. a UTF-8-encoded accented character) is syntactically
        // VALID opaque header-value content and parses fine, so a genuinely
        // invalid value needs a disallowed control character instead (here, a
        // bare newline — the same class of value CRLF-injection defenses reject).
        let parsed =
            "line one\nline two".parse::<tonic::metadata::MetadataValue<tonic::metadata::Ascii>>();
        assert!(parsed.is_err());
    }
}

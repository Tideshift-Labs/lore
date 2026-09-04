// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::sync::OnceLock;

use async_trait::async_trait;
use dashmap::DashMap;
use lore_base::types::LockResource;
use lore_error_set::prelude::*;
use lore_transport::Connection;
use serde::Deserialize;
use serde::Serialize;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::interface::LoreArray;
use crate::interface::LoreString;
use crate::lore::Address;
use crate::lore::BranchId;
use crate::lore::Hash;
use crate::lore::RepositoryId;
use crate::lore_debug;
use crate::repository::RepositoryContext;

#[error_set]
pub enum NotificationError {}

impl crate::event::EventError for NotificationError {}

/// Data for a notification that a branch received a new revision.
#[repr(C)]
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoreNotificationBranchPushedEventData {
    /// Hash of the pushed revision.
    pub revision: Hash,
    /// Sequence number of the pushed revision.
    pub revision_number: u64,
    /// Identifier of the branch that received the revision.
    pub branch: BranchId,
    /// Identifier of the user that pushed the revision.
    pub user_id: LoreString,
}

/// Data for a notification that a branch was created.
#[repr(C)]
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoreNotificationBranchCreatedEventData {
    /// Identifier of the created branch.
    pub branch: BranchId,
}

/// Data for a notification that a branch was deleted.
#[repr(C)]
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoreNotificationBranchDeletedEventData {
    /// Identifier of the deleted branch.
    pub branch: BranchId,
}

/// Data for a notification that resources were locked.
#[repr(C)]
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoreNotificationResourceLockedEventData {
    /// Identifier of the user that locked the resources.
    pub user_id: LoreString,
    /// Identifier of the branch the resources belong to.
    pub branch: BranchId,
    /// Paths of the locked resources.
    pub paths: LoreArray<LoreString>,
}

/// Data for a notification that resources were unlocked.
#[repr(C)]
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoreNotificationResourceUnlockedEventData {
    /// Identifier of the user that unlocked the resources.
    pub user_id: LoreString,
    /// Identifier of the branch the resources belong to.
    pub branch: BranchId,
    /// Paths of the unlocked resources.
    pub paths: LoreArray<LoreString>,
}

/// Data for a notification carrying a text message.
#[repr(C)]
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoreNotificationTextEventData {
    /// Text content of the notification.
    pub text: LoreString,
}

/// Data for a notification carrying binary content.
#[repr(C)]
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoreNotificationBinaryDataEventData {
    /// Binary content of the notification.
    pub data: LoreArray<u8>,
}

/// Data for a notification that a subscription to a repository was established.
#[repr(C)]
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoreNotificationSubscribedEventData {
    /// Identifier of the subscribed repository.
    pub repository: RepositoryId,
}

/// Data for a notification that a subscription to a repository was removed.
#[repr(C)]
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoreNotificationUnsubscribedEventData {
    /// Identifier of the unsubscribed repository.
    pub repository: RepositoryId,
}

#[async_trait]
pub trait NotificationService: Send + Sync {
    async fn create_client(
        &self,
        remote: Arc<Connection>,
        endpoint: &str,
    ) -> Result<Arc<dyn NotificationClient>, NotificationError>;
}

#[async_trait]
pub trait NotificationClient {
    async fn subscribe_repository(
        self: Arc<Self>,
        repository: RepositoryId,
        route: NotificationRoute,
    ) -> Result<NotificationSubscription, NotificationError>;
}

/// Where one repository's notification subscription connects, and what additive
/// request metadata it carries.
///
/// A repository's notification endpoint is normally derived from its own remote
/// ([`Environment::notification_url`](lore_transport::Environment::notification_url)),
/// which assumes notifications are served by the same host that stores the
/// repository. An embedder that serves them from a separate address supplies that
/// address here instead. Nothing else about the call changes: the authorization
/// exchange still runs against the repository's own auth URL, and the token is
/// still scoped to this repository.
///
/// `metadata` is ADDITIVE. It is applied on top of the metadata the authorization
/// interceptor already injects and may not replace those keys. Values travel as
/// ordinary (non-binary) gRPC metadata, so they must be printable ASCII.
#[derive(Debug, Clone, Default)]
pub struct NotificationRoute {
    /// Endpoint to dial instead of the repository-derived one. `None` keeps the
    /// derived endpoint, which is the stock behaviour.
    ///
    /// Must carry a scheme that a notification service is registered for
    /// (`lores`/`grpcs`/`https` for TLS, their unsuffixed forms for plaintext);
    /// the scheme also selects TLS, and an unregistered one fails the subscribe.
    ///
    /// ⚠️ `LORE_GRPC_PORT` overrides the port of EVERY gRPC dial, including this
    /// one. An environment that sets it to reach a TLS-terminating load balancer
    /// will silently redirect a routed endpoint to that same port, so a separately
    /// hosted notification service and that variable cannot both be used.
    pub endpoint: Option<String>,
    /// Additive request metadata sent with `Subscribe`.
    pub metadata: Vec<(String, String)>,
}

/// A host-supplied policy for notification subscriptions.
///
/// Registered process-wide, the same shape [`register_notification_service`] uses,
/// because a subscription is established deep inside a repository call that has no
/// place to thread per-call options through. Both methods have defaults, so an
/// embedder implements only the half it needs.
///
/// # Contract
///
/// Both methods are called synchronously from inside the subscription's own task,
/// on the async runtime. An implementation MUST NOT block and MUST NOT panic: it
/// runs on a runtime worker, so blocking stalls unrelated work, and it runs on a
/// task the subscription owns, so a panic aborts that task partway. Do the work a
/// lookup and a map write take, and nothing more.
pub trait NotificationRouter: Send + Sync {
    /// Where this repository's subscription connects, and what extra request
    /// metadata it carries. The default routes nothing, which is stock behaviour.
    fn route(&self, _repository: RepositoryId) -> NotificationRoute {
        NotificationRoute::default()
    }

    /// How the stream ended, delivered exactly once when it closes for any reason:
    /// a clean end, a transport error, or a server status.
    ///
    /// Trailers and the closing status are the only channels a server has to say
    /// something after it has begun streaming, and a client that reconnects needs
    /// whatever the server said on the way out.
    fn on_stream_close(&self, _repository: RepositoryId, _close: NotificationStreamClose) {}
}

/// What a notification stream said on the way out.
///
/// Both halves matter and neither substitutes for the other: a server states its
/// reason in the status while carrying resume state in the trailers, so a client
/// that read only one of them would either know where it got to without knowing
/// whether that position is still usable, or the reverse.
#[derive(Debug, Clone, Default)]
pub struct NotificationStreamClose {
    /// The numeric gRPC status code the stream ended with. `0` is a clean end of
    /// stream; `None` means nobody said, which happens on exactly one path — this
    /// process cancelled its own subscription, so the stream was never wound down
    /// far enough to carry a status.
    ///
    /// Locally synthesized transport failures also arrive here as codes, so this
    /// says what ended the stream, not necessarily what a server decided.
    ///
    /// Numeric rather than a transport enum so this crate's public surface does
    /// not commit to one gRPC library's type.
    pub status_code: Option<i32>,
    /// The status message. Servers use it as a diagnostic; it is advisory, and a
    /// client must not require it to be present or to take any particular form.
    pub message: String,
    /// The stream's TRAILING metadata, printable-ASCII pairs with lowercase keys.
    ///
    /// Binary (`-bin`) keys are skipped rather than decoded: their bytes are not
    /// text, and handing a caller a lossy string of them invites it to be compared
    /// or logged as though it were the value.
    pub trailers: Vec<(String, String)>,
}

static NOTIFICATION_ROUTER: std::sync::RwLock<Option<Arc<dyn NotificationRouter>>> =
    std::sync::RwLock::new(None);

/// Install the process-wide notification router, replacing any previous one.
pub fn set_notification_router(router: Arc<dyn NotificationRouter>) {
    let mut slot = NOTIFICATION_ROUTER
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    *slot = Some(router);
}

/// Remove the process-wide notification router, returning it if there was one.
///
/// The slot is process-global, so without this a test that installs a router
/// silently governs every later subscription in the same test binary, and a host
/// that stops routing has no way to say so. Restores stock behaviour exactly.
pub fn clear_notification_router() -> Option<Arc<dyn NotificationRouter>> {
    NOTIFICATION_ROUTER
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take()
}

/// The installed notification router, if any.
pub fn notification_router() -> Option<Arc<dyn NotificationRouter>> {
    NOTIFICATION_ROUTER
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

pub struct NotificationSubscription {
    task: JoinHandle<()>,
    cancellation_token: CancellationToken,
}

impl NotificationSubscription {
    pub fn new(task: JoinHandle<()>, cancellation_token: CancellationToken) -> Self {
        NotificationSubscription {
            task,
            cancellation_token,
        }
    }

    /// Whether the subscription is still listening for notifications.
    ///
    /// A subscription goes inactive when its client gives up on its own, for
    /// example when the network drops and reconnecting keeps failing.
    pub fn is_active(&self) -> bool {
        !self.cancellation_token.is_cancelled() && !self.task.is_finished()
    }

    /// Cancel the subscription and wait for its task to finish.
    async fn shutdown(self) {
        self.cancellation_token.cancel();
        let _ = self.task.await;
    }
}

static NOTIFICATION_SUBSCRIBERS: OnceLock<DashMap<RepositoryId, NotificationSubscription>> =
    OnceLock::new();

fn notification_subscribers() -> &'static DashMap<RepositoryId, NotificationSubscription> {
    NOTIFICATION_SUBSCRIBERS.get_or_init(DashMap::new)
}

/// Subscribe to notifications for the given repository
pub async fn subscribe(repository: Arc<RepositoryContext>) -> Result<(), NotificationError> {
    if let Some(subscriber) = notification_subscribers().get(&repository.id)
        && subscriber.is_active()
    {
        return Ok(());
    }

    // A client that bailed out leaves its entry behind. Drop it so the caller
    // can resubscribe without having to unsubscribe first.
    if let Some((_, stale)) = notification_subscribers().remove(&repository.id) {
        lore_debug!(
            "Discarding inactive notification subscription for {}",
            repository.id
        );
        stale.shutdown().await;
    }

    let Ok(remote) = repository.remote().await else {
        return Err(NotificationError::internal(
            "notifications not available when offline",
        ));
    };

    let remote_url = remote.remote_url.to_string();
    // The endpoint this repository's own remote implies. An installed router may
    // point the subscription elsewhere; when none is installed the derived value
    // stands, which is the stock behaviour.
    let derived = remote.environment.notification_url(&remote_url).to_string();
    let route = notification_router()
        .map(|router| router.route(repository.id))
        .unwrap_or_default();
    let endpoint = route.endpoint.clone().unwrap_or(derived);

    lore_debug!("Creating notification client");
    let client = create_client(remote, &endpoint).await?;

    lore_debug!(
        "Subscribe to repository notifications for {}",
        repository.id
    );
    let subscriber = client.subscribe_repository(repository.id, route).await?;
    // A concurrent subscribe may have won the race; stop its task rather than
    // detaching it by dropping the join handle.
    if let Some(previous) = notification_subscribers().insert(repository.id, subscriber) {
        previous.shutdown().await;
    }
    lore_debug!(
        "Subscribed to repository notifications for {}",
        repository.id
    );

    Ok(())
}

/// Unsubscribe from notifications for the given repository
pub async fn unsubscribe(repository: Arc<RepositoryContext>) -> Result<(), NotificationError> {
    let Some((_, subscriber)) = notification_subscribers().remove(&repository.id) else {
        return Err(NotificationError::internal(
            "notifications not available when offline",
        ));
    };

    lore_debug!("Unsubscribing notification client from {}", repository.id);

    subscriber.shutdown().await;

    lore_debug!("Unsubscribed notification client from {}", repository.id);

    Ok(())
}

async fn create_client(
    remote: Arc<Connection>,
    endpoint: &str,
) -> Result<Arc<dyn NotificationClient>, NotificationError> {
    lore_debug!("Creating notification client for endpoint: {}", endpoint);
    let service_name = endpoint.split("://").next().unwrap_or("lores");
    let Some(service) = notification_service_registry().get(service_name) else {
        return Err(NotificationError::internal(
            "notification service type not supported",
        ));
    };

    service.value().create_client(remote, endpoint).await
}

static NOTIFICATION_SERVICE: OnceLock<DashMap<String, Arc<dyn NotificationService>>> =
    OnceLock::new();

fn notification_service_registry() -> &'static DashMap<String, Arc<dyn NotificationService>> {
    NOTIFICATION_SERVICE.get_or_init(DashMap::new)
}

pub fn register_notification_service(id: &str, service: Arc<dyn NotificationService>) {
    notification_service_registry().insert(id.to_string(), service);
}

#[async_trait]
pub trait NotificationSender
where
    Self: Send + Sync,
{
    async fn branch_created(&self, repository: RepositoryId, branch: BranchId);

    async fn branch_pushed(
        &self,
        repository: RepositoryId,
        branch: BranchId,
        user_id: &str,
        revision: Hash,
        revision_number: u64,
    );

    async fn branch_deleted(&self, repository: RepositoryId, branch: BranchId);

    async fn resource_locked(
        &self,
        repository: RepositoryId,
        branch: BranchId,
        user_id: &str,
        resources: &[LockResource],
    );

    async fn resource_unlocked(
        &self,
        repository: RepositoryId,
        branch: BranchId,
        user_id: &str,
        resources: &[LockResource],
    );

    async fn obliterate(
        &self,
        repository: RepositoryId,
        address: Address,
    ) -> Result<(), NotificationError>;

    #[allow(clippy::too_many_arguments)]
    async fn compliance_check(
        &self,
        stream_name: &str,
        repository: RepositoryId,
        branch: BranchId,
        user_id: &str,
        revision: Hash,
        revision_number: u64,
        ip_addr: Option<String>,
    );
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::MutexGuard;
    use std::sync::PoisonError;

    use super::*;

    /// Installs `router` as the process-wide notification router for the life of
    /// this guard: serialized against every other guard of this type (the same
    /// static lock, taken here and held until drop) because `NOTIFICATION_ROUTER`
    /// is one process-global slot, and cleared automatically on drop — including
    /// when the test panics, so a failing assertion can never leak a router into a
    /// later test sharing this binary. Replaces a bare `#[serial]` + manual
    /// `set_notification_router` pair: those left the slot installed past a
    /// panicking assertion, since nothing ran on the unwind path.
    struct InstalledRouter {
        _lock: MutexGuard<'static, ()>,
    }

    impl InstalledRouter {
        fn new(router: Arc<dyn NotificationRouter>) -> Self {
            static LOCK: Mutex<()> = Mutex::new(());
            let lock = LOCK.lock().unwrap_or_else(PoisonError::into_inner);
            set_notification_router(router);
            Self { _lock: lock }
        }
    }

    impl Drop for InstalledRouter {
        fn drop(&mut self) {
            clear_notification_router();
        }
    }

    // ── NotificationRoute / NotificationStreamClose: defaults are the stock,
    // no-router behaviour ───────────────────────────────────────────────────

    #[test]
    fn notification_route_default_routes_nothing_and_carries_no_metadata() {
        let route = NotificationRoute::default();
        assert!(route.endpoint.is_none());
        assert!(route.metadata.is_empty());
    }

    #[test]
    fn notification_stream_close_default_carries_no_status_message_or_trailers() {
        let close = NotificationStreamClose::default();
        assert!(close.status_code.is_none());
        assert_eq!(close.message, "");
        assert!(close.trailers.is_empty());
    }

    /// A `NotificationRouter` that overrides neither method — the shape every
    /// embedder that only wants ONE half (route vs. close observation) is
    /// expected to write.
    struct NoopRouter;
    impl NotificationRouter for NoopRouter {}

    #[test]
    fn notification_router_default_route_method_is_the_stock_default() {
        let router = NoopRouter;
        let route = router.route(RepositoryId::default());
        assert!(route.endpoint.is_none());
        assert!(route.metadata.is_empty());
    }

    #[test]
    fn notification_router_default_on_stream_close_method_is_a_silent_no_op() {
        // Must not panic — the whole point of a default is that an embedder
        // implementing only `route()` can ignore stream-close entirely.
        let router = NoopRouter;
        router.on_stream_close(RepositoryId::default(), NotificationStreamClose::default());
    }

    /// A router that routes every repository to a fixed endpoint with fixed
    /// additive metadata, and records every `on_stream_close` call it receives.
    struct RecordingRouter {
        route: NotificationRoute,
        closes: Mutex<Vec<(RepositoryId, NotificationStreamClose)>>,
    }

    impl NotificationRouter for RecordingRouter {
        fn route(&self, _repository: RepositoryId) -> NotificationRoute {
            self.route.clone()
        }

        fn on_stream_close(&self, repository: RepositoryId, close: NotificationStreamClose) {
            self.closes.lock().unwrap().push((repository, close));
        }
    }

    #[test]
    fn set_notification_router_then_notification_router_returns_the_installed_router() {
        let router = Arc::new(RecordingRouter {
            route: NotificationRoute {
                endpoint: Some("grpc://gateway.example.com".to_string()),
                metadata: vec![("authorization".to_string(), "Bearer test-jwt".to_string())],
            },
            closes: Mutex::new(Vec::new()),
        });
        let _guard = InstalledRouter::new(router.clone());

        let installed = notification_router().expect("a router was just installed");
        let route = installed.route(RepositoryId::default());

        assert_eq!(
            route.endpoint.as_deref(),
            Some("grpc://gateway.example.com")
        );
        assert_eq!(
            route.metadata,
            vec![("authorization".to_string(), "Bearer test-jwt".to_string())]
        );
    }

    #[test]
    fn set_notification_router_replaces_a_previously_installed_router() {
        let first = Arc::new(RecordingRouter {
            route: NotificationRoute {
                endpoint: Some("grpc://first.example.com".to_string()),
                metadata: vec![],
            },
            closes: Mutex::new(Vec::new()),
        });
        let _first_guard = InstalledRouter::new(first);

        let second = Arc::new(RecordingRouter {
            route: NotificationRoute {
                endpoint: Some("grpc://second.example.com".to_string()),
                metadata: vec![],
            },
            closes: Mutex::new(Vec::new()),
        });
        // A second install while the first guard is still alive: this is the
        // real-world "replace" path (a fresh call to `set_notification_router`
        // over an existing installation), not a second, separately-locked guard —
        // `InstalledRouter`'s own lock would deadlock on a second acquire from the
        // same thread, which is not the shape being tested here.
        set_notification_router(second);

        let installed = notification_router().expect("a router was just installed");
        let route = installed.route(RepositoryId::default());
        assert_eq!(route.endpoint.as_deref(), Some("grpc://second.example.com"));
    }

    #[test]
    fn on_stream_close_delivers_the_full_close_shape_to_the_installed_router() {
        let router = Arc::new(RecordingRouter {
            route: NotificationRoute::default(),
            closes: Mutex::new(Vec::new()),
        });
        let _guard = InstalledRouter::new(router.clone());

        let repository = RepositoryId::default();
        let close = NotificationStreamClose {
            status_code: Some(16), // UNAUTHENTICATED
            message: "replay_truncation".to_string(),
            trailers: vec![(
                "lorehub-live-resume".to_string(),
                "lhrc1.deadbeef.cell-a.1.1234.cafebabe".to_string(),
            )],
        };

        notification_router()
            .expect("a router was just installed")
            .on_stream_close(repository, close.clone());

        let recorded = router.closes.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].0, repository);
        assert_eq!(recorded[0].1.status_code, close.status_code);
        assert_eq!(recorded[0].1.message, close.message);
        assert_eq!(recorded[0].1.trailers, close.trailers);
    }
}

// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Moved from `src/notification.rs` when the crate's lib test harness was turned off.
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;

use lore_revision::lore::RepositoryId;
use lore_revision::notification::*;

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

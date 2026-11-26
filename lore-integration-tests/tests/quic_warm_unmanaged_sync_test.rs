// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//
// D-QS3 refined: an UNMANAGED sync in a WARM process (it already used QUIC to the server through a
// relay) whose UDP path is then dropped, while TCP (gRPC) still answers, must fail closed with the
// typed `Disconnected` (ffi 28, naming the QUIC endpoint) about one quinn idle timeout plus one
// handshake after the path went dark, and must still recover when the path returns inside the
// reconnect bound.
//
// [CLIENT]-class (`lore-transport` reconnect deadline, `lore-revision` remote_connect pre-warm and
// sync readiness). Its own test binary (`[[test]] name = "quic_warm_unmanaged_sync"`) because the
// sandbox machine settings come from a constructor before `main`. It runs at the DEFAULT timeouts:
// the defect is the sum of quinn's 30 s idle timeout and the reconnect bounds (managed 60 s, then
// unmanaged 30 s), so a shortened bound would hide it.
//
// The defect (measured at 8e46e7ba): after the relay dropped UDP, a sync with a new remote
// revision ended with code 28 after 120 s (pre-warm Authorize waits quinn's 30 s idle timeout, then
// a fresh 60 s managed reconnect bound, then the sync's own read a fresh 30 s unmanaged bound), and
// a sync with nothing new ended with status 0 after 90 s (the pre-warm gave up and nothing failed
// closed). The fix counts a reconnect bound from when the path went silent, with a floor of one
// handshake attempt, and makes the sync fail closed on a pre-warm that gave up.
//
// The relay's block switch drops only UDP. gRPC is plain TCP on the same port number, so the sync
// still reaches the server over TCP and only the storage (QUIC) path is dark. Cases:
// - new_revision: warm sync with a new remote revision fails typed under 45 s.
// - nothing_new: warm sync with nothing new fails closed typed under 45 s.
// - path_returns: the path returns 8 s into the sync; the sync succeeds and has the new file.
// - stale_death: the connection died by idle timeout and more than one bound passed; a sync
//   started then gets the whole bound from now (not the 5 s floor) and recovers when the path
//   returns 8 s later.
// - cancelled_probes: the desktop drops each lore call at 15 s; back-to-back cancelled syncs must
//   still reach the typed `Disconnected` (the loss is on the connection, so the clock is not
//   restarted by each cancelled call).
//
// A hang guard wraps every await, so a regression fails red instead of hanging.
#[cfg(all(test, feature = "integration_tests"))]
#[allow(dead_code)]
mod common;
#[cfg(all(test, feature = "integration_tests"))]
mod quic_managed_write_support;

#[cfg(all(test, feature = "integration_tests"))]
pub fn setup_execution(
    user_id: String,
) -> std::sync::Arc<lore_revision::interface::ExecutionContext> {
    std::sync::Arc::new(lore_revision::interface::ExecutionContext::new_server(
        lore_revision::interface::LoreGlobalArgs::default(),
        lore_revision::relay::EventDispatcher::no_dispatch(),
        user_id,
    ))
}

#[cfg(all(test, feature = "integration_tests"))]
#[ctor::ctor]
fn sandbox_machine_settings() {
    let unique = uuid::Uuid::new_v4().simple().to_string();
    let sandbox = std::env::temp_dir().join(format!("lore-warm-sync-tests-{unique}"));
    std::fs::create_dir_all(&sandbox)
        .unwrap_or_else(|error| panic!("creating the sandbox at {}: {error}", sandbox.display()));
    unsafe {
        std::env::set_var("LORE_GLOBAL_PATH", &sandbox);
        std::env::set_var("LORE_AUTH_PATH", &sandbox);
        std::env::set_var(
            "LORE_SERVICE_SOCKET",
            format!("lore_service-warmsync-{}", &unique[..12]),
        );
    }
}

#[cfg(all(test, feature = "integration_tests"))]
mod tests {
    use std::collections::HashMap;
    use std::future::Future;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use std::time::Instant;

    use lore::branch;
    use lore::file;
    use lore::repository;
    use lore::revision;
    use lore_base::runtime::LORE_CONTEXT;
    use lore_base::test_util::TempDir;
    use lore_revision::environment::EnvironmentConfig;
    use lore_revision::interface::LoreArray;
    use lore_revision::interface::LoreEvent;
    use lore_revision::interface::LoreEventCallback;
    use lore_revision::interface::LoreGlobalArgs;
    use lore_revision::interface::LoreString;
    use lore_revision::repository::LoreSharedStoreMode;
    use lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
    use lore_server::authnz::repository_catalog::BaselineRepositoryCatalog;
    use lore_server::grpc::server::FeatureSettings;
    use lore_server::grpc::server::GrpcServerBuilder;
    use lore_server::grpc::server::GrpcTimeouts;
    use lore_server::hooks::HookDispatcher;
    use lore_server::settings::BaselineAccess;
    use lore_storage::ImmutableStore;
    use lore_storage::MutableStore;
    use uuid::Uuid;

    use crate::common::net_common::bind_matched_pair;
    use crate::quic_managed_write_support::Probe;
    use crate::quic_managed_write_support::fresh_stores;
    use crate::quic_managed_write_support::start_quic;

    const FIXTURE_TOKEN: &str = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2ZpeHR1cmUuaW52YWxpZC9pc3N1ZXIiLCJzdWIiOiJmaXh0dXJlLXVzZXIiLCJuYW1lIjoiZml4dHVyZS11c2VyIiwiZXhwIjo0MTAyNDQ0ODAwLCJhdWQiOiJmaXh0dXJlIn0.eA";

    /// The typed `Disconnected` detail every fail-closed case must carry.
    const TYPED_MESSAGE: &str = "no QUIC handshake completed in time";

    /// The fixed path: about one quinn idle timeout (30 s) plus one handshake (5 s). The defect
    /// took 90 s and 120 s.
    const FAIL_CLOSED_LIMIT: Duration = Duration::from_secs(45);

    /// Hang guards. A step that outlasts its guard is a regression, not a wait.
    const SETUP_GUARD: Duration = Duration::from_secs(120);
    const SYNC_GUARD: Duration = Duration::from_secs(150);
    const TEST_GUARD: Duration = Duration::from_secs(280);

    /// How long the recovery cases leave the path dark inside the sync.
    const DARK: Duration = Duration::from_secs(8);

    async fn guarded<T>(guard: Duration, what: &str, future: impl Future<Output = T>) -> T {
        tokio::time::timeout(guard, future)
            .await
            .unwrap_or_else(|_| panic!("{what} never ended within {guard:?}: a bound is missing"))
    }

    fn start_grpc(
        listener: std::net::TcpListener,
        stores: (Arc<dyn ImmutableStore>, Arc<dyn MutableStore>),
    ) -> tokio::sync::oneshot::Sender<()> {
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let (immutable, mutable) = stores;
        let notification_sender: Arc<dyn lore_revision::notification::NotificationSender> =
            Arc::new(lore_server::notification::local::NotificationSender::default());
        let hook_dispatcher = Arc::new(HookDispatcher::empty());
        let _server = lore_base::lore_spawn!(async move {
            let repository_catalog = Arc::new(BaselineRepositoryCatalog::new(
                BaselineAccess::Reachable,
                immutable.clone(),
                mutable.clone(),
            ));
            let _ = GrpcServerBuilder::new()
                .with_environment(EnvironmentConfig::default())
                .with_feature(FeatureSettings::default())
                .with_immutable_store(immutable.clone(), immutable, None)
                .with_mutable_store(mutable)
                .with_lock_store(None)
                .with_domain_context(None)
                .with_notification(notification_sender, None)
                .with_hook_dispatcher(hook_dispatcher)
                .with_tls_config(None, None, None)
                .expect("tls config")
                .with_admin_endpoints(HashMap::new(), vec![])
                .with_http2_config(
                    None,
                    None,
                    GrpcTimeouts {
                        request_handler: Duration::from_secs(30),
                        authorization: Duration::from_secs(30),
                    },
                    Default::default(),
                    Default::default(),
                    None,
                )
                .with_token_verification(
                    lore_server::auth::jwt::TokenVerification::Ignore,
                    false,
                    Arc::new(AllowAllRepositoryAuthorizer),
                    repository_catalog,
                )
                .expect("jwt verifier")
                .serve_with_listener(listener, async {
                    shutdown_rx.await.ok();
                })
                .await;
        });
        shutdown_tx
    }

    /// A UDP relay in front of the QUIC server. While `blocked` is set, nothing passes either way.
    fn start_relay(front: std::net::UdpSocket, upstream: SocketAddr) -> Arc<AtomicBool> {
        front.set_nonblocking(true).expect("nonblocking");
        let blocked = Arc::new(AtomicBool::new(false));
        let relay_blocked = blocked.clone();
        let _task = lore_base::lore_spawn!(async move {
            let front = Arc::new(tokio::net::UdpSocket::from_std(front).expect("front"));
            let mut peers: HashMap<SocketAddr, Arc<tokio::net::UdpSocket>> = HashMap::new();
            let mut buf = vec![0u8; 65536];
            loop {
                let Ok((n, from)) = front.recv_from(&mut buf).await else {
                    continue;
                };
                if relay_blocked.load(Ordering::Relaxed) {
                    continue;
                }
                let up = if let Some(up) = peers.get(&from) {
                    up.clone()
                } else {
                    let up = Arc::new(
                        tokio::net::UdpSocket::bind("127.0.0.1:0")
                            .await
                            .expect("upstream"),
                    );
                    up.connect(upstream).await.expect("connect upstream");
                    let back = up.clone();
                    let front = front.clone();
                    let blocked = relay_blocked.clone();
                    let _reverse = lore_base::lore_spawn!(async move {
                        let mut buf = vec![0u8; 65536];
                        while let Ok(n) = back.recv(&mut buf).await {
                            if !blocked.load(Ordering::Relaxed) {
                                let _ = front.send_to(&buf[..n], from).await;
                            }
                        }
                    });
                    peers.insert(from, up.clone());
                    up
                };
                let _ = up.send(&buf[..n]).await;
            }
        });
        blocked
    }

    fn globals(path: &std::path::Path) -> LoreGlobalArgs {
        LoreGlobalArgs {
            repository_path: path.into(),
            identity: "fixture-user".into(),
            identity_token: FIXTURE_TOKEN.into(),
            access_token: FIXTURE_TOKEN.into(),
            ..Default::default()
        }
    }

    /// The `Error` and `Complete` events of one lore call, as text.
    type Events = Arc<Mutex<Vec<String>>>;

    fn capture() -> (Events, LoreEventCallback) {
        let sink: Events = Arc::default();
        let s = sink.clone();
        let callback: LoreEventCallback = Some(Box::new(move |event: &LoreEvent| match event {
            LoreEvent::Error(data) => s
                .lock()
                .expect("events")
                .push(format!("Error: {}", data.error_inner)),
            LoreEvent::Complete(data) => s.lock().expect("events").push(format!(
                "Complete: code={} msg={}",
                data.error.error_code, data.error.message
            )),
            _ => {}
        }));
        (sink, callback)
    }

    /// One finished sync: its status, how long it took, and its events.
    struct Synced {
        status: i32,
        elapsed: Duration,
        events: Vec<String>,
    }

    impl Synced {
        /// The `Complete` event carries the typed `Disconnected` for this relay port.
        fn is_typed_disconnect(&self, port: u16) -> bool {
            self.status == 28
                && self.events.iter().any(|event| {
                    event.starts_with("Complete:")
                        && event.contains(TYPED_MESSAGE)
                        && event.contains(&port.to_string())
                })
        }
    }

    struct World {
        blocked: Arc<AtomicBool>,
        _quic: lore_server::quic::quinn::QuinnServer,
        _grpc: tokio::sync::oneshot::Sender<()>,
        source: PathBuf,
        clone: PathBuf,
        url: String,
        port: u16,
        _temp: TempDir,
    }

    impl World {
        /// A server behind the relay, a repository with one pushed revision, and a clone that
        /// already synced once through QUIC (the warm process).
        async fn start() -> Self {
            let server = crate::setup_execution("server".to_string());
            let (tcp, front, quic, quic_port, grpc) = LORE_CONTEXT
                .scope(server.clone(), async {
                    let (tcp, front) = bind_matched_pair();
                    let addr = tcp.local_addr().expect("addr");
                    let stores = fresh_stores().await;
                    let grpc = start_grpc(tcp, stores.clone());
                    for _ in 0..100 {
                        if tokio::net::TcpStream::connect(addr).await.is_ok() {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    let back = std::net::UdpSocket::bind("127.0.0.1:0").expect("back udp");
                    let quic_port = back.local_addr().expect("back addr").port();
                    let quic = start_quic(back, stores.clone(), Probe::default(), None, None);
                    (addr, front, quic, quic_port, grpc)
                })
                .await;
            let blocked = LORE_CONTEXT
                .scope(server.clone(), async {
                    start_relay(front, SocketAddr::from(([127, 0, 0, 1], quic_port)))
                })
                .await;
            let temp = TempDir::new("lore-warm-sync-");
            let source = temp.join("source");
            let clone = temp.join("clone");
            std::fs::create_dir_all(&source).expect("source dir");
            let port = tcp.port();
            let url = format!("lore://127.0.0.1:{port}/warm-sync");
            let status = repository::create(
                globals(&source),
                repository::LoreRepositoryCreateArgs {
                    repository_url: url.as_str().into(),
                    description: LoreString::default(),
                    id: LoreString::default(),
                    use_shared_store: LoreSharedStoreMode::Disabled,
                    shared_store_path: LoreString::default(),
                    vfs: Default::default(),
                },
                None,
            )
            .await;
            assert_eq!(status, 0, "repository create");
            let world = Self {
                blocked,
                _quic: quic,
                _grpc: grpc,
                source,
                clone,
                url,
                port,
                _temp: temp,
            };
            world.commit_and_push("first.txt").await;
            let status = repository::clone(
                globals(&world.clone),
                repository::LoreRepositoryCloneArgs {
                    repository_url: world.url.as_str().into(),
                    use_shared_store: LoreSharedStoreMode::Disabled,
                    ..Default::default()
                },
                None,
            )
            .await;
            assert_eq!(status, 0, "clone");
            let status = revision::sync(
                globals(&world.clone),
                revision::LoreRevisionSyncArgs::default(),
                None,
            )
            .await;
            assert_eq!(status, 0, "warm-up sync");
            world
        }

        /// Start a world with the guard every case needs.
        async fn warm() -> Self {
            guarded(SETUP_GUARD, "the world setup", Self::start()).await
        }

        async fn commit_and_push(&self, name: &str) {
            std::fs::write(
                self.source.join(name),
                format!("content of {name} {}", Uuid::new_v4()),
            )
            .expect("write");
            let status = file::stage(
                globals(&self.source),
                file::LoreFileStageArgs {
                    paths: LoreArray::from_vec(vec![LoreString::from(".")]),
                    case_change: 0,
                    scan: 1,
                },
                None,
            )
            .await;
            assert_eq!(status, 0, "stage");
            let status = revision::commit(
                globals(&self.source),
                revision::LoreRevisionCommitArgs {
                    message: format!("add {name}").as_str().into(),
                    ..Default::default()
                },
                None,
            )
            .await;
            assert_eq!(status, 0, "commit");
            // A managed push: an unmanaged push is refused with status 200.
            let status = Box::pin(branch::push_managed(
                globals(&self.source),
                branch::LoreBranchPushArgs {
                    branch: LoreString::default(),
                    fast_forward_merge: 0,
                },
                None,
                None,
            ))
            .await;
            assert_eq!(status, 0, "push");
        }

        /// The new file must reach the source's remote before the path goes dark.
        async fn push_second_revision(&self) {
            guarded(
                SETUP_GUARD,
                "pushing the second revision",
                self.commit_and_push("second.txt"),
            )
            .await;
        }

        fn block(&self) {
            self.blocked.store(true, Ordering::Relaxed);
        }

        fn unblock(&self) {
            self.blocked.store(false, Ordering::Relaxed);
        }

        /// One unmanaged sync of the clone, timed from now.
        async fn sync(&self) -> Synced {
            let (sink, callback) = capture();
            let started = Instant::now();
            let status = guarded(
                SYNC_GUARD,
                "the sync",
                revision::sync(
                    globals(&self.clone),
                    revision::LoreRevisionSyncArgs::default(),
                    callback,
                ),
            )
            .await;
            let synced = Synced {
                status,
                elapsed: started.elapsed(),
                events: sink.lock().expect("events").clone(),
            };
            // Shown with `--nocapture`, so a run's numbers are on record.
            println!(
                "sync finished: status={} elapsed={:?}",
                synced.status, synced.elapsed
            );
            synced
        }

        /// A sync while the path returns `after` the sync starts.
        async fn sync_unblocking_after(&self, after: Duration) -> Synced {
            let unblock = async {
                tokio::time::sleep(after).await;
                self.unblock();
            };
            let (synced, ()) = tokio::join!(self.sync(), unblock);
            synced
        }

        fn clone_has(&self, name: &str) -> bool {
            self.clone.join(name).is_file()
        }
    }

    fn assert_typed_disconnect(synced: &Synced, port: u16, what: &str) {
        assert!(
            synced.is_typed_disconnect(port),
            "{what}: want status 28 whose Complete message names `{TYPED_MESSAGE}` and port \
             {port}, got status {} after {:?} with events {:?}",
            synced.status,
            synced.elapsed,
            synced.events
        );
        assert!(
            synced.elapsed < FAIL_CLOSED_LIMIT,
            "{what}: took {:?}, limit {FAIL_CLOSED_LIMIT:?} (one idle timeout plus one handshake)",
            synced.elapsed
        );
    }

    fn run(case: impl Future<Output = ()>) {
        lore::runtime().block_on(async {
            guarded(TEST_GUARD, "the case", case).await;
        });
    }

    /// The remote has a revision the clone does not hold, then the path goes dark. The sync fails
    /// typed within one idle timeout plus a handshake. Defect: code 28 after 120 s.
    #[test]
    fn warm_sync_with_a_new_remote_revision_fails_typed_within_one_idle_plus_a_handshake() {
        run(async {
            let world = World::warm().await;
            world.push_second_revision().await;
            world.block();
            let synced = world.sync().await;
            assert_typed_disconnect(&synced, world.port, "new revision");
            assert!(!world.clone_has("second.txt"), "nothing arrived");

            // The give-up is for the dead connection, not for the process: once the path returns,
            // the next sync and a managed push in the same process reach storage again.
            world.unblock();
            let recovered = world.sync().await;
            assert_eq!(
                recovered.status, 0,
                "the sync after the path returned: {:?} {:?}",
                recovered.elapsed, recovered.events
            );
            assert!(
                world.clone_has("second.txt"),
                "the sync after the path returned must fetch the new revision"
            );
            assert!(
                recovered.elapsed < FAIL_CLOSED_LIMIT,
                "recovery took {:?}",
                recovered.elapsed
            );
            guarded(
                SETUP_GUARD,
                "a managed push after the path returned",
                world.commit_and_push("third.txt"),
            )
            .await;
        });
    }

    /// Nothing new on the remote, the path goes dark. The sync still fails closed typed rather than
    /// reporting success it did not verify. Defect: status 0 after 90 s.
    #[test]
    fn warm_sync_with_nothing_new_fails_closed_typed() {
        run(async {
            let world = World::warm().await;
            world.block();
            let synced = world.sync().await;
            assert_typed_disconnect(&synced, world.port, "nothing new");
        });
    }

    /// The path returns 8 s into the sync, inside the bound: the sync recovers and has the file.
    #[test]
    fn warm_sync_recovers_when_the_path_returns_within_eight_seconds() {
        run(async {
            let world = World::warm().await;
            world.push_second_revision().await;
            world.block();
            let synced = world.sync_unblocking_after(DARK).await;
            assert_eq!(
                synced.status, 0,
                "a path that returns inside the bound must not fail the sync: {:?} {:?}",
                synced.elapsed, synced.events
            );
            assert!(
                world.clone_has("second.txt"),
                "the sync reported success but the new revision's file is missing"
            );
        });
    }

    /// The connection died by idle timeout (about 30 s) and then more than one 30 s bound passed
    /// unnoticed. That death is stale: a sync started now gets the whole bound from now, not the 5 s
    /// floor, so a path that returns 8 s later still recovers.
    #[test]
    fn a_stale_death_gets_the_full_reconnect_window() {
        run(async {
            let world = World::warm().await;
            world.push_second_revision().await;
            world.block();
            // 30 s idle death, then more than one 30 s bound.
            tokio::time::sleep(Duration::from_secs(63)).await;
            let synced = world.sync_unblocking_after(DARK).await;
            assert_eq!(
                synced.status, 0,
                "a stale death must get the full window, not the floor: {:?} {:?}",
                synced.elapsed, synced.events
            );
            assert!(
                synced.elapsed >= DARK - Duration::from_secs(1),
                "cannot succeed before the path returns: {:?}",
                synced.elapsed
            );
            assert!(
                world.clone_has("second.txt"),
                "the sync reported success but the new revision's file is missing"
            );
        });
    }

    /// The desktop drops each lore call at 15 s and probes again. Each cancelled call must not
    /// restart the clock: one of the back-to-back calls reaches the typed `Disconnected` within
    /// 50 s of the block. Defect: the clock restarted each time and it never came.
    #[test]
    fn cancelled_probes_still_reach_the_typed_disconnected() {
        run(async {
            let world = World::warm().await;
            world.push_second_revision().await;
            let probe_budget = Duration::from_secs(15);
            let reach = Duration::from_secs(50);
            let cap = Duration::from_secs(100);
            world.block();
            let blocked_at = Instant::now();
            let mut calls = 0u32;
            let mut found: Option<Synced> = None;
            let mut last: Vec<String> = Vec::new();
            while blocked_at.elapsed() < cap {
                calls += 1;
                let (sink, callback) = capture();
                let started = Instant::now();
                let result = tokio::time::timeout(
                    probe_budget,
                    revision::sync(
                        globals(&world.clone),
                        revision::LoreRevisionSyncArgs::default(),
                        callback,
                    ),
                )
                .await;
                let events = sink.lock().expect("events").clone();
                if let Ok(status) = result {
                    let synced = Synced {
                        status,
                        elapsed: blocked_at.elapsed(),
                        events,
                    };
                    println!(
                        "probe call {calls} finished: status={status} since block={:?}",
                        synced.elapsed
                    );
                    if synced.is_typed_disconnect(world.port) {
                        found = Some(synced);
                        break;
                    }
                    last = vec![format!(
                        "call {calls}: status {status} after {:?}: {:?}",
                        started.elapsed(),
                        synced.events
                    )];
                }
            }
            let synced = found.unwrap_or_else(|| {
                panic!(
                    "no probe reached the typed Disconnected in {:?} ({calls} calls); last \
                     finished call: {last:?}",
                    blocked_at.elapsed()
                )
            });
            assert!(
                synced.elapsed < reach,
                "typed Disconnected reached {:?} after the block, limit {reach:?}",
                synced.elapsed
            );
        });
    }
}

// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//
// An UNMANAGED `revision::sync` (the API lorehub-desktop's lore-engine calls) against a server that
// accepts the QUIC read and then goes silent on a LIVE connection must end after about one managed
// idle bound once the process opted in with `lore_transport::quic::client::bound_unmanaged_silence()`,
// as the desktop does. Without the opt-in the sync waits for ever on the silent answer (no reconnect
// is ever triggered: the connection is healthy, the answer simply never comes).
//
// [CLIENT]-class (`lore-transport` `send_command_tracked`). Its own test binary
// (`[[test]] name = "quic_unmanaged_silence_sync"`) because the sandbox machine settings and the
// bound (`LORE_QUIC_MANAGED_IDLE_TIMEOUT`) are process-wide and come from a constructor before
// `main`, and `bound_unmanaged_silence()` is a one-way process switch.
//
// The server is the real strict `StorageServiceV4` wrapped by the shared `ProbeService`, whose hold
// withholds EVERY applied answer to one opcode (`hold_all`) for a very long grace once armed. The
// hold is armed AFTER the setup (a pushed first revision, a clone, a warm-up sync) and after a second
// revision is pushed from another clone, so only the sync under test meets the silence.
//
// A hang guard wraps the sync, so a missing bound fails red instead of hanging.
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
pub const BOUND_SECS: u64 = 4;

#[cfg(all(test, feature = "integration_tests"))]
#[ctor::ctor]
fn sandbox_machine_settings() {
    let unique = uuid::Uuid::new_v4().simple().to_string();
    let sandbox = std::env::temp_dir().join(format!("lore-silence-sync-tests-{unique}"));
    std::fs::create_dir_all(&sandbox)
        .unwrap_or_else(|error| panic!("creating the sandbox at {}: {error}", sandbox.display()));
    unsafe {
        std::env::set_var("LORE_GLOBAL_PATH", &sandbox);
        std::env::set_var("LORE_AUTH_PATH", &sandbox);
        std::env::set_var(
            "LORE_SERVICE_SOCKET",
            format!("lore_service-silencesync-{}", &unique[..12]),
        );
        std::env::set_var("LORE_QUIC_MANAGED_IDLE_TIMEOUT", BOUND_SECS.to_string());
    }
}

#[cfg(all(test, feature = "integration_tests"))]
mod tests {
    use std::collections::HashMap;
    use std::future::Future;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::Mutex;
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
    use lore_transport::quic::storage_service::Command;
    use uuid::Uuid;

    use crate::BOUND_SECS;
    use crate::common::net_common::bind_matched_pair;
    use crate::quic_managed_write_support::HoldFirstPutAnswer;
    use crate::quic_managed_write_support::Probe;
    use crate::quic_managed_write_support::fresh_stores;
    use crate::quic_managed_write_support::hold_first_answer_of;
    use crate::quic_managed_write_support::start_quic;

    const FIXTURE_TOKEN: &str = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2ZpeHR1cmUuaW52YWxpZC9pc3N1ZXIiLCJzdWIiOiJmaXh0dXJlLXVzZXIiLCJuYW1lIjoiZml4dHVyZS11c2VyIiwiZXhwIjo0MTAyNDQ0ODAwLCJhdWQiOiJmaXh0dXJlIn0.eA";

    const BOUND: Duration = Duration::from_secs(BOUND_SECS);
    /// One bound plus the connect, the readiness probes and CI jitter before the bounded read.
    const MARGIN: Duration = Duration::from_secs(6);
    /// A step that outlasts this is a missing bound, not a wait.
    const HANG_GUARD: Duration = Duration::from_secs(60);
    const SETUP_GUARD: Duration = Duration::from_secs(120);

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

    fn globals(path: &std::path::Path) -> LoreGlobalArgs {
        LoreGlobalArgs {
            repository_path: path.into(),
            identity: "fixture-user".into(),
            identity_token: FIXTURE_TOKEN.into(),
            access_token: FIXTURE_TOKEN.into(),
            ..Default::default()
        }
    }

    type Events = Arc<Mutex<Vec<String>>>;

    /// The `Error` and `Complete` events of one lore call, as text.
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

    struct World {
        probe: Probe,
        hold: HoldFirstPutAnswer,
        _quic: lore_server::quic::quinn::QuinnServer,
        _grpc: tokio::sync::oneshot::Sender<()>,
        source: PathBuf,
        clone: PathBuf,
        url: String,
        _temp: TempDir,
    }

    impl World {
        /// A strict server whose Get hold is built but NOT armed, a repository with one pushed
        /// revision, and a clone that already synced once (so it is the "already-synced client").
        async fn start() -> Self {
            let server = crate::setup_execution("server".to_string());
            let probe = Probe::default();
            let mut hold = hold_first_answer_of(Command::Get);
            hold.armed.store(false, Ordering::SeqCst);
            // Far past the hang guard: the answer never comes inside this test.
            hold.grace = Duration::from_secs(600);
            let (tcp, quic, grpc) = LORE_CONTEXT
                .scope(server.clone(), async {
                    let (tcp, udp) = bind_matched_pair();
                    let stores = fresh_stores().await;
                    let addr = tcp.local_addr().expect("addr");
                    let grpc = start_grpc(tcp, stores.clone());
                    for _ in 0..100 {
                        if tokio::net::TcpStream::connect(addr).await.is_ok() {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                    let quic = start_quic(udp, stores, probe.clone(), Some(hold.clone()), None);
                    (addr, quic, grpc)
                })
                .await;
            let temp = TempDir::new("lore-silence-sync-");
            let source = temp.join("source");
            let clone = temp.join("clone");
            std::fs::create_dir_all(&source).expect("source dir");
            let url = format!("lore://127.0.0.1:{}/silence-sync", tcp.port());
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
                probe,
                hold,
                _quic: quic,
                _grpc: grpc,
                source,
                clone,
                url,
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
            // A managed push: an unmanaged push is refused with status 200 by the strict cell.
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

        fn clone_has(&self, name: &str) -> bool {
            self.clone.join(name).is_file()
        }
    }

    /// An unmanaged sync that meets a server that takes the Get and never answers it ends with a
    /// failure at about one bound, the Get having reached the server.
    #[test]
    fn a_sync_whose_read_is_never_answered_ends_at_one_bound_once_the_process_opted_in() {
        // The desktop does this once at startup. One-way and process-wide, which is why this test
        // has its own binary.
        lore_transport::quic::client::bound_unmanaged_silence();
        assert!(lore_transport::quic::client::bounds_unmanaged_silence());

        lore::runtime().block_on(async {
            let world = guarded(SETUP_GUARD, "the world setup", World::start()).await;
            guarded(
                SETUP_GUARD,
                "pushing the second revision",
                world.commit_and_push("second.txt"),
            )
            .await;

            // Arm the hold only now: every Get the server applies from here on is answered
            // after ten minutes.
            let gets_before = world.probe.count_opcode(Command::Get);
            world.hold.hold_all.store(true, Ordering::SeqCst);

            let (sink, callback) = capture();
            let started = Instant::now();
            let status = tokio::time::timeout(
                HANG_GUARD,
                revision::sync(
                    globals(&world.clone),
                    revision::LoreRevisionSyncArgs::default(),
                    callback,
                ),
            )
            .await;
            let elapsed = started.elapsed();
            let events = sink.lock().expect("events").clone();
            let gets = world.probe.count_opcode(Command::Get) - gets_before;
            println!(
                "silent-read sync: bound={BOUND_SECS}s status={status:?} elapsed_ms={} gets={gets} \
                 events={events:?}",
                elapsed.as_millis()
            );

            let status = status.unwrap_or_else(|_| {
                panic!(
                    "the unmanaged sync never ended (hang guard {HANG_GUARD:?}): a server that \
                     takes a read and goes silent holds it for ever; gets={gets} events={events:?}"
                )
            });
            assert_eq!(
                status, 28,
                "a read the transport bound ended must reach the caller as Disconnected (ffi 28), \
                 not the stale-session retry path: {events:?}"
            );
            assert!(
                events
                    .iter()
                    .any(|event| event.starts_with("Complete: code=28")),
                "the Complete event must carry code 28: {events:?}"
            );
            assert_eq!(
                gets,
                1,
                "exactly one Get: a bound-ended read is not retried on a fresh session; wire \
                 opcodes: {:?}",
                world
                    .probe
                    .wire()
                    .iter()
                    .map(|wire| wire.opcode)
                    .collect::<Vec<_>>()
            );
            assert!(
                elapsed >= BOUND - Duration::from_millis(500),
                "gave up before the bound: {elapsed:?}"
            );
            assert!(
                elapsed < BOUND + MARGIN,
                "outlasted one bound plus {MARGIN:?}: {elapsed:?}"
            );
            assert!(
                !world.clone_has("second.txt"),
                "the file cannot have arrived without its fragment"
            );
        });
    }
}

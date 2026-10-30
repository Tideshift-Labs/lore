// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//
// WP-124: a managed push over `lore://` whose QUIC path dies must end at the managed bound with
// ffi 28 (`Disconnected`), not hang on a reconnect that has no deadline.
//
// [CLIENT]-class. Its own test binary (`[[test]] name = "quic_managed_push_hang"`) because the
// bound is the process-wide `LORE_QUIC_MANAGED_IDLE_TIMEOUT`, set from a constructor before `main`
// (the same reason and the same way as `quic_lores_tls_test.rs`).
//
// The order every case shares (the live fault the desktop met): push #1 lands over QUIC; a second
// commit is made while QUIC is still up; the QUIC server closes; a UDP socket that never reads
// takes its port (QUIC unreachable, gRPC on TCP still answering); the push under test runs.
//
// Entries:
// - `lore::branch::push_managed`, the desktop's entry (lorehub-desktop `lore-engine`, with and
//   without an observer). It has NO managed scope until each `ManagedPushRunner::run_stage`, so the
//   first await on the repository's remote runs outside any caller operation: this is what the
//   managed workflow scope (`with_managed_workflow`) bounds.
// - `lore::branch::push_with_attempt_store` inside `with_managed_caller`: an embedder that sets its
//   own managed caller. A control; it was bounded before the workflow scope existed.
//
// Where the deadline comes from. A spawn drops every managed task-local, so the reconnects in the
// repository's connect task (its session-pool pre-warm), in `Connection::session`'s session starts
// and in the push's fragment Query batches had no managed deadline. `carry_managed_wait_scope`
// carries the scope across each of those spawns (as a marker, never as a managed caller), and the
// reconnect loop bounds itself per command. Nothing caps the total time of a push: a reconnect that
// is not needed costs nothing. The connect resolves to the marker when its pre-warm expires, so a
// managed push ends after about ONE bound; if the marker were swallowed the push would reconnect
// again and take about two, which the upper limit below catches.
// Each point case here resolves the remote first, then kills QUIC, then drives `push_with_runner`
// on that context inside a managed workflow:
// - "session": the push runs under a correlation id with no pinned session pool, so
//   `Connection::session` has to start sessions on the dead connection.
// - "query": the push runs under the pre-warmed correlation id (pool pinned, the fast path), so
//   the first QUIC use is the Query of the fragments the second commit added.
// A hang guard of 40 s turns a missing bound into a failure that does not wait out the unbounded
// reconnect (about 236 s measured).
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

/// Points this binary's global config, credentials and service socket at names of its own, and
/// sets the managed bound, before `main` (single-threaded, so no reader races the writes).
#[cfg(all(test, feature = "integration_tests"))]
#[ctor::ctor]
fn sandbox_machine_settings() {
    let unique = uuid::Uuid::new_v4().simple().to_string();
    let sandbox = std::env::temp_dir().join(format!("lore-push-hang-tests-{unique}"));
    std::fs::create_dir_all(&sandbox)
        .unwrap_or_else(|error| panic!("creating the sandbox at {}: {error}", sandbox.display()));
    // Safety: constructors run before `main`.
    unsafe {
        std::env::set_var("LORE_GLOBAL_PATH", &sandbox);
        std::env::set_var("LORE_AUTH_PATH", &sandbox);
        std::env::set_var(
            "LORE_SERVICE_SOCKET",
            format!("lore_service-hang-{}", &unique[..12]),
        );
        std::env::set_var("LORE_QUIC_MANAGED_IDLE_TIMEOUT", BOUND_SECS.to_string());
    }
}

#[cfg(all(test, feature = "integration_tests"))]
mod hang {
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::Duration;
    use std::time::Instant;

    use async_trait::async_trait;
    use lore::branch;
    use lore::file;
    use lore::repository;
    use lore::revision;
    use lore_base::runtime::LORE_CONTEXT;
    use lore_base::test_util::TempDir;
    use lore_revision::branch::push::PushOptions;
    use lore_revision::environment::EnvironmentConfig;
    use lore_revision::interface::ExecutionContext;
    use lore_revision::interface::LoreArray;
    use lore_revision::interface::LoreGlobalArgs;
    use lore_revision::interface::LoreString;
    use lore_revision::managed_push::ManagedPushObserver;
    use lore_revision::managed_push::ManagedPushRunner;
    use lore_revision::repository::LoreSharedStoreMode;
    use lore_revision::repository::RepositoryAccess;
    use lore_revision::repository::RepositoryWriteToken;
    use lore_revision::repository_fence::RepositoryMutationGuard;
    use lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
    use lore_server::authnz::repository_catalog::BaselineRepositoryCatalog;
    use lore_server::grpc::server::FeatureSettings;
    use lore_server::grpc::server::GrpcServerBuilder;
    use lore_server::grpc::server::GrpcTimeouts;
    use lore_server::hooks::HookDispatcher;
    use lore_server::settings::BaselineAccess;
    use lore_storage::ImmutableStore;
    use lore_storage::MutableStore;
    use lore_transport::ProtocolError;
    use lore_transport::attempt_store::AttemptStore;
    use uuid::Uuid;

    use crate::BOUND_SECS;
    use crate::common::net_common::bind_matched_pair;
    use crate::quic_managed_write_support::Cell;
    use crate::quic_managed_write_support::CountingJournal;
    use crate::quic_managed_write_support::Probe;
    use crate::quic_managed_write_support::fresh_stores;
    use crate::quic_managed_write_support::rebind_udp;
    use crate::quic_managed_write_support::start_quic;

    const FFI_DISCONNECTED: i32 = 28;
    const BOUND: Duration = Duration::from_secs(BOUND_SECS);
    /// Longer than any correct expiry, much shorter than the unbounded reconnect.
    const HANG_GUARD: Duration = Duration::from_secs(40);
    /// What a push adds to the bound: the dead-path steps before and after the one bounded wait.
    /// Under a second bound, so a swallowed marker (a second reconnect) fails the upper limit.
    const MARGIN: Duration = Duration::from_secs(3);
    /// A syntactic JWT (the server runs auth off and does not verify it), as the desktop's
    /// external-credential mode supplies, so the managed journal can bind a namespace.
    const FIXTURE_TOKEN: &str = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2ZpeHR1cmUuaW52YWxpZC9pc3N1ZXIiLCJzdWIiOiJmaXh0dXJlLXVzZXIiLCJuYW1lIjoiZml4dHVyZS11c2VyIiwiZXhwIjo0MTAyNDQ0ODAwLCJhdWQiOiJmaXh0dXJlIn0.eA";

    /// The gRPC leg a `lore://` URL resolves through: a baseline server that lets the repository
    /// be created and pushed to.
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
                .with_immutable_store(immutable.clone(), immutable)
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
                .with_jwt_verifier(
                    None,
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

    /// A loopback cell with the baseline gRPC leg and a probed QUIC server on the matched port.
    async fn baseline_cell() -> Cell {
        let (tcp, udp) = bind_matched_pair();
        let addr = tcp.local_addr().expect("local addr");
        let stores = fresh_stores().await;
        let grpc = start_grpc(tcp, stores.clone());
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let probe = Probe::default();
        let quic = start_quic(udp, stores.clone(), probe.clone(), None, None);
        Cell {
            port: addr.port(),
            probe,
            stores,
            quic: Some(quic),
            _grpc: grpc,
        }
    }
    /// A live loopback cell with a repository that has pushed once over QUIC and holds a second,
    /// unpushed commit.
    struct Live {
        cell: Cell,
        source: PathBuf,
        globals: LoreGlobalArgs,
        server: Arc<ExecutionContext>,
        _temp: TempDir,
    }

    impl Live {
        async fn start() -> Self {
            let server = crate::setup_execution("server".to_string());
            let cell = LORE_CONTEXT.scope(server.clone(), baseline_cell()).await;
            let port = cell.port;

            let temp = TempDir::new("lore-push-hang-");
            let source = temp.join("source");
            std::fs::create_dir_all(&source).expect("creating the source directory");
            let globals = LoreGlobalArgs {
                repository_path: source.as_path().into(),
                identity: "fixture-user".into(),
                identity_token: FIXTURE_TOKEN.into(),
                access_token: FIXTURE_TOKEN.into(),
                ..Default::default()
            };
            let url = format!("lore://127.0.0.1:{port}/push-hang");
            let status = repository::create(
                globals.clone(),
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

            let live = Self {
                cell,
                source,
                globals,
                server,
                _temp: temp,
            };
            live.stage_and_commit("first.txt").await;
            let first = Box::pin(branch::push_managed(
                live.globals.clone(),
                push_args(),
                None,
                None,
            ))
            .await;
            assert_eq!(first, 0, "push #1 must land over QUIC");
            assert!(
                live.cell
                    .probe
                    .count_opcode(lore_transport::quic::storage_service::Command::Put)
                    >= 1,
                "push #1 must have used the QUIC storage path: {:?}",
                live.cell.probe.wire()
            );
            // The second commit is made while QUIC is up, so the push under test is the first
            // operation to meet the dead path (the desktop commits before it pushes).
            live.stage_and_commit("second.txt").await;
            live
        }

        async fn stage_and_commit(&self, name: &str) {
            std::fs::write(
                self.source.join(name),
                format!("content of {name} {}", Uuid::new_v4()),
            )
            .expect("writing the fixture file");
            let status = file::stage(
                self.globals.clone(),
                file::LoreFileStageArgs {
                    paths: LoreArray::from_vec(vec![LoreString::from(".")]),
                    case_change: 0,
                    scan: 1,
                },
                None,
            )
            .await;
            assert_eq!(status, 0, "stage {name}");
            let status = revision::commit(
                self.globals.clone(),
                revision::LoreRevisionCommitArgs {
                    message: format!("add {name}").as_str().into(),
                    link: Default::default(),
                    link_paths: Default::default(),
                    layer: Default::default(),
                    layer_paths: Default::default(),
                    link_messages: Default::default(),
                    layer_messages: Default::default(),
                },
                None,
            )
            .await;
            assert_eq!(status, 0, "commit {name}");
        }

        /// Close the QUIC server, then take its UDP port with a socket that never reads. The
        /// returned socket keeps the black hole open.
        async fn kill_quic(&mut self) -> std::net::UdpSocket {
            let port = self.cell.port;
            let quic = self.cell.quic.take().expect("the QUIC server is up");
            let black_hole = LORE_CONTEXT
                .scope(self.server.clone(), async move {
                    quic.close().await;
                    drop(quic);
                    rebind_udp(port).await
                })
                .await;
            tokio::time::sleep(Duration::from_millis(500)).await;
            black_hole
        }

        /// Client globals naming a correlation id, as one command's execution context carries.
        fn execution(&self, correlation_id: &str) -> Arc<ExecutionContext> {
            let globals = LoreGlobalArgs {
                correlation_id: correlation_id.into(),
                ..self.globals.clone()
            };
            Arc::new(ExecutionContext::new_client_with_user_id(
                globals,
                lore_revision::relay::EventDispatcher::no_dispatch(),
                "fixture-user".to_string(),
            ))
        }
    }

    fn push_args() -> branch::LoreBranchPushArgs {
        branch::LoreBranchPushArgs {
            branch: LoreString::default(),
            fast_forward_merge: 0,
        }
    }

    /// An observer that adds nothing: the stage journals into the shared store.
    struct PassThroughObserver;

    #[async_trait]
    impl ManagedPushObserver for PassThroughObserver {
        async fn begin_stage(
            &self,
            _parent: Uuid,
            _repository: lore_base::types::RepositoryId,
            shared: Arc<lore_revision::attempt_store::RepositoryAttemptStore>,
            _label: &str,
        ) -> Result<Arc<dyn AttemptStore>, ProtocolError> {
            Ok(shared)
        }
        async fn complete_stage_body(
            &self,
            _parent: Uuid,
            _status: i32,
        ) -> Result<(), ProtocolError> {
            Ok(())
        }
        async fn finish_stage(&self, _parent: Uuid) -> Result<(), ProtocolError> {
            Ok(())
        }
    }

    enum Entry {
        /// `push_managed(.., None)`
        Managed,
        /// `push_managed(.., Some(observer))`
        ManagedObserved,
        /// `push_with_attempt_store` inside `with_managed_caller`
        EmbedderManagedCaller,
    }

    /// Run the whole live order for `entry` and return (status, elapsed) of the second push.
    async fn push_after_quic_dies(entry: Entry) -> (Option<i32>, Duration) {
        let mut live = Live::start().await;
        let _black_hole = live.kill_quic().await;

        let globals = live.globals.clone();
        let started = Instant::now();
        let status = match entry {
            Entry::Managed => {
                tokio::time::timeout(
                    HANG_GUARD,
                    Box::pin(branch::push_managed(globals, push_args(), None, None)),
                )
                .await
            }
            Entry::ManagedObserved => {
                let observer: Arc<dyn ManagedPushObserver> = Arc::new(PassThroughObserver);
                tokio::time::timeout(
                    HANG_GUARD,
                    Box::pin(branch::push_managed(
                        globals,
                        push_args(),
                        None,
                        Some(observer),
                    )),
                )
                .await
            }
            Entry::EmbedderManagedCaller => {
                let attempts: Arc<dyn AttemptStore> = Arc::new(CountingJournal::default());
                tokio::time::timeout(
                    HANG_GUARD,
                    lore_transport::caller_operation::with_managed_caller(
                        Uuid::new_v4(),
                        attempts.clone(),
                        Box::pin(branch::push_with_attempt_store(
                            globals,
                            push_args(),
                            None,
                            attempts,
                        )),
                    ),
                )
                .await
            }
        };
        (status.ok(), started.elapsed())
    }

    fn assert_ended_at_the_bound(status: Option<i32>, elapsed: Duration) {
        let status = status.unwrap_or_else(|| {
            panic!("the managed push never ended (hang guard after {elapsed:?}): its wait on a dead QUIC path has no deadline")
        });
        assert_eq!(
            status, FFI_DISCONNECTED,
            "expected Disconnected (28), not Internal (-1)"
        );
        assert!(
            elapsed >= BOUND - Duration::from_millis(500),
            "gave up before the bound: {elapsed:?}"
        );
        assert!(elapsed < BOUND + MARGIN, "outlasted the bound: {elapsed:?}");
    }

    /// The defect: the desktop's entry has no managed scope until its first stage, so the wait on
    /// the repository's remote (a connect whose pre-warm reconnects with no deadline) ran for
    /// minutes.
    #[test]
    fn push_managed_after_the_quic_path_dies_ends_disconnected_at_the_bound() {
        let (status, elapsed) = lore::runtime().block_on(push_after_quic_dies(Entry::Managed));
        assert_ended_at_the_bound(status, elapsed);
    }

    /// The same entry with an observer, as the desktop passes one.
    #[test]
    fn push_managed_with_an_observer_after_the_quic_path_dies_ends_disconnected_at_the_bound() {
        let (status, elapsed) =
            lore::runtime().block_on(push_after_quic_dies(Entry::ManagedObserved));
        assert_ended_at_the_bound(status, elapsed);
    }

    /// Control: an embedder that sets its own managed caller was bounded before the workflow scope.
    #[test]
    fn push_with_attempt_store_in_a_managed_caller_after_the_quic_path_dies_ends_disconnected_at_the_bound()
     {
        let (status, elapsed) =
            lore::runtime().block_on(push_after_quic_dies(Entry::EmbedderManagedCaller));
        assert_ended_at_the_bound(status, elapsed);
    }

    /// Resolve the remote under one correlation id, kill QUIC, then run `push_with_runner` on that
    /// context under `push_correlation_id`, inside a managed workflow.
    async fn point_bound_push(push_correlation_id: &str) -> (Option<i32>, Duration) {
        const WARM: &str = "warm-correlation";
        let mut live = Live::start().await;
        let path = live.source.clone();

        // The connect resolves, and its pre-warm pins a session pool under `WARM`.
        let (context, token) = LORE_CONTEXT
            .scope(live.execution(WARM), async {
                let token = RepositoryWriteToken::acquire(path.as_path()).await;
                let context = lore_revision::repository::load_and_connect_with_token(
                    path.as_path(),
                    RepositoryAccess::ReadWrite,
                    Some(token.share()),
                )
                .await
                .expect("opening the repository");
                context
                    .remote()
                    .await
                    .expect("the remote connects over QUIC");
                (context, token)
            })
            .await;
        let _black_hole = live.kill_quic().await;

        let fence = Arc::new(
            RepositoryMutationGuard::acquire(path.as_path())
                .await
                .expect("the repository fence"),
        );
        let runner = Arc::new(ManagedPushRunner::new(fence, None));
        let started = Instant::now();
        let result = tokio::time::timeout(
            HANG_GUARD,
            LORE_CONTEXT.scope(
                live.execution(push_correlation_id),
                lore_transport::with_managed_workflow(Box::pin(
                    lore_revision::branch::push::push_with_runner(
                        context.clone(),
                        &token,
                        PushOptions::default(),
                        None,
                        Some(runner),
                    ),
                )),
            ),
        )
        .await;
        let elapsed = started.elapsed();
        let status = result.ok().map(|result| match result {
            Ok(()) => 0,
            Err(error) => lore::error_set::FfiError::ffi_code(&error),
        });
        drop(context);
        (status, elapsed)
    }

    /// `Connection::session` starts its sessions in spawned tasks. With no pool pinned under this
    /// correlation id, it has to start them on the dead connection, outside the managed scope.
    #[test]
    fn a_session_start_on_a_dead_quic_path_ends_disconnected_at_the_bound() {
        let (status, elapsed) =
            lore::runtime().block_on(point_bound_push("a-correlation-id-with-no-pinned-pool"));
        assert_ended_at_the_bound(status, elapsed);
    }

    /// With the pre-warmed pool pinned, the first QUIC use is the Query of the fragments the
    /// second commit added; its batches run in spawned tasks.
    #[test]
    fn a_fragment_query_on_a_dead_quic_path_ends_disconnected_at_the_bound() {
        let (status, elapsed) = lore::runtime().block_on(point_bound_push("warm-correlation"));
        assert_ended_at_the_bound(status, elapsed);
    }
}

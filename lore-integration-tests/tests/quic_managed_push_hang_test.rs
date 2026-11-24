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
//
// The unmanaged cases (no managed scope anywhere) pin the other half of the fix: the repository's
// connect always runs its session-pool pre-warm in a managed workflow, so an unmanaged open or a
// local commit after QUIC died waits about one bound for the pre-warm and ignores its error
// instead of waiting out the whole reconnect loop.
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

    /// A loopback cell with the baseline gRPC leg and a probed QUIC server on the matched port.
    async fn baseline_cell(
        hold: Option<crate::quic_managed_write_support::HoldFirstPutAnswer>,
    ) -> Cell {
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
        let quic = start_quic(udp, stores.clone(), probe.clone(), hold, None);
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
            Self::start_with_hold(None).await
        }

        /// [`Self::start`] on a cell whose QUIC server can withhold one applied `Put` answer. The
        /// caller arms the hold (`armed`) once the fixture has finished pushing.
        async fn start_with_hold(
            hold: Option<crate::quic_managed_write_support::HoldFirstPutAnswer>,
        ) -> Self {
            let server = crate::setup_execution("server".to_string());
            let cell = LORE_CONTEXT
                .scope(server.clone(), baseline_cell(hold))
                .await;
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
                    refuse_locked_by_others: 0,
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

    /// Unmanaged: opening the repository after QUIC died. The connect's pre-warm reconnects on a
    /// dead path; it must end at the managed bound and be ignored, so `remote()` resolves Ok.
    /// Before the fix this waited the whole reconnect loop (about 236 s).
    #[test]
    fn an_unmanaged_remote_after_the_quic_path_dies_resolves_ok_within_the_bound() {
        let (result, elapsed) = lore::runtime().block_on(async {
            let mut live = Live::start().await;
            let path = live.source.clone();
            let _black_hole = live.kill_quic().await;

            let started = Instant::now();
            let result = tokio::time::timeout(
                HANG_GUARD,
                LORE_CONTEXT.scope(live.execution("unmanaged-open"), async {
                    let token = RepositoryWriteToken::acquire(path.as_path()).await;
                    let context = lore_revision::repository::load_and_connect_with_token(
                        path.as_path(),
                        RepositoryAccess::ReadWrite,
                        Some(token.share()),
                    )
                    .await
                    .expect("opening the repository");
                    assert!(!lore_transport::in_managed_wait_scope());
                    let remote = context.remote().await.map(|_| ());
                    drop(context);
                    drop(token);
                    remote
                }),
            )
            .await;
            (result, started.elapsed())
        });
        eprintln!("unmanaged remote() after kill_quic resolved in {elapsed:?}");
        let remote = result.unwrap_or_else(|_| {
            panic!("an unmanaged remote() never returned (hang guard, {elapsed:?}): the pre-warm has no deadline")
        });
        assert!(
            remote.is_ok(),
            "an unmanaged caller ignores every pre-warm error: {remote:?}"
        );
        assert!(elapsed < BOUND + MARGIN, "outlasted the bound: {elapsed:?}");
    }

    /// Unmanaged: a local stage of a new file and a commit through the public API after QUIC
    /// died. Each command opens the repository and awaits the remote, so each is held by the
    /// bounded pre-warm. Each must succeed (status 0) within the bound plus margin.
    #[test]
    fn an_unmanaged_stage_and_commit_after_the_quic_path_dies_succeed_within_the_bound() {
        let (stage, commit) = lore::runtime().block_on(async {
            let mut live = Live::start().await;
            let _black_hole = live.kill_quic().await;
            std::fs::write(live.source.join("after-quic-death.txt"), "unmanaged edit")
                .expect("writing the fixture file");

            let started = Instant::now();
            let staged = tokio::time::timeout(
                HANG_GUARD,
                file::stage(
                    live.globals.clone(),
                    file::LoreFileStageArgs {
                        paths: LoreArray::from_vec(vec![LoreString::from(".")]),
                        case_change: 0,
                        scan: 1,
                    },
                    None,
                ),
            )
            .await;
            let stage = (staged, started.elapsed());

            let started = Instant::now();
            let committed = tokio::time::timeout(
                HANG_GUARD,
                revision::commit(
                    live.globals.clone(),
                    revision::LoreRevisionCommitArgs {
                        message: "after quic death".into(),
                        link: Default::default(),
                        link_paths: Default::default(),
                        layer: Default::default(),
                        layer_paths: Default::default(),
                        link_messages: Default::default(),
                        layer_messages: Default::default(),
                        refuse_locked_by_others: 0,
                    },
                    None,
                ),
            )
            .await;
            (stage, (committed, started.elapsed()))
        });
        eprintln!(
            "unmanaged stage took {:?}, commit took {:?}",
            stage.1, commit.1
        );
        assert_eq!(stage.0.ok(), Some(0), "stage ({:?})", stage.1);
        assert_eq!(commit.0.ok(), Some(0), "commit ({:?})", commit.1);
        assert!(
            stage.1 < BOUND + MARGIN,
            "stage outlasted the bound: {:?}",
            stage.1
        );
        // Two bounds: the open's pre-warm ends at one, then the commit's first best-effort upload
        // ends at its own; the session latch then stops a third for later fragments.
        assert!(
            commit.1 < BOUND * 2 + MARGIN,
            "commit outlasted two bounds: {:?}",
            commit.1
        );
    }

    // -----------------------------------------------------------------------------------------
    // WP-124 K10: a commit's uploads as declared, best-effort writes
    // (`lore::revision::commit_with_managed_uploads`, `lore_revision::managed_commit_uploads`,
    // `lore_storage::managed_uploads::ManagedUploads`).
    //
    // 1. A strict cell accepts a managed commit's uploads, they are durable (the push after it
    //    uploads nothing), and the stock commit on the same cell is the refused control.
    // 2. A dead QUIC path costs the managed commit ONE bound, in both orders: the pre-warm expires
    //    (the flag path), or the pre-warm succeeds and the path dies before the first upload (the
    //    latch path). The fragments stay local and the next push uploads them once the path is
    //    back.
    // 3. A peer that applies a commit upload and never answers: one dispatch, no resend, the
    //    commit's fragment stays local.
    // -----------------------------------------------------------------------------------------
    mod k10 {
        use std::sync::Mutex as StdMutex;

        use lore_revision::commit::CommitOptions;
        use lore_revision::managed_commit_uploads;
        use lore_storage::fragment_flags::FragmentFlags;
        use lore_storage::managed_uploads::ManagedUploads;
        use lore_storage::write::store_fragment;
        use lore_storage::write_tracker::WriteContext;
        use lore_transport::quic::storage_service::Command;

        use super::*;
        use crate::quic_managed_write_support::ACTION_START_DECLARED;
        use crate::quic_managed_write_support::RESEND_SETTLE;
        use crate::quic_managed_write_support::connect;
        use crate::quic_managed_write_support::eventually;
        use crate::quic_managed_write_support::hold_first_put_answer;
        use crate::quic_managed_write_support::in_context;
        use crate::quic_managed_write_support::lose_answer_and_restart;
        use crate::quic_managed_write_support::start_quic;

        /// What one dead-path command may cost over the bound: 1.5 x the bound in all.
        const ONE_BOUND_LIMIT: Duration = Duration::from_millis(BOUND_SECS * 1500);

        // --- the server's own refusal count -------------------------------------------------

        /// `(execution context key, refusals)`: the strict refusals a cell answered.
        static REFUSALS: StdMutex<Vec<(usize, usize)>> = StdMutex::new(Vec::new());

        fn context_key(context: &Arc<dyn std::any::Any + Send + Sync>) -> usize {
            Arc::as_ptr(context).cast::<()>() as usize
        }

        struct LabelVisitor(bool);

        impl tracing::field::Visit for LabelVisitor {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                if field.name() == "handler_error_label"
                    && format!("{value:?}").contains("UnsupportedClient")
                {
                    self.0 = true;
                }
            }

            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                if field.name() == "handler_error_label" && value.contains("UnsupportedClient") {
                    self.0 = true;
                }
            }
        }

        fn count_refusal(event: &tracing::Event<'_>) {
            let mut visitor = LabelVisitor(false);
            event.record(&mut visitor);
            if !visitor.0 {
                return;
            }
            let Ok(key) = LORE_CONTEXT.try_with(context_key) else {
                return;
            };
            if let Ok(mut entries) = REFUSALS.lock()
                && let Some((_, count)) = entries.iter_mut().find(|(entry, _)| *entry == key)
            {
                *count += 1;
            }
        }

        /// Count the refusals of the cell whose server tasks run under `server`. The server's
        /// stream handler runs on the net runtime's threads, so this counts through the binary's
        /// one process-global subscriber, attributing each event by its task's execution context.
        fn count_refusals_for(server: &Arc<ExecutionContext>) -> usize {
            assert!(
                crate::common::tracing_common::add_event_tap(count_refusal),
                "another global tracing subscriber is installed; cannot count refusals"
            );
            let context: Arc<dyn std::any::Any + Send + Sync> = server.clone();
            let key = context_key(&context);
            REFUSALS.lock().expect("refusal registry").push((key, 0));
            key
        }

        fn refusals_for(key: usize) -> usize {
            REFUSALS
                .lock()
                .expect("refusal registry")
                .iter()
                .find(|(entry, _)| *entry == key)
                .map_or(0, |(_, count)| *count)
        }

        // --- fixtures ----------------------------------------------------------------------

        fn commit_args(message: &str) -> revision::LoreRevisionCommitArgs {
            revision::LoreRevisionCommitArgs {
                message: message.into(),
                link: Default::default(),
                link_paths: Default::default(),
                layer: Default::default(),
                layer_paths: Default::default(),
                link_messages: Default::default(),
                layer_messages: Default::default(),
                refuse_locked_by_others: 0,
            }
        }

        fn puts(live: &Live) -> usize {
            live.cell.probe.count_opcode(Command::Put)
        }

        impl Live {
            /// Write a new file and stage it, leaving the commit to the caller.
            async fn stage_file(&self, name: &str) {
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
            }

            /// A managed push of everything not yet on the server.
            async fn push(&self) -> i32 {
                tokio::time::timeout(
                    HANG_GUARD,
                    Box::pin(branch::push_managed(
                        self.globals.clone(),
                        push_args(),
                        None,
                        None,
                    )),
                )
                .await
                .expect("the push must end")
            }

            /// `commit_with_managed_uploads` of the staged files, with a hang guard. Returns the
            /// status and the time it took.
            async fn managed_commit(&self, message: &str) -> (i32, Duration) {
                self.managed_commit_as(self.globals.clone(), message).await
            }

            /// [`Self::managed_commit`] with these globals.
            async fn managed_commit_as(
                &self,
                globals: LoreGlobalArgs,
                message: &str,
            ) -> (i32, Duration) {
                let started = Instant::now();
                let status = tokio::time::timeout(
                    HANG_GUARD,
                    Box::pin(revision::commit_with_managed_uploads(
                        globals,
                        commit_args(message),
                        None,
                    )),
                )
                .await
                .unwrap_or_else(|_| {
                    panic!(
                        "the managed commit never ended (hang guard): {:?}",
                        started.elapsed()
                    )
                });
                (status, started.elapsed())
            }

            /// Bring a QUIC server back on the black-holed port, over the same stores.
            async fn restore_quic(&mut self, black_hole: std::net::UdpSocket) {
                drop(black_hole);
                let port = self.cell.port;
                let stores = self.cell.stores.clone();
                let probe = self.cell.probe.clone();
                let quic = LORE_CONTEXT
                    .scope(self.server.clone(), async move {
                        let udp = rebind_udp(port).await;
                        start_quic(udp, stores, probe, None, None)
                    })
                    .await;
                self.cell.quic = Some(quic);
            }
        }

        // --- 1. a strict cell ---------------------------------------------------------------

        /// A managed commit's uploads are accepted by a strict (`require_outcome_unknown_v1`) cell:
        /// no unsupported-client refusal, accepted Puts, declared sessions that end with the command.
        /// They are durable: the push after it uploads nothing. The stock commit on the same cell is
        /// the control: refused, local, and the push after it does the uploading.
        #[test]
        fn a_managed_commit_is_accepted_by_a_strict_cell_and_the_push_after_it_uploads_nothing() {
            lore::runtime().block_on(async {
                let live = Live::start().await;
                let key = count_refusals_for(&live.server);
                // Drain the unmanaged commit `start` left behind, so what follows is measured alone.
                assert_eq!(live.push().await, 0, "draining push");

                // The managed commit.
                live.stage_file("managed.txt").await;
                let (puts_before, refusals_before) = (puts(&live), refusals_for(key));
                let keys_before = live.cell.probe.put_keys().len();
                let declared_before = live.cell.probe.count_action(ACTION_START_DECLARED);
                let (status, elapsed) = live.managed_commit("managed commit").await;
                assert_eq!(status, 0, "the managed commit succeeds ({elapsed:?})");
                let accepted = puts(&live) - puts_before;
                eprintln!("managed commit: {accepted} Puts in {elapsed:?}");
                assert!(accepted > 0, "the commit's uploads reached the strict cell");
                let keys = live.cell.probe.put_keys().split_off(keys_before);
                assert_eq!(keys.len(), accepted, "one key per Put the commit sent");
                let distinct: std::collections::HashSet<_> = keys.iter().collect();
                assert_eq!(
                    distinct.len(),
                    keys.len(),
                    "positive control: the Put key tells fragments apart (no fragment is sent twice)"
                );
                assert_eq!(
                    refusals_for(key),
                    refusals_before,
                    "the strict cell refused none of the managed uploads: {:?}",
                    live.cell.probe.wire()
                );
                assert!(
                    live.cell.probe.count_action(ACTION_START_DECLARED) > declared_before,
                    "the uploads ran on a declared session"
                );
                eventually("the commit's declared sessions to be stopped", || {
                    live.cell.probe.declared_live() == 0
                })
                .await;

                // Durable: nothing is left for the push to upload.
                let before_push = puts(&live);
                assert_eq!(live.push().await, 0, "push after the managed commit");
                assert_eq!(
                    puts(&live),
                    before_push,
                    "the managed commit's fragments were already durable: {:?}",
                    live.cell.probe.wire()
                );

                // Control: the stock commit on the same cell is refused and leaves fragments local.
                live.stage_file("control.txt").await;
                let refusals_before = refusals_for(key);
                let status = revision::commit(
                    live.globals.clone(),
                    commit_args("stock commit"),
                    None,
                )
                .await;
                assert_eq!(status, 0, "the stock commit still succeeds");
                assert!(
                    refusals_for(key) > refusals_before,
                    "the stock commit's uploads are refused by the strict cell (control)"
                );
                let before_push = puts(&live);
                assert_eq!(live.push().await, 0, "push after the stock commit");
                assert!(
                    puts(&live) > before_push,
                    "the push uploads what the refused stock commit left local"
                );
            });
        }

        // --- 2. a dead QUIC path ------------------------------------------------------------

        /// The public entry (`commit_with_managed_uploads`) when the QUIC path is already dead: the
        /// pre-warm expires, every upload is skipped, and the command ends within one bound plus
        /// margin. The fragments are not durable, so the push after the path is back uploads them.
        #[test]
        fn a_managed_commit_on_a_dead_quic_path_ends_within_one_bound_and_the_push_uploads_later() {
            lore::runtime().block_on(async {
                let mut live = Live::start().await;
                assert_eq!(live.push().await, 0, "draining push");
                live.stage_file("dead.txt").await;
                let black_hole = live.kill_quic().await;

                let (status, elapsed) = live.managed_commit("commit on a dead path").await;
                eprintln!(
                    "MEASURED managed commit on a dead QUIC path: {elapsed:?} (bound {BOUND:?})"
                );
                assert_eq!(status, 0, "the commit succeeds locally ({elapsed:?})");
                assert!(
                    elapsed >= BOUND - Duration::from_millis(500),
                    "the commit never met the dead path: {elapsed:?}"
                );
                assert!(
                    elapsed < ONE_BOUND_LIMIT,
                    "a dead path must cost the commit one bound, not more: {elapsed:?}"
                );

                // Path restored: the fragments were not durable, so the push uploads them.
                live.restore_quic(black_hole).await;
                let before = puts(&live);
                assert_eq!(live.push().await, 0, "push after the path is back");
                assert!(
                    puts(&live) > before,
                    "the commit left its fragments local, so the push uploads them"
                );
            });
        }

        /// What the two low-level cases below share: open the repository under ONE execution
        /// context, install the scope the commit would, run `commit_boxed`. `kill_after_open` kills
        /// the QUIC path once the open (and its pre-warm) has finished.
        async fn low_level_commit(
            live: &mut Live,
            name: &str,
            kill_before_open: bool,
            kill_after_open: bool,
            managed: bool,
        ) -> (Duration, bool, usize, std::net::UdpSocket) {
            const WARM: &str = "k10-correlation";
            let exec = live.execution(WARM);
            let path = live.source.clone();
            let mut black_hole = None;
            if kill_before_open {
                black_hole = Some(live.kill_quic().await);
            }
            let mut started = Instant::now();
            let (context, token) = LORE_CONTEXT
                .scope(exec.clone(), async {
                    let token = RepositoryWriteToken::acquire(path.as_path()).await;
                    let context = lore_revision::repository::load_and_connect_with_token(
                        path.as_path(),
                        RepositoryAccess::ReadWrite,
                        Some(token.share()),
                    )
                    .await
                    .expect("opening the repository");
                    // The connect (and its pre-warm) has finished.
                    let _ = context.remote().await;
                    (context, token)
                })
                .await;
            if kill_after_open {
                black_hole = Some(live.kill_quic().await);
                started = Instant::now();
            }
            let watch_started = started;
            let latched_at = Arc::new(StdMutex::new(None::<Duration>));
            let (latched, declared) = tokio::time::timeout(
                HANG_GUARD,
                LORE_CONTEXT.scope(
                    exec,
                    managed_commit_uploads::with_managed_commit_uploads(Box::pin(async {
                        context.set_disable_upload(false);
                        if !managed {
                            let outcome = lore_revision::commit::commit_boxed(
                                context.clone(),
                                &token,
                                CommitOptions::new(format!("commit {name}")),
                            )
                            .await;
                            assert!(
                                outcome.is_ok(),
                                "the stock commit succeeds locally: {outcome:?}"
                            );
                            return (false, 0);
                        }
                        let uploads = managed_commit_uploads::install(&context)
                            .expect("a managed commit installs its scope");
                        let watched = uploads.uploads().clone();
                        let seen = latched_at.clone();
                        let _watcher = lore_base::lore_spawn!(async move {
                            while !watched.is_latched() {
                                tokio::time::sleep(Duration::from_millis(50)).await;
                            }
                            *seen.lock().expect("latch time") = Some(watch_started.elapsed());
                        });
                        let outcome = lore_revision::commit::commit_boxed(
                            context.clone(),
                            &token,
                            CommitOptions::new(format!("commit {name}")),
                        )
                        .await;
                        assert!(outcome.is_ok(), "the commit succeeds locally: {outcome:?}");
                        // What the public entry does when a command ends: persist the state.
                        context
                            .flush(lore_storage::FlushOptions::SYNC_DATA)
                            .await
                            .expect("flushing the repository state");
                        (
                            uploads.uploads().is_latched(),
                            uploads.uploads().declared_session_count(),
                        )
                    })),
                ),
            )
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "the commit never ended (hang guard): {:?}",
                    started.elapsed()
                )
            });
            let elapsed = started.elapsed();
            eprintln!(
                "scope latched at {:?}, command ended at {elapsed:?}",
                latched_at.lock().expect("latch time")
            );
            drop(context);
            drop(token);
            (
                elapsed,
                latched,
                declared,
                black_hole.expect("the path was killed"),
            )
        }

        /// Order 1, the pre-warm flag path: the path is dead when the repository opens. The pre-warm
        /// expires at the bound and the scope's `ready` answers false, so no upload starts: the scope
        /// never latches, opens no session, and the whole command costs one bound.
        #[test]
        fn a_commit_whose_prewarm_expired_skips_every_upload_at_one_bound() {
            lore::runtime().block_on(async {
                let mut live = Live::start().await;
                assert_eq!(live.push().await, 0, "draining push");
                live.stage_file("prewarm.txt").await;

                let (elapsed, latched, declared, black_hole) =
                    low_level_commit(&mut live, "prewarm", true, false, true).await;
                eprintln!("MEASURED flag path (prewarm expired) open + commit: {elapsed:?}");
                assert!(
                    !latched,
                    "the uploads were skipped by `ready`, not by a failed upload"
                );
                assert_eq!(declared, 0, "no declared session was opened");
                assert!(
                    elapsed >= BOUND - Duration::from_millis(500),
                    "the open never met the dead path: {elapsed:?}"
                );
                assert!(elapsed < ONE_BOUND_LIMIT, "one bound, not two: {elapsed:?}");

                live.restore_quic(black_hole).await;
                let before = puts(&live);
                let wire_before = live.cell.probe.wire().len();
                let pushed = live.push().await;
                eprintln!(
                    "flag path: push status {pushed}, Puts {before} -> {}; wire after: {:?}",
                    puts(&live),
                    &live.cell.probe.wire()[wire_before..]
                );
                assert_eq!(pushed, 0);
                assert!(
                    puts(&live) > before,
                    "the fragments stayed local for the push"
                );
            });
        }

        /// Order 2, the latch path: the pre-warm succeeded and the path dies before the first
        /// upload. The first upload's reconnect expires at the bound and latches the scope; the rest
        /// skip. One bound in all.
        #[test]
        fn a_commit_whose_path_dies_after_the_prewarm_latches_at_one_bound() {
            lore::runtime().block_on(async {
                let mut live = Live::start().await;
                assert_eq!(live.push().await, 0, "draining push");
                live.stage_file("latch.txt").await;

                let (elapsed, latched, _declared, black_hole) =
                    low_level_commit(&mut live, "latch", false, true, true).await;
                eprintln!("MEASURED latch path (path dies after the pre-warm) commit: {elapsed:?}");
                assert!(latched, "the first upload's expiry latches the scope");
                assert!(
                    elapsed >= BOUND - Duration::from_millis(500),
                    "the commit never met the dead path: {elapsed:?}"
                );
                assert!(
                    elapsed < ONE_BOUND_LIMIT,
                    "one bound, not one per fragment: {elapsed:?}"
                );

                live.restore_quic(black_hole).await;
                let before = puts(&live);
                assert_eq!(live.push().await, 0);
                assert!(
                    puts(&live) > before,
                    "the fragments stayed local for the push"
                );
            });
        }

        /// Control for the latch-path case above, no assertion on the time: the STOCK commit (no
        /// scope) with the same fault order, so a cost shared with the stock commit is told from one
        /// the scope adds. Prints the time.
        #[test]
        fn control_the_stock_commit_with_the_path_dying_after_the_prewarm_is_measured() {
            lore::runtime().block_on(async {
                let mut live = Live::start().await;
                assert_eq!(live.push().await, 0, "draining push");
                live.stage_file("stock-latch.txt").await;
                let (elapsed, _, _, _black_hole) =
                    low_level_commit(&mut live, "stock-latch", false, true, false).await;
                eprintln!("MEASURED stock commit, path dies after the pre-warm: {elapsed:?}");
            });
        }

        /// The endpoint is not dead but silent: QUIC is black-holed and the gRPC port accepts TCP
        /// and never answers (a hung proxy). The repository connect never resolves, so the scope's
        /// `ready` must stop waiting after one bound and skip the uploads. The commit succeeds
        /// locally and ends in about one bound (it waited 150 s before the fix).
        #[test]
        fn a_managed_commit_against_an_endpoint_that_accepts_tcp_and_never_answers_ends_at_one_bound()
         {
            lore::runtime().block_on(async {
                let mut live = Live::start().await;
                assert_eq!(live.push().await, 0, "draining push");
                live.stage_file("silent.txt").await;
                let port = live.cell.port;
                let _black_hole = live.kill_quic().await;
                // Replace the real gRPC server with a listener that never answers.
                let real_grpc =
                    std::mem::replace(&mut live.cell._grpc, tokio::sync::oneshot::channel().0);
                let _ = real_grpc.send(());
                let mut silent = None;
                for _ in 0..100 {
                    if let Ok(listener) = std::net::TcpListener::bind(("127.0.0.1", port)) {
                        silent = Some(listener);
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                let _silent = silent.expect("could not take the gRPC port");

                let (status, elapsed) = live
                    .managed_commit("commit against a silent endpoint")
                    .await;
                eprintln!(
                    "MEASURED managed commit, silent TCP endpoint: {elapsed:?} (bound {BOUND:?})"
                );
                assert_eq!(status, 0, "the commit succeeds locally ({elapsed:?})");
                assert!(
                    elapsed < ONE_BOUND_LIMIT + MARGIN,
                    "a silent endpoint must cost the commit about one bound: {elapsed:?}"
                );
            });
        }
        /// A connection that has gone silent: the server applies every Put and answers none. The
        /// first lost answer latches the scope, so the commit ends in about one bound (it took one
        /// bound per wave of uploads before), succeeds locally, and no fragment is sent twice.
        #[test]
        fn a_commit_with_every_upload_answer_withheld_ends_at_one_bound_and_resends_nothing() {
            lore::runtime().block_on(async {
                let hold = crate::quic_managed_write_support::HoldFirstPutAnswer {
                    grace: Duration::from_secs(120),
                    ..hold_first_put_answer()
                };
                hold.armed.store(false, std::sync::atomic::Ordering::SeqCst);
                let live = Live::start_with_hold(Some(hold.clone())).await;
                assert_eq!(live.push().await, 0, "draining push");
                live.stage_file("silent-answers.txt").await;
                let before = live.cell.probe.put_keys().len();
                hold.hold_all
                    .store(true, std::sync::atomic::Ordering::SeqCst);

                let (status, elapsed) = live.managed_commit("commit with no answers").await;
                eprintln!("MEASURED every Put answer withheld: {elapsed:?} (bound {BOUND:?})");
                assert_eq!(status, 0, "the commit succeeds locally ({elapsed:?})");
                assert!(
                    elapsed < ONE_BOUND_LIMIT,
                    "withheld answers must cost one bound, not one per wave: {elapsed:?}"
                );
                let keys: Vec<Vec<u8>> = live.cell.probe.put_keys().split_off(before);
                assert!(!keys.is_empty(), "the commit uploaded");
                let distinct: std::collections::HashSet<_> = keys.iter().collect();
                assert_eq!(
                    distinct.len(),
                    keys.len(),
                    "a fragment's Put was sent twice"
                );
                hold.hold_all
                    .store(false, std::sync::atomic::Ordering::SeqCst);
            });
        }

        /// The desktop passes a display name as `globals.identity`. A managed commit's uploads must
        /// still go out and be accepted, and the revision is authored by the display name.
        #[test]
        fn a_managed_commit_with_a_display_name_identity_uploads_and_is_authored_by_it() {
            lore::runtime().block_on(async {
                let live = Live::start().await;
                let key = count_refusals_for(&live.server);
                assert_eq!(live.push().await, 0, "draining push");
                live.stage_file("named.txt").await;
                let (puts_before, refusals_before) = (puts(&live), refusals_for(key));
                let globals = LoreGlobalArgs {
                    identity: "Display Name".into(),
                    ..live.globals.clone()
                };

                let (status, elapsed) = live.managed_commit_as(globals, "named commit").await;

                assert_eq!(status, 0, "the commit succeeds ({elapsed:?})");
                assert!(puts(&live) > puts_before, "the uploads reached the cell");
                assert_eq!(refusals_for(key), refusals_before, "none refused");
                let before_push = puts(&live);
                assert_eq!(live.push().await, 0);
                assert_eq!(
                    puts(&live),
                    before_push,
                    "the commit's fragments were durable"
                );

                let path = live.source.clone();
                let (created_by, committed_by) = LORE_CONTEXT
                    .scope(live.execution("k10-read"), async {
                        let token = RepositoryWriteToken::acquire(path.as_path()).await;
                        let context = lore_revision::repository::load_and_connect_with_token(
                            path.as_path(),
                            RepositoryAccess::ReadWrite,
                            Some(token.share()),
                        )
                        .await
                        .expect("opening the repository");
                        let (revision, _branch) =
                            lore_revision::instance::load_current_anchor_boxed(&context)
                                .await
                                .expect("the current anchor");
                        let state =
                            lore_revision::state::State::deserialize(context.clone(), revision)
                                .await
                                .expect("the head state");
                        let metadata = state
                            .revision_metadata(context.clone())
                            .await
                            .expect("the revision metadata");
                        (metadata.created_by, metadata.committed_by)
                    })
                    .await;
                eprintln!("authors: created_by {created_by:?}, committed_by {committed_by:?}");
                assert_eq!(committed_by.as_deref(), Some("Display Name"));
            });
        }
        // --- 3. a lost answer ---------------------------------------------------------------

        /// A commit-style upload through a `ManagedUploads` scope over live QUIC, whose `Put` the
        /// server applies and then loses the answer of (the server is closed under it): the Put is
        /// dispatched exactly once, nothing reaches the replacement server (no resend, no new
        /// session), the write succeeds with the fragment local and not durable, and the scope
        /// latches, so the next upload in it sends nothing.
        #[test]
        fn a_commit_upload_with_a_lost_answer_is_dispatched_once_and_the_fragment_stays_local() {
            lore::runtime().block_on(async {
                in_context(async {
                    let hold = hold_first_put_answer();
                    let mut cell =
                        crate::quic_managed_write_support::cell(Some(hold.clone()), None, None)
                            .await;
                    let partition = rand::random::<lore_base::types::RepositoryId>();
                    let connection = connect("lore", cell.port, partition).await?;
                    let session = connection.session(partition, "k10-lost").await?;
                    let (local, _local_mutable) = fresh_stores().await;
                    let scope = ManagedUploads::new(async { true });
                    let server = cell.quic.take().expect("the cell's QUIC server");

                    let (mut fragment, address, payload) =
                        lore_revision::fragment::generate_random();
                    fragment.flags = FragmentFlags::PayloadStoredLocal.bits();
                    let writes =
                        WriteContext::counted(None).with_managed_uploads(Some(scope.clone()));
                    let (result, (replacement_server, replacement)) = tokio::join!(
                        tokio::time::timeout(
                            Duration::from_secs(30),
                            store_fragment(
                                local.clone(),
                                partition,
                                address,
                                fragment,
                                payload,
                                true,
                                Some(session.clone()),
                                writes,
                                None,
                            ),
                        ),
                        lose_answer_and_restart(&hold, server, cell.port, &cell.stores, async {}),
                    );
                    cell.quic = Some(replacement_server);
                    let result = result
                        .expect("a lost answer must end the upload, not hang it")
                        .expect("a commit upload never fails the write");

                    assert!(result.stored_local, "the fragment stays local");
                    assert!(!result.stored_durable, "a lost answer is not durable");
                    assert_eq!(
                        cell.probe.count_opcode(Command::Put),
                        1,
                        "the Put is dispatched exactly once: {:?}",
                        cell.probe.wire()
                    );
                    tokio::time::sleep(RESEND_SETTLE).await;
                    assert_eq!(
                        replacement.count_opcode(Command::Put),
                        0,
                        "the lost Put was resent to the replacement: {:?}",
                        replacement.wire()
                    );
                    assert_eq!(
                        replacement.count_opcode(Command::Authorize),
                        0,
                        "the lost Put started a session on the replacement: {:?}",
                        replacement.wire()
                    );
                    assert!(scope.is_latched(), "a lost answer latches the scope");

                    // The scope is latched, so the next upload sends nothing to the replacement.
                    let (mut next, next_address, next_payload) =
                        lore_revision::fragment::generate_random();
                    next.flags = FragmentFlags::PayloadStoredLocal.bits();
                    let landed = store_fragment(
                        local.clone(),
                        partition,
                        next_address,
                        next,
                        next_payload,
                        true,
                        Some(session.clone()),
                        WriteContext::counted(None).with_managed_uploads(Some(scope.clone())),
                        None,
                    )
                    .await?;
                    assert!(!landed.stored_durable, "a latched scope uploads nothing");
                    assert!(landed.stored_local);
                    assert_eq!(
                        replacement.count_opcode(Command::Put),
                        0,
                        "{:?}",
                        replacement.wire()
                    );
                    assert_eq!(replacement.count_action(ACTION_START_DECLARED), 0);
                    Ok(())
                })
                .await
                .expect("the lost-answer case");
            });
        }
        /// The same loss in a real commit: the server applies one of the commit's Puts and is
        /// closed under its answer, a replacement is up at once. The commit succeeds, and no
        /// fragment's Put is dispatched twice, on either server. (A resend of the lost Put would
        /// repeat a key.)
        #[test]
        fn a_commit_with_one_lost_upload_answer_sends_no_fragment_twice() {
            lore::runtime().block_on(async {
                let hold = hold_first_put_answer();
                hold.armed.store(false, std::sync::atomic::Ordering::SeqCst);
                let mut live = Live::start_with_hold(Some(hold.clone())).await;
                assert_eq!(live.push().await, 0, "draining push");
                live.stage_file("lost.txt").await;
                hold.armed.store(true, std::sync::atomic::Ordering::SeqCst);
                let server = live.cell.quic.take().expect("the QUIC server is up");
                let port = live.cell.port;
                let stores = live.cell.stores.clone();
                let original = live.cell.probe.clone();
                let before = original.put_keys().len();

                let ((status, elapsed), (replacement_server, replacement)) = tokio::join!(
                    live.managed_commit("commit with a lost answer"),
                    LORE_CONTEXT.scope(
                        live.server.clone(),
                        lose_answer_and_restart(&hold, server, port, &stores, async {}),
                    ),
                );
                live.cell.quic = Some(replacement_server);
                tokio::time::sleep(RESEND_SETTLE).await;

                assert_eq!(
                    status, 0,
                    "the commit succeeds with one answer lost ({elapsed:?})"
                );
                let mut keys: Vec<Vec<u8>> = original.put_keys().split_off(before);
                assert!(
                    !keys.is_empty(),
                    "the commit uploaded through the original server"
                );
                keys.extend(replacement.put_keys());
                let distinct: std::collections::HashSet<_> = keys.iter().collect();
                assert_eq!(
                    distinct.len(),
                    keys.len(),
                    "a fragment's Put was dispatched twice (a lost answer must not be resent)"
                );
            });
        }
    }
}

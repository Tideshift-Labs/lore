// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//
// WP-124: a managed push whose READ (the fragment Query) is sent on a QUIC connection that is
// dead or black-holed must end after about ONE managed bound with ffi 28 (`Disconnected`).
//
// [CLIENT]-class. Its own test binary (`[[test]] name = "quic_managed_read_bound"`) because the
// bound is the process-wide `LORE_QUIC_MANAGED_IDLE_TIMEOUT`, set from a constructor before `main`.
//
// The defect: a read sent on a LIVE connection whose path then went black waited for quinn's 30 s
// idle timeout, then reconnected under a fresh bound (34 s at a 4 s bound). `send_command_tracked`
// now bounds the read's writer-lock, write and answer phases inside a managed wait scope, and
// `classify` turns a bounded-phase timeout of a ReadRetryable command into a terminal
// `ManagedReconnectExpired` rather than a reconnect.
//
// A UDP relay sits in front of the QUIC server so the path can be blacked out while the client's
// connection stays up. Cases:
// - closed: the server closes the connection (a close frame reaches the client), then the relay
//   drops everything.
// - blackhole: the connection is live, then the relay drops everything.
// - idle_closed: the relay drops and the client waits out quinn's 30 s idle timeout first (the
//   wait is quinn's, not ours, so it is the floor for this case).
// - blackhole_second_connect: as blackhole, plus an unmanaged connect of a second context started
//   mid-wait, which must not stretch the push.
//
// Limits. Lower: the bound minus 500 ms (the push must not give up early). Upper: the bound plus
// 3 s (7 s at a 4 s bound). Two bounds is 8 s and the pre-fix blackhole took 34 s, so the upper
// limit fails both a second bound and the quinn idle wait; the 3 s covers the Query/connect
// before the bounded phase and CI jitter. A 40 s hang guard keeps a missing bound a failure
// instead of a wait.
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
    let sandbox = std::env::temp_dir().join(format!("lore-read-bound-tests-{unique}"));
    std::fs::create_dir_all(&sandbox)
        .unwrap_or_else(|error| panic!("creating the sandbox at {}: {error}", sandbox.display()));
    unsafe {
        std::env::set_var("LORE_GLOBAL_PATH", &sandbox);
        std::env::set_var("LORE_AUTH_PATH", &sandbox);
        std::env::set_var(
            "LORE_SERVICE_SOCKET",
            format!("lore_service-readbound-{}", &unique[..12]),
        );
        std::env::set_var("LORE_QUIC_MANAGED_IDLE_TIMEOUT", BOUND_SECS.to_string());
    }
}

#[cfg(all(test, feature = "integration_tests"))]
mod tests {
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicU64;
    use std::sync::atomic::Ordering;
    use std::time::Duration;
    use std::time::Instant;

    use bytes::Bytes;
    use lore::branch;
    use lore::file;
    use lore::repository;
    use lore::revision;
    use lore_base::runtime::LORE_CONTEXT;
    use lore_base::test_util::TempDir;
    use lore_base::types::Address;
    use lore_base::types::Context;
    use lore_base::types::Fragment;
    use lore_base::types::Hash;
    use lore_revision::environment::EnvironmentConfig;
    use lore_revision::interface::ExecutionContext;
    use lore_revision::interface::LoreArray;
    use lore_revision::interface::LoreGlobalArgs;
    use lore_revision::interface::LoreString;
    use lore_revision::lore::RepositoryId;
    use lore_revision::repository::LoreSharedStoreMode;
    use lore_revision::repository::RepositoryAccess;
    use lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
    use lore_server::authnz::repository_catalog::BaselineRepositoryCatalog;
    use lore_server::grpc::server::FeatureSettings;
    use lore_server::grpc::server::GrpcServerBuilder;
    use lore_server::grpc::server::GrpcTimeouts;
    use lore_server::hooks::HookDispatcher;
    use lore_server::settings::BaselineAccess;
    use lore_storage::ImmutableStore;
    use lore_storage::MutableStore;
    use lore_transport::CallerOperationContext;
    use lore_transport::VolatileAttemptStore;
    use lore_transport::session::StorageSession;
    use lore_transport::with_caller_operation;
    use uuid::Uuid;

    use crate::BOUND_SECS;
    use crate::common::net_common::bind_matched_pair;
    use crate::quic_managed_write_support::Probe;
    use crate::quic_managed_write_support::fresh_stores;
    use crate::quic_managed_write_support::start_quic;

    const FIXTURE_TOKEN: &str = "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwczovL2ZpeHR1cmUuaW52YWxpZC9pc3N1ZXIiLCJzdWIiOiJmaXh0dXJlLXVzZXIiLCJuYW1lIjoiZml4dHVyZS11c2VyIiwiZXhwIjo0MTAyNDQ0ODAwLCJhdWQiOiJmaXh0dXJlIn0.eA";
    const FFI_DISCONNECTED: i32 = 28;
    const BOUND: Duration = Duration::from_secs(BOUND_SECS);
    const HANG_GUARD: Duration = Duration::from_secs(40);
    const MARGIN: Duration = Duration::from_secs(3);
    /// quinn's idle timeout is 30 s; wait past it so the client has closed the connection itself.
    const QUINN_IDLE_WAIT: Duration = Duration::from_secs(32);

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

    /// A UDP relay on the front port, one upstream socket per client address. `blocked` drops
    /// every datagram in both directions.
    ///
    /// `rate` caps the server-to-client direction in bytes per second (0 is unlimited). It is a
    /// bottleneck link: a datagram leaves at its slot on the rate, and one that finds the queue
    /// full is dropped, as a router would, so the sender's congestion control settles at the rate
    /// and the client sees a steady trickle with no multi-second gap.
    struct Relay {
        blocked: Arc<AtomicBool>,
        rate: Arc<AtomicU64>,
    }

    /// Datagrams the throttled direction holds before it drops (about 19 KB). Kept short so the
    /// queueing delay at the slow rate stays well under the managed bound.
    const THROTTLE_QUEUE: usize = 16;

    fn start_relay(front: std::net::UdpSocket, upstream: SocketAddr) -> Relay {
        front.set_nonblocking(true).expect("nonblocking");
        let blocked = Arc::new(AtomicBool::new(false));
        let relay_blocked = blocked.clone();
        let rate = Arc::new(AtomicU64::new(0));
        let relay_rate = rate.clone();
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
                    let rate = relay_rate.clone();
                    let (queue_tx, mut queue_rx) =
                        tokio::sync::mpsc::channel::<Vec<u8>>(THROTTLE_QUEUE);
                    let _reverse = lore_base::lore_spawn!(async move {
                        let mut buf = vec![0u8; 65536];
                        while let Ok(n) = back.recv(&mut buf).await {
                            if blocked.load(Ordering::Relaxed) {
                                continue;
                            }
                            if rate.load(Ordering::Relaxed) == 0 {
                                // Unlimited: wait for room rather than drop.
                                if queue_tx.send(buf[..n].to_vec()).await.is_err() {
                                    break;
                                }
                            } else {
                                let _ = queue_tx.try_send(buf[..n].to_vec());
                            }
                        }
                    });
                    let blocked = relay_blocked.clone();
                    let rate = relay_rate.clone();
                    let front = front.clone();
                    let _forward = lore_base::lore_spawn!(async move {
                        let mut slot = tokio::time::Instant::now();
                        while let Some(datagram) = queue_rx.recv().await {
                            // Zero is unlimited: no slot to wait for.
                            let nanos = (datagram.len() as u64 * 1_000_000_000)
                                .checked_div(rate.load(Ordering::Relaxed));
                            if let Some(nanos) = nanos {
                                slot = slot.max(tokio::time::Instant::now())
                                    + Duration::from_nanos(nanos);
                                tokio::time::sleep_until(slot).await;
                            }
                            if !blocked.load(Ordering::Relaxed) {
                                let _ = front.send_to(&datagram, from).await;
                            }
                        }
                    });
                    peers.insert(from, up.clone());
                    up
                };
                let _ = up.send(&buf[..n]).await;
            }
        });
        Relay { blocked, rate }
    }

    /// The servers and the relay in front of the QUIC one; `port` serves gRPC (TCP) and the relay
    /// (UDP) alike.
    struct Cell {
        relay: Relay,
        _quic: lore_server::quic::quinn::QuinnServer,
        port: u16,
        _grpc: tokio::sync::oneshot::Sender<()>,
    }

    impl Cell {
        async fn start() -> Self {
            let server = crate::setup_execution("server".to_string());
            let (addr, front, quic, quic_port, grpc) = LORE_CONTEXT
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
            let relay = LORE_CONTEXT
                .scope(server.clone(), async {
                    start_relay(front, SocketAddr::from(([127, 0, 0, 1], quic_port)))
                })
                .await;
            Self {
                relay,
                _quic: quic,
                port: addr.port(),
                _grpc: grpc,
            }
        }
    }

    struct Live {
        relay: Relay,
        quic: Option<lore_server::quic::quinn::QuinnServer>,
        source: PathBuf,
        globals: LoreGlobalArgs,
        server: Arc<ExecutionContext>,
        _grpc: tokio::sync::oneshot::Sender<()>,
        _temp: TempDir,
    }

    impl Live {
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
            let relay = LORE_CONTEXT
                .scope(server.clone(), async {
                    start_relay(front, SocketAddr::from(([127, 0, 0, 1], quic_port)))
                })
                .await;
            let port = tcp.port();

            let temp = TempDir::new("lore-read-bound-");
            let source = temp.join("source");
            std::fs::create_dir_all(&source).expect("source dir");
            let globals = LoreGlobalArgs {
                repository_path: source.as_path().into(),
                identity: "fixture-user".into(),
                identity_token: FIXTURE_TOKEN.into(),
                access_token: FIXTURE_TOKEN.into(),
                ..Default::default()
            };
            let url = format!("lore://127.0.0.1:{port}/read-bound");
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
                relay,
                quic: Some(quic),
                source,
                globals,
                server,
                _grpc: grpc,
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
            assert_eq!(first, 0, "push #1 must land");
            live.stage_and_commit("second.txt").await;
            live
        }

        async fn stage_and_commit(&self, name: &str) {
            std::fs::write(
                self.source.join(name),
                format!("content of {name} {}", Uuid::new_v4()),
            )
            .expect("write");
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
            assert_eq!(status, 0, "stage");
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
            assert_eq!(status, 0, "commit");
        }

        /// Close the QUIC server (a close frame reaches the client), then block the relay.
        async fn close_server_then_block(&mut self) {
            let quic = self.quic.take().expect("quic up");
            LORE_CONTEXT
                .scope(self.server.clone(), async move {
                    quic.close().await;
                    drop(quic);
                })
                .await;
            tokio::time::sleep(Duration::from_millis(500)).await;
            self.relay.blocked.store(true, Ordering::Relaxed);
        }

        fn block(&self) {
            self.relay.blocked.store(true, Ordering::Relaxed);
        }

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

    async fn timed_push(live: &Live) -> (Option<i32>, Duration) {
        let started = Instant::now();
        let status = tokio::time::timeout(
            HANG_GUARD,
            Box::pin(branch::push_managed(
                live.globals.clone(),
                push_args(),
                None,
                None,
            )),
        )
        .await;
        (status.ok(), started.elapsed())
    }

    fn assert_ended_at_the_bound(case: &str, status: Option<i32>, elapsed: Duration) {
        println!(
            "{case}: bound={BOUND_SECS}s status={status:?} elapsed_ms={}",
            elapsed.as_millis()
        );
        let status = status.unwrap_or_else(|| {
            panic!("{case}: the managed push never ended (hang guard after {elapsed:?})")
        });
        assert_eq!(
            status, FFI_DISCONNECTED,
            "{case}: expected Disconnected (28), not Internal (-1)"
        );
        assert!(
            elapsed >= BOUND - Duration::from_millis(500),
            "{case}: gave up before the bound: {elapsed:?}"
        );
        assert!(
            elapsed < BOUND + MARGIN,
            "{case}: outlasted one bound (pre-fix: 34 s): {elapsed:?}"
        );
    }

    #[test]
    fn closed_connection_ends_disconnected_at_one_bound() {
        lore::runtime().block_on(async {
            let mut live = Live::start().await;
            live.close_server_then_block().await;
            let (status, elapsed) = timed_push(&live).await;
            assert_ended_at_the_bound("closed", status, elapsed);
        });
    }

    #[test]
    fn blackholed_live_connection_ends_disconnected_at_one_bound() {
        lore::runtime().block_on(async {
            let live = Live::start().await;
            live.block();
            let (status, elapsed) = timed_push(&live).await;
            assert_ended_at_the_bound("blackhole", status, elapsed);
        });
    }

    #[test]
    fn idle_closed_connection_ends_disconnected_at_one_bound() {
        lore::runtime().block_on(async {
            let live = Live::start().await;
            live.block();
            tokio::time::sleep(QUINN_IDLE_WAIT).await;
            let (status, elapsed) = timed_push(&live).await;
            assert_ended_at_the_bound("idle-closed", status, elapsed);
        });
    }

    /// Size of the object the slow-read cases download: the largest one fragment (one answer) holds.
    const OBJECT_BYTES: usize = lore_base::types::FRAGMENT_SIZE_THRESHOLD;
    /// How long the throttled download takes if the link rate holds.
    const THROTTLED_DOWNLOAD: Duration = Duration::from_secs(11);

    /// A stream the transport cannot compress: a counter run through a hash.
    fn incompressible(len: usize) -> Bytes {
        let mut out = Vec::with_capacity(len + 32);
        let mut counter = 0u64;
        while out.len() < len {
            let block = Hash::hash_buffer(counter.to_le_bytes().as_slice());
            out.extend_from_slice(block.as_ref());
            counter += 1;
        }
        out.truncate(len);
        Bytes::from(out)
    }

    /// A cell with `OBJECT_BYTES` stored through the QUIC write path (relay open), a session to
    /// read it back, and the relay throttled to `THROTTLED_DOWNLOAD` for the object.
    async fn throttled_cell_with_object() -> (Cell, Arc<StorageSession>, Address, Bytes) {
        let cell = Cell::start().await;
        let partition = rand::random::<RepositoryId>();
        let connection = lore_revision::protocol::connect(
            &format!("lore://127.0.0.1:{}", cell.port),
            "",
            partition,
        )
        .await
        .expect("connect");
        let session = connection
            .session(partition, "read-bound")
            .await
            .expect("session");
        let payload = incompressible(OBJECT_BYTES);
        let address = Address {
            hash: Hash::hash_buffer(&payload),
            context: rand::random::<Context>(),
        };
        let fragment = Fragment {
            flags: 0,
            size_payload: payload.len() as u32,
            size_content: payload.len() as u64,
        };
        let scope = CallerOperationContext::new(
            Uuid::now_v7(),
            partition,
            Arc::new(VolatileAttemptStore::default()),
        );
        tokio::time::timeout(
            HANG_GUARD,
            with_caller_operation(scope, session.put(address, fragment, Some(payload.clone()))),
        )
        .await
        .expect("the write hung")
        .expect("the object is stored");
        cell.relay.rate.store(
            (OBJECT_BYTES as u64) / THROTTLED_DOWNLOAD.as_secs(),
            Ordering::Relaxed,
        );
        (cell, session, address, payload)
    }

    /// The bound is an IDLE bound: a read whose bytes keep arriving must not expire however long
    /// the whole download takes. The answer phase re-arms from the last byte received.
    ///
    /// Through the real QUIC `StorageClient` (`StorageSession::get`) inside a managed workflow.
    #[test]
    fn slow_but_steady_read_inside_a_managed_scope_does_not_expire() {
        lore::runtime().block_on(LORE_CONTEXT.scope(crate::setup_execution("client".to_string()), async {
            let (_cell, session, address, payload) = throttled_cell_with_object().await;
            {
                {
                    let started = Instant::now();
                    let result = tokio::time::timeout(
                        HANG_GUARD,
                        lore_transport::with_managed_workflow(session.get(&address)),
                    )
                    .await
                    .expect("the slow read hung");
                    let elapsed = started.elapsed();
                    println!(
                        "slow-read: bound={BOUND_SECS}s elapsed_ms={} ok={}",
                        elapsed.as_millis(),
                        result.is_ok()
                    );
                    let (_, bytes) = result.expect("a steady download must not expire");
                    assert!(bytes == payload, "the bytes read back differ");
                    assert!(
                        elapsed > BOUND * 2,
                        "the download must outlast two bounds to prove the bound is idle: {elapsed:?}"
                    );
                }
            }
        }));
    }

    /// The negative twin: the same download with the path blacked out part way ends at the
    /// managed expiry about one bound after the last byte, not after the whole download.
    #[test]
    fn stalled_read_inside_a_managed_scope_expires_one_bound_after_the_stall() {
        lore::runtime().block_on(LORE_CONTEXT.scope(
            crate::setup_execution("client".to_string()),
            async {
                let (cell, session, address, _payload) = throttled_cell_with_object().await;
                {
                    {
                        let read = tokio::time::timeout(
                            HANG_GUARD,
                            lore_transport::with_managed_workflow(session.get(&address)),
                        );
                        let stall = async {
                            tokio::time::sleep(BOUND * 3 / 4).await;
                            cell.relay.blocked.store(true, Ordering::Relaxed);
                            Instant::now()
                        };
                        let started = Instant::now();
                        let (result, stalled_at) = tokio::join!(read, stall);
                        let after_stall = stalled_at.elapsed();
                        println!(
                            "stalled-read: bound={BOUND_SECS}s since_start_ms={} since_stall_ms={}",
                            started.elapsed().as_millis(),
                            after_stall.as_millis()
                        );
                        let error = result
                            .expect("the stalled read never ended (hang guard)")
                            .expect_err("a stalled read cannot succeed");
                        assert!(
                            lore_transport::is_managed_reconnect_expired(&error),
                            "expected the managed expiry: {error:?}"
                        );
                        assert!(
                            after_stall >= BOUND - Duration::from_millis(500),
                            "gave up before the bound: {after_stall:?}"
                        );
                        assert!(
                            after_stall < BOUND + MARGIN,
                            "outlasted one bound after the stall: {after_stall:?}"
                        );
                    }
                }
            },
        ));
    }

    /// As the blackhole case, plus an unmanaged connect of a second context (a resubscribe's
    /// `remote()` and its pre-warm under its own correlation id) started half way into the bound.
    /// It must not stretch the managed push.
    #[test]
    fn blackhole_with_unmanaged_second_connect_stays_within_one_bound() {
        lore::runtime().block_on(async {
            let live = Live::start().await;
            live.block();
            let path = live.source.clone();
            let side = live.execution("resubscribe-correlation");
            let second = lore_base::lore_spawn!(LORE_CONTEXT.scope(side, async move {
                tokio::time::sleep(BOUND / 2).await;
                let context = lore_revision::repository::load_and_connect(
                    path.as_path(),
                    RepositoryAccess::ReadOnly,
                )
                .await;
                if let Ok(context) = context {
                    // Outcome is irrelevant here; it only has to be in flight during the push.
                    let _ = tokio::time::timeout(HANG_GUARD, context.remote()).await;
                }
            }));
            let (status, elapsed) = timed_push(&live).await;
            assert_ended_at_the_bound("blackhole-second-connect", status, elapsed);
            second.await.expect("side task");
        });
    }
}

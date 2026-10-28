// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//
// WP-124 slice 5b: the QUIC token-expiry re-check, live.
//
// [SERVER]-class (the check is the server's), exercised through the stock `lore-transport` client.
// One in-process, auth-ON loopback cell: the real `lore-server` gRPC stack (which serves the
// environment the `lore://` connect reads) and a real QUIC listener whose `lore-storage/0.4`
// service is built as `server.rs` builds it, behind a real `JwtVerifier`. The tokens are minted
// here (HS256, a static JWKS), so a test chooses each token's `exp`.
//
// Two cases, each the end-to-end form of a unit-tier claim:
//
//   managed pushes cross expiry: a managed (declared-session) sequence of puts whose token
//     expires partway through completes after exactly ONE rebind. Every fragment is applied
//     exactly once (a recording store counts the puts that reach it), and the server holds two
//     declared sessions in all: the first, and the one that replaced it. The client noticed the
//     expiry on its own clock and rebound before sending, so no put was refused.
//
//   an expired session loses write access: a session whose token is past `exp + leeway` is
//     refused with storage status 201 on every write, with no store effect, while the entry stays
//     (siblings are refused too); reads follow `TOKEN_EXPIRY_GATES_READS`; the same token cannot
//     start a replacement (the verifier refuses it, so a revoked user whose exchange no longer
//     renews cannot write again), and a StorageSession put fails with nothing stored.
//
// The revocation case uses a token whose `exp` is already 45 s old: the verifier's 60 s leeway
// still accepts it at session start, and the server's per-command check refuses it once that
// leeway has run out, about 15 s later. That is the shortest real wait the leeway allows; the
// leeway is a constant, not configuration (`TOKEN_EXP_LEEWAY_SECS`).
//
// Not covered live: a 201 that reaches a `StorageSession` and is absorbed by its reactive rebind.
// The client rebinds on its own clock the moment `exp` passes, 60 s before the server would
// refuse, so a fixed token never produces that race against a real server. The reactive path is
// proved on the scripted peer (`lore-transport/tests/session_expiry_attempt.rs`).
#[cfg(all(test, feature = "integration_tests"))]
mod quic_token_expiry_tests {
    use std::collections::HashMap;
    use std::error::Error;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use async_trait::async_trait;
    use bytes::Bytes;
    use lore_base::runtime::LORE_CONTEXT;
    use lore_base::types::Address;
    use lore_base::types::Context;
    use lore_base::types::Fragment;
    use lore_base::types::Partition;
    use lore_revision::environment::EnvironmentConfig;
    use lore_revision::fragment;
    use lore_revision::lore::RepositoryId;
    use lore_server::auth::jwk::JWKServiceError;
    use lore_server::auth::jwt::JwtVerifier;
    use lore_server::authnz::repository_authorizer::RepositoryAuthorizer;
    use lore_server::authnz::repository_catalog::BaselineRepositoryCatalog;
    use lore_server::grpc::caller_capabilities::CallerCapabilityPolicy;
    use lore_server::grpc::server::FeatureSettings;
    use lore_server::grpc::server::GrpcServerBuilder;
    use lore_server::grpc::server::GrpcTimeouts;
    use lore_server::hooks::HookDispatcher;
    use lore_server::protocol::attribute_map::AttributeMap;
    use lore_server::protocol::storage::session::SessionMap;
    use lore_server::protocol::storage::session::TOKEN_EXP_LEEWAY_SECS;
    use lore_server::protocol::storage::session::TOKEN_EXPIRY_GATES_READS;
    use lore_server::quic::StreamDataHandler;
    use lore_server::quic::StreamHandlerFactory;
    use lore_server::quic::quinn::QuinnConfigBuilder;
    use lore_server::quic::quinn::QuinnServer;
    use lore_server::quic::quinn::service_store::ServiceStore;
    use lore_server::quic::quinn::service_store::StreamDataHandlerBuilder;
    use lore_server::quic::storage_service_v4::StorageServiceV4;
    use lore_server::quic::stream_handler::AdmissionLimits;
    use lore_server::quic::stream_handler::StreamHandler;
    use lore_server::quic::tests::TEST_PROTOCOL_V4;
    use lore_server::quic::tests::server_certs;
    use lore_server::settings::BaselineAccess;
    use lore_storage::ImmutableStore;
    use lore_storage::MutableStore;
    use lore_storage::StoreError;
    use lore_storage::StoreGetData;
    use lore_storage::StoreMatchResult;
    use lore_storage::StoreObliterateStats;
    use lore_storage::immutable_store::CopyBehavior;
    use lore_storage::local::immutable_store::ImmutableStoreCreateOptions;
    use lore_storage::local::immutable_store::ImmutableStoreSettings;
    use lore_telemetry::user_agent_filter::UserAgentFilter;
    use lore_transport::attempt_store::VolatileAttemptStore;
    use lore_transport::caller_operation::CallerOperationContext;
    use lore_transport::caller_operation::with_caller_operation;
    use lore_transport::error::is_session_expired;
    use rand::random;

    use crate::common::net_common::bind_matched_pair;
    use crate::setup_execution;

    type TestResult = Result<(), Box<dyn Error>>;

    const KID: &str = "wp124-expiry-key";
    const SECRET: &[u8] = b"wp124-expiry-hs256-secret";
    const AUDIENCE: &str = "wp124-expiry-audience";
    const ISSUER: &str = "wp124-expiry-issuer";
    /// Advertised so the client presents its supplied token; never contacted, because a supplied
    /// access token short-circuits the exchange.
    const UNREACHABLE_AUTH_URL: &str = "https://auth.invalid/wp124-expiry";

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs()
    }

    #[derive(Debug)]
    struct StaticJwkService;

    #[async_trait]
    impl lore_server::auth::jwk::JWKService for StaticJwkService {
        async fn get_key(
            &self,
            kid: &str,
        ) -> Result<(jsonwebtoken::DecodingKey, jsonwebtoken::Algorithm), JWKServiceError> {
            if kid != KID {
                return Err(JWKServiceError::NotFound);
            }
            Ok((
                jsonwebtoken::DecodingKey::from_secret(SECRET),
                jsonwebtoken::Algorithm::HS256,
            ))
        }

        fn get_cached_key(
            &self,
            kid: &str,
        ) -> Option<(jsonwebtoken::DecodingKey, jsonwebtoken::Algorithm)> {
            (kid == KID).then(|| {
                (
                    jsonwebtoken::DecodingKey::from_secret(SECRET),
                    jsonwebtoken::Algorithm::HS256,
                )
            })
        }

        async fn refresh_key(
            &self,
            _kid: &str,
        ) -> Result<Option<(jsonwebtoken::DecodingKey, jsonwebtoken::Algorithm)>, JWKServiceError>
        {
            Ok(None)
        }
    }

    fn verifier() -> JwtVerifier {
        JwtVerifier {
            jwk_service: Arc::new(StaticJwkService),
            jwt_issuer: None,
            jwt_audience: Some(vec![AUDIENCE.to_string()]),
            jwt_typ: None,
            identity_claim: lore_server::auth::jwt::DEFAULT_IDENTITY_CLAIM.to_string(),
        }
    }

    /// The authorizer production builds for `resource_claim = "resources"`.
    fn authorizer() -> Arc<dyn RepositoryAuthorizer> {
        let auth: lore_server::settings::AuthSettings = serde_json::from_value(serde_json::json!({
            "jwt_issuer": ISSUER,
            "jwt_audience": [AUDIENCE],
            "resource_claim": "resources",
        }))
        .expect("the fixture's [server.auth] settings parse");
        lore_server::authnz::repository_authorizer::repository_authorizer(Some(&auth), None)
            .expect("ResourceGrants is a valid selection")
    }

    /// A read+write token for `repository` whose `exp` is `exp` (Unix seconds).
    fn token(repository: RepositoryId, exp: u64) -> String {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = Some(KID.to_string());
        let claims = serde_json::json!({
            "sub": "wp124-expiry-user",
            "iss": ISSUER,
            "iat": 0,
            "exp": exp,
            "aud": [AUDIENCE],
            "env": "test",
            "name": "WP-124 expiry",
            "preferred_username": "wp124-expiry-user",
            "idp": "test-idp",
            "resources": [{
                "resource_id": format!("urc-{repository}"),
                "permission": ["read", "write"],
            }],
        });
        jsonwebtoken::encode(
            &header,
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(SECRET),
        )
        .expect("minting a test token")
    }

    /// Counts the `put`s that reach the store, per address, and passes everything through.
    struct RecordingImmutableStore {
        inner: Arc<dyn ImmutableStore>,
        puts: std::sync::Mutex<Vec<Address>>,
        calls: AtomicUsize,
    }

    impl RecordingImmutableStore {
        fn puts_of(&self, address: Address) -> usize {
            self.puts
                .lock()
                .expect("puts lock")
                .iter()
                .filter(|a| **a == address)
                .count()
        }

        fn total_puts(&self) -> usize {
            self.puts.lock().expect("puts lock").len()
        }
    }

    #[async_trait]
    impl ImmutableStore for RecordingImmutableStore {
        async fn get(
            self: Arc<Self>,
            partition: Partition,
            address: Address,
        ) -> Result<StoreGetData, StoreError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.clone().get(partition, address).await
        }

        async fn query(
            self: Arc<Self>,
            partition: Partition,
            addresses: &[Address],
            results: &mut [StoreMatchResult],
        ) -> Result<(), StoreError> {
            self.inner
                .clone()
                .query(partition, addresses, results)
                .await
        }

        async fn get_metadata(
            self: Arc<Self>,
            partition: Partition,
            address: Address,
        ) -> Result<StoreGetData, StoreError> {
            self.inner.clone().get_metadata(partition, address).await
        }

        async fn put(
            self: Arc<Self>,
            partition: Partition,
            address: Address,
            fragment: Fragment,
            payload: Option<Bytes>,
            force: bool,
        ) -> Result<(), StoreError> {
            self.puts.lock().expect("puts lock").push(address);
            self.inner
                .clone()
                .put(partition, address, fragment, payload, force)
                .await
        }

        async fn obliterate(
            self: Arc<Self>,
            partition: Partition,
            address: Address,
            stats: Arc<StoreObliterateStats>,
        ) -> Result<(), StoreError> {
            self.inner
                .clone()
                .obliterate(partition, address, stats)
                .await
        }

        async fn evict(
            self: Arc<Self>,
            max_capacity: usize,
            sync_data: bool,
            sink: Option<lore_storage::gc_event::GcEventSinkRef>,
        ) -> Result<usize, StoreError> {
            self.inner
                .clone()
                .evict(max_capacity, sync_data, sink)
                .await
        }

        async fn compact(
            self: Arc<Self>,
            max_size: usize,
            at: Option<usize>,
            sync_data: bool,
            sink: Option<lore_storage::gc_event::GcEventSinkRef>,
        ) -> Result<Option<usize>, StoreError> {
            self.inner
                .clone()
                .compact(max_size, at, sync_data, sink)
                .await
        }

        async fn compact_resume_at(self: Arc<Self>) -> Option<usize> {
            self.inner.clone().compact_resume_at().await
        }

        fn max_query_batch(&self) -> Option<usize> {
            self.inner.max_query_batch()
        }

        async fn flush(self: Arc<Self>, sync_data: bool) -> Result<(), StoreError> {
            self.inner.clone().flush(sync_data).await
        }

        async fn verify(self: Arc<Self>, heal: bool) -> Result<(), StoreError> {
            self.inner.clone().verify(heal).await
        }

        async fn copy(
            self: Arc<Self>,
            source_partition: Partition,
            source_address: Address,
            destination_partition: Partition,
            destination_context: Context,
            behavior: CopyBehavior,
        ) -> Result<(), StoreError> {
            self.inner
                .clone()
                .copy(
                    source_partition,
                    source_address,
                    destination_partition,
                    destination_context,
                    behavior,
                )
                .await
        }
    }

    /// The public QUIC storage factory, built the way production builds the `lore-storage/0.4`
    /// service: auth on, write enforcement on, and the configured policy applied. Every service it
    /// builds hands its session map to `maps`, so a test reads the server's own session table.
    struct ExpiryQuicFactory {
        service_store: ServiceStore,
    }

    impl ExpiryQuicFactory {
        fn new(
            immutable: Arc<dyn ImmutableStore>,
            mutable: Arc<dyn MutableStore>,
            policy: CallerCapabilityPolicy,
            maps: Arc<std::sync::Mutex<Vec<Arc<SessionMap>>>>,
        ) -> Self {
            let repository_authorizer = authorizer();
            let jwt_verifier = Arc::new(Some(verifier()));
            let mut service_store = ServiceStore::default();
            service_store.add_service(
                TEST_PROTOCOL_V4,
                Box::new(move |context: Arc<AttributeMap>| {
                    let service = StorageServiceV4::new(
                        jwt_verifier.clone(),
                        repository_authorizer.clone(),
                        immutable.clone(),
                        immutable.clone(),
                        mutable.clone(),
                        true,
                        Arc::new(UserAgentFilter::default()),
                    )
                    .with_caller_capability_policy(policy);
                    maps.lock()
                        .expect("maps lock")
                        .push(service.session_map.clone());
                    Box::new(StreamHandler::new(
                        Arc::new(service),
                        context,
                        AdmissionLimits {
                            process_limit: 100,
                            inflight_limit: 800,
                            handler_timeout: None,
                            permit_timeout: None,
                        },
                    )) as Box<dyn StreamDataHandler>
                }),
            );
            Self { service_store }
        }
    }

    impl StreamHandlerFactory for ExpiryQuicFactory {
        fn supported_protocols(&self) -> Vec<String> {
            self.service_store.get_supported_services()
        }

        fn get_stream_handler_builder(
            &self,
            protocol: &str,
        ) -> Option<(&&'static str, &StreamDataHandlerBuilder)> {
            self.service_store.get_stream_builder(protocol)
        }
    }

    async fn fresh_stores() -> (Arc<dyn ImmutableStore>, Arc<dyn MutableStore>) {
        let immutable = lore_storage::local::immutable_store::create(
            None::<&str>,
            ImmutableStoreCreateOptions::none(),
            false,
            ImmutableStoreSettings {
                protect_local_fragment: false,
                implicit_durable_stored: true,
                isolate_partitions: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let mutable = lore_storage::local::mutable_store::create(
            None::<&str>,
            lore_storage::MutableStoreSettings::default(),
            immutable.clone(),
        )
        .await
        .unwrap();
        (immutable, mutable)
    }

    /// The real auth-ON gRPC stack on `listener`, serving the environment a `lore://` connect
    /// reads and the SAME stores the QUIC listener serves.
    async fn start_grpc(
        listener: std::net::TcpListener,
        addr: SocketAddr,
        immutable: Arc<dyn ImmutableStore>,
        mutable: Arc<dyn MutableStore>,
        policy: CallerCapabilityPolicy,
    ) -> tokio::sync::oneshot::Sender<()> {
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let signal = async {
            shutdown_rx.await.ok();
        };
        let notification_sender: Arc<dyn lore_revision::notification::NotificationSender> =
            Arc::new(lore_server::notification::local::NotificationSender::default());
        let hook_dispatcher = Arc::new(HookDispatcher::empty());
        let environment = EnvironmentConfig {
            endpoint: Some(lore_transport::Endpoint {
                auth_url: Some(UNREACHABLE_AUTH_URL.to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let (stopped_tx, mut stopped_rx) = tokio::sync::oneshot::channel::<String>();
        // Background server task in a test; LORE_CONTEXT propagation is unnecessary here.
        #[allow(clippy::disallowed_methods)]
        tokio::spawn(async move {
            let repository_catalog = Arc::new(BaselineRepositoryCatalog::new(
                BaselineAccess::Reachable,
                immutable.clone(),
                mutable.clone(),
            ));
            let outcome = async {
                GrpcServerBuilder::new()
                    .with_environment(environment)
                    .with_feature(FeatureSettings::default())
                    .with_immutable_store(immutable.clone(), immutable)
                    .with_mutable_store(mutable)
                    .with_lock_store(None)
                    .with_domain_context(None)
                    .with_notification(notification_sender, None)
                    .with_hook_dispatcher(hook_dispatcher)
                    .with_tls_config(None, None, None)?
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
                    .with_caller_capability_policy(policy)
                    .with_jwt_verifier(Some(verifier()), true, authorizer(), repository_catalog)?
                    .serve_with_listener(listener, signal)
                    .await
            }
            .await;
            let _ = stopped_tx.send(match outcome {
                Ok(()) => "stopped before the test finished".to_string(),
                Err(error) => format!("failed: {error}"),
            });
        });
        for _ in 0..50 {
            if let Ok(reason) = stopped_rx.try_recv() {
                panic!("test gRPC server on {addr} {reason}");
            }
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                return shutdown_tx;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("test gRPC server on {addr} never accepted a connection");
    }

    /// The running cell and the handles a test reads it through.
    struct Cell {
        addr: SocketAddr,
        /// The raw store, uncounted: reads of what is really stored.
        immutable: Arc<dyn ImmutableStore>,
        /// The counting wrapper both listeners serve.
        recording: Arc<RecordingImmutableStore>,
        maps: Arc<std::sync::Mutex<Vec<Arc<SessionMap>>>>,
        _grpc: tokio::sync::oneshot::Sender<()>,
        _quic: QuinnServer,
    }

    async fn start_cell(policy: CallerCapabilityPolicy) -> Cell {
        let (tcp, udp) = bind_matched_pair();
        let addr: SocketAddr = tcp.local_addr().expect("tcp addr");
        let (raw, mutable) = fresh_stores().await;
        let recording = Arc::new(RecordingImmutableStore {
            inner: raw.clone(),
            puts: std::sync::Mutex::new(Vec::new()),
            calls: AtomicUsize::new(0),
        });
        let immutable: Arc<dyn ImmutableStore> = recording.clone();
        let maps = Arc::new(std::sync::Mutex::new(Vec::new()));
        let grpc = start_grpc(tcp, addr, immutable.clone(), mutable.clone(), policy).await;
        let (cert_file, pkey_file, _ca) = server_certs().expect("test certificate paths");
        let quic = QuinnServer::start(
            QuinnConfigBuilder::new()
                .socket(udp)
                .cert_file(cert_file)
                .pkey_file(pkey_file)
                .stream_handler_factory(Box::new(ExpiryQuicFactory::new(
                    immutable,
                    mutable,
                    policy,
                    maps.clone(),
                )))
                .build()
                .expect("quinn config"),
        )
        .expect("quinn server start");
        Cell {
            addr,
            immutable: raw,
            recording,
            maps,
            _grpc: grpc,
            _quic: quic,
        }
    }

    impl Cell {
        async fn stored(&self, partition: RepositoryId, address: Address) -> bool {
            self.immutable.clone().get(partition, address).await.is_ok()
        }

        /// Every session the cell's one QUIC connection holds: `(declared, expires_at)`.
        fn sessions(&self) -> Vec<(bool, Option<u64>)> {
            self.maps
                .lock()
                .expect("maps lock")
                .iter()
                .flat_map(|map| {
                    map.entries
                        .iter()
                        .map(|entry| (entry.declared, entry.expires_at))
                        .collect::<Vec<_>>()
                })
                .collect()
        }
    }

    /// A connection over the production connect path with `access_token`. The identity is unique
    /// per call because the transport's connection cache is process-global and keyed by url plus
    /// identity.
    async fn connect(
        cell: &Cell,
        partition: RepositoryId,
        access_token: &str,
    ) -> Result<(Arc<lore_transport::Connection>, String), Box<dyn Error>> {
        let identity = format!("wp124-expiry-{}", random::<u32>());
        let connection = lore_transport::connect(
            &format!("lore://{}", cell.addr),
            &identity,
            partition,
            1,
            "",
            access_token,
        )
        .await?;
        Ok((connection, identity))
    }

    // ---- managed pushes cross expiry --------------------------------------------------------

    /// A managed sequence of puts whose token expires partway through completes after exactly one
    /// rebind, and every fragment is applied exactly once.
    #[tokio::test]
    async fn a_managed_push_that_crosses_token_expiry_completes_after_one_rebind() -> TestResult {
        let execution = setup_execution("test".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                // Strict: a managed write needs a declared session, so the rebind must re-declare.
                let cell = start_cell(CallerCapabilityPolicy::RequireOutcomeUnknownV1).await;
                let partition = random::<RepositoryId>();
                let exp = now_secs() + 3;
                let (connection, identity) =
                    connect(&cell, partition, &token(partition, exp)).await?;
                let session = connection.session(partition, "wp124-expiry").await?;
                let operation = CallerOperationContext::new(
                    uuid::Uuid::now_v7(),
                    partition,
                    Arc::new(VolatileAttemptStore::new()),
                );

                let mut addresses = Vec::new();
                let put_one = |addresses: &mut Vec<Address>| {
                    let (fragment, address, payload) = fragment::generate_random();
                    addresses.push(address);
                    let session = session.clone();
                    let operation = operation.clone();
                    async move {
                        with_caller_operation(
                            operation,
                            session.put(address, fragment, Some(payload)),
                        )
                        .await
                    }
                };

                // Before expiry: the declared session opens once.
                for _ in 0..2 {
                    put_one(&mut addresses).await?;
                }
                assert_eq!(operation.declared_session_count(), 1);
                let before = cell.sessions();
                assert_eq!(
                    before.iter().filter(|(declared, _)| *declared).count(),
                    1,
                    "one declared session before expiry: {before:?}"
                );
                assert!(now_secs() < exp, "the first puts ran inside the token's life");

                // The token expires on the client's clock; the credentials are refreshed, the way
                // a signed-in user's are.
                while now_secs() <= exp {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                let renewed = lore_transport::connect(
                    &format!("lore://{}", cell.addr),
                    &identity,
                    partition,
                    1,
                    "",
                    &token(partition, now_secs() + 3600),
                )
                .await?;
                assert!(Arc::ptr_eq(&renewed, &connection));

                // After expiry: the rest of the sequence goes through, with no refusal anywhere.
                for _ in 0..4 {
                    put_one(&mut addresses).await?;
                }

                let sessions = cell.sessions();
                assert_eq!(
                    sessions.iter().filter(|(declared, _)| *declared).count(),
                    2,
                    "exactly one rebind: the first declared session and its replacement {sessions:?}"
                );
                assert_eq!(operation.declared_session_count(), 1);
                assert_eq!(addresses.len(), 6);
                for address in &addresses {
                    assert!(cell.stored(partition, *address).await, "{address:?}");
                    assert_eq!(
                        cell.recording.puts_of(*address),
                        1,
                        "each fragment reached the store exactly once"
                    );
                }
                assert_eq!(cell.recording.total_puts(), 6);
                Ok(())
            })
            .await
    }

    // ---- an expired session loses write access ----------------------------------------------

    #[tokio::test]
    async fn a_session_past_its_token_expiry_plus_leeway_loses_write_access() -> TestResult {
        let execution = setup_execution("test".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                let cell = start_cell(CallerCapabilityPolicy::CompatibleSingleReplica).await;
                let partition = random::<RepositoryId>();
                // 45 s old: the verifier's 60 s leeway still accepts it for ~15 s.
                let exp = now_secs().saturating_sub(TOKEN_EXP_LEEWAY_SECS - 15);
                let stale = token(partition, exp);
                let (connection, _) = connect(&cell, partition, &stale).await?;
                // The raw storage handle: no session layer, so nothing rebinds on the client's
                // own clock and the server's check is what answers.
                let storage = connection.storage().await?;
                let session_id = storage.session_start(partition, "wp124-revoked").await?;

                // Control: inside the leeway the session writes and reads normally.
                let (fragment, address, payload) = fragment::generate_random();
                storage
                    .put(session_id, address, fragment, Some(payload.clone()))
                    .await
                    .map_err(|error| format!("inside the leeway the put is served: {error:?}"))?;
                assert!(cell.stored(partition, address).await);
                let (_, served) = storage.get(session_id, &address).await?;
                assert_eq!(served, payload);
                assert_eq!(
                    cell.sessions().len(),
                    1,
                    "one session, with expires_at = exp + leeway"
                );
                assert_eq!(
                    cell.sessions()[0].1,
                    Some(exp + TOKEN_EXP_LEEWAY_SECS),
                    "the server derived the session's expiry from the token"
                );

                // Past exp + leeway the same session is refused.
                while now_secs() <= exp + TOKEN_EXP_LEEWAY_SECS {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
                let puts_before = cell.recording.total_puts();
                let calls_before = cell.recording.calls.load(Ordering::SeqCst);

                let (fragment, refused_address, refused_payload) = fragment::generate_random();
                let error = storage
                    .put(session_id, refused_address, fragment, Some(refused_payload))
                    .await
                    .expect_err("an expired session may not write");
                assert!(is_session_expired(&error), "storage status 201: {error:?}");
                assert!(!error.is_outcome_unknown(), "{error:?}");
                assert!(
                    !cell.stored(partition, refused_address).await,
                    "the refused put left nothing behind"
                );
                assert_eq!(
                    cell.recording.total_puts(),
                    puts_before,
                    "the refused put never reached the store"
                );

                // The entry stays, so a sibling is refused the same way.
                let (fragment, sibling_address, sibling_payload) = fragment::generate_random();
                let sibling = storage
                    .put(session_id, sibling_address, fragment, Some(sibling_payload))
                    .await
                    .expect_err("a sibling on the same expired id");
                assert!(is_session_expired(&sibling), "{sibling:?}");
                assert_eq!(cell.sessions().len(), 1, "the refusal kept the entry");

                // Reads follow the one switch.
                let read = storage.get(session_id, &address).await;
                if TOKEN_EXPIRY_GATES_READS {
                    let error = read.expect_err("reads are gated while the switch is on");
                    assert!(is_session_expired(&error), "{error:?}");
                    assert_eq!(
                        cell.recording.calls.load(Ordering::SeqCst),
                        calls_before,
                        "a refused read never reached the store"
                    );
                } else {
                    assert_eq!(read?.1, payload, "reads stay open with the switch off");
                }

                // The user cannot get a replacement: the verifier refuses the same token at
                // session start, and a StorageSession built on it cannot write.
                let renewal = storage
                    .session_start(partition, "wp124-revoked-renew")
                    .await;
                assert!(
                    renewal.is_err(),
                    "a token past exp + leeway cannot start a session"
                );
                let pool_session = connection.session(partition, "wp124-revoked-pool").await;
                let (fragment, stranded_address, stranded_payload) = fragment::generate_random();
                let stranded = match pool_session {
                    Ok(session) => session
                        .put(stranded_address, fragment, Some(stranded_payload))
                        .await
                        .map(|_| ()),
                    Err(error) => Err(error),
                };
                assert!(stranded.is_err(), "no write after revocation");
                assert!(!cell.stored(partition, stranded_address).await);
                assert_eq!(cell.recording.total_puts(), puts_before);
                Ok(())
            })
            .await
    }
}

// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//
// WP-120 strict caller admission with QUIC on.
//
// [SERVER]-class: one in-process, auth-ON loopback cell serving the real `lore-server` gRPC
// stack (`GrpcServerBuilder` with the caller-capability policy applied; strict requires JWT
// authentication, so a real `JwtVerifier` is installed) and a real QUIC listener whose
// `lore-storage/0.4` service is built the way `server.rs`'s public QUIC factory builds it
// (`StorageServiceV4::new(..).with_caller_capability_policy(policy)`). The client side is the
// stock `lore-transport` client over the production connect path: `lore://` puts storage on
// QUIC, `grpc://` puts it on gRPC, and `with_caller_operation` is the managed declaration.
//
// What it proves, per policy:
//   strict:     a stock (undeclared) QUIC Put is refused with storage status 200 and the
//               fragment is absent from the server's store; a stock gRPC Put is refused (the gRPC
//               gate is live); a managed gRPC Put is admitted; a QUIC Get of that gRPC-seeded
//               fragment returns its bytes; a managed (declared-session) QUIC Put is admitted,
//               stored and readable, while the identical undeclared QUIC Put of the same fragment
//               was refused first, so the admission is the declaration's and not an open door.
//   compatible: the same stock QUIC Put is stored (positive control for the refusal).
//
// The declared session is witnessed on the client (`CallerOperationContext::declared_session_count`
// is 1 for the QUIC Put and 0 for the gRPC Put), not inferred from the URL. The server's own
// session table is not read here; `quic_declared_session_test.rs` does that.
//
// Not covered here: the settings-to-policy read in `server.rs`'s `async_main` and the private
// `QuicPublicStreamHandler`. A strict boot of the real binary needs the coordinated Postgres
// fragment route and governed domain enforcement, which no in-repo live tier provisions today.
#[cfg(all(test, feature = "integration_tests"))]
mod quic_strict_admission_tests {
    use std::collections::HashMap;
    use std::error::Error;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use async_trait::async_trait;
    use lore_base::runtime::LORE_CONTEXT;
    use lore_base::types::Context;
    use lore_base::types::Hash;
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
    use lore_storage::local::immutable_store::ImmutableStoreCreateOptions;
    use lore_storage::local::immutable_store::ImmutableStoreSettings;
    use lore_telemetry::user_agent_filter::UserAgentFilter;
    use lore_transport::attempt_store::AttemptRecord;
    use lore_transport::attempt_store::AttemptResolution;
    use lore_transport::attempt_store::AttemptStore;
    use lore_transport::attempt_store::LockOwnership;
    use lore_transport::attempt_store::VolatileAttemptStore;
    use lore_transport::caller_operation::CallerOperationContext;
    use lore_transport::caller_operation::ManagedAttemptIntent;
    use lore_transport::caller_operation::with_caller_operation;
    use lore_transport::error::ProtocolError;
    use lore_transport::outcome::AttemptId;
    use rand::random;

    use crate::common::net_common::bind_matched_pair;
    use crate::setup_execution;

    type TestResult = Result<(), Box<dyn Error>>;

    const KID: &str = "wp120-strict-quic-key";
    const SECRET: &[u8] = b"wp120-strict-quic-hs256-secret";
    const AUDIENCE: &str = "wp120-strict-quic-audience";
    const ISSUER: &str = "wp120-strict-quic-issuer";
    /// Advertised so the client presents its supplied token; never contacted, because a
    /// supplied access token short-circuits the exchange.
    const UNREACHABLE_AUTH_URL: &str = "https://auth.invalid/wp120-strict-quic";

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

    /// A read+write token for `repository`, so every refusal below is admission, not authz.
    fn token(repository: RepositoryId) -> String {
        let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
        header.kid = Some(KID.to_string());
        let expires = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs()
            + 3600;
        let claims = serde_json::json!({
            "sub": "wp120-strict-quic-user",
            "iss": ISSUER,
            "iat": 0,
            "exp": expires,
            "aud": [AUDIENCE],
            "env": "test",
            "name": "WP-120 strict QUIC",
            "preferred_username": "wp120-strict-quic-user",
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

    /// An in-memory journal that accepts managed intents. `VolatileAttemptStore` alone refuses
    /// them (a legacy journal must not implicitly promise managed recovery).
    #[derive(Default)]
    struct ManagedJournal {
        inner: VolatileAttemptStore,
        /// Every record of either kind, so a test can prove an RPC wrote nothing.
        records: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl AttemptStore for ManagedJournal {
        async fn record_managed(
            &self,
            record: &AttemptRecord,
            _intent: &ManagedAttemptIntent,
        ) -> Result<(), ProtocolError> {
            self.records
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.record(record).await
        }
        async fn record(&self, record: &AttemptRecord) -> Result<(), ProtocolError> {
            self.records
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.record(record).await
        }
        async fn lookup(&self, id: &AttemptId) -> Result<Option<AttemptRecord>, ProtocolError> {
            self.inner.lookup(id).await
        }
        async fn unresolved(&self) -> Result<Vec<AttemptRecord>, ProtocolError> {
            self.inner.unresolved().await
        }
        async fn record_ownership(&self, ownership: &LockOwnership) -> Result<(), ProtocolError> {
            self.inner.record_ownership(ownership).await
        }
        async fn ownership_for(
            &self,
            branch: &Context,
            resource_hash: &Hash,
        ) -> Result<Option<LockOwnership>, ProtocolError> {
            self.inner.ownership_for(branch, resource_hash).await
        }
        async fn clear_ownership(
            &self,
            branch: &Context,
            resource_hash: &Hash,
        ) -> Result<(), ProtocolError> {
            self.inner.clear_ownership(branch, resource_hash).await
        }
        async fn resolve(
            &self,
            id: &AttemptId,
            resolution: AttemptResolution,
        ) -> Result<(), ProtocolError> {
            self.inner.resolve(id, resolution).await
        }
    }

    /// The public QUIC storage factory, built the way production builds the `lore-storage/0.4`
    /// service: auth on, write enforcement on, and the configured policy applied.
    struct PolicyQuicFactory {
        service_store: ServiceStore,
    }

    impl PolicyQuicFactory {
        fn new(
            immutable: Arc<dyn ImmutableStore>,
            mutable: Arc<dyn MutableStore>,
            policy: CallerCapabilityPolicy,
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

    impl StreamHandlerFactory for PolicyQuicFactory {
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

    /// The real auth-ON gRPC stack on `listener`, with `policy` installed as the
    /// caller-capability layer, serving the SAME stores the QUIC listener serves.
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

    fn start_quic(
        udp: std::net::UdpSocket,
        immutable: Arc<dyn ImmutableStore>,
        mutable: Arc<dyn MutableStore>,
        policy: CallerCapabilityPolicy,
    ) -> QuinnServer {
        let (cert_file, pkey_file, _ca) = server_certs().expect("test certificate paths");
        QuinnServer::start(
            QuinnConfigBuilder::new()
                .socket(udp)
                .cert_file(cert_file)
                .pkey_file(pkey_file)
                .stream_handler_factory(Box::new(PolicyQuicFactory::new(
                    immutable, mutable, policy,
                )))
                .build()
                .expect("quinn config"),
        )
        .expect("quinn server start")
    }

    /// A storage session over the production connect path. `scheme` picks the transport:
    /// `lore` is QUIC storage, `grpc` is gRPC storage. The identity is unique per call because
    /// the transport's connection cache is process-global and keyed by url plus identity.
    async fn session(
        scheme: &str,
        addr: SocketAddr,
        partition: RepositoryId,
    ) -> Result<Arc<lore_transport::session::StorageSession>, ProtocolError> {
        let identity = format!("wp120-strict-quic-{scheme}-{}", random::<u32>());
        let connection = lore_transport::connect(
            &format!("{scheme}://{addr}"),
            &identity,
            partition,
            1,
            "",
            &token(partition),
        )
        .await?;
        connection.session(partition, "wp120-strict-quic").await
    }

    fn managed(partition: RepositoryId) -> (CallerOperationContext, Arc<ManagedJournal>) {
        let journal = Arc::new(ManagedJournal::default());
        (
            CallerOperationContext::new(uuid::Uuid::now_v7(), partition, journal.clone()),
            journal,
        )
    }

    async fn stored(
        immutable: &Arc<dyn ImmutableStore>,
        partition: RepositoryId,
        address: lore_base::types::Address,
    ) -> bool {
        immutable.clone().get(partition, address).await.is_ok()
    }

    #[tokio::test]
    async fn strict_cell_refuses_undeclared_writes_and_admits_declared_managed_writes_on_both_transports()
    -> TestResult {
        let execution = setup_execution("test".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                let (tcp, udp) = bind_matched_pair();
                let addr: SocketAddr = tcp.local_addr()?;
                let policy = CallerCapabilityPolicy::RequireOutcomeUnknownV1;
                let (immutable, mutable) = fresh_stores().await;
                let _grpc = start_grpc(tcp, addr, immutable.clone(), mutable.clone(), policy).await;
                let _quic = start_quic(udp, immutable.clone(), mutable.clone(), policy);
                let partition = random::<RepositoryId>();

                // 1. A stock QUIC Put is refused with storage status 200 and stores nothing.
                let quic = session("lore", addr, partition).await?;
                let (fragment, address, payload) = fragment::generate_random();
                let error = quic
                    .put(address, fragment, Some(payload))
                    .await
                    .expect_err("strict must refuse an undeclared QUIC Put");
                assert!(
                    !error.is_outcome_unknown(),
                    "a pre-dispatch refusal is decisive, never an unknown outcome: {error:?}"
                );
                assert!(
                    format!("{error:?} {error}").contains("200"),
                    "the refusal must carry storage status 200 (unsupported-client): {error:?}"
                );
                assert!(
                    !stored(&immutable, partition, address).await,
                    "a refused QUIC Put must leave no fragment behind"
                );

                // 2. A stock gRPC Put is refused too: the gRPC gate is live on this cell.
                let grpc = session("grpc", addr, partition).await?;
                let (fragment, address, payload) = fragment::generate_random();
                let error = grpc
                    .put(address, fragment, Some(payload))
                    .await
                    .expect_err("strict must refuse an undeclared gRPC Put");
                assert!(!error.is_outcome_unknown(), "{error:?}");
                assert!(!stored(&immutable, partition, address).await);

                // 3. A managed gRPC Put is admitted and stored, and (a fragment Put being
                //    unjournaled) records nothing in the caller's attempt journal.
                let (fragment, address, payload) = fragment::generate_random();
                let (operation, journal) = managed(partition);
                with_caller_operation(
                    operation.clone(),
                    grpc.put(address, fragment, Some(payload.clone())),
                )
                .await
                .map_err(|error| format!("a managed gRPC Put must be admitted: {error:?}"))?;
                assert!(stored(&immutable, partition, address).await);
                assert_eq!(
                    journal.records.load(std::sync::atomic::Ordering::SeqCst),
                    0,
                    "a managed fragment Put must write no journal child"
                );
                assert!(journal.unresolved().await?.is_empty());
                assert_eq!(
                    operation.declared_session_count(),
                    0,
                    "gRPC declares per request and starts no QUIC declared session"
                );

                // 4. A QUIC Get of the gRPC-seeded fragment returns its bytes.
                let (read_fragment, read_payload) = quic.get(&address).await?;
                assert_eq!(read_fragment.size_content, fragment.size_content);
                assert_eq!(
                    read_payload, payload,
                    "QUIC Get must return the seeded bytes"
                );

                // 5. The undeclared QUIC Put of a fresh fragment is refused, then the SAME fragment
                //    Put inside a managed scope on the SAME session is admitted and stored. The
                //    refusal first makes the admission the declaration's: nothing else changed
                //    between the two calls.
                let (declared_fragment, declared_address, declared_payload) =
                    fragment::generate_random();
                let refused = quic
                    .put(
                        declared_address,
                        declared_fragment,
                        Some(declared_payload.clone()),
                    )
                    .await
                    .expect_err("strict must refuse the undeclared QUIC Put of this fragment");
                assert!(lore_transport::error::is_unsupported_client(&refused));
                assert!(
                    !stored(&immutable, partition, declared_address).await,
                    "the refused QUIC Put must store nothing"
                );
                let (quic_operation, quic_journal) = managed(partition);
                with_caller_operation(
                    quic_operation.clone(),
                    quic.put(
                        declared_address,
                        declared_fragment,
                        Some(declared_payload.clone()),
                    ),
                )
                .await
                .map_err(|error| format!("a managed QUIC Put must be admitted: {error:?}"))?;
                assert_eq!(
                    quic_operation.declared_session_count(),
                    1,
                    "the managed QUIC Put ran on one declared session"
                );
                assert!(
                    stored(&immutable, partition, declared_address).await,
                    "the admitted managed QUIC Put must reach the store"
                );
                assert_eq!(
                    quic_journal
                        .records
                        .load(std::sync::atomic::Ordering::SeqCst),
                    0,
                    "a managed QUIC fragment Put writes no journal child"
                );

                // 6. It reads back over QUIC, undeclared, with the same bytes.
                let (_, declared_read) = quic.get(&declared_address).await?;
                assert_eq!(
                    declared_read, declared_payload,
                    "the managed QUIC write must read back"
                );
                Ok(())
            })
            .await
    }

    /// Counts the strict QUIC refusals the SERVER answered, from the event its stream handler
    /// emits for each (`handler_error_label = "UnsupportedClient"`).
    ///
    /// The handler runs on the net runtime's threads, so the subscriber is process-global. Tests
    /// in this binary run concurrently, so each refusal is attributed by the execution context
    /// its task runs under: a test registers its own context and reads only its own count.
    struct RefusalCounter;

    static REFUSALS: std::sync::Mutex<Vec<(usize, usize)>> = std::sync::Mutex::new(Vec::new());

    fn context_key(context: &Arc<dyn std::any::Any + Send + Sync>) -> usize {
        Arc::as_ptr(context).cast::<()>() as usize
    }

    /// Installs the process-global counting subscriber (once) and registers `execution` so its
    /// refusals are counted. Returns the key to read them with.
    fn count_refusals_for(
        execution: &Arc<lore_revision::interface::ExecutionContext>,
    ) -> Result<usize, Box<dyn Error>> {
        static INSTALLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        let installed = *INSTALLED.get_or_init(|| {
            tracing::subscriber::set_global_default(tracing_subscriber::layer::SubscriberExt::with(
                tracing_subscriber::registry(),
                RefusalCounter,
            ))
            .is_ok()
        });
        if !installed {
            return Err("another global tracing subscriber is installed; cannot count".into());
        }
        let context: Arc<dyn std::any::Any + Send + Sync> = execution.clone();
        let key = context_key(&context);
        REFUSALS
            .lock()
            .map_err(|_poisoned| "refusal registry poisoned")?
            .push((key, 0));
        Ok(key)
    }

    fn refusals_for(key: usize) -> usize {
        REFUSALS
            .lock()
            .ok()
            .and_then(|entries| {
                entries
                    .iter()
                    .find(|(entry, _)| *entry == key)
                    .map(|(_, count)| *count)
            })
            .unwrap_or(0)
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

    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for RefusalCounter {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
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
    }

    /// Stores `count` fragments the way `lore commit` does: unmanaged, each through the write
    /// tracker, dispatched back to back without awaiting one before the next starts. Returns
    /// their addresses.
    async fn commit_style_store(
        local: &Arc<dyn ImmutableStore>,
        session: &Arc<lore_transport::session::StorageSession>,
        partition: RepositoryId,
        count: usize,
    ) -> Result<Vec<lore_base::types::Address>, Box<dyn Error>> {
        let tracker = Arc::new(lore_storage::write_tracker::WriteTracker::new());
        let mut addresses = Vec::new();
        for _ in 0..count {
            let (fragment, address, payload) = fragment::generate_random();
            lore_storage::write::store_fragment(
                local.clone(),
                partition,
                address,
                fragment,
                payload,
                true,
                Some(session.clone()),
                lore_storage::write_tracker::WriteContext::tracked(Some(tracker.clone()), None),
                None,
            )
            .await?;
            addresses.push(address);
        }
        tracker.await_all().await?;
        Ok(addresses)
    }

    /// WP-124 follow-up (b), measured: how many refusals a strict QUIC cell answers for an
    /// unmanaged commit-style store of 64 fragments dispatched concurrently through the write
    /// tracker. Without the latch every fragment is refused; with it, only the writes already in
    /// flight when the first refusal lands are. The count is printed so a run can be compared
    /// across trees.
    #[tokio::test]
    async fn strict_cell_refusals_for_a_concurrent_commit_style_store_are_measured() -> TestResult {
        const FRAGMENTS: usize = 64;
        let execution = setup_execution("test".to_string());
        let key = count_refusals_for(&execution)?;
        LORE_CONTEXT
            .scope(execution, async move {
                let (tcp, udp) = bind_matched_pair();
                let addr: SocketAddr = tcp.local_addr()?;
                let policy = CallerCapabilityPolicy::RequireOutcomeUnknownV1;
                let (immutable, mutable) = fresh_stores().await;
                let _grpc = start_grpc(tcp, addr, immutable.clone(), mutable.clone(), policy).await;
                let _quic = start_quic(udp, immutable.clone(), mutable.clone(), policy);
                let partition = random::<RepositoryId>();
                let (local, _local_mutable) = fresh_stores().await;
                let quic = session("lore", addr, partition).await?;

                let addresses = commit_style_store(&local, &quic, partition, FRAGMENTS).await?;

                let refusals = refusals_for(key);
                eprintln!(
                    "MEASURED server refusals for {FRAGMENTS} concurrent fragments: {refusals}"
                );
                assert!(refusals >= 1, "the strict cell refused the stock writes");
                for address in &addresses {
                    assert!(
                        !stored(&immutable, partition, *address).await,
                        "a strict cell stores none of an unmanaged write"
                    );
                    assert!(
                        stored(&local, partition, *address).await,
                        "every fragment stays in the local store for push"
                    );
                }
                Ok(())
            })
            .await
    }

    /// The deterministic form: one fragment is stored and awaited, so the cell's refusal is
    /// known, and then 63 more are stored. A strict cell answers exactly one refusal in total
    /// (without the latch it answers 64).
    #[tokio::test]
    async fn strict_cell_answers_one_refusal_once_a_commit_style_store_has_learned_it() -> TestResult
    {
        const REST: usize = 63;
        let execution = setup_execution("test".to_string());
        let key = count_refusals_for(&execution)?;
        LORE_CONTEXT
            .scope(execution, async move {
                let (tcp, udp) = bind_matched_pair();
                let addr: SocketAddr = tcp.local_addr()?;
                let policy = CallerCapabilityPolicy::RequireOutcomeUnknownV1;
                let (immutable, mutable) = fresh_stores().await;
                let _grpc = start_grpc(tcp, addr, immutable.clone(), mutable.clone(), policy).await;
                let _quic = start_quic(udp, immutable.clone(), mutable.clone(), policy);
                let partition = random::<RepositoryId>();
                let (local, _local_mutable) = fresh_stores().await;
                let quic = session("lore", addr, partition).await?;

                commit_style_store(&local, &quic, partition, 1).await?;
                let after_first = refusals_for(key);
                let rest = commit_style_store(&local, &quic, partition, REST).await?;

                let refusals = refusals_for(key);
                eprintln!("MEASURED server refusals for 1 + {REST} staged fragments: {refusals}");
                assert_eq!(after_first, 1, "the first write is refused once");
                assert_eq!(refusals, 1, "the strict cell is not asked again");
                for address in &rest {
                    assert!(!stored(&immutable, partition, *address).await);
                    assert!(stored(&local, partition, *address).await);
                }
                Ok(())
            })
            .await
    }
    /// Positive control: the identical stock QUIC Put is stored when the policy is compatible.
    #[tokio::test]
    async fn compatible_cell_stores_a_stock_quic_put() -> TestResult {
        let execution = setup_execution("test".to_string());
        LORE_CONTEXT
            .scope(execution, async move {
                let (tcp, udp) = bind_matched_pair();
                let addr: SocketAddr = tcp.local_addr()?;
                let policy = CallerCapabilityPolicy::CompatibleSingleReplica;
                let (immutable, mutable) = fresh_stores().await;
                let _grpc = start_grpc(tcp, addr, immutable.clone(), mutable.clone(), policy).await;
                let _quic = start_quic(udp, immutable.clone(), mutable.clone(), policy);
                let partition = random::<RepositoryId>();

                let quic = session("lore", addr, partition).await?;
                let (fragment, address, payload) = fragment::generate_random();
                quic.put(address, fragment, Some(payload)).await?;
                assert!(stored(&immutable, partition, address).await);
                Ok(())
            })
            .await
    }
}

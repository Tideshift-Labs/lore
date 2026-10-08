// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::sync::Arc;

use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_base::types::RepositoryId;
use lore_proto::RepositoryQueryRequest;
use lore_revision::repository;
use lore_revision::repository::RepositoryContext;
use lore_revision::repository::RepositoryMetadata;
use lore_server::authnz::repository_authorizer::AllowAllRepositoryAuthorizer;
use lore_server::authnz::repository_authorizer::RepositoryAuthorizer;
use lore_server::authnz::repository_authorizer::VerifiedToken;
use lore_server::grpc::handlers::repository_query::*;
use rand::random;
use tonic::Code;
use tonic::Request;
use tonic::Status;

use crate::store::test_support::test_store_create;

/// Denies every request.
struct DenyAllRepositoryAuthorizer;

#[async_trait::async_trait]
impl RepositoryAuthorizer for DenyAllRepositoryAuthorizer {
    async fn check_repository_access(
        &self,
        _token: Option<&VerifiedToken<'_>>,
        _repository_id: RepositoryId,
        _action: Option<&str>,
    ) -> Result<(), Status> {
        Err(Status::permission_denied("denied"))
    }
}

/// Writes the metadata blob, its pointer and the name → id mapping so a
/// query for `name` or `id` resolves.
async fn seed_repository(
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
    id: RepositoryId,
    name: &str,
) {
    let repository = Arc::new(RepositoryContext::new_server_context(
        immutable_store,
        mutable_store,
        id,
    ));
    let metadata_hash = repository::metadata_store(
        repository.clone(),
        RepositoryMetadata {
            name: name.to_string(),
            creator: "alice".into(),
            ..Default::default()
        },
    )
    .await
    .expect("Failed to store repository metadata");
    repository::metadata_store_hash(repository.clone(), metadata_hash)
        .await
        .expect("Failed to store repository metadata hash");
    repository::store_name_to_id(repository, name, id)
        .await
        .expect("Failed to store repository name to id mapping");
}

fn query_by_id(id: RepositoryId) -> Request<RepositoryQueryRequest> {
    Request::new(RepositoryQueryRequest {
        query: Some(lore_proto::repository_query_request::Query::Id(id.into())),
    })
}

fn query_by_name(name: &str) -> Request<RepositoryQueryRequest> {
    Request::new(RepositoryQueryRequest {
        query: Some(lore_proto::repository_query_request::Query::Name(
            name.into(),
        )),
    })
}

/// Denial answers `RepositoryNotFound`, not `permission_denied`: a
/// distinct status would let an unauthorized caller distinguish a
/// partition that exists from one that does not.
#[tokio::test]
async fn denied_query_answers_not_found_for_an_existing_repository() {
    let id = random::<RepositoryId>();
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");
    LORE_CONTEXT
        .scope(execution, async move {
            seed_repository(immutable_store.clone(), mutable_store.clone(), id, "repo").await;
            for request in [query_by_id(id), query_by_name("repo")] {
                let err = handler(
                    request,
                    Arc::new(DenyAllRepositoryAuthorizer),
                    immutable_store.clone(),
                    mutable_store.clone(),
                )
                .await
                .expect_err("denied query must fail");
                assert_eq!(err.code(), Code::NotFound, "{err:?}");
            }
        })
        .await;
}

#[tokio::test]
async fn permitted_query_resolves_by_id_and_by_name() {
    let id = random::<RepositoryId>();
    let (immutable_store, mutable_store, execution) =
        test_store_create().await.expect("Failed to create stores");
    LORE_CONTEXT
        .scope(execution, async move {
            seed_repository(immutable_store.clone(), mutable_store.clone(), id, "repo").await;
            for request in [query_by_id(id), query_by_name("repo")] {
                let response = handler(
                    request,
                    Arc::new(AllowAllRepositoryAuthorizer),
                    immutable_store.clone(),
                    mutable_store.clone(),
                )
                .await
                .expect("permitted query must succeed");
                let repository = response
                    .into_inner()
                    .repository
                    .expect("response should include Repository");
                assert_eq!(repository.name, "repo");
            }
        })
        .await;
}

/// Shared fixtures for the repo-scoped-authz tests on the four
/// `RepositoryMetadataGet`/`RepositoryMetadataSet` handlers (v0 + v1): a
/// stub `UrcAuthApi.CheckUserPermission` server and local, tempdir-backed
/// store + seed helpers. Colocated here because this is where
/// `check_repository_query_authorization` (the thing under test) lives;
/// `pub(crate)` so `repository_metadata_{get,set}.rs` and
/// `repository/v1/repository_metadata_{get,set}.rs` can each host their own
/// `#[cfg(test)] mod tests` against it.
pub(crate) mod authz_test_support {
    use std::convert::Infallible;
    use std::path::Path;
    use std::sync::Arc;

    use lore_base::types::Hash;
    use lore_revision::lore::RepositoryId;
    use lore_revision::repository;
    use lore_revision::repository::RepositoryContext;
    use lore_revision::repository::RepositoryMetadata;
    use lore_storage::ImmutableStore;
    use lore_storage::ImmutableStoreSettings;
    use lore_storage::LocalImmutableStore;
    use lore_storage::LocalMutableStore;
    use lore_storage::MutableStore;
    use lore_storage::MutableStoreSettings;
    use tonic::codegen::*;

    /// Hand-rolled stand-in for the auth service's `UrcAuthApi` gRPC server.
    /// `lore-proto`'s build script compiles `auth_api.proto` with
    /// `.build_server(false)` (lore-server is only ever a *client* of this
    /// API), so there is no generated `UrcAuthApiServer` to bind a fake
    /// implementation to. This mirrors the single-method shape
    /// `tonic-prost-build` emits for a unary RPC (compare
    /// `lore.repository.v1.rs`'s `repository_service_server` module) so the
    /// real `LoreAuthClientHelper` (`lore_server::authnz::auth`) talks to it over
    /// actual HTTP/2, exactly as it would to the real auth service.
    #[derive(Clone)]
    struct StubAuthService {
        allowed_repository_id: RepositoryId,
    }

    impl tonic::server::NamedService for StubAuthService {
        const NAME: &'static str = "epic_urc.UrcAuthApi";
    }

    impl<B> Service<http::Request<B>> for StubAuthService
    where
        B: Body + std::marker::Send + 'static,
        B::Error: Into<StdError> + std::marker::Send + 'static,
    {
        type Response = http::Response<tonic::body::Body>;
        type Error = Infallible;
        type Future = BoxFuture<Self::Response, Self::Error>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            if req.uri().path() != "/epic_urc.UrcAuthApi/CheckUserPermission" {
                return Box::pin(async move {
                    let mut response = http::Response::new(tonic::body::Body::default());
                    let headers = response.headers_mut();
                    headers.insert(
                        tonic::Status::GRPC_STATUS,
                        (tonic::Code::Unimplemented as i32).into(),
                    );
                    headers.insert(
                        http::header::CONTENT_TYPE,
                        tonic::metadata::GRPC_CONTENT_TYPE,
                    );
                    Ok(response)
                });
            }

            #[allow(non_camel_case_types)]
            struct CheckUserPermissionSvc(RepositoryId);
            impl tonic::server::UnaryService<lore_proto::auth::CheckUserPermissionRequest>
                for CheckUserPermissionSvc
            {
                type Response = lore_proto::auth::CheckUserPermissionResponse;
                type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;

                fn call(
                    &mut self,
                    request: tonic::Request<lore_proto::auth::CheckUserPermissionRequest>,
                ) -> Self::Future {
                    let allowed_resource_id = format!("urc-{}", self.0);
                    let fut = async move {
                        let resource_id = request
                            .into_inner()
                            .resource_id
                            .into_iter()
                            .next()
                            .unwrap_or_default();
                        if resource_id == allowed_resource_id {
                            Ok(tonic::Response::new(
                                lore_proto::auth::CheckUserPermissionResponse {
                                    allowed_resource_permission: vec![
                                        lore_proto::auth::ResourcePermission {
                                            resource_id,
                                            permission: vec![
                                                "read".to_string(),
                                                "write".to_string(),
                                            ],
                                        },
                                    ],
                                    denied_resource_permission: vec![],
                                },
                            ))
                        } else {
                            Err(tonic::Status::permission_denied(
                                "stub auth: repository not authorized",
                            ))
                        }
                    };
                    Box::pin(fut)
                }
            }

            let method = CheckUserPermissionSvc(self.allowed_repository_id);
            let codec = tonic_prost::ProstCodec::default();
            let mut grpc = tonic::server::Grpc::new(codec);
            let fut = async move {
                let res = grpc.unary(method, req).await;
                Ok(res)
            };
            Box::pin(fut)
        }
    }

    /// Starts a plaintext (h2c) stub `UrcAuthApi` server on an ephemeral
    /// loopback port that allows exactly `allowed_repository_id` (regardless
    /// of the bearer token presented — the stub only inspects
    /// `resource_id`) and denies every other repository. Returns the
    /// `http://` URL to pass in as `auth_url`; `LoreAuthClientHelper` only
    /// adds TLS when the URL starts with `https://`, so plaintext is enough
    /// here. The server task is detached for the test's lifetime.
    ///
    /// Serves directly on the listener returned by the (already listening)
    /// `bind`, rather than dropping it and handing `Server::serve` a bare
    /// address to rebind — that drop-then-rebind window is a real TOCTOU
    /// race (another process can grab the port before the server rebinds).
    /// Because the socket is listening as soon as `bind` returns, the OS
    /// backlog queues connection attempts even before the spawned task
    /// starts polling `accept`, so no readiness sleep is needed either.
    pub(crate) async fn start_stub_auth_server(allowed_repository_id: RepositoryId) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("read local_addr");

        lore_base::lore_spawn!(async move {
            let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
            let _ = tonic::transport::Server::builder()
                .add_service(StubAuthService {
                    allowed_repository_id,
                })
                .serve_with_incoming(incoming)
                .await;
        });

        format!("http://{addr}")
    }

    /// Fresh, empty, tempdir-backed local stores for a single test.
    pub(crate) async fn new_test_stores() -> (Arc<dyn ImmutableStore>, Arc<dyn MutableStore>) {
        let immutable = LocalImmutableStore::new(None, ImmutableStoreSettings::default())
            .await
            .expect("create immutable store");
        let mutable: Arc<dyn MutableStore> = Arc::new(
            LocalMutableStore::new(
                None::<&Path>,
                MutableStoreSettings::default(),
                immutable.clone(),
            )
            .await
            .expect("create mutable store"),
        );
        (immutable, mutable)
    }

    /// Serializes a minimal metadata blob for `repository_id` and publishes
    /// it as the repository's current metadata pointer (mirroring what a
    /// real `RepositoryCreate` leaves behind), so `RepositoryMetadataGet`
    /// can resolve it and `RepositoryMetadataSet` has a real `expected_hash`
    /// to CAS against. Returns the published hash.
    pub(crate) async fn seed_repository_metadata(
        immutable: Arc<dyn ImmutableStore>,
        mutable: Arc<dyn MutableStore>,
        repository_id: RepositoryId,
        name: &str,
        description: &str,
    ) -> Hash {
        let repository = Arc::new(RepositoryContext::new_server_context(
            immutable,
            mutable,
            repository_id,
        ));
        let hash = repository::metadata_store(
            repository.clone(),
            RepositoryMetadata {
                name: name.to_string(),
                description: description.to_string(),
                default_branch: Default::default(),
                default_branch_name: "main".to_string(),
                creator: "alice".to_string(),
                created: 0,
            },
        )
        .await
        .expect("serialize seed metadata");
        repository::metadata_store_hash(repository, hash)
            .await
            .expect("publish seed metadata pointer");
        hash
    }
}

mod fork_tests {
    use std::sync::Arc;

    use lore_base::types::Hash;
    use lore_base::types::KeyType;
    use lore_storage::KeyValueStream;
    use lore_storage::MutableStore;
    use lore_storage::Partition;
    use lore_storage::StoreError;

    use super::authz_test_support::new_test_stores;
    use super::authz_test_support::seed_repository_metadata;
    use super::*;

    /// Wraps a real `MutableStore`, delegating every method except `store()`,
    /// which always fails once wrapped. Mirrors the self-heal write's actual
    /// failure mode under CR-029 enforcement (the domain-key bypass guard
    /// rejects a `RepositoryId`-typed write on the generic mutable path —
    /// see `lore-postgres/tests/domain_bypass.rs`) without depending on a
    /// live Postgres store.
    struct FailStoreWritesMutableStore {
        inner: Arc<dyn MutableStore>,
    }

    #[async_trait::async_trait]
    impl MutableStore for FailStoreWritesMutableStore {
        async fn load(
            self: Arc<Self>,
            partition: Partition,
            key: Hash,
            key_type: KeyType,
        ) -> Result<Hash, StoreError> {
            self.inner.clone().load(partition, key, key_type).await
        }

        async fn store(
            self: Arc<Self>,
            _partition: Partition,
            _key: Hash,
            _value: Hash,
            _key_type: KeyType,
        ) -> Result<(), StoreError> {
            Err(StoreError::internal(
                "simulated domain-key bypass guard rejection",
            ))
        }

        async fn compare_and_swap(
            self: Arc<Self>,
            partition: Partition,
            key: Hash,
            expected: Hash,
            value: Hash,
            key_type: KeyType,
        ) -> Result<Hash, StoreError> {
            self.inner
                .clone()
                .compare_and_swap(partition, key, expected, value, key_type)
                .await
        }

        async fn list(
            self: Arc<Self>,
            partition: Partition,
            key_type: KeyType,
        ) -> Result<KeyValueStream, StoreError> {
            self.inner.clone().list(partition, key_type).await
        }

        async fn flush(self: Arc<Self>, sync_data: bool) -> Result<(), StoreError> {
            self.inner.clone().flush(sync_data).await
        }
    }

    // CR-029, self-heal writer pin (companion to `lore-postgres/tests/
    // domain_bypass.rs`, which proves the guard itself rejects the write —
    // this proves the call site at line 134 swallows that rejection rather
    // than propagating it). The reviewer's defence for leaving this handler
    // ungated is that a missing name -> ID mapping is repaired best-effort;
    // if a future cleanup ever turns the `let _ = ...` into a `?`, this test
    // must go red.
    #[tokio::test]
    async fn missing_name_mapping_repair_failure_does_not_fail_the_query() {
        let (immutable, mutable) = new_test_stores().await;
        let repository_id: RepositoryId = Context::from([9u8; 16]).into();
        let metadata_hash = seed_repository_metadata(
            immutable.clone(),
            mutable.clone(),
            repository_id,
            "my-repo",
            "a description",
        )
        .await;

        let faulty_mutable: Arc<dyn MutableStore> =
            Arc::new(FailStoreWritesMutableStore { inner: mutable });
        let repository = Arc::new(RepositoryContext::new_server_context(
            immutable,
            faulty_mutable,
            repository_id,
        ));

        let data = repository_query_id(repository, repository_id, None, None)
            .await
            .expect("a failed name-mapping repair must not fail the query itself");

        assert_eq!(data.id, repository_id);
        assert_eq!(data.name, "my-repo");
        assert_eq!(data.metadata, metadata_hash);
    }
}

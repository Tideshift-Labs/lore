// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use std::str::FromStr;
use std::sync::Arc;

use lore_base::error::RepositoryNotFound;
use lore_base::runtime::LORE_CONTEXT;
use lore_base::types::Context;
use lore_error_set::prelude::*;
use lore_proto::RepositoryQueryRequest;
use lore_proto::RepositoryQueryResponse;
use lore_proto::auth::CheckUserPermissionRequest;
use lore_revision::lore::RepositoryId;
use lore_revision::lore_debug;
use lore_revision::repository;
use lore_revision::repository::RepositoryContext;
use lore_revision::repository::RepositoryError;
use lore_transport::RepositoryData;
use tonic::Code;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::info;
use tracing::warn;

use crate::authnz::auth::grpc_get_auth_client;
use crate::authnz::common::create_request_with_authorization;
use crate::grpc::ServerResultExt;
use crate::grpc::extract_correlation_id;
use crate::grpc::get_user_id;
use crate::util::setup_execution;

#[tracing::instrument(name = "RepositoryQuery::handle", skip_all)]
pub async fn handler(
    request: Request<RepositoryQueryRequest>,
    auth_url: Option<String>,
    immutable_store: Arc<dyn lore_storage::ImmutableStore>,
    mutable_store: Arc<dyn lore_storage::MutableStore>,
) -> Result<Response<RepositoryQueryResponse>, Status> {
    let user_id = get_user_id(request.extensions());
    let correlation_id = extract_correlation_id(&request).unwrap_or_default();
    let authorization = request
        .metadata()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .map(|s| s.to_string());
    let req = request.into_inner();

    let Some(query) = req.query else {
        return Err(Status::invalid_argument("Invalid query"));
    };

    let execution = setup_execution(module_path!(), correlation_id, user_id);

    let repository = Arc::new(RepositoryContext::new_server_context(
        immutable_store,
        mutable_store,
        RepositoryId::default(),
    ));

    LORE_CONTEXT
        .scope(execution, async move {
            let repository = match query {
                lore_proto::repository_query_request::Query::Id(id) => {
                    let id: RepositoryId = Context::from(id).into();
                    repository_query_id(repository.clone(), id, auth_url, authorization)
                        .await
                        .map_err(|err| {
                            warn!("Repository ID {id} not known: {err}",);
                            Status::not_found(err.to_string())
                        })?
                }
                lore_proto::repository_query_request::Query::Name(name) => repository_query_name(
                    repository.clone(),
                    name.as_str(),
                    auth_url,
                    authorization,
                )
                .await
                .map_err(|err| {
                    warn!("Repository name {name} not known: {err}");
                    Status::not_found(err.to_string())
                })?,
            };
            Ok(Response::new(RepositoryQueryResponse {
                repository: Some(lore_proto::Repository {
                    id: repository.id.into(),
                    name: repository.name,
                    metadata: repository.metadata.into(),
                }),
            }))
        })
        .await
}

#[allow(clippy::map_err_ignore)]
pub async fn repository_query_id(
    repository: Arc<RepositoryContext>,
    id: RepositoryId,
    auth_url: Option<String>,
    authorization: Option<String>,
) -> Result<RepositoryData, RepositoryError> {
    if let Some(auth_url) = auth_url {
        check_repository_query_authorization(auth_url, authorization, id)
            .await
            .map_err(|status| {
                warn!("User authorization failed: {status}");
                RepositoryError::from(RepositoryNotFound {
                    repository: id.to_string(),
                })
            })?;
    }

    let repository = Arc::new(repository.to_server_context(id));
    let metadata_hash = repository::metadata_hash(repository.clone())
        .await
        .forward_with::<RepositoryError, _>(|| {
            format!("Repository {id} metadata hash not found")
        })?;
    let metadata = repository::metadata(repository.clone(), metadata_hash)
        .await
        .forward_with::<RepositoryError, _>(|| format!("Repository {id} metadata not found"))?;

    // Verify the name -> ID mapping resolves back to the same ID, repair if missing
    let name_repository = Arc::new(repository.to_server_context(RepositoryId::default()));
    match repository::id_from_name(name_repository, &metadata.name).await {
        Ok(resolved_id) if resolved_id != id => {
            warn!(
                "Repository {} name {} maps to different repository {}, returning not found",
                id, metadata.name, resolved_id
            );
            return Err(RepositoryError::from(RepositoryNotFound {
                repository: id.to_string(),
            }));
        }
        Err(_) => {
            info!(
                "Repairing missing name -> ID mapping: {} -> {}",
                metadata.name, id
            );
            let _ = repository::store_name_to_id(repository.clone(), &metadata.name, id)
                .await
                .inspect_err(|err| warn!("Failed to repair name -> ID mapping: {err}"));
        }
        Ok(_) => {}
    }

    info!("Repository query ID {id} found {metadata:?}");
    Ok(RepositoryData {
        id,
        name: metadata.name,
        metadata: metadata_hash,
    })
}

#[allow(clippy::map_err_ignore)]
pub async fn repository_query_name(
    repository: Arc<RepositoryContext>,
    name: &str,
    auth_url: Option<String>,
    authorization: Option<String>,
) -> Result<RepositoryData, RepositoryError> {
    // If the name is a parseable context ID, use the query-by-ID path directly
    if let Ok(id) = RepositoryId::from_str(name) {
        return repository_query_id(repository, id, auth_url, authorization).await;
    }

    let name_repository = Arc::new(repository.to_server_context(RepositoryId::default()));
    let id = repository::id_from_name(name_repository, name).await?;

    if let Some(auth_url) = auth_url {
        check_repository_query_authorization(auth_url, authorization, id)
            .await
            .map_err(|status| {
                warn!("User authorization failed: {status}");
                RepositoryError::from(RepositoryNotFound {
                    repository: name.to_string(),
                })
            })?;
    }

    let repository = Arc::new(repository.to_server_context(id));
    let metadata_hash = repository::metadata_hash(repository.clone())
        .await
        .forward_with::<RepositoryError, _>(|| {
            format!("Repository {name} metadata hash not found")
        })?;
    let metadata = repository::metadata(repository.clone(), metadata_hash)
        .await
        .forward_with::<RepositoryError, _>(|| format!("Repository {name} metadata not found"))?;

    // Verify the metadata name matches the queried name — if not, the name -> ID mapping is stale
    if metadata.name != name {
        warn!(
            "Stale name -> ID mapping: {} maps to {} but metadata name is {}, deleting mapping",
            name, id, metadata.name
        );
        let _ = repository::delete_name_to_id(repository.clone(), name)
            .await
            .inspect_err(|err| warn!("Failed to delete stale name -> ID mapping: {err}"));
        return Err(RepositoryError::from(RepositoryNotFound {
            repository: name.to_string(),
        }));
    }

    info!("Repository query name {name} found {metadata:?}");
    Ok(RepositoryData {
        id,
        name: metadata.name,
        metadata: metadata_hash,
    })
}

pub(crate) async fn check_repository_query_authorization(
    auth_url: String,
    authorization: Option<String>,
    repository_id: RepositoryId,
) -> Result<(), Status> {
    lore_debug!("Repository query authorization check for {}", repository_id,);

    let mut client = grpc_get_auth_client(auth_url).await?;
    let resource_id = format!("urc-{repository_id}");
    let request = create_request_with_authorization(
        CheckUserPermissionRequest {
            resource_id: vec![resource_id.clone()],
            target_user: None,
        },
        authorization,
    )?;

    let permissions = client
        .check_user_permission(request)
        .await
        .warn_map_err(|err| {
            if err.code() == Code::PermissionDenied {
                return Status::permission_denied("Query resource denied");
            } else if err.code() == Code::Unauthenticated {
                return Status::unauthenticated("Query resource failed - unauthenticated");
            }
            Status::internal(format!("Failed to call auth check_user_permission: {err}"))
        })?;

    if permissions
        .into_inner()
        .allowed_resource_permission
        .first()
        .ok_or(Status::internal("No permissions for resource"))?
        .resource_id
        == resource_id
    {
        Ok(())
    } else {
        Err(Status::internal("Unexpected resource_id"))
    }
}

/// Shared fixtures for the repo-scoped-authz tests on the four
/// `RepositoryMetadataGet`/`RepositoryMetadataSet` handlers (v0 + v1): a
/// stub `UrcAuthApi.CheckUserPermission` server and local, tempdir-backed
/// store + seed helpers. Colocated here because this is where
/// `check_repository_query_authorization` (the thing under test) lives;
/// `pub(crate)` so `repository_metadata_{get,set}.rs` and
/// `repository/v1/repository_metadata_{get,set}.rs` can each host their own
/// `#[cfg(test)] mod tests` against it.
#[cfg(test)]
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
    /// real `LoreAuthClientHelper` (`crate::authnz::auth`) talks to it over
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

        tokio::spawn(async move {
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

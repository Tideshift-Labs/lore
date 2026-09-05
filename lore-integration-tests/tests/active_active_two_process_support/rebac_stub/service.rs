// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Hand-rolled tonic servers for the two auth services loreserver is only ever
//! a client of.
//!
//! `lore-proto`'s build script compiles both `auth_api.proto` and
//! `rebac_api.proto` with `.build_server(false)`, so there is no generated
//! `RebacApiServer` or `UrcAuthApiServer` to bind an implementation to. These
//! two mirror the single-method shape `tonic-prost-build` emits for a unary RPC
//! — compare `lore.environment.v1.rs`'s `environment_service_server` module, and
//! `lore-server`'s own `repository_query::authz_test_support`, which already
//! does exactly this for `UrcAuthApi`.
//!
//! Two structs rather than one, because tonic's router derives a service's path
//! prefix from `NamedService::NAME` and one implementation can carry only one
//! name. They share `StubState`, so the two rails cannot end up disagreeing
//! about who the caller is.
//!
//! The message types come from `lore_proto`. That is load-bearing rather than
//! convenient: the bytes on this wire are then encoded and decoded by the very
//! types loreserver uses, so a field-number or presence drift in the proto
//! cannot pass unnoticed here.

use std::convert::Infallible;

use tonic::codegen::*;

use super::StubState;

/// The FORK-LOCAL WP-120 direct-authorization rail.
#[derive(Clone)]
pub(crate) struct RebacApiStub {
    state: Arc<StubState>,
}

impl RebacApiStub {
    pub(crate) fn new(state: Arc<StubState>) -> Self {
        Self { state }
    }
}

impl tonic::server::NamedService for RebacApiStub {
    const NAME: &'static str = "ucs.auth.RebacApi";
}

/// The pinned method paths. `lore-server`'s private rail is bound to these
/// exact strings, so they are written out rather than assembled.
const AUTHORIZE_DIRECT_PATH: &str = "/ucs.auth.RebacApi/AuthorizeDirectRepositoryOperation";
const CREATE_RESOURCE_PATH: &str = "/ucs.auth.RebacApi/CreateResource";
const DELETE_RESOURCE_PATH: &str = "/ucs.auth.RebacApi/DeleteResource";
const CHECK_USER_PERMISSION_PATH: &str = "/epic_urc.UrcAuthApi/CheckUserPermission";

/// The `Unimplemented` a router returns for a path it does not serve.
///
/// Deliberately not a panic and not an `Ok` with an empty body: a loreserver
/// that starts calling one of the five CR-029 maintenance verifiers, or
/// `CreateResource`, must get a decisive answer this harness can see in a
/// failure message, rather than a hang or a silent success.
fn unimplemented() -> http::Response<tonic::body::Body> {
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
    response
}

impl<B> Service<http::Request<B>> for RebacApiStub
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
        // `CreateResource` is not optional plumbing: setting `auth_url` makes
        // EVERY repository create call it, governed or not, so leaving it
        // unimplemented fails the very first RPC of case A.
        match req.uri().path() {
            AUTHORIZE_DIRECT_PATH => {}
            CREATE_RESOURCE_PATH => {
                #[allow(non_camel_case_types)]
                struct CreateResourceSvc(Arc<StubState>);
                impl tonic::server::UnaryService<lore_proto::rebac::CreateResourceRequest> for CreateResourceSvc {
                    type Response = lore_proto::rebac::CreateResourceResponse;
                    type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;

                    fn call(
                        &mut self,
                        request: tonic::Request<lore_proto::rebac::CreateResourceRequest>,
                    ) -> Self::Future {
                        let state = Arc::clone(&self.0);
                        Box::pin(async move {
                            let (metadata, _extensions, message) = request.into_parts();
                            state
                                .create_resource(&metadata, message)
                                .map(tonic::Response::new)
                        })
                    }
                }
                let method = CreateResourceSvc(Arc::clone(&self.state));
                let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                return Box::pin(async move { Ok(grpc.unary(method, req).await) });
            }
            DELETE_RESOURCE_PATH => {
                #[allow(non_camel_case_types)]
                struct DeleteResourceSvc(Arc<StubState>);
                impl tonic::server::UnaryService<lore_proto::rebac::DeleteResourceRequest> for DeleteResourceSvc {
                    type Response = lore_proto::rebac::DeleteResourceResponse;
                    type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;

                    fn call(
                        &mut self,
                        request: tonic::Request<lore_proto::rebac::DeleteResourceRequest>,
                    ) -> Self::Future {
                        let state = Arc::clone(&self.0);
                        Box::pin(async move {
                            let (metadata, _extensions, message) = request.into_parts();
                            state
                                .delete_resource(&metadata, message)
                                .map(tonic::Response::new)
                        })
                    }
                }
                let method = DeleteResourceSvc(Arc::clone(&self.state));
                let mut grpc = tonic::server::Grpc::new(tonic_prost::ProstCodec::default());
                return Box::pin(async move { Ok(grpc.unary(method, req).await) });
            }
            _ => return Box::pin(async move { Ok(unimplemented()) }),
        }

        #[allow(non_camel_case_types)]
        struct AuthorizeDirectSvc(Arc<StubState>);
        impl
            tonic::server::UnaryService<
                lore_proto::rebac::AuthorizeDirectRepositoryOperationRequest,
            > for AuthorizeDirectSvc
        {
            type Response = lore_proto::rebac::AuthorizeDirectRepositoryOperationResponse;
            type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;

            fn call(
                &mut self,
                request: tonic::Request<
                    lore_proto::rebac::AuthorizeDirectRepositoryOperationRequest,
                >,
            ) -> Self::Future {
                let state = Arc::clone(&self.0);
                Box::pin(async move {
                    // Metadata and body are split before the decision, because
                    // the bearer is the authority and the body is the echo: the
                    // policy must never be able to read one for the other.
                    let (metadata, _extensions, message) = request.into_parts();
                    state
                        .authorize_direct(&metadata, message)
                        .map(tonic::Response::new)
                })
            }
        }

        let method = AuthorizeDirectSvc(Arc::clone(&self.state));
        let codec = tonic_prost::ProstCodec::default();
        let mut grpc = tonic::server::Grpc::new(codec);
        Box::pin(async move { Ok(grpc.unary(method, req).await) })
    }
}

/// The upstream permission-check rail, which `auth_url` also switches on.
#[derive(Clone)]
pub(crate) struct UrcAuthApiStub {
    state: Arc<StubState>,
}

impl UrcAuthApiStub {
    pub(crate) fn new(state: Arc<StubState>) -> Self {
        Self { state }
    }
}

impl tonic::server::NamedService for UrcAuthApiStub {
    const NAME: &'static str = "epic_urc.UrcAuthApi";
}

impl<B> Service<http::Request<B>> for UrcAuthApiStub
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
        if req.uri().path() != CHECK_USER_PERMISSION_PATH {
            return Box::pin(async move { Ok(unimplemented()) });
        }

        #[allow(non_camel_case_types)]
        struct CheckUserPermissionSvc(Arc<StubState>);
        impl tonic::server::UnaryService<lore_proto::auth::CheckUserPermissionRequest>
            for CheckUserPermissionSvc
        {
            type Response = lore_proto::auth::CheckUserPermissionResponse;
            type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;

            fn call(
                &mut self,
                request: tonic::Request<lore_proto::auth::CheckUserPermissionRequest>,
            ) -> Self::Future {
                let state = Arc::clone(&self.0);
                Box::pin(async move {
                    let (metadata, _extensions, message) = request.into_parts();
                    state
                        .check_user_permission(&metadata, message)
                        .map(tonic::Response::new)
                })
            }
        }

        let method = CheckUserPermissionSvc(Arc::clone(&self.state));
        let codec = tonic_prost::ProstCodec::default();
        let mut grpc = tonic::server::Grpc::new(codec);
        Box::pin(async move { Ok(grpc.unary(method, req).await) })
    }
}

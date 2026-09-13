// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Count public RPC work until its response stream ends or is dropped.
//! Installed inside CoreHop so a detached handler retains its registration.
//! A missing drain state preserves default-off behavior without registration.
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;

use http::Request;
use http::Response;
use http_body::Body;
use http_body::Frame;
use http_body::SizeHint;
use pin_project::pin_project;
use tower::Layer;
use tower::Service;

use crate::drain::DrainState;
use crate::drain::RpcGuard;

#[derive(Clone)]
pub struct GrpcDrainLayer(pub Option<Arc<DrainState>>);

impl<S> Layer<S> for GrpcDrainLayer {
    type Service = GrpcDrainService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        GrpcDrainService {
            inner,
            state: self.0.clone(),
        }
    }
}

#[derive(Clone)]
pub struct GrpcDrainService<S> {
    inner: S,
    state: Option<Arc<DrainState>>,
}

impl<S, B, C> Service<Request<B>> for GrpcDrainService<S>
where
    S: Service<Request<B>, Response = Response<C>>,
    C: Body,
{
    type Response = Response<GrpcDrainBody<C>>;
    type Error = S::Error;
    type Future = GrpcDrainFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let guard = self.state.as_ref().map(DrainState::begin_rpc);
        GrpcDrainFuture {
            inner: self.inner.call(request),
            guard,
        }
    }
}

#[pin_project]
pub struct GrpcDrainFuture<F> {
    #[pin]
    inner: F,
    guard: Option<RpcGuard>,
}

impl<F, B, E> Future for GrpcDrainFuture<F>
where
    F: Future<Output = Result<Response<B>, E>>,
    B: Body,
{
    type Output = Result<Response<GrpcDrainBody<B>>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this.inner.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                this.guard.take();
                Poll::Ready(Err(error))
            }
            Poll::Ready(Ok(response)) => {
                let mut guard = this.guard.take();
                if response.body().is_end_stream() {
                    guard.take();
                }
                Poll::Ready(Ok(response.map(|inner| GrpcDrainBody { inner, guard })))
            }
        }
    }
}

#[pin_project]
pub struct GrpcDrainBody<B> {
    #[pin]
    inner: B,
    guard: Option<RpcGuard>,
}

impl<B: Body> Body for GrpcDrainBody<B> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();
        let result = this.inner.as_mut().poll_frame(cx);
        if matches!(result, Poll::Ready(None | Some(Err(_)))) || this.inner.is_end_stream() {
            this.guard.take();
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
#[path = "drain_tests.rs"]
mod tests;

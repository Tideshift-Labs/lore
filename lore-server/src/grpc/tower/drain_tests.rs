// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use futures::FutureExt;
use http::Request;
use http::Response;
use http_body::Frame;
use http_body_util::BodyExt;
use http_body_util::Empty;
use http_body_util::Full;
use http_body_util::StreamBody;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tokio_stream::wrappers::ReceiverStream;
use tower::Layer;
use tower::Service;
use tower::service_fn;

use super::GrpcDrainLayer;
use crate::drain::DrainState;

#[tokio::test]
async fn held_unary_counts_from_call_until_last_body_frame() {
    let state = DrainState::new();
    let (send, receive) = oneshot::channel::<()>();
    let mut receive = Some(receive);
    let inner = service_fn(move |_: Request<()>| {
        let receive = receive.take().unwrap();
        async move {
            receive.await.unwrap();
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"reply"))))
        }
    });
    let mut service = GrpcDrainLayer(Some(state.clone())).layer(inner);
    let mut future = Box::pin(service.call(Request::new(())));
    assert_eq!(state.active_rpc_requests(), 1, "count before first poll");
    assert!(future.as_mut().now_or_never().is_none());
    send.send(()).unwrap();
    let mut response = future.as_mut().await.unwrap();
    drop(future);
    assert_eq!(
        state.active_rpc_requests(),
        1,
        "handler return is not response completion"
    );
    assert_eq!(
        response
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .into_data()
            .unwrap(),
        "reply"
    );
    assert_eq!(
        state.active_rpc_requests(),
        0,
        "last data frame may set EOS without another poll"
    );
    drop(response);
    assert_eq!(state.active_rpc_requests(), 0, "drop cannot release twice");
}

#[tokio::test]
async fn streaming_response_remains_counted_between_frames_until_eos() {
    let state = DrainState::new();
    let (send, receive) = mpsc::channel::<Result<Frame<Bytes>, Infallible>>(2);
    let mut receive = Some(receive);
    let mut service =
        GrpcDrainLayer(Some(state.clone())).layer(service_fn(move |_: Request<()>| {
            let body = StreamBody::new(ReceiverStream::new(receive.take().unwrap()));
            async move { Ok::<_, Infallible>(Response::new(body)) }
        }));
    let mut response = service.call(Request::new(())).await.unwrap();
    assert_eq!(state.active_rpc_requests(), 1);
    assert!(response.body_mut().frame().now_or_never().is_none());
    send.send(Ok(Frame::data(Bytes::from_static(b"first"))))
        .await
        .unwrap();
    assert!(
        response
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .is_data()
    );
    assert_eq!(state.active_rpc_requests(), 1);
    send.send(Ok(Frame::trailers(http::HeaderMap::new())))
        .await
        .unwrap();
    assert!(
        response
            .body_mut()
            .frame()
            .await
            .unwrap()
            .unwrap()
            .is_trailers()
    );
    drop(send);
    assert!(response.body_mut().frame().await.is_none());
    assert_eq!(state.active_rpc_requests(), 0);
    drop(response);
    assert_eq!(state.active_rpc_requests(), 0);
}

#[tokio::test]
async fn future_cancellation_and_error_release_exactly_once() {
    for error in [false, true] {
        let state = DrainState::new();
        let sibling = state.begin_rpc();
        let (send, receive) = oneshot::channel::<()>();
        let mut receive = Some(receive);
        let mut service =
            GrpcDrainLayer(Some(state.clone())).layer(service_fn(move |_: Request<()>| {
                let receive = receive.take().unwrap();
                async move {
                    let _ = receive.await;
                    Err::<Response<Empty<Bytes>>, _>("handler failed")
                }
            }));
        let mut future = Box::pin(service.call(Request::new(())));
        assert_eq!(state.active_rpc_requests(), 2);
        if error {
            send.send(()).unwrap();
            assert!(future.as_mut().await.is_err());
            assert_eq!(state.active_rpc_requests(), 1);
        } else {
            assert!(future.as_mut().now_or_never().is_none());
        }
        drop(future);
        assert_eq!(
            state.active_rpc_requests(),
            1,
            "sibling must survive cancellation/error cleanup"
        );
        drop(sibling);
        assert_eq!(state.active_rpc_requests(), 0);
    }
}

#[tokio::test]
async fn response_body_error_and_cancellation_release_exactly_once() {
    for error in [false, true] {
        let state = DrainState::new();
        let sibling = state.begin_rpc();
        let (send, receive) = mpsc::channel::<Result<Frame<Bytes>, &'static str>>(1);
        let mut receive = Some(receive);
        let mut service =
            GrpcDrainLayer(Some(state.clone())).layer(service_fn(move |_: Request<()>| {
                let body = StreamBody::new(ReceiverStream::new(receive.take().unwrap()));
                async move { Ok::<_, Infallible>(Response::new(body)) }
            }));
        let mut response = service.call(Request::new(())).await.unwrap();
        assert_eq!(state.active_rpc_requests(), 2);
        if error {
            send.send(Err("stream failed")).await.unwrap();
            assert!(response.body_mut().frame().await.unwrap().is_err());
            assert_eq!(state.active_rpc_requests(), 1);
        }
        drop(response);
        assert_eq!(state.active_rpc_requests(), 1);
        drop(sibling);
        assert_eq!(state.active_rpc_requests(), 0);
    }
}

#[tokio::test]
async fn empty_body_completes_at_handler_return_and_drain_does_not_reject_calls() {
    let state = DrainState::new();
    state.begin_drain();
    let observed = state.clone();
    let mut service =
        GrpcDrainLayer(Some(state.clone())).layer(service_fn(move |_: Request<()>| {
            assert_eq!(observed.active_rpc_requests(), 1);
            async { Ok::<_, Infallible>(Response::new(Empty::<Bytes>::new())) }
        }));
    let response = service.call(Request::new(())).await.unwrap();
    assert_eq!(response.status(), http::StatusCode::OK);
    assert_eq!(state.active_rpc_requests(), 0);
    drop(response);
    assert_eq!(state.active_rpc_requests(), 0);
}

#[tokio::test]
async fn disabled_layer_preserves_response_without_registering_work() {
    let state = DrainState::new();
    let observed = state.clone();
    let mut service = GrpcDrainLayer(None).layer(service_fn(move |_: Request<()>| {
        assert_eq!(observed.active_rpc_requests(), 0);
        async { Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(b"unchanged")))) }
    }));
    let response = service.call(Request::new(())).await.unwrap();
    assert_eq!(state.active_rpc_requests(), 0);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "unchanged"
    );
    assert_eq!(
        Arc::strong_count(&state),
        2,
        "disabled layer has no drain-state ownership"
    );
}

#[derive(Clone, PartialEq, prost::Message)]
struct DrainProbe {
    #[prost(string, tag = "1")]
    value: String,
}

#[derive(Clone)]
struct HeldRpc {
    entered: Arc<tokio::sync::Notify>,
    release: Arc<tokio::sync::Notify>,
}

impl tonic::server::NamedService for HeldRpc {
    const NAME: &'static str = "test.DrainProbe";
}

impl tonic::server::UnaryService<DrainProbe> for HeldRpc {
    type Response = DrainProbe;
    type Future = tonic::codegen::BoxFuture<tonic::Response<DrainProbe>, tonic::Status>;

    fn call(&mut self, request: tonic::Request<DrainProbe>) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            this.entered.notify_one();
            this.release.notified().await;
            Ok(tonic::Response::new(request.into_inner()))
        })
    }
}

impl<B> Service<Request<B>> for HeldRpc
where
    B: http_body::Body + Send + 'static,
    B::Error: Into<tonic::codegen::StdError> + Send + 'static,
{
    type Response = Response<tonic::body::Body>;
    type Error = Infallible;
    type Future = tonic::codegen::BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(
        &mut self,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let service = self.clone();
        Box::pin(async move {
            let codec = tonic_prost::ProstCodec::default();
            Ok(tonic::server::Grpc::new(codec)
                .unary(service, request)
                .await)
        })
    }
}

#[tokio::test]
async fn loopback_tonic_shutdown_keeps_held_rpc_counted_until_response_completes() {
    use std::time::Duration;

    let state = DrainState::new();
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let shutdown_started = Arc::new(tokio::sync::Notify::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (shutdown, shutdown_rx) = oneshot::channel();
    let service = HeldRpc {
        entered: entered.clone(),
        release: release.clone(),
    };
    let server_guard = state.register_public_grpc();
    let server_state = state.clone();
    let shutdown_notice = shutdown_started.clone();
    let server = lore_base::lore_spawn!(async move {
        let _server_guard = server_guard;
        let shutdown_state = server_state.clone();
        tonic::transport::Server::builder()
            .layer(crate::util::core_hop::CoreHopLayer)
            .layer(GrpcDrainLayer(Some(server_state)))
            .add_service(service)
            .serve_with_incoming_shutdown(
                tokio_stream::wrappers::TcpListenerStream::new(listener),
                async move {
                    shutdown_rx.await.unwrap();
                    shutdown_state.begin_drain();
                    shutdown_state.wait_quic_idle().await;
                    shutdown_notice.notify_one();
                },
            )
            .await
            .unwrap();
    });
    let channel = tonic::transport::Endpoint::from_shared(format!("http://{address}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    let call = lore_base::lore_spawn!(async move {
        let mut client = tonic::client::Grpc::new(channel);
        client.ready().await.unwrap();
        let response: tonic::Response<DrainProbe> = client
            .unary(
                tonic::Request::new(DrainProbe {
                    value: "held response".into(),
                }),
                http::uri::PathAndQuery::from_static("/test.DrainProbe/Hold"),
                tonic_prost::ProstCodec::default(),
            )
            .await
            .unwrap();
        response.into_inner().value
    });
    tokio::time::timeout(Duration::from_secs(5), entered.notified())
        .await
        .unwrap();
    assert_eq!(state.active_rpc_requests(), 1);
    assert_eq!(state.total_active(), 0);
    shutdown.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(5), shutdown_started.notified())
        .await
        .unwrap();
    assert!(!server.is_finished());
    assert!(!state.is_drained());
    assert!(state.wait_idle().now_or_never().is_none());
    release.notify_one();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), call)
            .await
            .unwrap()
            .unwrap(),
        "held response"
    );
    tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(state.active_rpc_requests(), 0);
    assert!(state.is_drained());
}

#[tokio::test]
async fn core_hop_caller_cancellation_does_not_hide_the_detached_handler() {
    use std::time::Duration;

    let state = DrainState::new();
    let entered = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let inner_entered = entered.clone();
    let inner_release = release.clone();
    let inner = service_fn(move |_: Request<()>| {
        let entered = inner_entered.clone();
        let release = inner_release.clone();
        async move {
            entered.notify_one();
            release.notified().await;
            Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                b"detached response",
            ))))
        }
    });
    let mut service =
        crate::util::core_hop::CoreHopLayer.layer(GrpcDrainLayer(Some(state.clone())).layer(inner));
    let future = service.call(Request::new(()));
    assert_eq!(
        state.active_rpc_requests(),
        1,
        "CoreHop counts before scheduling its handler"
    );
    tokio::time::timeout(Duration::from_secs(5), entered.notified())
        .await
        .unwrap();
    assert_eq!(state.active_rpc_requests(), 1);
    drop(future);
    assert_eq!(
        state.active_rpc_requests(),
        1,
        "dropping CoreHop join handle leaves its task running"
    );
    state.begin_drain();
    assert!(state.wait_idle().now_or_never().is_none());
    assert!(!state.is_drained());
    release.notify_one();
    tokio::time::timeout(Duration::from_secs(5), state.wait_idle())
        .await
        .unwrap();
    assert_eq!(
        state.active_rpc_requests(),
        0,
        "abandoned response body releases the retained guard"
    );
    assert!(state.is_drained());
}

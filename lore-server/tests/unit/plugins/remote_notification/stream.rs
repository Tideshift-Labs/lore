// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_server::plugins::remote_notification::stream::*;
use lore_server::plugins::remote_notification::wire;

fn envelope() -> wire::PrivateEnvelopeV1 {
    wire::PrivateEnvelopeV1 {
        transport_version: wire::TRANSPORT_VERSION,
        ..Default::default()
    }
}

#[tokio::test]
async fn an_exhausted_script_reports_caught_up_rather_than_failing() {
    let stream = FakeDurableStream::at(StreamPlacement::new("DURABLE-a", 8), 900);
    assert_eq!(
        stream.next().await.expect("read succeeds"),
        StreamDelivery::CaughtUp
    );
}

fn capture_request(generation: i64, placement: StreamPlacement) -> CaptureRequest {
    CaptureRequest {
        receiver_identity: "receiver-1".to_string(),
        membership_generation: generation,
        placement,
        placement_revision: 1,
        resume_from: None,
    }
}

#[tokio::test]
async fn capture_records_the_generation_it_was_taken_for() {
    let placement = StreamPlacement::new("DURABLE-a", 8);
    let stream = FakeDurableStream::at(placement.clone(), 900);
    let captured = stream
        .capture(&capture_request(4, placement))
        .await
        .expect("captures");
    assert_eq!(captured.start_sequence, 900);
    assert_eq!(captured.placement.stream_epoch, 8);
    assert_eq!(stream.captures(), vec![("receiver-1".to_string(), 4)]);
}

/// The request asserts the placement the receiver believes authoritative,
/// so a gateway serving a different one refuses at the capture instead of
/// pinning a position the readiness compare-and-set would reject later.
#[tokio::test]
async fn a_capture_asserting_the_wrong_placement_is_refused() {
    let stream = FakeDurableStream::at(StreamPlacement::new("DURABLE-a", 8), 900);
    let outcome = stream
        .capture(&capture_request(4, StreamPlacement::new("DURABLE-a", 7)))
        .await;
    assert!(matches!(outcome, Err(StreamError::PlacementMoved { .. })));
}

#[tokio::test]
async fn a_resume_position_overrides_the_streams_default_start() {
    let placement = StreamPlacement::new("DURABLE-a", 8);
    let stream = FakeDurableStream::at(placement.clone(), 900);
    let mut request = capture_request(4, placement);
    request.resume_from = Some(950);
    let captured = stream.capture(&request).await.expect("captures");
    assert_eq!(captured.start_sequence, 950);
}

/// The script is a queue, so a delivery followed by a failure arrives in
/// that order. Tests depend on this to place a fault at an exact boundary.
#[tokio::test]
async fn scripted_steps_are_served_in_order() {
    let stream = FakeDurableStream::at(StreamPlacement::new("DURABLE-a", 8), 900);
    stream.push_envelope(900, envelope());
    stream.push_error(StreamError::Transient("broker down".into()));
    assert!(matches!(
        stream.next().await,
        Ok(StreamDelivery::Message(_))
    ));
    assert!(matches!(
        stream.next().await,
        Err(StreamError::Transient(_))
    ));
    assert_eq!(stream.pending_steps(), 0);
}

#[tokio::test]
async fn a_moved_placement_is_visible_to_the_next_capture() {
    let stream = FakeDurableStream::at(StreamPlacement::new("DURABLE-a", 8), 900);
    let moved = StreamPlacement::new("DURABLE-a-r2", 1);
    stream.set_placement(moved.clone());
    let captured = stream
        .capture(&capture_request(5, moved))
        .await
        .expect("captures");
    assert_eq!(captured.placement.stream_identity, "DURABLE-a-r2");
    assert_eq!(captured.placement.stream_epoch, 1);
}

/// The receiver-side status mapping is not the publisher's. Getting these
/// backwards either spins a retired generation or throws away a live one.
#[test]
fn the_receiver_status_mapping_differs_from_the_publishers() {
    let current = StreamPlacement::new("DURABLE-a", 8);
    assert!(matches!(
        status_to_stream_error(&tonic::Status::unavailable("down"), &current),
        StreamError::Transient(_)
    ));
    assert!(matches!(
        status_to_stream_error(&tonic::Status::failed_precondition("epoch"), &current),
        StreamError::PlacementMoved { .. }
    ));
    // The publisher retries both of these; a receiver must not.
    assert!(matches!(
        status_to_stream_error(&tonic::Status::permission_denied("role"), &current),
        StreamError::Refused(_)
    ));
    assert!(matches!(
        status_to_stream_error(&tonic::Status::unauthenticated("mtls"), &current),
        StreamError::Refused(_)
    ));
    assert!(matches!(
        status_to_stream_error(&tonic::Status::invalid_argument("malformed"), &current),
        StreamError::Refused(_)
    ));
}

/// Every `uint64` on this surface is stored in an `i64`, so a value above
/// `i64::MAX` is malformed rather than a number to wrap. Wrapping would
/// turn an enormous sequence into a small one and let a frontier appear to
/// advance.
#[test]
fn a_sequence_above_i64_max_is_malformed_rather_than_wrapped() {
    assert_eq!(narrow(900, "broker_sequence"), Ok(900));
    assert_eq!(narrow(i64::MAX as u64, "broker_sequence"), Ok(i64::MAX));
    assert!(matches!(
        narrow(u64::MAX, "broker_sequence"),
        Err(StreamError::Refused(_))
    ));
}

#[tokio::test]
async fn a_failing_ack_records_nothing() {
    let stream = FakeDurableStream::at(StreamPlacement::new("DURABLE-a", 8), 900);
    stream.fail_acks_with(Some(StreamError::Transient("ack lost".into())));
    assert!(stream.ack(901).await.is_err());
    assert!(stream.acked().is_empty());
}

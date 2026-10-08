// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use bytes::Bytes;
use lore_server::plugins::remote_notification::client::*;
use lore_server::plugins::remote_notification::envelope::EventId;
use lore_server::plugins::remote_notification::error::NotAcceptedReason;
use lore_server::plugins::remote_notification::error::PublishFailure;
use lore_server::plugins::remote_notification::error::TerminalClass;
use lore_server::plugins::remote_notification::error::TransientClass;
use lore_server::plugins::remote_notification::wire;
use tonic::Code;

fn event_id() -> EventId {
    EventId::from_bytes([7; 16])
}

fn accepted() -> wire::PublishResultV1 {
    wire::PublishResultV1 {
        transport_version: wire::TRANSPORT_VERSION,
        outcome: wire::PublishOutcomeV1::Accepted as i32,
        event_id: Bytes::copy_from_slice(event_id().as_bytes()),
        stream_identity: "DURABLE-sfo3-cell-a".to_string(),
        stream_epoch: 8,
        broker_sequence: 918,
        publisher_contract_version: 1,
        broker_accepted_at: None,
        failure_class: 0,
    }
}

#[test]
fn a_complete_versioned_acceptance_is_the_only_result_that_proves_acceptance() {
    let acceptance = classify_result(event_id(), &accepted()).expect("accepted");
    assert_eq!(acceptance.stream_identity, "DURABLE-sfo3-cell-a");
    assert_eq!(acceptance.stream_epoch, 8);
    assert_eq!(acceptance.broker_sequence, 918);
    assert_eq!(acceptance.publisher_contract_version, 1);
}

#[test]
fn an_unversioned_response_is_not_accepted() {
    let mut result = accepted();
    result.transport_version = 0;
    assert_eq!(
        classify_result(event_id(), &result).expect_err("unversioned"),
        PublishFailure::NotAccepted(NotAcceptedReason::UnversionedResponse)
    );
}

#[test]
fn every_missing_acceptance_evidence_field_makes_the_response_not_accepted() {
    for mutate in [
        (|r: &mut wire::PublishResultV1| r.stream_identity.clear()) as fn(&mut _),
        |r: &mut wire::PublishResultV1| r.stream_epoch = 0,
        |r: &mut wire::PublishResultV1| r.broker_sequence = 0,
        |r: &mut wire::PublishResultV1| r.publisher_contract_version = 0,
    ] {
        let mut result = accepted();
        mutate(&mut result);
        assert_eq!(
            classify_result(event_id(), &result).expect_err("incomplete evidence"),
            PublishFailure::NotAccepted(NotAcceptedReason::IncompleteAcceptanceEvidence)
        );
    }
}

#[test]
fn an_echoed_event_id_that_does_not_match_the_claim_is_not_accepted() {
    let mut result = accepted();
    result.event_id = Bytes::from_static(&[9; 16]);
    assert_eq!(
        classify_result(event_id(), &result).expect_err("event id mismatch"),
        PublishFailure::NotAccepted(NotAcceptedReason::EventIdMismatch)
    );
}

#[test]
fn an_unrecognized_publisher_contract_is_not_accepted() {
    let mut result = accepted();
    result.publisher_contract_version = 2;
    assert_eq!(
        classify_result(event_id(), &result).expect_err("publisher contract"),
        PublishFailure::NotAccepted(NotAcceptedReason::UnrecognizedPublisherContract)
    );
}

#[test]
fn retryable_and_terminal_result_classes_map_to_the_cr_032_dispositions() {
    let cases = [
        (
            wire::PublishOutcomeV1::Retryable,
            wire::PublishFailureClassV1::BrokerUnavailable,
            PublishFailure::Transient(TransientClass::BrokerUnavailable),
        ),
        (
            wire::PublishOutcomeV1::Retryable,
            wire::PublishFailureClassV1::PlacementQuiescing,
            PublishFailure::Transient(TransientClass::PlacementQuiescing),
        ),
        (
            wire::PublishOutcomeV1::Retryable,
            wire::PublishFailureClassV1::StreamFull,
            PublishFailure::Transient(TransientClass::StreamFull),
        ),
        (
            wire::PublishOutcomeV1::Terminal,
            wire::PublishFailureClassV1::ScopeMismatch,
            PublishFailure::Terminal(TerminalClass::ScopeMismatch),
        ),
        (
            wire::PublishOutcomeV1::Terminal,
            wire::PublishFailureClassV1::UnsupportedSchema,
            PublishFailure::Terminal(TerminalClass::UnsupportedSchema),
        ),
    ];
    for (outcome, class, expected) in cases {
        let mut result = accepted();
        result.outcome = outcome as i32;
        result.failure_class = class as i32;
        assert_eq!(
            classify_result(event_id(), &result).expect_err("failure"),
            expected
        );
    }
}

#[test]
fn a_timeout_outcome_never_fabricates_acceptance() {
    let mut result = accepted();
    result.outcome = wire::PublishOutcomeV1::Timeout as i32;
    assert_eq!(
        classify_result(event_id(), &result).expect_err("timeout"),
        PublishFailure::Transient(TransientClass::Timeout)
    );
}

#[test]
fn an_unspecified_or_unknown_outcome_is_not_accepted() {
    let mut result = accepted();
    result.outcome = wire::PublishOutcomeV1::Unspecified as i32;
    assert_eq!(
        classify_result(event_id(), &result).expect_err("unspecified"),
        PublishFailure::NotAccepted(NotAcceptedReason::UnrecognizedOutcome)
    );

    let mut result = accepted();
    result.outcome = 99;
    assert_eq!(
        classify_result(event_id(), &result).expect_err("unknown outcome"),
        PublishFailure::NotAccepted(NotAcceptedReason::UnrecognizedOutcome)
    );
}

#[test]
fn every_grpc_code_has_an_explicit_disposition() {
    let cases = [
        (
            Code::Cancelled,
            PublishFailure::Transient(TransientClass::Transport),
        ),
        (
            Code::Unknown,
            PublishFailure::Transient(TransientClass::BrokerUnavailable),
        ),
        (
            Code::InvalidArgument,
            PublishFailure::Terminal(TerminalClass::InvalidRequest),
        ),
        (
            Code::DeadlineExceeded,
            PublishFailure::Transient(TransientClass::Timeout),
        ),
        (
            Code::NotFound,
            PublishFailure::NotAccepted(NotAcceptedReason::OffContractStatus),
        ),
        (
            Code::AlreadyExists,
            PublishFailure::NotAccepted(NotAcceptedReason::OffContractStatus),
        ),
        (
            Code::PermissionDenied,
            PublishFailure::Transient(TransientClass::IdentityRejected),
        ),
        (
            Code::ResourceExhausted,
            PublishFailure::Transient(TransientClass::RateLimited),
        ),
        (
            Code::FailedPrecondition,
            PublishFailure::Transient(TransientClass::PlacementQuiescing),
        ),
        (
            Code::Aborted,
            PublishFailure::Transient(TransientClass::BrokerUnavailable),
        ),
        (
            Code::OutOfRange,
            PublishFailure::Terminal(TerminalClass::InvalidRequest),
        ),
        (
            Code::Unimplemented,
            PublishFailure::Terminal(TerminalClass::UnsupportedSchema),
        ),
        (
            Code::Internal,
            PublishFailure::Transient(TransientClass::BrokerUnavailable),
        ),
        (
            Code::Unavailable,
            PublishFailure::Transient(TransientClass::BrokerUnavailable),
        ),
        (
            Code::DataLoss,
            PublishFailure::NotAccepted(NotAcceptedReason::OffContractStatus),
        ),
        (
            Code::Unauthenticated,
            PublishFailure::Transient(TransientClass::IdentityRejected),
        ),
    ];
    for (code, expected) in cases {
        assert_eq!(
            classify_status(&tonic::Status::new(code, "test")),
            expected,
            "unexpected disposition for {code:?}"
        );
    }
}

#[test]
fn transport_faults_retry_and_event_specific_rejections_do_not() {
    assert!(classify_status(&tonic::Status::resource_exhausted("429")).is_retryable());
    assert!(classify_status(&tonic::Status::unavailable("5xx")).is_retryable());
    // A refused credential retries: credential rotation is a contract step,
    // and dead-lettering a committed durable row over a rotation lag would
    // lose the mutation event.
    assert!(classify_status(&tonic::Status::permission_denied("no")).is_retryable());
    assert!(classify_status(&tonic::Status::unauthenticated("no")).is_retryable());
    // An event-specific rejection does not.
    assert!(!classify_status(&tonic::Status::invalid_argument("bad")).is_retryable());
    assert!(!classify_status(&tonic::Status::unimplemented("v2 only")).is_retryable());
    // An off-contract answer is neither retried here nor dead-lettered: the
    // caller retains the intent with its original stable keys.
    assert!(!classify_status(&tonic::Status::not_found("no cell")).is_retryable());
}

// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
mod live_tests;

use bytes::Bytes;
use lore_proto::lore::domain::v1::DomainOperationOutcome;
use lore_proto::lore::domain::v1::DomainOperationReceiptGetResponse;
use lore_proto::lore::domain::v1::DomainOperationReceiptStatus;
use lore_transport::domain_receipt::DomainReceiptOutcome;
use lore_transport::domain_receipt::DomainReceiptQuery;
use lore_transport::domain_receipt::DomainReceiptState;
use lore_transport::grpc::domain_operation_client::*;
use uuid::Uuid;

fn digest() -> Bytes {
    Bytes::from_static(&[7u8; 32])
}

fn query() -> DomainReceiptQuery {
    DomainReceiptQuery {
        org_uuid: Uuid::now_v7(),
        initiating_principal_namespace: Bytes::from_static(b"principal-v1\0user"),
        operation_id: Uuid::now_v7(),
        method: "RevisionService.BranchCreate".to_string(),
        scope: Bytes::from_static(b"scope"),
        fingerprint_version: 1,
        fingerprint: digest(),
        canonical_intent_digest: digest(),
        authorization_revision: 3,
        consumed_ticket_sha256: digest(),
    }
}

fn response(status: DomainOperationReceiptStatus) -> DomainOperationReceiptGetResponse {
    DomainOperationReceiptGetResponse {
        status: status as i32,
        outcome: DomainOperationOutcome::Unspecified as i32,
        reason_version: None,
        reason: String::new(),
        from_future_marker: false,
        prepared_at_unix_millis: None,
        hard_expires_at_unix_millis: None,
        verification_nonce: digest(),
        bound_fields_digest: digest(),
        consumed_ticket_sha256: digest(),
        authorization_revision: 3,
    }
}

/// The equality CR-029 v1 requires is produced by the client, not asked of the caller.
#[test]
fn the_request_binds_authorization_id_to_the_operation_id() {
    let query = query();
    let request = build_request(&query);

    assert_eq!(request.operation_id, request.authorization_id);
    assert_eq!(request.operation_id.as_ref(), query.operation_id.as_bytes());
}

/// Only a committed receipt attributes anything, and only it exposes an outcome.
#[test]
fn committed_is_the_only_attributive_state() {
    let mut committed = response(DomainOperationReceiptStatus::Committed);
    committed.outcome = DomainOperationOutcome::Applied as i32;
    assert!(decode_receipt(committed).unwrap().state.is_attributive());

    for status in [
        DomainOperationReceiptStatus::Mismatch,
        DomainOperationReceiptStatus::Expired,
        DomainOperationReceiptStatus::ExpiredOrUnknown,
        DomainOperationReceiptStatus::NotFound,
    ] {
        let receipt = decode_receipt(response(status)).unwrap();
        assert!(
            !receipt.state.is_attributive(),
            "{status:?} must not attribute an outcome"
        );
    }
}

/// A committed receipt whose outcome is missing is refused, not read as either verdict.
#[test]
fn a_committed_receipt_without_an_outcome_is_refused() {
    let error = decode_receipt(response(DomainOperationReceiptStatus::Committed))
        .expect_err("an unspecified outcome must not decode");

    assert!(
        format!("{error}").contains("unspecified outcome"),
        "expected the unspecified-outcome refusal, got: {error}"
    );
}

/// A `NOT_APPLIED` keeps its versioned reason as data for the caller to branch on.
#[test]
fn a_not_applied_receipt_keeps_its_versioned_reason() {
    let mut committed = response(DomainOperationReceiptStatus::Committed);
    committed.outcome = DomainOperationOutcome::NotApplied as i32;
    committed.reason_version = Some(2);
    committed.reason = "BRANCH_PROTECTED".to_string();
    committed.from_future_marker = true;

    let receipt = decode_receipt(committed).unwrap();

    assert_eq!(
        receipt.state,
        DomainReceiptState::Committed {
            outcome: DomainReceiptOutcome::NotApplied {
                reason_version: 2,
                reason: "BRANCH_PROTECTED".to_string(),
            },
            from_future_marker: true,
        }
    );
}

/// WP-120 makes a `NOT_APPLIED` decisive only when it is versioned, and the server always
/// sends a version with one. An unversioned one is refused rather than acted on.
#[test]
fn a_not_applied_receipt_without_a_reason_version_is_refused() {
    let mut committed = response(DomainOperationReceiptStatus::Committed);
    committed.outcome = DomainOperationOutcome::NotApplied as i32;
    committed.reason = "BRANCH_PROTECTED".to_string();

    let error = decode_receipt(committed).expect_err("an unversioned NOT_APPLIED must decode");

    assert!(
        format!("{error}").contains("no reason version"),
        "expected the missing-reason-version refusal, got: {error}"
    );
}

/// The safety property, stated as a test rather than left to the shape of the types: an
/// outcome riding along on a status that does not attribute anything is dropped on the
/// floor. A reconciler cannot see it, so it cannot resolve a record on it.
#[test]
fn an_outcome_on_a_non_committed_status_never_surfaces() {
    for status in [
        DomainOperationReceiptStatus::Mismatch,
        DomainOperationReceiptStatus::Expired,
        DomainOperationReceiptStatus::ExpiredOrUnknown,
        DomainOperationReceiptStatus::NotFound,
    ] {
        let mut smuggled = response(status);
        smuggled.outcome = DomainOperationOutcome::Applied as i32;
        smuggled.reason_version = Some(1);
        smuggled.reason = "must not surface".to_string();
        smuggled.from_future_marker = true;

        let receipt = decode_receipt(smuggled)
            .unwrap_or_else(|e| panic!("{status:?} must still decode: {e}"));

        assert!(
            !receipt.state.is_attributive(),
            "{status:?} must not attribute an outcome"
        );
        assert!(
            !matches!(receipt.state, DomainReceiptState::Committed { .. }),
            "{status:?} must not decode as committed"
        );
    }
}

/// A prepare missing either timestamp is refused rather than back-filled with a default.
#[test]
fn a_prepared_receipt_needs_both_timestamps() {
    let mut prepared = response(DomainOperationReceiptStatus::Prepared);
    prepared.prepared_at_unix_millis = Some(10);

    assert!(decode_receipt(prepared.clone()).is_err());

    prepared.hard_expires_at_unix_millis = Some(20);
    assert_eq!(
        decode_receipt(prepared).unwrap().state,
        DomainReceiptState::Prepared {
            prepared_at_unix_millis: 10,
            hard_expires_at_unix_millis: 20,
        }
    );
}

/// A status outside this build's vocabulary is refused, never softened into absence.
#[test]
fn an_unreadable_status_is_refused_rather_than_read_as_absence() {
    let mut unknown = response(DomainOperationReceiptStatus::NotFound);
    unknown.status = 4242;

    assert!(decode_receipt(unknown).is_err());
    assert!(decode_receipt(response(DomainOperationReceiptStatus::Unspecified)).is_err());
}

/// The structural checks run before anything reaches the wire.
#[test]
fn a_structurally_impossible_query_is_rejected() {
    let mut short_digest = query();
    short_digest.fingerprint = Bytes::from_static(&[1u8; 16]);
    assert!(short_digest.validate().is_err());

    let mut zero_version = query();
    zero_version.fingerprint_version = 0;
    assert!(zero_version.validate().is_err());

    let mut not_v7 = query();
    not_v7.operation_id = Uuid::from_bytes([9u8; 16]);
    assert!(not_v7.validate().is_err());

    assert!(query().validate().is_ok());
}

// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
use lore_postgres::domain::outbox::reset::AckInputs;
use lore_server::event_relay::reset_service::*;
use lore_server::event_relay::reset_wire::RESET_SCHEMA_VERSION;
use lore_server::event_relay::reset_wire::ResetReasonV1;
use lore_server::event_relay::reset_wire::ResetReportErrorV1;
use lore_server::event_relay::reset_wire::StreamResetAckV1;
use lore_server::event_relay::reset_wire::StreamResetReportV1;
use lore_server::event_relay::reset_wire::detection_id;
use lore_server::event_relay::reset_wire::reset_fingerprint;

#[test]
fn a_spiffe_id_resolves_its_cell_segment() {
    assert_eq!(
        spiffe_cell("spiffe://tideshift/cell/sfo3-cell-a/wp110"),
        Some("sfo3-cell-a")
    );
    assert_eq!(
        spiffe_cell("spiffe://tideshift/region/sfo3/cell/sfo3-cell-a"),
        Some("sfo3-cell-a")
    );
}

#[test]
fn a_principal_without_a_cell_segment_resolves_nothing() {
    assert_eq!(spiffe_cell("spiffe://tideshift/wp110"), None);
    assert_eq!(spiffe_cell("spiffe://tideshift/cell"), None);
    assert_eq!(spiffe_cell("spiffe://tideshift/cell/"), None);
    assert_eq!(spiffe_cell("https://tideshift/cell/sfo3-cell-a"), None);
    assert_eq!(spiffe_cell("spiffe://tideshift"), None);
    assert_eq!(spiffe_cell(""), None);
}

/// A segment whose VALUE is "cell" must not be read as the marker for the
/// segment after it unless it is in the key position. This is the ordinary
/// reading of the scan, pinned because a future rewrite to `contains` would
/// break it silently.
#[test]
fn the_cell_marker_is_a_path_segment_not_a_substring() {
    assert_eq!(spiffe_cell("spiffe://tideshift/cellular/sfo3-cell-a"), None);
    assert_eq!(
        spiffe_cell("spiffe://tideshift/cell/cell/sfo3-cell-a"),
        Some("cell")
    );
}

fn request() -> StreamResetReportV1 {
    let fingerprint = reset_fingerprint(
        "sfo3-01:JS-9Q2F7K3M1X",
        "sfo3-cell-a",
        "DURABLE-sfo3-cell-a",
        7,
        "DURABLE-sfo3-cell-a",
        8,
    );
    StreamResetReportV1 {
        schema_version: RESET_SCHEMA_VERSION,
        detection_id: detection_id(&fingerprint),
        reset_fingerprint: bytes::Bytes::copy_from_slice(&fingerprint),
        broker_reset_identity: "sfo3-01:JS-9Q2F7K3M1X".to_string(),
        cell_id: "sfo3-cell-a".to_string(),
        placement_revision: 4,
        old_stream_identity: "DURABLE-sfo3-cell-a".to_string(),
        old_stream_epoch: 7,
        new_stream_identity: "DURABLE-sfo3-cell-a".to_string(),
        new_stream_epoch: 8,
        reason_code: ResetReasonV1::StreamEpochAdvanced as i32,
        detected_at_unix_ms: 1_787_000_000_000,
    }
}

fn detail_of(status: &tonic::Status) -> String {
    status.message().to_string()
}

#[test]
fn a_well_formed_report_converts() {
    let report = validate_and_convert(&request()).expect("a valid report");
    assert_eq!(report.cell_id, "sfo3-cell-a");
    assert_eq!(report.old_stream_epoch, 7);
    assert_eq!(report.new_stream_epoch, 8);
    assert_eq!(
        report.reason_code,
        ResetReasonV1::StreamEpochAdvanced as i32
    );
}

/// A fingerprint that does not recompute is MALFORMED, never a mismatch and
/// never an invalid successor. Returning either of those would leak whether
/// a stored record exists.
#[test]
fn a_fingerprint_that_does_not_recompute_is_malformed() {
    let mut request = request();
    request.reset_fingerprint = bytes::Bytes::from(vec![0x00; 32]);
    let status = validate_and_convert(&request).expect_err("a forged fingerprint");
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(detail_of(&status).starts_with("MALFORMED_REPORT_V1"));
    assert!(detail_of(&status).contains("does not recompute"));
}

#[test]
fn a_fingerprint_of_the_wrong_width_is_malformed() {
    let mut request = request();
    request.reset_fingerprint = bytes::Bytes::from(vec![0x11; 31]);
    let status = validate_and_convert(&request).expect_err("a short fingerprint");
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(detail_of(&status).contains("exactly 32 bytes"));
}

/// A detection ID that is not the `UUIDv5` of the fingerprint is likewise
/// malformed, even when the fingerprint itself is perfect.
#[test]
fn a_detection_id_that_is_not_the_uuid_of_the_fingerprint_is_malformed() {
    let mut request = request();
    request.detection_id = "00000000-0000-5000-8000-000000000000".to_string();
    let status = validate_and_convert(&request).expect_err("a mismatched detection id");
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(detail_of(&status).contains("UUIDv5"));
}

#[test]
fn the_unspecified_reason_is_malformed() {
    let mut request = request();
    request.reason_code = ResetReasonV1::Unspecified as i32;
    let status = validate_and_convert(&request).expect_err("the proto3 zero value");
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(detail_of(&status).contains("UNSPECIFIED"));
}

#[test]
fn an_unknown_reason_is_malformed() {
    let mut request = request();
    request.reason_code = 6;
    assert_eq!(
        validate_and_convert(&request)
            .expect_err("an unknown reason")
            .code(),
        tonic::Code::InvalidArgument
    );
}

#[test]
fn a_wrong_schema_version_is_malformed() {
    for version in [0, 2, 99] {
        let mut request = request();
        request.schema_version = version;
        let status = validate_and_convert(&request).expect_err("a wrong schema version");
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert!(detail_of(&status).contains("schema_version"));
    }
}

/// The contract's `max-epoch-boundary` vector uses `u64::MAX`, which is
/// representable on the wire and not in a `bigint`. It is refused with a
/// named reason rather than wrapping to a negative epoch that a `>= 1` CHECK
/// would then reject for an unrelated-looking reason.
#[test]
fn an_epoch_above_the_storable_range_is_refused_by_name() {
    let fingerprint = reset_fingerprint(
        "sfo3-02:JS-0000000000",
        "sfo3-cell-c",
        "DURABLE-sfo3-cell-c",
        u64::MAX - 1,
        "DURABLE-sfo3-cell-c",
        u64::MAX,
    );
    let request = StreamResetReportV1 {
        schema_version: RESET_SCHEMA_VERSION,
        detection_id: detection_id(&fingerprint),
        reset_fingerprint: bytes::Bytes::copy_from_slice(&fingerprint),
        broker_reset_identity: "sfo3-02:JS-0000000000".to_string(),
        cell_id: "sfo3-cell-c".to_string(),
        placement_revision: 1,
        old_stream_identity: "DURABLE-sfo3-cell-c".to_string(),
        old_stream_epoch: u64::MAX - 1,
        new_stream_identity: "DURABLE-sfo3-cell-c".to_string(),
        new_stream_epoch: u64::MAX,
        reason_code: ResetReasonV1::StreamEpochAdvanced as i32,
        detected_at_unix_ms: 1,
    };
    let status = validate_and_convert(&request).expect_err("an unstorable epoch");
    assert_eq!(status.code(), tonic::Code::InvalidArgument);
    assert!(detail_of(&status).contains("storable range"));
}

/// The stored ack is what goes on the wire, so a round trip through the
/// encoder must reproduce every frozen field.
#[test]
fn the_built_ack_carries_every_frozen_field() {
    let inputs = AckInputs {
        cell_id: "sfo3-cell-a".to_string(),
        detection_id: "efaa31a7-a8db-5666-a6fe-3eb00881fd27".to_string(),
        reset_fingerprint: [0x11; 32],
        reset_generation: 3,
        evidence_id: "rst-3-1111111111111111".to_string(),
        persisted_at_unix_ms: 1_787_000_000_000,
    };
    let bytes = build_ack(&inputs);
    let decoded = <StreamResetAckV1 as prost::Message>::decode(bytes.as_slice())
        .expect("the ack we just encoded");
    assert_eq!(decoded.schema_version, RESET_SCHEMA_VERSION);
    assert_eq!(decoded.cell_id, inputs.cell_id);
    assert_eq!(decoded.detection_id, inputs.detection_id);
    assert_eq!(
        decoded.reset_fingerprint.as_ref(),
        &inputs.reset_fingerprint
    );
    assert_eq!(decoded.reset_generation, 3);
    assert_eq!(decoded.evidence_id, inputs.evidence_id);
    assert_eq!(decoded.persisted_at_unix_ms, inputs.persisted_at_unix_ms);
    assert!(decoded.evidence_id.chars().count() <= 64);
}

/// The replay path re-drives the requeue only while the fence stands, so
/// the state it compares against must be the one the storage layer writes.
/// A drift here would silently turn every replay back into a bare ack
/// lookup.
#[test]
fn the_in_progress_state_matches_the_storage_vocabulary() {
    assert_eq!(
        RESET_STATE_IN_PROGRESS,
        lore_postgres::domain::outbox::schema::RESET_STATE_IN_PROGRESS
    );
    assert_ne!(
        RESET_STATE_IN_PROGRESS,
        lore_postgres::domain::outbox::schema::RESET_STATE_CLEARED
    );
}

#[test]
fn every_rejection_detail_maps_to_its_frozen_code() {
    assert_eq!(
        ResetReportErrorV1::ResetDetectionMismatch.status().code(),
        tonic::Code::AlreadyExists
    );
    assert_eq!(
        ResetReportErrorV1::PlacementMismatch.status().code(),
        tonic::Code::FailedPrecondition
    );
    assert_eq!(
        ResetReportErrorV1::StaleOldStream.status().code(),
        tonic::Code::FailedPrecondition
    );
    assert_eq!(
        ResetReportErrorV1::InvalidSuccessorStream.status().code(),
        tonic::Code::FailedPrecondition
    );
    assert_eq!(
        ResetReportErrorV1::UnauthenticatedReport.status().code(),
        tonic::Code::Unauthenticated
    );
    assert_eq!(
        ResetReportErrorV1::CrossCellReport.status().code(),
        tonic::Code::PermissionDenied
    );
    assert_eq!(
        ResetReportErrorV1::UnauthorizedReport.status().code(),
        tonic::Code::PermissionDenied
    );
}

/// A request with no TLS connect info carries no peer certificate, which is
/// exactly what an endpoint running with `verify_client_certs = false`
/// produces. It is refused rather than treated as an anonymous local caller.
#[test]
fn a_request_with_no_peer_certificate_is_unauthenticated() {
    let request = tonic::Request::new(request());
    let status = authenticate(&request).expect_err("a request with no TLS connect info");
    assert_eq!(status.code(), tonic::Code::Unauthenticated);
    assert_eq!(status.message(), "UNAUTHENTICATED_REPORT_V1");
}

#[test]
fn a_principal_from_another_cell_is_refused_as_cross_cell() {
    let status = authorize(
        "sfo3-cell-a",
        "spiffe://tideshift/cell/sfo3-cell-b/wp110",
        "sfo3-cell-a",
    )
    .expect_err("a principal from another cell");
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
    assert_eq!(status.message(), "CROSS_CELL_REPORT_V1");
}

/// A principal for this cell reporting about a different cell is cross-cell
/// too. Both halves are checked, because either one alone would let a
/// correctly-authenticated emitter mutate a cell it does not belong to.
#[test]
fn a_report_naming_another_cell_is_refused_even_from_a_local_principal() {
    let status = authorize(
        "sfo3-cell-a",
        "spiffe://tideshift/cell/sfo3-cell-a/wp110",
        "sfo3-cell-b",
    )
    .expect_err("a report about another cell");
    assert_eq!(status.message(), "CROSS_CELL_REPORT_V1");
    assert!(
        authorize(
            "sfo3-cell-a",
            "spiffe://tideshift/cell/sfo3-cell-a/wp110",
            "sfo3-cell-a",
        )
        .is_ok()
    );
}

#[test]
fn a_principal_with_no_cell_segment_is_unauthorized_not_cross_cell() {
    let status = authorize("sfo3-cell-a", "spiffe://tideshift/wp110", "sfo3-cell-a")
        .expect_err("a principal with no cell");
    assert_eq!(status.message(), "UNAUTHORIZED_REPORT_V1");
}

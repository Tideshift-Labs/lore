// Copyright 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! [CLIENT wire] Structured uncertainty survives the in-band status boundary.

use lore_proto::lore::model::v1::ItemStatus;
use prost::Message;

#[test]
fn ordinary_item_codes_do_not_manufacture_semantic_uncertainty() {
    for code in [
        tonic::Code::Ok,
        tonic::Code::Aborted,
        tonic::Code::Cancelled,
        tonic::Code::Internal,
    ] {
        let original = tonic::Status::new(code, "ordinary item verdict");
        let item = ItemStatus::from(&original);
        assert!(!item.has_outcome_unknown());
        let decoded = ItemStatus::decode(item.encode_to_vec().as_slice()).unwrap();
        let status = tonic::Status::from(&decoded);
        assert_eq!(status.code(), code);
        assert!(!status.metadata().contains_key("lore-outcome-unknown"));
    }
}

#[test]
fn marked_status_roundtrips_its_operation_and_attempt_on_the_wire() {
    let mut status = tonic::Status::aborted("provider result is indeterminate");
    status
        .metadata_mut()
        .insert("lore-outcome-unknown", "v1".parse().unwrap());
    status.metadata_mut().insert(
        "lore-outcome-unknown-operation",
        "StorageService.Copy".parse().unwrap(),
    );
    status.metadata_mut().insert(
        "lore-outcome-unknown-attempt",
        "018f0000-0000-7000-8000-000000000001".parse().unwrap(),
    );
    let item = ItemStatus::from(&status);
    assert_eq!(item.outcome_unknown_version, 1);
    let decoded = ItemStatus::decode(item.encode_to_vec().as_slice()).unwrap();
    let restored = tonic::Status::from(&decoded);
    for key in [
        "lore-outcome-unknown",
        "lore-outcome-unknown-operation",
        "lore-outcome-unknown-attempt",
    ] {
        assert_eq!(restored.metadata().get(key), status.metadata().get(key));
    }
}

#[test]
fn future_or_incomplete_markers_cannot_turn_into_success() {
    for (version, operation, attempt) in [
        (1, "", ""),
        (77, "", ""),
        (0, "Copy", ""),
        (0, "", "attempt"),
        (1, "non-ascii-☃", "\n"),
    ] {
        let item = ItemStatus {
            code: 0,
            outcome_unknown_version: version,
            outcome_unknown_operation: operation.into(),
            outcome_unknown_attempt: attempt.into(),
            ..Default::default()
        };
        let decoded = ItemStatus::decode(item.encode_to_vec().as_slice()).unwrap();
        assert!(decoded.has_outcome_unknown());
        assert!(!decoded.is_ok());
        assert_eq!(
            tonic::Status::from(&decoded)
                .metadata()
                .get("lore-outcome-unknown")
                .unwrap(),
            "v1"
        );
    }
}

#[test]
fn additive_marker_field_tags_are_stable() {
    let item = ItemStatus {
        outcome_unknown_version: 1,
        outcome_unknown_operation: "x".into(),
        outcome_unknown_attempt: "y".into(),
        ..Default::default()
    };
    assert_eq!(
        item.encode_to_vec(),
        [0x18, 1, 0x22, 1, b'x', 0x2a, 1, b'y']
    );
    assert!(ItemStatus::decode(&[][..]).unwrap().is_ok());
}

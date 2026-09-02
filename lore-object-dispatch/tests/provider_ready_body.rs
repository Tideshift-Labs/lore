// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use std::path::PathBuf;

use lore_object_dispatch::ProviderClientError;
use lore_object_dispatch::PutSpoolReadyOutcome;
use lore_object_dispatch::bind_durable_put_body_from_ready;
use lore_object_dispatch::spool::SpoolLayout;
use lore_object_dispatch::spool::SpoolObjectKey;
use lore_object_dispatch::spool::SpoolObjectKind;
use uuid::Uuid;

const BOUNDARY: &str = "cell-alpha-boundary";
const LOGICAL_REQUEST_ID: &str = "018bcfe5-6800-7abc-8def-000000000001";
const ATTEMPT_ID: &str = "018bcfe5-6800-7abc-8def-000000000002";
const OTHER_LOGICAL_REQUEST_ID: &str = "018bcfe5-6800-7abc-8def-000000000011";
const OTHER_ATTEMPT_ID: &str = "018bcfe5-6800-7abc-8def-000000000012";
const SIZE: u64 = 262_144;
const DIGEST: [u8; 32] = [0xa5; 32];

fn root() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from("C:\\lore-spool")
    } else {
        PathBuf::from("/lore-spool")
    }
}

fn uuid(value: &str) -> Uuid {
    match Uuid::parse_str(value) {
        Ok(value) => value,
        Err(error) => panic!("fixture UUID must parse: {error}"),
    }
}

fn handle_for(boundary: &str, logical_request_id: &str, attempt_id: &str) -> String {
    let layout = match SpoolLayout::new(root()) {
        Ok(layout) => layout,
        Err(error) => panic!("fixture root must be valid: {error}"),
    };
    let key = SpoolObjectKey {
        provider_boundary_id: boundary.to_string(),
        logical_request_id: logical_request_id.to_string(),
        attempt_id: attempt_id.to_string(),
        kind: SpoolObjectKind::Put,
    };
    match layout.derive_paths(&key) {
        Ok(paths) => paths.opaque_handle().to_string(),
        Err(error) => panic!("fixture key must derive: {error}"),
    }
}

fn ready() -> PutSpoolReadyOutcome {
    PutSpoolReadyOutcome {
        spool_object_id: uuid("018bcfe5-6800-7abc-8def-000000000003"),
        logical_request_id: uuid(LOGICAL_REQUEST_ID),
        attempt_id: uuid(ATTEMPT_ID),
        upload_id: uuid("018bcfe5-6800-7abc-8def-000000000004"),
        upload_fence: 9,
        durable_handle: handle_for(BOUNDARY, LOGICAL_REQUEST_ID, ATTEMPT_ID),
        committed_size: SIZE,
        committed_blake3: DIGEST,
        ready_at_unix_ms: 1_700_000_000_000,
        reserve_put_ack_canonical_bytes: vec![1, 2, 3],
        reserve_put_ack_blake3: [0xb6; 32],
        spool_revision: 7,
        record_blake3: [0xc7; 32],
    }
}

#[test]
fn ready_result_projects_the_exact_handle_identity_size_and_hash() {
    let ready = ready();
    let body = match bind_durable_put_body_from_ready(root(), BOUNDARY, &ready) {
        Ok(body) => body,
        Err(error) => panic!("valid ready result must bind: {error}"),
    };

    assert_eq!(body.opaque_handle(), ready.durable_handle);
    assert_eq!(body.provider_boundary_id(), BOUNDARY);
    assert_eq!(body.logical_request_id(), LOGICAL_REQUEST_ID);
    assert_eq!(body.spool_attempt_id(), ATTEMPT_ID);
    assert_eq!(body.size(), SIZE);
    assert_eq!(body.blake3(), &DIGEST);
}

#[test]
fn ready_result_rejects_an_invalid_shared_root_before_binding() {
    assert_eq!(
        bind_durable_put_body_from_ready(PathBuf::from("relative-spool"), BOUNDARY, &ready()),
        Err(ProviderClientError::InvalidSpoolKey)
    );
}

#[test]
fn ready_result_rejects_a_handle_derived_for_another_boundary() {
    assert_eq!(
        bind_durable_put_body_from_ready(root(), "cell-beta-boundary", &ready()),
        Err(ProviderClientError::PutBodyHandleMismatch)
    );
}

#[test]
fn ready_result_handle_binds_both_logical_and_attempt_identity() {
    let mut wrong_logical = ready();
    wrong_logical.logical_request_id = uuid(OTHER_LOGICAL_REQUEST_ID);
    assert_eq!(
        bind_durable_put_body_from_ready(root(), BOUNDARY, &wrong_logical),
        Err(ProviderClientError::PutBodyHandleMismatch)
    );

    let mut wrong_attempt = ready();
    wrong_attempt.attempt_id = uuid(OTHER_ATTEMPT_ID);
    assert_eq!(
        bind_durable_put_body_from_ready(root(), BOUNDARY, &wrong_attempt),
        Err(ProviderClientError::PutBodyHandleMismatch)
    );
}

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Character-class coverage for the canonical-ID validation that CR-033's contract-move refactor
//! relocates from `auth::validate_id` to `contract::validate_canonical_id`.
//!
//! `contract` is crate-private, so this suite drives the moved logic through its public callers:
//! `SpoolLayout::derive_boundary_binding` (`spool.rs`), which maps the boundary to its own typed
//! error (`SpoolLayoutError::InvalidBoundaryId`), and `fingerprint_object_store_request`
//! (`request.rs`), which applies the same check to `provider_boundary_id` at the CR-033 D3
//! `authority.rs`-fold call site and maps it to `RequestContractError::InvalidCanonicalText`.
//! `auth.rs` and its `AuthorizedCallerRegistry` wrapper were the character-class matrix's third
//! caller before CR-033 removed the source-dark service shell (D1/D6/P2).

use std::path::PathBuf;

use lore_object_dispatch::AuthenticatedConsumerIdentity;
use lore_object_dispatch::ObjectStoreOperationLimits;
use lore_object_dispatch::RequestContractError;
use lore_object_dispatch::RequestFingerprintLimits;
use lore_object_dispatch::RequestIdentityLimits;
use lore_object_dispatch::ReservationPolicyLimits;
use lore_object_dispatch::SpoolLayout;
use lore_object_dispatch::SpoolLayoutError;
use lore_object_dispatch::fingerprint_object_store_request;
use lore_proto::lore::object_dispatch::v1::HeadBucketV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreRequestV1;
use lore_proto::lore::object_dispatch::v1::ReservedDimensionV1;
use lore_proto::lore::object_dispatch::v1::ResultConsumerContextV1;
use lore_proto::lore::object_dispatch::v1::StartupAdmissionConsumerContextV1;
use lore_proto::lore::object_dispatch::v1::object_store_request_v1;
use lore_proto::lore::object_dispatch::v1::result_consumer_context_v1;

fn spool_root() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\object-dispatch-spool-canonical-id-fixture")
    } else {
        PathBuf::from("/var/lib/object-dispatch-spool-canonical-id-fixture")
    }
}

fn spool_boundary_result(provider_boundary_id: &str) -> Result<(), SpoolLayoutError> {
    let layout =
        SpoolLayout::new(spool_root()).expect("absolute normalized test root must be valid");
    layout
        .derive_boundary_binding(provider_boundary_id)
        .map(|_| ())
}

fn request_authority_limits() -> RequestFingerprintLimits {
    RequestFingerprintLimits {
        identity: RequestIdentityLimits {
            max_identity_bytes: 256,
            max_authenticated_scope_bytes: 256,
        },
        reservations: ReservationPolicyLimits {
            max_reserved_dimensions_per_request: 4,
            max_reservation_id_bytes: 64,
            max_physical_dimension_id_bytes: 64,
            max_operation_class_id_bytes: 64,
        },
        operation: ObjectStoreOperationLimits {
            max_bucket_bytes: 63,
            max_key_bytes: 64,
            max_opaque_value_bytes: 64,
            max_body_handle_bytes: 64,
            max_metadata_entries: 4,
            max_metadata_key_bytes: 32,
            max_metadata_value_bytes: 64,
            max_metadata_aggregate_bytes: 128,
            max_list_entries: 100,
            max_result_bytes: 1024,
            max_body_bytes: 1024,
            allowed_metadata_keys: Vec::new(),
        },
        max_fingerprint_preimage_bytes: 4096,
    }
}

/// Drives `contract::validate_canonical_id` through `fingerprint_object_store_request`'s
/// `provider_boundary_id` check, the CR-033 D3 `authority.rs`-fold call site (`request.rs`), rather
/// than through `spool.rs`'s unrelated wrapper. Uses `HeadBucket` with `StartupAdmission` consumer
/// context, which never reconstructs an authenticated scope from identity fields, so a varying
/// `provider_boundary_id` stays isolated to the charset check under test.
fn request_authority_result(provider_boundary_id: &str) -> Result<(), RequestContractError> {
    let identity = AuthenticatedConsumerIdentity {
        provider_boundary_id: provider_boundary_id.to_string(),
        authenticated_cell_id: "cell".to_string(),
        authenticated_tenant_id: "tenant".to_string(),
        principal_id: "principal".to_string(),
    };
    let request = ObjectStoreRequestV1 {
        protocol_revision: "protocol-1".to_string(),
        provider_boundary_id: provider_boundary_id.to_string(),
        authenticated_cell_id: "cell".to_string(),
        authenticated_tenant_id: "tenant".to_string(),
        logical_request_id: "018f3e12-a456-7abc-8def-0123456789ab".to_string(),
        attempt_id: "018f3e12-a457-7abc-8def-0123456789ab".to_string(),
        canonical_fingerprint: Default::default(),
        allocation_revision: "allocation-1".to_string(),
        allocation_fence: 7,
        cell_admission_id: String::new(),
        cell_admission_fence: 0,
        deadline_unix_ms: 1_725_000_000_000,
        reservations: vec![ReservedDimensionV1 {
            reservation_id: "reservation-a".to_string(),
            physical_dimension_id: "physical-a".to_string(),
            operation_class_id: "class-a".to_string(),
            units: 1,
        }],
        consumer_context: Some(ResultConsumerContextV1 {
            consumer: Some(result_consumer_context_v1::Consumer::StartupAdmission(
                StartupAdmissionConsumerContextV1 {
                    policy_revision: "policy-1".to_string(),
                    allocation_revision: "allocation-1".to_string(),
                    config_revision: "config-1".to_string(),
                    startup_attempt_id: "startup-1".to_string(),
                    readiness_generation: 1,
                },
            )),
        }),
        policy_revision: "policy-1".to_string(),
        operation: Some(object_store_request_v1::Operation::HeadBucket(
            HeadBucketV1 {
                bucket: "bucket-1".to_string(),
            },
        )),
    };
    fingerprint_object_store_request(&request, &identity, &request_authority_limits()).map(|_| ())
}

// -- Character-class matrix, driven through the two surviving public callers -----------------

#[test]
fn empty_id_is_rejected() {
    assert_eq!(
        spool_boundary_result(""),
        Err(SpoolLayoutError::InvalidBoundaryId)
    );
    assert_eq!(
        request_authority_result(""),
        Err(RequestContractError::InvalidCanonicalText)
    );
}

#[test]
fn id_at_exactly_256_bytes_is_accepted() {
    let id = "a".repeat(256);
    assert_eq!(id.len(), 256);
    assert!(spool_boundary_result(&id).is_ok());
    assert!(request_authority_result(&id).is_ok());
}

#[test]
fn id_at_257_bytes_is_rejected() {
    let id = "a".repeat(257);
    assert_eq!(id.len(), 257);
    assert_eq!(
        spool_boundary_result(&id),
        Err(SpoolLayoutError::InvalidBoundaryId)
    );
    assert_eq!(
        request_authority_result(&id),
        Err(RequestContractError::InvalidCanonicalText)
    );
}

#[test]
fn leading_byte_must_be_ascii_alphanumeric() {
    for leading in ['.', '_', ':', '/', '-'] {
        let id = format!("{leading}rest-of-id");
        assert_eq!(
            spool_boundary_result(&id),
            Err(SpoolLayoutError::InvalidBoundaryId),
            "leading {leading:?} must be rejected"
        );
        assert_eq!(
            request_authority_result(&id),
            Err(RequestContractError::InvalidCanonicalText),
            "leading {leading:?} must be rejected"
        );
    }
}

#[test]
fn embedded_space_is_rejected() {
    assert_eq!(
        spool_boundary_result("valid id"),
        Err(SpoolLayoutError::InvalidBoundaryId)
    );
    assert_eq!(
        request_authority_result("valid id"),
        Err(RequestContractError::InvalidCanonicalText)
    );
}

#[test]
fn embedded_nul_is_rejected() {
    assert_eq!(
        spool_boundary_result("valid\0id"),
        Err(SpoolLayoutError::InvalidBoundaryId)
    );
    assert_eq!(
        request_authority_result("valid\0id"),
        Err(RequestContractError::InvalidCanonicalText)
    );
}

#[test]
fn non_ascii_multibyte_utf8_is_rejected() {
    // "valid\u{00e9}id" contains an accented e (U+00E9), which encodes as two UTF-8 bytes, neither
    // of which is ASCII alphanumeric or one of the five allowed punctuation bytes.
    assert_eq!(
        spool_boundary_result("valid\u{00e9}id"),
        Err(SpoolLayoutError::InvalidBoundaryId)
    );
    assert_eq!(
        request_authority_result("valid\u{00e9}id"),
        Err(RequestContractError::InvalidCanonicalText)
    );
}

#[test]
fn ascii_control_byte_is_rejected() {
    let id = format!("valid{}id", '\u{0001}');
    assert_eq!(
        spool_boundary_result(&id),
        Err(SpoolLayoutError::InvalidBoundaryId)
    );
    assert_eq!(
        request_authority_result(&id),
        Err(RequestContractError::InvalidCanonicalText)
    );
}

#[test]
fn ascii_punctuation_outside_the_allowed_five_is_rejected() {
    for byte in ['!', '@', '#', '$', '%', '+', ',', ';', '=', '\\'] {
        let id = format!("valid{byte}id");
        assert_eq!(
            spool_boundary_result(&id),
            Err(SpoolLayoutError::InvalidBoundaryId),
            "punctuation {byte:?} must be rejected"
        );
        assert_eq!(
            request_authority_result(&id),
            Err(RequestContractError::InvalidCanonicalText),
            "punctuation {byte:?} must be rejected"
        );
    }
}

#[test]
fn allowed_character_set_is_accepted() {
    // Every allowed punctuation byte (`.` `_` `:` `/` `-`) plus alphanumerics, first byte alphanumeric.
    assert!(spool_boundary_result("a0.b_c:d/e-F9").is_ok());
    assert!(request_authority_result("a0.b_c:d/e-F9").is_ok());
}

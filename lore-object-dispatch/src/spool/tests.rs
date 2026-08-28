// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use std::path::PathBuf;

use super::*;

const LOGICAL_ID: &str = "018f3e12-a456-7abc-8def-0123456789ab";
const ATTEMPT_ID: &str = "018f3e12-a457-7abc-8def-0123456789ab";
const BOUNDARY_TOKEN: &str = "odsb_pah6z3goyhrxzmhifdrnh3wbpj6aoykz2e52gfny2yj7a6vgtsia";
const BOUNDARY_DIGEST: [u8; 32] = [
    0x78, 0x0f, 0xec, 0xec, 0xce, 0xc1, 0xe3, 0x7c, 0xb0, 0xe8, 0x28, 0xe2, 0xd3, 0xee, 0xc1, 0x7a,
    0x7c, 0x07, 0x61, 0x59, 0xd1, 0x3b, 0xa3, 0x15, 0xb8, 0xd6, 0x13, 0xf0, 0x7a, 0xa6, 0x9c, 0x90,
];
const BODY_DIGEST: [u8; 32] = [0x11; 32];
const OTHER_DIGEST: [u8; 32] = [0x22; 32];
const RELEASE_DIGEST: [u8; 32] = [0x33; 32];
const VERIFIER_ROOT_BINDING: [u8; 32] = [0x44; 32];
const ADVERSARIAL_BOUNDARY_DIGEST: [u8; 32] = [
    0x4c, 0x54, 0x87, 0xd0, 0xcc, 0xc4, 0xab, 0x6e, 0x0a, 0xc5, 0x1c, 0x63, 0xbd, 0x73, 0x57, 0x42,
    0x01, 0x98, 0x0b, 0xe0, 0x7c, 0xd1, 0xb1, 0x21, 0xed, 0x74, 0x50, 0xb9, 0x28, 0x58, 0x4e, 0x6a,
];
const ADVERSARIAL_BOUNDARY_TOKEN: &str =
    "odsb_jrkipugmysvw4cwfdrr3242xiiazqc7apti3cipnorilskcyjzva";

fn absolute_root() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\object-dispatch-spool")
    } else {
        PathBuf::from("/var/lib/object-dispatch-spool")
    }
}

fn key(kind: SpoolObjectKind) -> SpoolObjectKey {
    SpoolObjectKey {
        provider_boundary_id: "boundary".to_string(),
        logical_request_id: LOGICAL_ID.to_string(),
        attempt_id: ATTEMPT_ID.to_string(),
        kind,
    }
}

fn layout() -> SpoolLayout {
    SpoolLayout::new(absolute_root()).expect("absolute normalized test root must be valid")
}

fn expected_relative(kind: &str) -> String {
    format!(
        "object-store-spool-layout-v1/{BOUNDARY_TOKEN}/{kind}/4f78/{LOGICAL_ID}/{ATTEMPT_ID}.blob"
    )
}

fn assert_fail_closed(
    ledger: &LedgerSpoolView,
    observation: VerifiedFileObservation,
    expected: SpoolRecoveryInconsistency,
) {
    assert_eq!(
        classify_spool_recovery(ledger, observation, &paths()),
        SpoolRecoveryDecision::FailClosed(expected)
    );
}

fn paths() -> SpoolPaths {
    layout()
        .derive_paths(&key(SpoolObjectKind::Put))
        .expect("canonical PUT identity must derive paths")
}

fn observation_for(
    paths: &SpoolPaths,
    kind: VerifiedFileObservationKind,
) -> VerifiedFileObservation {
    VerifiedFileObservation {
        path_binding_blake3: paths.observation_binding_blake3,
        verifier_root_binding_blake3: VERIFIER_ROOT_BINDING,
        kind,
    }
}

fn observation(kind: VerifiedFileObservationKind) -> VerifiedFileObservation {
    observation_for(&paths(), kind)
}

fn no_file() -> VerifiedFileObservation {
    observation(VerifiedFileObservationKind::None)
}

fn part(size: u64, blake3: Option<[u8; 32]>) -> VerifiedFileObservation {
    observation(VerifiedFileObservationKind::Part { size, blake3 })
}

fn blob(size: u64, blake3: [u8; 32]) -> VerifiedFileObservation {
    observation(VerifiedFileObservationKind::Blob { size, blake3 })
}

fn both() -> VerifiedFileObservation {
    observation(VerifiedFileObservationKind::Both)
}

fn unsafe_file() -> VerifiedFileObservation {
    observation(VerifiedFileObservationKind::UnsafeOrNonRegular)
}

#[test]
fn derive_put_paths_pins_boundary_token_fanout_handle_and_physical_paths() {
    let paths = layout()
        .derive_paths(&key(SpoolObjectKind::Put))
        .expect("canonical PUT identity must derive paths");
    let relative = expected_relative("put");

    assert_eq!(paths.opaque_handle(), relative);
    assert_eq!(paths.final_path(), absolute_root().join(&relative));
    assert_eq!(
        paths.part_path(),
        absolute_root().join(relative.replace(".blob", ".part"))
    );
}

#[test]
fn derive_result_paths_pins_the_closed_kind_component() {
    let paths = layout()
        .derive_paths(&key(SpoolObjectKind::Result))
        .expect("canonical result identity must derive paths");

    assert_eq!(paths.opaque_handle(), expected_relative("result"));
}

#[test]
fn opaque_handle_is_posix_and_platform_independent() {
    let handle = layout()
        .derive_paths(&key(SpoolObjectKind::Put))
        .expect("canonical PUT identity must derive paths")
        .opaque_handle()
        .to_string();

    assert_eq!(handle.matches('/').count(), 5);
    assert!(!handle.contains('\\'));
}

#[test]
fn boundary_binding_pins_full_digest_and_lowercase_unpadded_base32_token() {
    let binding = layout()
        .derive_boundary_binding("boundary")
        .expect("canonical boundary must derive a binding");

    assert_eq!(binding.provider_boundary_id(), "boundary");
    assert_eq!(binding.boundary_blake3(), &BOUNDARY_DIGEST);
    assert_eq!(binding.boundary_token(), BOUNDARY_TOKEN);
    validate_spool_boundary_binding(
        "boundary",
        binding.provider_boundary_id(),
        binding.boundary_blake3(),
        binding.boundary_token(),
    )
    .expect("the exact boundary, digest, and token tuple must validate");
}

#[test]
fn boundary_binding_rejects_token_digest_and_boundary_tuple_mismatch() {
    let canonical = layout()
        .derive_boundary_binding("boundary")
        .expect("canonical boundary must derive a binding");
    for (stored_boundary, stored_digest, stored_token) in [
        (
            "boundary",
            *canonical.boundary_blake3(),
            format!("{}x", canonical.boundary_token()),
        ),
        (
            "boundary",
            OTHER_DIGEST,
            canonical.boundary_token().to_string(),
        ),
        (
            "other-boundary",
            *canonical.boundary_blake3(),
            canonical.boundary_token().to_string(),
        ),
    ] {
        assert_eq!(
            validate_spool_boundary_binding(
                "boundary",
                stored_boundary,
                &stored_digest,
                &stored_token,
            ),
            Err(SpoolLayoutError::BoundaryBindingMismatch)
        );
    }
}

#[test]
fn adversarial_boundary_bytes_never_become_path_components() {
    let valid_adversarial = [
        "slash/value",
        "segment/../value",
        "colon:value",
        "BOUNDARY",
        "boundary",
    ];
    let mut tokens = Vec::new();

    for provider_boundary_id in valid_adversarial {
        let mut object_key = key(SpoolObjectKind::Put);
        object_key.provider_boundary_id = provider_boundary_id.to_string();
        let paths = layout()
            .derive_paths(&object_key)
            .expect("raw boundary bytes must be isolated behind a digest token");
        let handle = paths.opaque_handle();
        let token = handle
            .split('/')
            .nth(1)
            .expect("canonical handle must contain a boundary token");

        assert_eq!(token.len(), 57);
        assert!(token.starts_with("odsb_"));
        assert!(
            token[5..]
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
        );
        assert!(!handle.contains(provider_boundary_id));
        tokens.push(token.to_string());
    }

    tokens.sort();
    tokens.dedup();
    assert_eq!(tokens.len(), valid_adversarial.len());
}

#[test]
fn noncanonical_boundary_ids_fail_before_path_derivation() {
    for provider_boundary_id in [
        r"backslash\value",
        "..",
        ".hidden",
        r"C:\drive",
        r"\\server\share",
        "nul\0value",
        "é",
    ] {
        let mut object_key = key(SpoolObjectKind::Put);
        object_key.provider_boundary_id = provider_boundary_id.to_string();

        assert_eq!(
            layout().derive_paths(&object_key),
            Err(SpoolLayoutError::InvalidBoundaryId)
        );
    }
}

#[test]
fn adversarial_boundary_vector_pins_exact_utf8_hashing() {
    let mut object_key = key(SpoolObjectKind::Put);
    object_key.provider_boundary_id = "Bound/ary:segment".to_string();
    let paths = layout()
        .derive_paths(&object_key)
        .expect("boundary bytes must hash without path interpretation");
    let binding = paths.boundary_binding();

    assert_eq!(binding.boundary_blake3(), &ADVERSARIAL_BOUNDARY_DIGEST);
    assert_eq!(binding.boundary_token(), ADVERSARIAL_BOUNDARY_TOKEN);
    assert!(!paths.opaque_handle().contains("Bound/ary:segment"));
}

#[test]
fn derive_rejects_noncanonical_uuidv7_identifiers() {
    for logical_request_id in [
        "018F3E12-A456-7ABC-8DEF-0123456789AB",
        "018f3e12a4567abc8def0123456789ab",
        "{018f3e12-a456-7abc-8def-0123456789ab}",
        "018f3e12-a456-6abc-8def-0123456789ab",
        "018f3e12-a456-7abc-0def-0123456789ab",
        "not-a-uuid",
    ] {
        let mut object_key = key(SpoolObjectKind::Put);
        object_key.logical_request_id = logical_request_id.to_string();

        assert_eq!(
            layout().derive_paths(&object_key),
            Err(SpoolLayoutError::InvalidUuidV7)
        );
    }

    let mut object_key = key(SpoolObjectKind::Put);
    object_key.attempt_id = "018f3e12-a457-4abc-8def-0123456789ab".to_string();
    assert_eq!(
        layout().derive_paths(&object_key),
        Err(SpoolLayoutError::InvalidUuidV7)
    );
}

#[test]
fn new_rejects_relative_or_lexically_unnormalized_roots() {
    assert_eq!(
        SpoolLayout::new(PathBuf::from("relative/spool")),
        Err(SpoolLayoutError::InvalidSharedSpoolRoot)
    );

    let unnormalized = if cfg!(windows) {
        PathBuf::from(r"C:\spool\..\other")
    } else {
        PathBuf::from("/var/spool/../other")
    };
    assert_eq!(
        SpoolLayout::new(unnormalized),
        Err(SpoolLayoutError::InvalidSharedSpoolRoot)
    );
}

#[test]
fn absent_ledger_matrix_is_closed() {
    let ledger = LedgerSpoolView::Absent;
    assert_eq!(
        classify_spool_recovery(&ledger, no_file(), &paths()),
        SpoolRecoveryDecision::ConsistentAbsent
    );
    for observation in [part(1, None), blob(1, BODY_DIGEST), both()] {
        assert_eq!(
            classify_spool_recovery(&ledger, observation, &paths()),
            SpoolRecoveryDecision::CleanupOnlyCandidate
        );
    }
    assert_fail_closed(
        &ledger,
        unsafe_file(),
        SpoolRecoveryInconsistency::UnsafeFileType,
    );
}

#[test]
fn reserved_ledger_reconstructs_only_the_exact_safe_crash_boundaries() {
    let empty = LedgerSpoolView::Reserved {
        expected_size: 10,
        expected_blake3: BODY_DIGEST,
        accounted_prefix_bytes: 0,
    };
    assert_eq!(
        classify_spool_recovery(&empty, no_file(), &paths()),
        SpoolRecoveryDecision::AwaitUpload
    );

    let partial = LedgerSpoolView::Reserved {
        expected_size: 10,
        expected_blake3: BODY_DIGEST,
        accounted_prefix_bytes: 4,
    };
    assert_eq!(
        classify_spool_recovery(&partial, part(4, None), &paths(),),
        SpoolRecoveryDecision::RevalidateAccountedPrefix
    );
    assert_eq!(
        classify_spool_recovery(
            &LedgerSpoolView::Reserved {
                expected_size: 10,
                expected_blake3: BODY_DIGEST,
                accounted_prefix_bytes: 10,
            },
            part(10, Some(BODY_DIGEST)),
            &paths(),
        ),
        SpoolRecoveryDecision::CandidateForFinalPublication
    );
    assert_eq!(
        classify_spool_recovery(&partial, blob(10, BODY_DIGEST), &paths(),),
        SpoolRecoveryDecision::CandidateForReadyCommit
    );
}

#[test]
fn reserved_ledger_fails_closed_on_missing_or_conflicting_evidence() {
    let ledger = LedgerSpoolView::Reserved {
        expected_size: 10,
        expected_blake3: BODY_DIGEST,
        accounted_prefix_bytes: 4,
    };
    assert_fail_closed(
        &ledger,
        no_file(),
        SpoolRecoveryInconsistency::MissingAccountedPrefix,
    );
    assert_fail_closed(
        &ledger,
        part(5, None),
        SpoolRecoveryInconsistency::UnexpectedPartLength,
    );
    assert_fail_closed(
        &ledger,
        blob(9, BODY_DIGEST),
        SpoolRecoveryInconsistency::BlobMismatch,
    );
    assert_fail_closed(
        &ledger,
        blob(10, OTHER_DIGEST),
        SpoolRecoveryInconsistency::BlobMismatch,
    );
    assert_fail_closed(
        &ledger,
        both(),
        SpoolRecoveryInconsistency::MultipleArtifacts,
    );
    assert_fail_closed(
        &ledger,
        unsafe_file(),
        SpoolRecoveryInconsistency::UnsafeFileType,
    );
}

#[test]
fn complete_part_requires_the_exact_digest() {
    let ledger = LedgerSpoolView::Reserved {
        expected_size: 10,
        expected_blake3: BODY_DIGEST,
        accounted_prefix_bytes: 10,
    };
    for observation in [part(10, None), part(10, Some(OTHER_DIGEST))] {
        assert_fail_closed(
            &ledger,
            observation,
            SpoolRecoveryInconsistency::PartDigestMismatch,
        );
    }
}

#[test]
fn ready_ledger_accepts_only_the_exact_blob() {
    let handle = expected_relative("put");
    let ledger = LedgerSpoolView::Ready {
        opaque_handle: handle,
        size: 10,
        blake3: BODY_DIGEST,
    };
    assert_eq!(
        classify_spool_recovery(&ledger, blob(10, BODY_DIGEST), &paths(),),
        SpoolRecoveryDecision::ConsistentReady
    );

    for (observation, inconsistency) in [
        (
            blob(9, BODY_DIGEST),
            SpoolRecoveryInconsistency::BlobMismatch,
        ),
        (
            blob(10, OTHER_DIGEST),
            SpoolRecoveryInconsistency::BlobMismatch,
        ),
        (no_file(), SpoolRecoveryInconsistency::MissingReadyBlob),
        (
            part(10, Some(BODY_DIGEST)),
            SpoolRecoveryInconsistency::MissingReadyBlob,
        ),
        (both(), SpoolRecoveryInconsistency::MultipleArtifacts),
        (unsafe_file(), SpoolRecoveryInconsistency::UnsafeFileType),
    ] {
        assert_fail_closed(&ledger, observation, inconsistency);
    }
}

#[test]
fn released_ledger_requires_receipt_and_never_adopts_artifacts() {
    let ledger = LedgerSpoolView::Released {
        release_receipt_blake3: RELEASE_DIGEST,
    };
    assert_eq!(
        classify_spool_recovery(&ledger, no_file(), &paths()),
        SpoolRecoveryDecision::ConsistentAbsent
    );
    for observation in [part(4, None), blob(10, BODY_DIGEST), both()] {
        assert_eq!(
            classify_spool_recovery(&ledger, observation, &paths()),
            SpoolRecoveryDecision::CleanupOnlyCandidate
        );
    }
    assert_fail_closed(
        &ledger,
        unsafe_file(),
        SpoolRecoveryInconsistency::UnsafeFileType,
    );
}

#[test]
fn reserved_ledger_rejects_prefix_overflow() {
    assert_fail_closed(
        &LedgerSpoolView::Reserved {
            expected_size: 10,
            expected_blake3: BODY_DIGEST,
            accounted_prefix_bytes: 11,
        },
        no_file(),
        SpoolRecoveryInconsistency::InvalidLedgerState,
    );
}

#[test]
fn reserved_ledger_handles_u64_max_without_arithmetic_wraparound() {
    let ledger = LedgerSpoolView::Reserved {
        expected_size: u64::MAX,
        expected_blake3: BODY_DIGEST,
        accounted_prefix_bytes: u64::MAX,
    };

    assert_eq!(
        classify_spool_recovery(&ledger, part(u64::MAX, Some(BODY_DIGEST)), &paths(),),
        SpoolRecoveryDecision::CandidateForFinalPublication
    );
}

#[test]
fn ready_ledger_rejects_noncanonical_handle() {
    for opaque_handle in [
        String::new(),
        "object-store-spool-layout-v1/x.part".to_string(),
    ] {
        assert_fail_closed(
            &LedgerSpoolView::Ready {
                opaque_handle,
                size: 10,
                blake3: BODY_DIGEST,
            },
            no_file(),
            SpoolRecoveryInconsistency::ReadyHandleMismatch,
        );
    }
}

#[test]
fn cross_request_observation_fails_closed_before_state_classification() {
    let expected_paths = paths();
    let mut other_key = key(SpoolObjectKind::Put);
    other_key.logical_request_id = "018f3e12-a458-7abc-8def-0123456789ab".to_string();
    let other_paths = layout()
        .derive_paths(&other_key)
        .expect("second canonical request must derive distinct paths");
    let observation = observation_for(
        &other_paths,
        VerifiedFileObservationKind::Blob {
            size: 10,
            blake3: BODY_DIGEST,
        },
    );

    assert_eq!(
        classify_spool_recovery(&LedgerSpoolView::Absent, observation, &expected_paths),
        SpoolRecoveryDecision::FailClosed(SpoolRecoveryInconsistency::ObservationPathMismatch)
    );
}

#[test]
fn debug_and_display_never_expose_root_boundary_ids_or_handles() {
    let mut object_key = key(SpoolObjectKind::Put);
    object_key.provider_boundary_id = "debug/secret-boundary".to_string();
    let paths = layout()
        .derive_paths(&object_key)
        .expect("canonical key must derive paths");
    let binding = layout()
        .derive_boundary_binding(&object_key.provider_boundary_id)
        .expect("canonical boundary must derive a binding");
    let part_observation = observation_for(
        &paths,
        VerifiedFileObservationKind::Part {
            size: 7,
            blake3: Some(BODY_DIGEST),
        },
    );
    let blob_observation = observation_for(
        &paths,
        VerifiedFileObservationKind::Blob {
            size: 9,
            blake3: OTHER_DIGEST,
        },
    );
    let secret_values = vec![
        absolute_root().to_string_lossy().into_owned(),
        object_key.provider_boundary_id.clone(),
        object_key.logical_request_id.clone(),
        object_key.attempt_id.clone(),
        paths.opaque_handle().to_string(),
        format!("{:?}", paths.observation_binding_blake3),
        format!("{BODY_DIGEST:?}"),
        format!("{OTHER_DIGEST:?}"),
    ];
    let rendered = [
        format!("{:#?}", layout()),
        format!("{object_key:#?}"),
        format!("{paths:#?}"),
        format!("{binding:#?}"),
        format!("{part_observation:#?}"),
        format!("{blob_observation:#?}"),
        format!(
            "{:#?}",
            LedgerSpoolView::Ready {
                opaque_handle: paths.opaque_handle().to_string(),
                size: 10,
                blake3: BODY_DIGEST,
            }
        ),
        SpoolLayoutError::InvalidUuidV7.to_string(),
        format!("{:?}", SpoolRecoveryInconsistency::InvalidLedgerState),
    ]
    .join("\n");

    for secret in secret_values {
        assert!(
            !rendered.contains(&secret),
            "rendered diagnostics leaked a secret"
        );
    }
}

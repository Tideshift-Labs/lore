// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_object_dispatch::EvidenceReference;
use lore_object_dispatch::NoDispatchProof;
use lore_object_dispatch::NoDispatchProofFields;
use lore_object_dispatch::NoDispatchReason;
use lore_object_dispatch::ObjectStoreQuotaUnits;
use lore_object_dispatch::ReservePutAdmissionInput;
use lore_object_dispatch::ReservePutAdmissionSnapshot;
use lore_object_dispatch::ReservePutError;
use lore_object_dispatch::ReservePutState;
use lore_object_dispatch::ReservePutStateSnapshot;
use lore_object_dispatch::build_no_dispatch_proof;
use lore_object_dispatch::calculate_reserve_put_admission;
use lore_object_dispatch::is_reserve_put_cleanup_eligible;
use lore_object_dispatch::validate_persisted_reserve_put_admission;
use lore_object_dispatch::validate_reserve_put_state_snapshot;

fn admission_input() -> ReservePutAdmissionInput {
    ReservePutAdmissionInput {
        database_now_unix_ms: 1_000,
        reservation_deadline_unix_ms: 1_500,
        allocation_hard_expiry_unix_ms: Some(1_600),
        current_allocation_hard_expiry_unix_ms: 1_600,
        prepared_ttl_ms: 200,
    }
}

fn admission() -> ReservePutAdmissionSnapshot {
    calculate_reserve_put_admission(admission_input()).expect("canonical admission must validate")
}

fn evidence(fill: u8) -> EvidenceReference {
    EvidenceReference::from_slice(&[fill; 32]).expect("32-byte evidence must validate")
}

fn no_dispatch_proof(reason: NoDispatchReason) -> NoDispatchProof {
    build_no_dispatch_proof(
        NoDispatchProofFields {
            reason,
            proof_id: "00000000-03e8-7000-8000-000000000000".to_string(),
            proof_fence: 1,
            committed_at_unix_ms: 1_000,
            authority_epoch: 2,
        },
        1024,
    )
    .expect("canonical no-dispatch proof must validate")
    .proof()
    .clone()
}

fn state_snapshot(state: ReservePutState, mask: u8) -> ReservePutStateSnapshot {
    ReservePutStateSnapshot {
        state,
        admission: admission(),
        reserved_quota: ObjectStoreQuotaUnits {
            bytes: 10,
            rows: 2,
            concurrency: 1,
        },
        spool_ready: (mask & 1 != 0).then(|| evidence(1)),
        closure: (mask & 2 != 0).then(|| evidence(2)),
        no_dispatch_proof: (mask & 4 != 0)
            .then(|| no_dispatch_proof(NoDispatchReason::PreparedTtlExpired)),
        payload_release_receipt: (mask & 8 != 0).then(|| evidence(4)),
    }
}

fn mask_is_valid(state: ReservePutState, mask: u8) -> bool {
    match state {
        ReservePutState::Reserved => mask == 0,
        ReservePutState::SpoolReady => mask == 1,
        ReservePutState::PreparedExpired => mask == 12,
        ReservePutState::Closed => mask == 2,
        ReservePutState::PayloadDisposed => mask == 10 || mask == 12,
    }
}

#[test]
fn reserve_put_admission_selects_each_exact_minimum_and_ties() {
    let cases = [
        (
            ReservePutAdmissionInput {
                reservation_deadline_unix_ms: 1_100,
                ..admission_input()
            },
            1_100,
        ),
        (
            ReservePutAdmissionInput {
                prepared_ttl_ms: 100,
                ..admission_input()
            },
            1_100,
        ),
        (
            ReservePutAdmissionInput {
                allocation_hard_expiry_unix_ms: Some(1_100),
                current_allocation_hard_expiry_unix_ms: 1_100,
                ..admission_input()
            },
            1_100,
        ),
        (
            ReservePutAdmissionInput {
                reservation_deadline_unix_ms: 1_200,
                allocation_hard_expiry_unix_ms: Some(1_200),
                current_allocation_hard_expiry_unix_ms: 1_200,
                prepared_ttl_ms: 200,
                ..admission_input()
            },
            1_200,
        ),
    ];

    for (input, expected) in cases {
        let result = calculate_reserve_put_admission(input).expect("minimum must be admitted");
        assert_eq!(result.admission_clock_unix_ms, 1_000);
        assert_eq!(result.expires_at_unix_ms, expected);
    }
}

#[test]
fn reserve_put_admission_pins_one_millisecond_future_boundaries() {
    let exact = ReservePutAdmissionInput {
        reservation_deadline_unix_ms: 1_001,
        allocation_hard_expiry_unix_ms: Some(1_001),
        current_allocation_hard_expiry_unix_ms: 1_001,
        prepared_ttl_ms: 1,
        ..admission_input()
    };
    assert_eq!(
        calculate_reserve_put_admission(exact)
            .expect("one millisecond future must be admitted")
            .expires_at_unix_ms,
        1_001
    );

    for input in [
        ReservePutAdmissionInput {
            reservation_deadline_unix_ms: 1_000,
            ..admission_input()
        },
        ReservePutAdmissionInput {
            allocation_hard_expiry_unix_ms: Some(1_000),
            current_allocation_hard_expiry_unix_ms: 1_000,
            ..admission_input()
        },
        ReservePutAdmissionInput {
            prepared_ttl_ms: 0,
            ..admission_input()
        },
    ] {
        assert!(calculate_reserve_put_admission(input).is_err());
    }
}

#[test]
fn reserve_put_admission_requires_present_exact_current_allocation_expiry() {
    let missing = ReservePutAdmissionInput {
        allocation_hard_expiry_unix_ms: None,
        ..admission_input()
    };
    let stale = ReservePutAdmissionInput {
        allocation_hard_expiry_unix_ms: Some(1_599),
        ..admission_input()
    };

    assert_eq!(
        calculate_reserve_put_admission(missing),
        Err(ReservePutError::MissingAllocationExpiry)
    );
    assert_eq!(
        calculate_reserve_put_admission(stale),
        Err(ReservePutError::AllocationExpiryMismatch)
    );
}

#[test]
fn reserve_put_admission_rejects_negative_inputs_and_checked_addition_overflow() {
    let negative_inputs = [
        ReservePutAdmissionInput {
            database_now_unix_ms: -1,
            ..admission_input()
        },
        ReservePutAdmissionInput {
            reservation_deadline_unix_ms: -1,
            ..admission_input()
        },
        ReservePutAdmissionInput {
            allocation_hard_expiry_unix_ms: Some(-1),
            ..admission_input()
        },
        ReservePutAdmissionInput {
            current_allocation_hard_expiry_unix_ms: -1,
            ..admission_input()
        },
        ReservePutAdmissionInput {
            prepared_ttl_ms: -1,
            ..admission_input()
        },
    ];
    for input in negative_inputs {
        assert_eq!(
            calculate_reserve_put_admission(input),
            Err(ReservePutError::NegativeTime)
        );
    }

    let overflow = ReservePutAdmissionInput {
        database_now_unix_ms: i64::MAX - 1,
        reservation_deadline_unix_ms: i64::MAX,
        allocation_hard_expiry_unix_ms: Some(i64::MAX),
        current_allocation_hard_expiry_unix_ms: i64::MAX,
        prepared_ttl_ms: 2,
    };
    assert_eq!(
        calculate_reserve_put_admission(overflow),
        Err(ReservePutError::ArithmeticOverflow)
    );
    assert_eq!(
        calculate_reserve_put_admission(ReservePutAdmissionInput {
            prepared_ttl_ms: 1,
            ..overflow
        })
        .expect("exact i64 boundary must be admitted")
        .expires_at_unix_ms,
        i64::MAX
    );
}

#[test]
fn persisted_reserve_put_admission_recomputes_every_original_input() {
    let persisted = admission();
    assert_eq!(
        validate_persisted_reserve_put_admission(persisted),
        Ok(persisted)
    );

    let mutations = [
        ReservePutAdmissionSnapshot {
            admission_clock_unix_ms: 1_001,
            ..persisted
        },
        ReservePutAdmissionSnapshot {
            expires_at_unix_ms: persisted.expires_at_unix_ms + 1,
            ..persisted
        },
        ReservePutAdmissionSnapshot {
            reservation_deadline_unix_ms: persisted.expires_at_unix_ms - 1,
            ..persisted
        },
        ReservePutAdmissionSnapshot {
            allocation_hard_expiry_unix_ms: persisted.expires_at_unix_ms - 1,
            ..persisted
        },
        ReservePutAdmissionSnapshot {
            prepared_ttl_ms: persisted.prepared_ttl_ms + 1,
            ..persisted
        },
    ];
    for mutation in mutations {
        assert!(validate_persisted_reserve_put_admission(mutation).is_err());
    }
}

#[test]
fn reserve_put_cleanup_eligibility_uses_inclusive_fresh_database_clock() {
    let persisted = admission();

    assert_eq!(
        is_reserve_put_cleanup_eligible(persisted, persisted.expires_at_unix_ms - 1),
        Ok(false)
    );
    assert_eq!(
        is_reserve_put_cleanup_eligible(persisted, persisted.expires_at_unix_ms),
        Ok(true)
    );
    assert_eq!(
        is_reserve_put_cleanup_eligible(persisted, persisted.expires_at_unix_ms + 1),
        Ok(true)
    );
    assert_eq!(
        is_reserve_put_cleanup_eligible(persisted, -1),
        Err(ReservePutError::NegativeTime)
    );
}

#[test]
fn reserve_put_state_exhaustively_accepts_exactly_six_of_eighty_presence_masks() {
    let states = [
        ReservePutState::Reserved,
        ReservePutState::SpoolReady,
        ReservePutState::PreparedExpired,
        ReservePutState::Closed,
        ReservePutState::PayloadDisposed,
    ];
    let mut accepted = 0;

    for state in states {
        for mask in 0..16 {
            let result = validate_reserve_put_state_snapshot(&state_snapshot(state, mask), 1024);
            assert_eq!(result.is_ok(), mask_is_valid(state, mask));
            accepted += usize::from(result.is_ok());
        }
    }
    assert_eq!(accepted, 6);
}

#[test]
fn prepared_expired_requires_reason_four_but_disposed_accepts_other_proven_reasons() {
    let mut prepared = state_snapshot(ReservePutState::PreparedExpired, 12);
    prepared.no_dispatch_proof = Some(no_dispatch_proof(NoDispatchReason::LocalValidationFailed));
    assert_eq!(
        validate_reserve_put_state_snapshot(&prepared, 1024),
        Err(ReservePutError::InvalidStateEvidence)
    );

    prepared.state = ReservePutState::PayloadDisposed;
    assert!(validate_reserve_put_state_snapshot(&prepared, 1024).is_ok());
}

#[test]
fn reserve_put_state_rejects_empty_quota_malformed_evidence_and_proof() {
    assert_eq!(
        EvidenceReference::from_slice(&[1; 31]),
        Err(ReservePutError::InvalidEvidenceDigest)
    );
    let mut empty = state_snapshot(ReservePutState::Reserved, 0);
    empty.reserved_quota = ObjectStoreQuotaUnits {
        bytes: 0,
        rows: 0,
        concurrency: 0,
    };
    assert_eq!(
        validate_reserve_put_state_snapshot(&empty, 1024),
        Err(ReservePutError::EmptyReservedQuota)
    );

    let mut malformed = state_snapshot(ReservePutState::PreparedExpired, 12);
    malformed
        .no_dispatch_proof
        .as_mut()
        .expect("fixture must contain proof")
        .proof_blake3[0] ^= 0xff;
    assert_eq!(
        validate_reserve_put_state_snapshot(&malformed, 1024),
        Err(ReservePutError::InvalidNoDispatchProof)
    );
    assert_eq!(
        validate_reserve_put_state_snapshot(&state_snapshot(ReservePutState::Reserved, 0), 0),
        Err(ReservePutError::InvalidNoDispatchMaximum)
    );
}

#[test]
fn reserve_put_state_retains_u64_quota_maxima_and_copies_evidence() {
    let mut snapshot = state_snapshot(ReservePutState::SpoolReady, 1);
    snapshot.reserved_quota = ObjectStoreQuotaUnits {
        bytes: u64::MAX,
        rows: u64::MAX,
        concurrency: u64::MAX,
    };
    let validated = validate_reserve_put_state_snapshot(&snapshot, 1024)
        .expect("u64 quota maxima must validate");

    assert_eq!(validated, snapshot);
    assert_eq!(validated.reserved_quota.bytes, u64::MAX);
    assert_eq!(validated.spool_ready, snapshot.spool_ready);
}

#[test]
fn reserve_put_evidence_diagnostics_redact_record_digests() {
    let evidence = evidence(3);
    let diagnostic = format!("{evidence:?}");

    assert!(diagnostic.contains("[REDACTED]"));
    assert!(!diagnostic.contains("3, 3, 3"));
}

#[test]
fn reserve_put_contract_remains_abstract_effect_free_and_unwired() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let service = std::fs::read_to_string(manifest.join("src/service.rs"))
        .expect("source-dark service source must be readable");
    let source = std::fs::read_to_string(manifest.join("src/reserve_put.rs"))
        .expect("ReservePut source must be readable");

    for forbidden in [
        "crate::reserve_put",
        "calculate_reserve_put_admission",
        "validate_reserve_put_state_snapshot",
    ] {
        assert!(
            !service.contains(forbidden),
            "source-dark service must not wire ReservePut primitive {forbidden}"
        );
    }
    for forbidden in [
        "tokio_postgres",
        "std::fs",
        "aws_sdk",
        "lore_aws",
        "lore_postgres",
        "PathBuf",
    ] {
        assert!(
            !source.contains(forbidden),
            "pure ReservePut contract must not depend on effect surface {forbidden}"
        );
    }
}

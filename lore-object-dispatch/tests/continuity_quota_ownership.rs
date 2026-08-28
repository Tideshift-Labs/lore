// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_object_dispatch::ContinuityQuotaOwnershipLimits;
use lore_object_dispatch::validate_and_encode_continuity_quota_ownership;
use lore_proto::lore::object_dispatch::v1::ObjectStoreContinuityQuotaOwnershipV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreQuotaUnitsV1;

const OWNERSHIP_DIGEST: [u8; 32] = [
    0x72, 0xfc, 0xb8, 0x69, 0xa0, 0x52, 0x9b, 0xfa, 0xec, 0x29, 0xf3, 0xa8, 0xb3, 0xdd, 0x42, 0x44,
    0x7d, 0x35, 0x56, 0x06, 0xa6, 0x42, 0xb9, 0x38, 0xc6, 0x94, 0xb5, 0x86, 0xf0, 0xb8, 0x07, 0x9d,
];

const OWNERSHIP_PREIMAGE_HEX: &str = concat!(
    "6f626a6563742d73746f72652d636f6e74696e756974792d71756f74612d",
    "6f776e6572736869702d763100",
    "00000013636f6e74696e756974792d706f6c6963792d31",
    "00000003505554",
    "000000000000006400000000000000020000000000000001",
    "000000216f626a6563742d73746f72652d636f6e74696e756974792d676c",
    "6f62616c2d7631",
    "0000000a626f756e646172792d31",
    "0000000663656c6c2d31",
    "0000000874656e616e742d31"
);

type OwnershipMutation = Box<dyn Fn(&mut ObjectStoreContinuityQuotaOwnershipV1)>;

fn limits() -> ContinuityQuotaOwnershipLimits {
    ContinuityQuotaOwnershipLimits {
        max_identity_bytes: 256,
        max_operation_quota_class_bytes: 64,
        max_policy_revision_bytes: 64,
        max_canonical_ownership_bytes: 4_096,
    }
}

fn ownership() -> ObjectStoreContinuityQuotaOwnershipV1 {
    ObjectStoreContinuityQuotaOwnershipV1 {
        continuity_policy_revision: "continuity-policy-1".to_string(),
        operation_quota_class: "PUT".to_string(),
        units: Some(ObjectStoreQuotaUnitsV1 {
            bytes: 100,
            rows: 2,
            concurrency: 1,
        }),
        global_scope_id: "object-store-continuity-global-v1".to_string(),
        provider_boundary_id: "boundary-1".to_string(),
        authenticated_cell_id: "cell-1".to_string(),
        authenticated_tenant_id: "tenant-1".to_string(),
        ownership_blake3: OWNERSHIP_DIGEST.to_vec().into(),
    }
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(std::str::from_utf8(pair).expect("hex is UTF-8"), 16)
                .expect("hex digit pair is valid")
        })
        .collect()
}

fn decode_digest(value: &str) -> Vec<u8> {
    let digest = decode_hex(value);
    assert_eq!(digest.len(), 32);
    digest
}

#[test]
fn pins_independently_assembled_preimage_digest_and_canonical_bytes() {
    let expected_preimage = decode_hex(OWNERSHIP_PREIMAGE_HEX);
    assert_eq!(expected_preimage.len(), 170);

    let encoded = validate_and_encode_continuity_quota_ownership(&ownership(), &limits())
        .expect("reference ownership must validate");

    assert_eq!(encoded.canonical_preimage(), expected_preimage);
    assert_eq!(encoded.ownership_blake3(), &OWNERSHIP_DIGEST);
    assert_eq!(
        encoded.canonical_bytes(),
        [expected_preimage.as_slice(), OWNERSHIP_DIGEST.as_slice()].concat()
    );
    assert_eq!(encoded.canonical_bytes().len(), 202);
}

#[test]
fn absent_digest_is_computed_and_populated_without_changing_canonical_bytes() {
    let supplied = validate_and_encode_continuity_quota_ownership(&ownership(), &limits())
        .expect("reference ownership must validate");
    let mut without_digest = ownership();
    without_digest.ownership_blake3 = Default::default();

    let computed = validate_and_encode_continuity_quota_ownership(&without_digest, &limits())
        .expect("absent digest must be computed");

    assert_eq!(computed.ownership_blake3(), &OWNERSHIP_DIGEST);
    assert_eq!(computed.value().ownership_blake3.as_ref(), OWNERSHIP_DIGEST);
    assert_eq!(computed.canonical_preimage(), supplied.canonical_preimage());
    assert_eq!(computed.canonical_bytes(), supplied.canonical_bytes());
}

#[test]
fn each_nonempty_quota_dimension_is_accepted() {
    for (units, digest) in [
        (
            ObjectStoreQuotaUnitsV1 {
                bytes: 1,
                rows: 0,
                concurrency: 0,
            },
            "eb411de0ab488b14d92c50d512265e9e2cc6029b8b271684fcd9c380b1c90bf3",
        ),
        (
            ObjectStoreQuotaUnitsV1 {
                bytes: 0,
                rows: 1,
                concurrency: 0,
            },
            "33a45f44eb70e3e2e7fec742d3c5cb22d5b32b27279f98a30d19dc6ec3a36828",
        ),
        (
            ObjectStoreQuotaUnitsV1 {
                bytes: 0,
                rows: 0,
                concurrency: 1,
            },
            "ea9452989b563afcf555d93d5e8b49451777084001db9dedf696fb1402341b49",
        ),
    ] {
        let mut input = ownership();
        input.units = Some(units);
        input.ownership_blake3 = decode_digest(digest).into();
        assert!(validate_and_encode_continuity_quota_ownership(&input, &limits()).is_ok());
    }
}

#[test]
fn requires_present_nonempty_quota_units() {
    for units in [
        None,
        Some(ObjectStoreQuotaUnitsV1 {
            bytes: 0,
            rows: 0,
            concurrency: 0,
        }),
    ] {
        let mut input = ownership();
        input.units = units;
        assert!(validate_and_encode_continuity_quota_ownership(&input, &limits()).is_err());
    }
}

#[test]
fn every_canonical_field_is_bound_by_the_digest() {
    let mutations: Vec<OwnershipMutation> = vec![
        Box::new(|value| value.continuity_policy_revision.push('x')),
        Box::new(|value| value.operation_quota_class.push('x')),
        Box::new(|value| value.units.as_mut().expect("fixture units").bytes += 1),
        Box::new(|value| value.units.as_mut().expect("fixture units").rows += 1),
        Box::new(|value| value.units.as_mut().expect("fixture units").concurrency += 1),
        Box::new(|value| value.global_scope_id.push('x')),
        Box::new(|value| value.provider_boundary_id.push('x')),
        Box::new(|value| value.authenticated_cell_id.push('x')),
        Box::new(|value| value.authenticated_tenant_id.push('x')),
    ];

    for mutate in mutations {
        let mut input = ownership();
        mutate(&mut input);
        assert!(validate_and_encode_continuity_quota_ownership(&input, &limits()).is_err());
    }
}

#[test]
fn requires_the_exact_global_scope_and_rejects_malformed_or_wrong_supplied_digests() {
    let mut wrong_scope = ownership();
    wrong_scope.global_scope_id = "object-store-continuity-global-v2".to_string();
    assert!(validate_and_encode_continuity_quota_ownership(&wrong_scope, &limits()).is_err());

    for digest in [vec![0_u8; 31], vec![0_u8; 32], vec![0_u8; 33]] {
        let mut input = ownership();
        input.ownership_blake3 = digest.into();
        assert!(validate_and_encode_continuity_quota_ownership(&input, &limits()).is_err());
    }
}

#[test]
fn canonical_text_rules_apply_to_every_text_class() {
    let mutations: Vec<OwnershipMutation> = vec![
        Box::new(|value| value.continuity_policy_revision.clear()),
        Box::new(|value| value.operation_quota_class.push('\0')),
        Box::new(|value| value.provider_boundary_id = "e\u{301}".to_string()),
        Box::new(|value| value.authenticated_cell_id.clear()),
        Box::new(|value| value.authenticated_tenant_id.push('\0')),
    ];

    for mutate in mutations {
        let mut input = ownership();
        mutate(&mut input);
        assert!(validate_and_encode_continuity_quota_ownership(&input, &limits()).is_err());
    }
}

#[test]
fn every_limit_is_positive_and_inclusive() {
    let input = ownership();
    let exact = ContinuityQuotaOwnershipLimits {
        max_identity_bytes: 33,
        max_operation_quota_class_bytes: 3,
        max_policy_revision_bytes: 19,
        max_canonical_ownership_bytes: 202,
    };
    assert!(validate_and_encode_continuity_quota_ownership(&input, &exact).is_ok());

    for invalid in [
        ContinuityQuotaOwnershipLimits {
            max_identity_bytes: 32,
            ..exact
        },
        ContinuityQuotaOwnershipLimits {
            max_operation_quota_class_bytes: 2,
            ..exact
        },
        ContinuityQuotaOwnershipLimits {
            max_policy_revision_bytes: 18,
            ..exact
        },
        ContinuityQuotaOwnershipLimits {
            max_canonical_ownership_bytes: 201,
            ..exact
        },
        ContinuityQuotaOwnershipLimits {
            max_identity_bytes: 0,
            ..exact
        },
        ContinuityQuotaOwnershipLimits {
            max_operation_quota_class_bytes: 0,
            ..exact
        },
        ContinuityQuotaOwnershipLimits {
            max_policy_revision_bytes: 0,
            ..exact
        },
        ContinuityQuotaOwnershipLimits {
            max_canonical_ownership_bytes: 0,
            ..exact
        },
    ] {
        assert!(validate_and_encode_continuity_quota_ownership(&input, &invalid).is_err());
    }
}

#[test]
fn validated_value_is_detached_and_replay_is_pure() {
    let mut input = ownership();
    let first = validate_and_encode_continuity_quota_ownership(&input, &limits())
        .expect("reference ownership must validate");
    let second = validate_and_encode_continuity_quota_ownership(&input, &limits())
        .expect("exact replay must validate");
    assert_eq!(first.value(), second.value());
    assert_eq!(first.canonical_bytes(), second.canonical_bytes());

    input.continuity_policy_revision = "mutated-after-validation".to_string();
    input.units.as_mut().expect("fixture units").bytes = 999;
    input.ownership_blake3 = vec![0; 32].into();
    assert_eq!(
        first.value().continuity_policy_revision,
        "continuity-policy-1"
    );
    assert_eq!(
        first.value().units.as_ref().expect("validated units").bytes,
        100
    );
    assert_eq!(first.ownership_blake3(), &OWNERSHIP_DIGEST);
}

#[test]
fn debug_redacts_identity_quota_preimage_and_digest_material() {
    let encoded = validate_and_encode_continuity_quota_ownership(&ownership(), &limits())
        .expect("reference ownership must validate");
    let debug = format!("{encoded:?}");

    for secret in [
        "continuity-policy-1",
        "PUT",
        "boundary-1",
        "cell-1",
        "tenant-1",
        "72fcb869",
        "100",
    ] {
        assert!(!debug.contains(secret), "Debug leaked {secret}: {debug}");
    }
}

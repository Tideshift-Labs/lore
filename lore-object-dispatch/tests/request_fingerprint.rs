// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_object_dispatch::AuthenticatedConsumerIdentity;
use lore_object_dispatch::DurablePutSpoolExpectation;
use lore_object_dispatch::ExistingFingerprint;
use lore_object_dispatch::ExpectedCellAdmission;
use lore_object_dispatch::ExpectedRequestAuthority;
use lore_object_dispatch::FirstSeenIdentityDecision;
use lore_object_dispatch::FirstSeenPrerequisites;
use lore_object_dispatch::IdempotencyDecision;
use lore_object_dispatch::ObjectStoreOperationLimits;
use lore_object_dispatch::RequestContractError;
use lore_object_dispatch::RequestFingerprintLimits;
use lore_object_dispatch::RequestIdentityLimits;
use lore_object_dispatch::ReservationPolicyLimits;
use lore_object_dispatch::ReservationRequirement;
use lore_object_dispatch::classify_first_seen_identity;
use lore_object_dispatch::classify_idempotency;
use lore_object_dispatch::fingerprint_object_store_request;
use lore_object_dispatch::validate_first_seen_prerequisites;
use lore_object_dispatch::validate_submitted_request_fingerprint;
use lore_proto::lore::object_dispatch::v1::DeleteObjectV1;
use lore_proto::lore::object_dispatch::v1::DurableConsumerContextV1;
use lore_proto::lore::object_dispatch::v1::DurableConsumerKindV1;
use lore_proto::lore::object_dispatch::v1::FragmentLifecycleConsumerContextV1;
use lore_proto::lore::object_dispatch::v1::GetObjectV1;
use lore_proto::lore::object_dispatch::v1::HeadBucketV1;
use lore_proto::lore::object_dispatch::v1::HeadObjectV1;
use lore_proto::lore::object_dispatch::v1::ListObjectVersionsV1;
use lore_proto::lore::object_dispatch::v1::ListObjectsV2v1;
use lore_proto::lore::object_dispatch::v1::ObjectMetadataEntryV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreRequestV1;
use lore_proto::lore::object_dispatch::v1::PutObjectV1;
use lore_proto::lore::object_dispatch::v1::ReservedDimensionV1;
use lore_proto::lore::object_dispatch::v1::ResultConsumerContextV1;
use lore_proto::lore::object_dispatch::v1::StartupAdmissionConsumerContextV1;
use lore_proto::lore::object_dispatch::v1::object_store_request_v1;
use lore_proto::lore::object_dispatch::v1::result_consumer_context_v1;

const LOGICAL_ID: &str = "018f3e12-a456-7abc-8def-0123456789ab";
const ATTEMPT_ID: &str = "018f3e12-a457-7abc-8def-0123456789ab";
const SCOPE: &str = "urn:lore:object-dispatch:Ym91bmRhcnk:Y2VsbA:dGVuYW50:job:cHJpbmNpcGFs";
// Repinned by WP-114 CD-3 for CR-033 D3's 2026-08-28 amendment: `allocation_revision` and
// `allocation_fence` are no longer written into the replay preimage. The superseded pair was
// digest a06dcf15…e903 over a 401-byte preimage; the 24 bytes that left are exactly
// `text("allocation-1") || u64BE(7)` at offset 155, and nothing else moved. The paired TypeScript
// vector in `lorehub/packages/control-plane/test/capacity/object-store-request-fingerprint.test.ts`
// assembles the same bytes independently from primitives and pins the same digest.
const GOLDEN_DIGEST: [u8; 32] = [
    0x9e, 0x99, 0x14, 0x35, 0xc9, 0xaf, 0xfb, 0xe2, 0x04, 0x57, 0x4d, 0xdb, 0x57, 0xee, 0xf2, 0x88,
    0xa3, 0xb0, 0xf5, 0x12, 0xfe, 0x87, 0xb8, 0xe9, 0x9b, 0x01, 0xe0, 0x91, 0x2b, 0xb5, 0xbd, 0x28,
];
const GOLDEN_PREIMAGE_HEX: &str = concat!(
    "6f626a6563742d64697370617463682d66696e6765727072696e742d7631000000000a70",
    "726f746f636f6c2d3100000008626f756e646172790000000463656c6c0000000674656e",
    "616e740000002430313866336531322d613435362d376162632d386465662d3031323334",
    "353637383961620000002430313866336531322d613435372d376162632d386465662d30",
    "31323334353637383961620000000b61646d697373696f6e2d3100000000000000080000",
    "0191a2032200000000010000000d7265736572766174696f6e2d610000000a7068797369",
    "63616c2d6100000007636c6173732d61000000000000000200000003010000004575726e",
    "3a6c6f72653a6f626a6563742d64697370617463683a596d3931626d5268636e6b3a5932",
    "567362413a64475675595735303a6a6f623a63484a70626d4e70634746730000000b6f70",
    "65726174696f6e2d310000000000000009000000000000000a00000008706f6c6963792d",
    "3100000014000000086275636b65742d31",
);

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("golden hex must be ASCII");
            u8::from_str_radix(text, 16).expect("golden preimage must be valid hex")
        })
        .collect()
}

fn independent_u8(output: &mut Vec<u8>, value: u8) {
    output.push(value);
}

fn independent_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn independent_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn independent_bytes(output: &mut Vec<u8>, value: &[u8]) {
    independent_u32(
        output,
        u32::try_from(value.len()).expect("literal vector length must fit u32"),
    );
    output.extend_from_slice(value);
}

fn independent_text(output: &mut Vec<u8>, value: &str) {
    independent_bytes(output, value.as_bytes());
}

fn independent_optional_text(output: &mut Vec<u8>, value: Option<&str>) {
    independent_u8(output, u8::from(value.is_some()));
    if let Some(value) = value {
        independent_text(output, value);
    }
}

fn independent_common_preimage(consumer: &[u8], operation: &[u8]) -> Vec<u8> {
    let mut output = b"object-dispatch-fingerprint-v1\0".to_vec();
    for value in [
        "protocol-1",
        "boundary",
        "cell",
        "tenant",
        LOGICAL_ID,
        ATTEMPT_ID,
    ] {
        independent_text(&mut output, value);
    }
    // No `allocation_revision` / `allocation_fence` here: CR-033 D3's amendment excludes the budget
    // pin from the replay preimage. `independent_startup_consumer` below still carries an
    // `allocation-1`, and that one is a different field — the StartupAdmission consumer context's
    // own record of the configuration its process started under, not the request's budget pin.
    independent_text(&mut output, "admission-1");
    independent_u64(&mut output, 8);
    independent_u64(&mut output, 1_725_000_000_000);
    independent_u32(&mut output, 1);
    for value in ["reservation-a", "physical-a", "class-a"] {
        independent_text(&mut output, value);
    }
    independent_u64(&mut output, 2);
    output.extend_from_slice(consumer);
    independent_text(&mut output, "policy-1");
    output.extend_from_slice(operation);
    output
}

fn independent_durable_consumer() -> Vec<u8> {
    let mut output = Vec::new();
    independent_u32(&mut output, 3);
    independent_u8(&mut output, 1);
    independent_text(&mut output, SCOPE);
    independent_text(&mut output, "operation-1");
    independent_u64(&mut output, 9);
    independent_u64(&mut output, 10);
    output
}

fn independent_fragment_consumer() -> Vec<u8> {
    let mut output = Vec::new();
    independent_u32(&mut output, 1);
    independent_bytes(&mut output, &[1; 32]);
    independent_optional_text(&mut output, None);
    independent_optional_text(&mut output, None);
    independent_u8(&mut output, 0);
    independent_u8(&mut output, 0);
    independent_u64(&mut output, 1);
    independent_u64(&mut output, 2);
    independent_u64(&mut output, 3);
    independent_optional_text(&mut output, None);
    independent_u8(&mut output, 0);
    output
}

fn independent_startup_consumer() -> Vec<u8> {
    let mut output = Vec::new();
    independent_u32(&mut output, 2);
    for value in ["policy-1", "allocation-1", "config-1", "startup-1"] {
        independent_text(&mut output, value);
    }
    independent_u64(&mut output, 1);
    output
}

fn independent_operation(tag: u32, fields: impl FnOnce(&mut Vec<u8>)) -> Vec<u8> {
    let mut output = Vec::new();
    independent_u32(&mut output, tag);
    fields(&mut output);
    output
}

fn identity() -> AuthenticatedConsumerIdentity {
    AuthenticatedConsumerIdentity {
        provider_boundary_id: "boundary".to_string(),
        authenticated_cell_id: "cell".to_string(),
        authenticated_tenant_id: "tenant".to_string(),
        principal_id: "principal".to_string(),
    }
}

fn limits() -> RequestFingerprintLimits {
    RequestFingerprintLimits {
        identity: RequestIdentityLimits {
            max_identity_bytes: 128,
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
            allowed_metadata_keys: vec!["x-a".to_string(), "x-b".to_string()],
        },
        max_fingerprint_preimage_bytes: 4096,
    }
}

fn durable_context(kind: DurableConsumerKindV1) -> ResultConsumerContextV1 {
    let kind_text = match kind {
        DurableConsumerKindV1::DurableConsumerKindJob => "job",
        DurableConsumerKindV1::DurableConsumerKindOperator => "operator",
        DurableConsumerKindV1::DurableConsumerKindMigrator => "migrator",
        _ => "invalid",
    };
    ResultConsumerContextV1 {
        consumer: Some(result_consumer_context_v1::Consumer::DurableConsumer(
            DurableConsumerContextV1 {
                consumer_kind: kind as i32,
                authenticated_scope: SCOPE.replace(":job:", &format!(":{kind_text}:")),
                operation_id: "operation-1".to_string(),
                checkpoint_revision: 9,
                checkpoint_fence: 10,
            },
        )),
    }
}

fn reservation(
    reservation_id: &str,
    physical_dimension_id: &str,
    operation_class_id: &str,
    units: u64,
) -> ReservedDimensionV1 {
    ReservedDimensionV1 {
        reservation_id: reservation_id.to_string(),
        physical_dimension_id: physical_dimension_id.to_string(),
        operation_class_id: operation_class_id.to_string(),
        units,
    }
}

fn base_request(operation: object_store_request_v1::Operation) -> ObjectStoreRequestV1 {
    ObjectStoreRequestV1 {
        protocol_revision: "protocol-1".to_string(),
        provider_boundary_id: "boundary".to_string(),
        authenticated_cell_id: "cell".to_string(),
        authenticated_tenant_id: "tenant".to_string(),
        logical_request_id: LOGICAL_ID.to_string(),
        attempt_id: ATTEMPT_ID.to_string(),
        canonical_fingerprint: Default::default(),
        allocation_revision: "allocation-1".to_string(),
        allocation_fence: 7,
        cell_admission_id: "admission-1".to_string(),
        cell_admission_fence: 8,
        deadline_unix_ms: 1_725_000_000_000,
        reservations: vec![reservation("reservation-a", "physical-a", "class-a", 2)],
        consumer_context: Some(durable_context(
            DurableConsumerKindV1::DurableConsumerKindJob,
        )),
        policy_revision: "policy-1".to_string(),
        operation: Some(operation),
    }
}

fn head_bucket() -> object_store_request_v1::Operation {
    object_store_request_v1::Operation::HeadBucket(HeadBucketV1 {
        bucket: "bucket-1".to_string(),
    })
}

fn put_object(metadata: Vec<ObjectMetadataEntryV1>) -> object_store_request_v1::Operation {
    object_store_request_v1::Operation::PutObject(PutObjectV1 {
        bucket: "bucket-1".to_string(),
        key: "key".to_string(),
        durable_body_handle: "spool-1".to_string(),
        body_size: 0,
        body_blake3: vec![7; 32].into(),
        metadata,
    })
}

fn operation_cases() -> Vec<object_store_request_v1::Operation> {
    vec![
        head_bucket(),
        object_store_request_v1::Operation::ListObjectsV2(ListObjectsV2v1 {
            bucket: "bucket-1".to_string(),
            prefix: String::new(),
            delimiter: String::new(),
            max_keys: 1,
            continuation_token: None,
        }),
        object_store_request_v1::Operation::HeadObject(HeadObjectV1 {
            bucket: "bucket-1".to_string(),
            key: "key".to_string(),
        }),
        object_store_request_v1::Operation::GetObject(GetObjectV1 {
            bucket: "bucket-1".to_string(),
            key: "key".to_string(),
            range_start: 0,
            range_length: 1,
        }),
        put_object(Vec::new()),
        object_store_request_v1::Operation::ListObjectVersions(ListObjectVersionsV1 {
            bucket: "bucket-1".to_string(),
            prefix: String::new(),
            delimiter: String::new(),
            max_keys: 1,
            key_marker: None,
            version_id_marker: None,
        }),
        object_store_request_v1::Operation::DeleteObject(DeleteObjectV1 {
            bucket: "bucket-1".to_string(),
            key: "key".to_string(),
            version_id: None,
        }),
    ]
}

fn fingerprint(request: &ObjectStoreRequestV1) -> lore_object_dispatch::ValidatedRequest {
    fingerprint_object_store_request(request, &identity(), &limits())
        .expect("canonical request must fingerprint")
}

fn expected_authority() -> ExpectedRequestAuthority {
    ExpectedRequestAuthority {
        protocol_revision: "protocol-1".to_string(),
        policy_revision: "policy-1".to_string(),
        provider_boundary_id: "boundary".to_string(),
        authenticated_cell_id: "cell".to_string(),
        authenticated_tenant_id: "tenant".to_string(),
        allocation_revision: "allocation-1".to_string(),
        allocation_fence: 7,
    }
}

fn expected_admission() -> ExpectedCellAdmission {
    ExpectedCellAdmission {
        cell_admission_id: "admission-1".to_string(),
        cell_admission_fence: 8,
    }
}

fn requirements() -> Vec<ReservationRequirement> {
    vec![ReservationRequirement {
        physical_dimension_id: "physical-a".to_string(),
        operation_class_id: "class-a".to_string(),
        units: 2,
        class_cap_required: true,
    }]
}

#[test]
fn fingerprint_pins_independent_literal_preimage_and_digest() {
    let result = fingerprint(&base_request(head_bucket()));

    assert_eq!(result.canonical_preimage(), decode_hex(GOLDEN_PREIMAGE_HEX));
    assert_eq!(result.canonical_preimage().len(), 377);
    assert_eq!(result.canonical_fingerprint(), &GOLDEN_DIGEST);
    assert_eq!(result.canonical_reservation_ids(), ["reservation-a"]);
}

#[test]
fn fingerprint_pins_independent_vectors_for_remaining_operations_and_contexts() {
    let durable = independent_durable_consumer();
    let list_operation = independent_operation(21, |output| {
        independent_text(output, "bucket-1");
        independent_text(output, "e\u{301}");
        independent_text(output, "");
        independent_u32(output, 1);
        independent_optional_text(output, Some(""));
    });
    let mut list_request = base_request(object_store_request_v1::Operation::ListObjectsV2(
        ListObjectsV2v1 {
            bucket: "bucket-1".to_string(),
            prefix: "e\u{301}".to_string(),
            delimiter: String::new(),
            max_keys: 1,
            continuation_token: Some(String::new()),
        },
    ));
    let head_operation = independent_operation(22, |output| {
        independent_text(output, "bucket-1");
        independent_text(output, "key");
    });
    let head_request = base_request(object_store_request_v1::Operation::HeadObject(
        HeadObjectV1 {
            bucket: "bucket-1".to_string(),
            key: "key".to_string(),
        },
    ));
    let get_operation = independent_operation(23, |output| {
        independent_text(output, "bucket-1");
        independent_text(output, "key");
        independent_u64(output, 0);
        independent_u64(output, 1);
    });
    let get_request = base_request(object_store_request_v1::Operation::GetObject(GetObjectV1 {
        bucket: "bucket-1".to_string(),
        key: "key".to_string(),
        range_start: 0,
        range_length: 1,
    }));
    let put_operation = independent_operation(24, |output| {
        independent_text(output, "bucket-1");
        independent_text(output, "key");
        independent_text(output, "spool-1");
        independent_u64(output, 0);
        independent_bytes(output, &[7; 32]);
        independent_u32(output, 0);
    });
    let put_request = base_request(put_object(Vec::new()));
    let versions_operation = independent_operation(25, |output| {
        independent_text(output, "bucket-1");
        independent_text(output, "");
        independent_text(output, "");
        independent_u32(output, 1);
        independent_optional_text(output, Some(""));
        independent_optional_text(output, None);
    });
    let versions_request = base_request(object_store_request_v1::Operation::ListObjectVersions(
        ListObjectVersionsV1 {
            bucket: "bucket-1".to_string(),
            prefix: String::new(),
            delimiter: String::new(),
            max_keys: 1,
            key_marker: Some(String::new()),
            version_id_marker: None,
        },
    ));
    let delete_operation = independent_operation(26, |output| {
        independent_text(output, "bucket-1");
        independent_text(output, "key");
        independent_optional_text(output, Some(""));
    });
    let delete_request = base_request(object_store_request_v1::Operation::DeleteObject(
        DeleteObjectV1 {
            bucket: "bucket-1".to_string(),
            key: "key".to_string(),
            version_id: Some(String::new()),
        },
    ));

    let fragment_context = ResultConsumerContextV1 {
        consumer: Some(result_consumer_context_v1::Consumer::FragmentLifecycle(
            FragmentLifecycleConsumerContextV1 {
                fragment_id: vec![1; 32].into(),
                lifecycle_generation: 1,
                fragment_epoch: 2,
                lifecycle_fence: 3,
                ..Default::default()
            },
        )),
    };
    let mut fragment_request = base_request(put_object(Vec::new()));
    fragment_request.consumer_context = Some(fragment_context);
    let startup_context = ResultConsumerContextV1 {
        consumer: Some(result_consumer_context_v1::Consumer::StartupAdmission(
            StartupAdmissionConsumerContextV1 {
                policy_revision: "policy-1".to_string(),
                allocation_revision: "allocation-1".to_string(),
                config_revision: "config-1".to_string(),
                startup_attempt_id: "startup-1".to_string(),
                readiness_generation: 1,
            },
        )),
    };
    let mut startup_request = base_request(head_bucket());
    startup_request.consumer_context = Some(startup_context);
    let head_bucket_operation = independent_operation(20, |output| {
        independent_text(output, "bucket-1");
    });

    list_request.canonical_fingerprint.clear();
    let cases = [
        (
            "list_objects_v2_raw_non_nfc_present_empty",
            list_request,
            independent_common_preimage(&durable, &list_operation),
            "7b1adb07d1d7ed0a0ccfe7fec987f299c1c6a00390ae81b426f507b61bd24f57",
        ),
        (
            "head_object",
            head_request,
            independent_common_preimage(&durable, &head_operation),
            "52ee9d6988d4a582061f823a794e69c091cb357d94cb2bbb317396415870a073",
        ),
        (
            "get_object",
            get_request,
            independent_common_preimage(&durable, &get_operation),
            "958e11a15160c4359c82f7982c3492bb6c519e58d2d6fcaba82d6cd964659b0d",
        ),
        (
            "put_object",
            put_request,
            independent_common_preimage(&durable, &put_operation),
            "ceb9bf1abc310a18eb29fd3a22491b0f1a69145074edd4f38b822f6cc7cf058a",
        ),
        (
            "list_object_versions_present_empty",
            versions_request,
            independent_common_preimage(&durable, &versions_operation),
            "fa56b6f3de41f216502b48602b37c5556796ef375879a56a987196196f05636a",
        ),
        (
            "delete_object_present_empty",
            delete_request,
            independent_common_preimage(&durable, &delete_operation),
            "5406d774d8684535af79cc7306332c800f53e67757a2e6c8ae1fa97b5b801171",
        ),
        (
            "fragment_context",
            fragment_request,
            independent_common_preimage(&independent_fragment_consumer(), &put_operation),
            "7c9e34b4aa91f9e040b3fc5d5ce9e6d0fdcac449accb695173f745c813526f91",
        ),
        (
            "startup_context",
            startup_request,
            independent_common_preimage(&independent_startup_consumer(), &head_bucket_operation),
            "41290768942f839c0df2841c70f7fd854513d41bb360061b38e8f63bd9e10b1f",
        ),
    ];

    for (label, request, expected_preimage, expected_digest_hex) in cases {
        let result = fingerprint_object_store_request(&request, &identity(), &limits())
            .unwrap_or_else(|error| panic!("{label} must fingerprint: {error}"));
        assert_eq!(
            result.canonical_preimage(),
            expected_preimage,
            "{label} preimage"
        );
        assert_eq!(
            result.canonical_fingerprint().as_slice(),
            decode_hex(expected_digest_hex),
            "{label} digest"
        );
    }
}

#[test]
fn fingerprint_exposes_exact_durable_lookup_key_and_uuid_timestamps() {
    let result = fingerprint(&base_request(head_bucket()));

    assert_eq!(result.durable_key().provider_boundary_id, "boundary");
    assert_eq!(result.durable_key().authenticated_cell_id, "cell");
    assert_eq!(result.durable_key().authenticated_tenant_id, "tenant");
    assert_eq!(result.durable_key().logical_request_id, LOGICAL_ID);
    assert_eq!(result.durable_key().attempt_id, ATTEMPT_ID);
    assert_eq!(
        result.logical_request_timestamp_unix_ms(),
        1_714_733_360_214
    );
    assert_eq!(result.attempt_timestamp_unix_ms(), 1_714_733_360_215);
}

#[test]
fn fingerprint_pins_all_seven_operation_tags() {
    let tags = operation_cases()
        .into_iter()
        .map(|operation| fingerprint(&base_request(operation)).operation_tag())
        .collect::<Vec<_>>();

    assert_eq!(tags, [20, 21, 22, 23, 24, 25, 26]);
}

#[test]
fn fingerprint_pins_consumer_tags_and_durable_kind_bytes() {
    let fragment = ResultConsumerContextV1 {
        consumer: Some(result_consumer_context_v1::Consumer::FragmentLifecycle(
            FragmentLifecycleConsumerContextV1 {
                fragment_id: vec![1; 32].into(),
                lifecycle_generation: 1,
                fragment_epoch: 2,
                lifecycle_fence: 3,
                ..Default::default()
            },
        )),
    };
    let startup = ResultConsumerContextV1 {
        consumer: Some(result_consumer_context_v1::Consumer::StartupAdmission(
            StartupAdmissionConsumerContextV1 {
                policy_revision: "policy-1".to_string(),
                allocation_revision: "allocation-1".to_string(),
                config_revision: "config-1".to_string(),
                startup_attempt_id: "startup-1".to_string(),
                readiness_generation: 1,
            },
        )),
    };
    let mut fragment_request = base_request(put_object(Vec::new()));
    fragment_request.consumer_context = Some(fragment);
    let mut startup_request = base_request(head_bucket());
    startup_request.consumer_context = Some(startup);
    let fragment_result = fingerprint(&fragment_request);
    let startup_result = fingerprint(&startup_request);
    let mut durable_results = Vec::new();
    for kind in [
        DurableConsumerKindV1::DurableConsumerKindJob,
        DurableConsumerKindV1::DurableConsumerKindOperator,
        DurableConsumerKindV1::DurableConsumerKindMigrator,
    ] {
        let mut request = base_request(head_bucket());
        request.consumer_context = Some(durable_context(kind));
        durable_results.push(fingerprint(&request));
    }

    assert_eq!(fragment_result.consumer_tag(), 1);
    assert_eq!(startup_result.consumer_tag(), 2);
    assert!(
        durable_results
            .iter()
            .all(|result| result.consumer_tag() == 3)
    );
    for (result, kind_tag) in durable_results.iter().zip([1, 2, 3]) {
        assert!(
            result
                .canonical_preimage()
                .windows(5)
                .any(|window| window == [0, 0, 0, 3, kind_tag])
        );
    }
}

#[test]
fn fragment_and_startup_fingerprints_ignore_an_unused_principal() {
    let fragment = ResultConsumerContextV1 {
        consumer: Some(result_consumer_context_v1::Consumer::FragmentLifecycle(
            FragmentLifecycleConsumerContextV1 {
                fragment_id: vec![1; 32].into(),
                lifecycle_generation: 1,
                fragment_epoch: 2,
                lifecycle_fence: 3,
                ..Default::default()
            },
        )),
    };
    let startup = ResultConsumerContextV1 {
        consumer: Some(result_consumer_context_v1::Consumer::StartupAdmission(
            StartupAdmissionConsumerContextV1 {
                policy_revision: "policy-1".to_string(),
                allocation_revision: "allocation-1".to_string(),
                config_revision: "config-1".to_string(),
                startup_attempt_id: "startup-1".to_string(),
                readiness_generation: 1,
            },
        )),
    };
    let mut fragment_request = base_request(put_object(Vec::new()));
    fragment_request.consumer_context = Some(fragment);
    let mut startup_request = base_request(head_bucket());
    startup_request.consumer_context = Some(startup);
    let canonical_identity = identity();
    let unused_principal_identity = AuthenticatedConsumerIdentity {
        principal_id: "e\u{301}".repeat(100),
        ..identity()
    };

    let canonical_fragment =
        fingerprint_object_store_request(&fragment_request, &canonical_identity, &limits())
            .expect("fragment context must accept its canonical authenticated scope");
    let unused_principal_fragment =
        fingerprint_object_store_request(&fragment_request, &unused_principal_identity, &limits())
            .expect("fragment context must not validate an unused principal");
    let canonical_startup =
        fingerprint_object_store_request(&startup_request, &canonical_identity, &limits())
            .expect("startup context must accept its canonical authenticated scope");
    let unused_principal_startup =
        fingerprint_object_store_request(&startup_request, &unused_principal_identity, &limits())
            .expect("startup context must not validate an unused principal");

    assert_eq!(
        canonical_fragment.canonical_fingerprint(),
        unused_principal_fragment.canonical_fingerprint()
    );
    assert_eq!(
        canonical_startup.canonical_fingerprint(),
        unused_principal_startup.canonical_fingerprint()
    );
}

#[test]
fn durable_fingerprint_rejects_a_noncanonical_overbound_principal() {
    let request = base_request(head_bucket());
    let invalid_identity = AuthenticatedConsumerIdentity {
        principal_id: "e\u{301}".repeat(100),
        ..identity()
    };

    assert_eq!(
        fingerprint_object_store_request(&request, &invalid_identity, &limits()),
        Err(RequestContractError::InvalidConsumerContext)
    );
}

#[test]
fn fingerprint_distinguishes_optional_absence_from_present_empty() {
    let absent = base_request(operation_cases().remove(1));
    let mut present = absent.clone();
    let Some(object_store_request_v1::Operation::ListObjectsV2(operation)) = &mut present.operation
    else {
        panic!("fixture must contain ListObjectsV2")
    };
    operation.continuation_token = Some(String::new());

    assert_ne!(
        fingerprint(&absent).canonical_fingerprint(),
        fingerprint(&present).canonical_fingerprint()
    );
}

#[test]
fn fingerprint_is_permutation_stable_without_mutating_inputs() {
    let metadata = vec![
        ObjectMetadataEntryV1 {
            key: "x-b".to_string(),
            value: "2".to_string(),
        },
        ObjectMetadataEntryV1 {
            key: "x-a".to_string(),
            value: "1".to_string(),
        },
    ];
    let extra = reservation("reservation-b", "physical-b", "class-b", 3);
    let mut first = base_request(put_object(metadata.clone()));
    first.reservations.push(extra.clone());
    let mut reversed_metadata = metadata.clone();
    reversed_metadata.reverse();
    let mut second = base_request(put_object(reversed_metadata));
    second.reservations.insert(0, extra);
    let first_before = first.clone();
    let second_before = second.clone();

    assert_eq!(
        fingerprint(&first).canonical_preimage(),
        fingerprint(&second).canonical_preimage()
    );
    assert_eq!(first, first_before);
    assert_eq!(second, second_before);
}

#[test]
fn fingerprint_accepts_exact_preimage_limit_and_rejects_one_byte_less() {
    let request = base_request(head_bucket());
    let size = fingerprint(&request).canonical_preimage().len() as u32;
    let mut exact = limits();
    exact.max_fingerprint_preimage_bytes = size;
    let mut short = exact.clone();
    short.max_fingerprint_preimage_bytes -= 1;

    assert_eq!(
        fingerprint_object_store_request(&request, &identity(), &exact)
            .expect("exact preimage boundary must be admitted")
            .canonical_preimage()
            .len(),
        size as usize
    );
    assert_eq!(
        fingerprint_object_store_request(&request, &identity(), &short),
        Err(RequestContractError::PreimageTooLarge)
    );
}

#[test]
fn fingerprint_rejects_duplicate_reservations_before_sorting() {
    let mut duplicate_id = base_request(head_bucket());
    duplicate_id
        .reservations
        .push(reservation("reservation-a", "physical-b", "class-b", 3));
    let mut duplicate_pair = base_request(head_bucket());
    duplicate_pair
        .reservations
        .push(reservation("reservation-b", "physical-a", "class-a", 3));

    assert_eq!(
        fingerprint_object_store_request(&duplicate_id, &identity(), &limits()),
        Err(RequestContractError::InvalidReservations)
    );
    assert_eq!(
        fingerprint_object_store_request(&duplicate_pair, &identity(), &limits()),
        Err(RequestContractError::InvalidReservations)
    );
}

#[test]
fn fingerprint_rejects_duplicate_metadata_before_sorting() {
    let request = base_request(put_object(vec![
        ObjectMetadataEntryV1 {
            key: "x-a".to_string(),
            value: "2".to_string(),
        },
        ObjectMetadataEntryV1 {
            key: "x-a".to_string(),
            value: "1".to_string(),
        },
    ]));

    assert_eq!(
        fingerprint_object_store_request(&request, &identity(), &limits()),
        Err(RequestContractError::InvalidOperation)
    );
}

#[test]
fn fingerprint_rejects_malformed_uuid_context_and_operation() {
    let mut malformed_uuid = base_request(head_bucket());
    malformed_uuid.logical_request_id = LOGICAL_ID.to_uppercase();
    let mut malformed_context = base_request(head_bucket());
    let Some(ResultConsumerContextV1 {
        consumer: Some(result_consumer_context_v1::Consumer::DurableConsumer(context)),
    }) = &mut malformed_context.consumer_context
    else {
        panic!("fixture must contain a durable context")
    };
    context.checkpoint_fence = 0;
    let mut malformed_operation = base_request(head_bucket());
    malformed_operation.operation = Some(object_store_request_v1::Operation::HeadBucket(
        HeadBucketV1 {
            bucket: "INVALID".to_string(),
        },
    ));

    assert_eq!(
        fingerprint_object_store_request(&malformed_uuid, &identity(), &limits()),
        Err(RequestContractError::InvalidUuidV7)
    );
    assert_eq!(
        fingerprint_object_store_request(&malformed_context, &identity(), &limits()),
        Err(RequestContractError::InvalidConsumerContext)
    );
    assert_eq!(
        fingerprint_object_store_request(&malformed_operation, &identity(), &limits()),
        Err(RequestContractError::InvalidOperation)
    );
}

#[test]
fn fingerprint_rejects_uuid_wrong_version_and_rfc_variant() {
    let mut wrong_version = base_request(head_bucket());
    wrong_version.logical_request_id = LOGICAL_ID.replace("-7abc-", "-6abc-");
    let mut wrong_variant = base_request(head_bucket());
    wrong_variant.attempt_id = ATTEMPT_ID.replace("-8def-", "-cdef-");

    assert_eq!(
        fingerprint_object_store_request(&wrong_version, &identity(), &limits()),
        Err(RequestContractError::InvalidUuidV7)
    );
    assert_eq!(
        fingerprint_object_store_request(&wrong_variant, &identity(), &limits()),
        Err(RequestContractError::InvalidUuidV7)
    );
}

#[test]
fn submitted_fingerprint_requires_exact_32_byte_digest() {
    let mut request = base_request(head_bucket());
    let validated = fingerprint(&request);
    request.canonical_fingerprint = validated.canonical_fingerprint().to_vec().into();
    assert_eq!(
        validate_submitted_request_fingerprint(&request, &validated),
        Ok(())
    );
    request.canonical_fingerprint = vec![0; 31].into();
    assert_eq!(
        validate_submitted_request_fingerprint(&request, &validated),
        Err(RequestContractError::InvalidFingerprint)
    );
}

#[test]
fn idempotency_classifies_absent_full_compact_and_mismatch_exactly() {
    let mut request = base_request(head_bucket());
    let validated = fingerprint(&request);
    request.canonical_fingerprint = validated.canonical_fingerprint().to_vec().into();
    let mismatch = [0x55; 32];

    assert_eq!(
        classify_idempotency(&request, &validated, ExistingFingerprint::Absent),
        Ok(IdempotencyDecision::FirstSeen)
    );
    assert_eq!(
        classify_idempotency(
            &request,
            &validated,
            ExistingFingerprint::Full(*validated.canonical_fingerprint())
        ),
        Ok(IdempotencyDecision::ExactReplay)
    );
    assert_eq!(
        classify_idempotency(
            &request,
            &validated,
            ExistingFingerprint::Compact(*validated.canonical_fingerprint())
        ),
        Ok(IdempotencyDecision::ExactReplay)
    );
    assert_eq!(
        classify_idempotency(&request, &validated, ExistingFingerprint::Full(mismatch)),
        Ok(IdempotencyDecision::IdentityReuseConflict)
    );
    assert_eq!(
        classify_idempotency(&request, &validated, ExistingFingerprint::Compact(mismatch)),
        Ok(IdempotencyDecision::IdentityReuseConflict)
    );
}

#[test]
fn idempotency_never_replays_a_missing_wrong_or_rebound_submitted_fingerprint() {
    let request = base_request(head_bucket());
    let validated = fingerprint(&request);
    let existing = ExistingFingerprint::Full(*validated.canonical_fingerprint());
    assert_eq!(
        classify_idempotency(&request, &validated, existing),
        Err(RequestContractError::InvalidFingerprint)
    );

    let mut wrong = request.clone();
    wrong.canonical_fingerprint = vec![0x55; 32].into();
    assert_eq!(
        classify_idempotency(&wrong, &validated, existing),
        Err(RequestContractError::InvalidFingerprint)
    );

    let mut rebound = request;
    rebound.canonical_fingerprint = validated.canonical_fingerprint().to_vec().into();
    rebound.policy_revision = "policy-2".to_string();
    assert_eq!(
        classify_idempotency(&rebound, &validated, existing),
        Err(RequestContractError::InvalidFingerprint)
    );
}

fn uuid_v7(timestamp_unix_ms: u64) -> String {
    let timestamp = format!("{timestamp_unix_ms:012x}");
    format!(
        "{}-{}-7000-8000-000000000000",
        &timestamp[..8],
        &timestamp[8..]
    )
}

#[test]
fn first_seen_identity_accepts_inclusive_past_and_future_boundaries() {
    const PAST_WINDOW_MS: i64 = 365 * 24 * 60 * 60 * 1_000;
    const FUTURE_WINDOW_MS: i64 = 5 * 60 * 1_000;
    let now = PAST_WINDOW_MS + 100;

    assert_eq!(
        classify_first_seen_identity(
            now,
            &uuid_v7(100),
            &uuid_v7((now + FUTURE_WINDOW_MS) as u64)
        ),
        Ok(FirstSeenIdentityDecision::Admit {
            logical_request_timestamp_unix_ms: 100,
            attempt_timestamp_unix_ms: (now + FUTURE_WINDOW_MS) as u64,
        })
    );
}

#[test]
fn first_seen_identity_prioritizes_future_over_stale_and_rejects_malformed() {
    const PAST_WINDOW_MS: i64 = 365 * 24 * 60 * 60 * 1_000;
    const FUTURE_WINDOW_MS: i64 = 5 * 60 * 1_000;
    let now = PAST_WINDOW_MS + 10;

    assert_eq!(
        classify_first_seen_identity(
            now,
            &uuid_v7(9),
            &uuid_v7((now + FUTURE_WINDOW_MS + 1) as u64)
        ),
        Ok(FirstSeenIdentityDecision::TimestampTooFarInFuture)
    );
    assert_eq!(
        classify_first_seen_identity(now, "not-a-uuid", &uuid_v7(now as u64)),
        Ok(FirstSeenIdentityDecision::InvalidUuidV7)
    );
}

#[test]
fn first_seen_prerequisites_classify_uuid_time_before_current_authority() {
    const NOW: i64 = 1_000_000;
    const FUTURE_WINDOW_MS: i64 = 5 * 60 * 1_000;
    let mut request = base_request(head_bucket());
    request.logical_request_id = uuid_v7(NOW as u64);
    request.attempt_id = uuid_v7((NOW + FUTURE_WINDOW_MS + 1) as u64);
    request.deadline_unix_ms = NOW;
    let computed = fingerprint(&request);
    request.canonical_fingerprint = computed.canonical_fingerprint().to_vec().into();
    let validated = fingerprint(&request);
    let mut wrong_authority = expected_authority();
    wrong_authority.allocation_fence += 1;
    let mut wrong_admission = expected_admission();
    wrong_admission.cell_admission_fence += 1;
    let wrong_requirements = [ReservationRequirement {
        units: 3,
        ..requirements()[0].clone()
    }];
    let impossible_spool = DurablePutSpoolExpectation {
        durable_body_handle: "spool-for-non-put".to_string(),
        body_size: 0,
        body_blake3: [7; 32],
    };
    let prerequisites = FirstSeenPrerequisites {
        expected_authority: &wrong_authority,
        expected_cell_admission: Some(&wrong_admission),
        reservation_requirements: &wrong_requirements,
        put_spool: Some(&impossible_spool),
        database_now_unix_ms: NOW,
        max_request_deadline_horizon_ms: 2_000,
        cell_allocation_hard_expiry_unix_ms: NOW + 2_000,
        dispatch_authority_hard_expiry_unix_ms: NOW + 2_000,
    };

    assert_eq!(
        validate_first_seen_prerequisites(&request, &validated, &prerequisites, &limits()),
        Ok(FirstSeenIdentityDecision::TimestampTooFarInFuture)
    );
}

#[test]
fn first_seen_prerequisites_accept_exact_authority_reservations_deadline_and_spool() {
    let mut request = base_request(put_object(Vec::new()));
    let computed = fingerprint(&request);
    request.canonical_fingerprint = computed.canonical_fingerprint().to_vec().into();
    let validated = fingerprint(&request);
    let authority = expected_authority();
    let admission = expected_admission();
    let requirements = requirements();
    let spool = DurablePutSpoolExpectation {
        durable_body_handle: "spool-1".to_string(),
        body_size: 0,
        body_blake3: [7; 32],
    };
    let prerequisites = FirstSeenPrerequisites {
        expected_authority: &authority,
        expected_cell_admission: Some(&admission),
        reservation_requirements: &requirements,
        put_spool: Some(&spool),
        database_now_unix_ms: 1_724_999_999_000,
        max_request_deadline_horizon_ms: 2_000,
        cell_allocation_hard_expiry_unix_ms: 1_725_000_001_000,
        dispatch_authority_hard_expiry_unix_ms: 1_725_000_001_000,
    };

    assert!(matches!(
        validate_first_seen_prerequisites(&request, &validated, &prerequisites, &limits()),
        Ok(FirstSeenIdentityDecision::Admit { .. })
    ));
}

#[test]
fn fingerprint_object_store_request_enforces_admission_all_or_none() {
    // CR-033 D3: the cell authority supplies neither `cell_admission_id` nor
    // `cell_admission_fence`, so both-absent is a legal retained state (migration 0007's
    // `CHECK (num_nonnulls(cell_admission_id, cell_admission_fence) IN (0, 2))`), but a
    // half-supplied pair is not.
    let mut absent = base_request(head_bucket());
    absent.cell_admission_id = String::new();
    absent.cell_admission_fence = 0;
    assert!(
        fingerprint_object_store_request(&absent, &identity(), &limits()).is_ok(),
        "both-absent admission must fingerprint"
    );

    let present = base_request(head_bucket());
    assert!(
        fingerprint_object_store_request(&present, &identity(), &limits()).is_ok(),
        "fully-supplied admission must still fingerprint"
    );

    let mut id_only = base_request(head_bucket());
    id_only.cell_admission_fence = 0;
    assert_eq!(
        fingerprint_object_store_request(&id_only, &identity(), &limits()),
        Err(RequestContractError::AuthorityMismatch)
    );

    let mut fence_only = base_request(head_bucket());
    fence_only.cell_admission_id = String::new();
    assert_eq!(
        fingerprint_object_store_request(&fence_only, &identity(), &limits()),
        Err(RequestContractError::AuthorityMismatch)
    );
}

#[test]
fn first_seen_prerequisites_accept_absent_cell_admission_and_reject_a_half_supplied_pair() {
    let mut absent = base_request(head_bucket());
    absent.cell_admission_id = String::new();
    absent.cell_admission_fence = 0;
    let computed = fingerprint(&absent);
    absent.canonical_fingerprint = computed.canonical_fingerprint().to_vec().into();
    let validated = fingerprint(&absent);
    let authority = expected_authority();
    let requirements = requirements();
    let prerequisites = FirstSeenPrerequisites {
        expected_authority: &authority,
        expected_cell_admission: None,
        reservation_requirements: &requirements,
        put_spool: None,
        database_now_unix_ms: 1_724_999_999_000,
        max_request_deadline_horizon_ms: 2_000,
        cell_allocation_hard_expiry_unix_ms: 1_725_000_001_000,
        dispatch_authority_hard_expiry_unix_ms: 1_725_000_001_000,
    };

    assert!(matches!(
        validate_first_seen_prerequisites(&absent, &validated, &prerequisites, &limits()),
        Ok(FirstSeenIdentityDecision::Admit { .. })
    ));

    let mut supplied = base_request(head_bucket());
    let supplied_computed = fingerprint(&supplied);
    supplied.canonical_fingerprint = supplied_computed.canonical_fingerprint().to_vec().into();
    let supplied_validated = fingerprint(&supplied);
    let supplied_prerequisites = FirstSeenPrerequisites {
        expected_cell_admission: None,
        ..prerequisites
    };
    assert_eq!(
        validate_first_seen_prerequisites(
            &supplied,
            &supplied_validated,
            &supplied_prerequisites,
            &limits()
        ),
        Err(RequestContractError::CellAdmissionMismatch)
    );
}

#[test]
fn first_seen_deadline_rejects_equality_with_database_time() {
    let database_now_unix_ms = 1_714_733_360_214;
    let mut request = base_request(head_bucket());
    request.deadline_unix_ms = database_now_unix_ms;
    let validated = fingerprint(&request);
    request.canonical_fingerprint = validated.canonical_fingerprint().to_vec().into();
    let authority = expected_authority();
    let admission = expected_admission();
    let requirements = requirements();
    let prerequisites = FirstSeenPrerequisites {
        expected_authority: &authority,
        expected_cell_admission: Some(&admission),
        reservation_requirements: &requirements,
        put_spool: None,
        database_now_unix_ms,
        max_request_deadline_horizon_ms: 10_000,
        cell_allocation_hard_expiry_unix_ms: database_now_unix_ms + 10_000,
        dispatch_authority_hard_expiry_unix_ms: database_now_unix_ms + 10_000,
    };

    assert_eq!(
        validate_first_seen_prerequisites(&request, &validated, &prerequisites, &limits()),
        Err(RequestContractError::InvalidDeadline)
    );
}

#[test]
fn first_seen_deadline_rejects_checked_horizon_addition_overflow() {
    const MAX_UUID_V7_TIMESTAMP: u64 = (1_u64 << 48) - 1;
    let database_now_unix_ms =
        i64::try_from(MAX_UUID_V7_TIMESTAMP).expect("48-bit UUID timestamp must fit i64");
    let mut request = base_request(head_bucket());
    request.logical_request_id = uuid_v7(MAX_UUID_V7_TIMESTAMP);
    request.attempt_id = uuid_v7(MAX_UUID_V7_TIMESTAMP);
    request.deadline_unix_ms = database_now_unix_ms + 1;
    let validated = fingerprint(&request);
    request.canonical_fingerprint = validated.canonical_fingerprint().to_vec().into();
    let authority = expected_authority();
    let admission = expected_admission();
    let requirements = requirements();
    let prerequisites = FirstSeenPrerequisites {
        expected_authority: &authority,
        expected_cell_admission: Some(&admission),
        reservation_requirements: &requirements,
        put_spool: None,
        database_now_unix_ms,
        max_request_deadline_horizon_ms: i64::MAX,
        cell_allocation_hard_expiry_unix_ms: database_now_unix_ms + 2,
        dispatch_authority_hard_expiry_unix_ms: database_now_unix_ms + 2,
    };

    assert_eq!(
        validate_first_seen_prerequisites(&request, &validated, &prerequisites, &limits()),
        Err(RequestContractError::ArithmeticOverflow)
    );
}

#[test]
fn first_seen_prerequisites_reject_authority_reservation_deadline_and_spool_mismatches() {
    let mut request = base_request(put_object(Vec::new()));
    let computed = fingerprint(&request);
    request.canonical_fingerprint = computed.canonical_fingerprint().to_vec().into();
    let validated = fingerprint(&request);
    let authority = expected_authority();
    let admission = expected_admission();
    let requirements = requirements();
    let bad_spool = DurablePutSpoolExpectation {
        durable_body_handle: "other".to_string(),
        body_size: 0,
        body_blake3: [7; 32],
    };
    let good_spool = DurablePutSpoolExpectation {
        durable_body_handle: "spool-1".to_string(),
        body_size: 0,
        body_blake3: [7; 32],
    };
    let base = FirstSeenPrerequisites {
        expected_authority: &authority,
        expected_cell_admission: Some(&admission),
        reservation_requirements: &requirements,
        put_spool: Some(&bad_spool),
        database_now_unix_ms: 1_724_999_999_000,
        max_request_deadline_horizon_ms: 2_000,
        cell_allocation_hard_expiry_unix_ms: 1_725_000_001_000,
        dispatch_authority_hard_expiry_unix_ms: 1_725_000_001_000,
    };
    assert_eq!(
        validate_first_seen_prerequisites(&request, &validated, &base, &limits()),
        Err(RequestContractError::PutSpoolMismatch)
    );

    let wrong_authority = ExpectedRequestAuthority {
        allocation_fence: 8,
        ..authority.clone()
    };
    let wrong_authority_prerequisites = FirstSeenPrerequisites {
        expected_authority: &wrong_authority,
        put_spool: None,
        ..base
    };
    assert_eq!(
        validate_first_seen_prerequisites(
            &request,
            &validated,
            &wrong_authority_prerequisites,
            &limits()
        ),
        Err(RequestContractError::AuthorityMismatch)
    );

    let wrong_requirements = [ReservationRequirement {
        units: 3,
        ..requirements[0].clone()
    }];
    let wrong_reservation_prerequisites = FirstSeenPrerequisites {
        expected_authority: &authority,
        reservation_requirements: &wrong_requirements,
        ..wrong_authority_prerequisites
    };
    assert_eq!(
        validate_first_seen_prerequisites(
            &request,
            &validated,
            &wrong_reservation_prerequisites,
            &limits()
        ),
        Err(RequestContractError::InvalidReservations)
    );

    let expired_prerequisites = FirstSeenPrerequisites {
        reservation_requirements: &requirements,
        put_spool: Some(&good_spool),
        database_now_unix_ms: request.deadline_unix_ms,
        ..wrong_reservation_prerequisites
    };
    assert_eq!(
        validate_first_seen_prerequisites(&request, &validated, &expired_prerequisites, &limits()),
        Err(RequestContractError::InvalidDeadline)
    );
}

fn identity_with_boundary(provider_boundary_id: &str) -> AuthenticatedConsumerIdentity {
    AuthenticatedConsumerIdentity {
        provider_boundary_id: provider_boundary_id.to_string(),
        ..identity()
    }
}

/// A `HeadBucket` request carrying `StartupAdmission` consumer context, whose validation never
/// reconstructs an authenticated scope from `identity`'s fields (unlike the default `DurableConsumer`
/// context `base_request` uses). That keeps a substituted `provider_boundary_id` isolated to the
/// identity charset check this test is pinning, instead of also tripping an unrelated scope mismatch.
fn request_with_boundary(provider_boundary_id: &str) -> ObjectStoreRequestV1 {
    let mut request = base_request(head_bucket());
    request.provider_boundary_id = provider_boundary_id.to_string();
    request.consumer_context = Some(ResultConsumerContextV1 {
        consumer: Some(result_consumer_context_v1::Consumer::StartupAdmission(
            StartupAdmissionConsumerContextV1 {
                policy_revision: "policy-1".to_string(),
                allocation_revision: "allocation-1".to_string(),
                config_revision: "config-1".to_string(),
                startup_attempt_id: "startup-1".to_string(),
                readiness_generation: 1,
            },
        )),
    });
    request
}

#[test]
fn fingerprint_and_first_seen_agree_on_the_identity_charset_boundary() {
    // Regression for a real defect: `fingerprint_object_store_request` used to validate
    // `provider_boundary_id`/`authenticated_cell_id`/`authenticated_tenant_id` with the permissive
    // `validate_canonical_text`, while `validate_first_seen_prerequisites` validated the same three
    // with the strict `validate_canonical_id`. An id containing e.g. `@` would fingerprint
    // successfully, get durably stored, and then be rejected by first-seen forever -- a wedged
    // request behind a durable row it could never clear. Asserting only that a bad id is rejected
    // "somewhere" would have passed against that broken code; the real assertion is agreement: an
    // id fingerprint accepts, first-seen must also accept, and an id fingerprint rejects must never
    // reach first-seen with a durable row at all (proven structurally: without a `ValidatedRequest`,
    // first-seen cannot be called).
    let cases: [(&str, bool); 5] = [
        ("boundary-a", true),
        ("boundary@bad", false),
        ("boundary+bad", false),
        ("boundary\u{00e9}bad", false),
        ("-leadbad", false),
    ];

    for (id, should_accept) in cases {
        let request = request_with_boundary(id);
        let identity = identity_with_boundary(id);
        let fingerprint_result = fingerprint_object_store_request(&request, &identity, &limits());

        assert_eq!(
            fingerprint_result.is_ok(),
            should_accept,
            "fingerprint acceptance for {id:?}"
        );

        let Ok(validated) = fingerprint_result else {
            // Rejected before any `ValidatedRequest` exists: there is no durable row for
            // first-seen to ever wedge behind, so there is nothing further to assert here.
            continue;
        };

        let mut committed = request.clone();
        committed.canonical_fingerprint = validated.canonical_fingerprint().to_vec().into();
        let committed_validated =
            fingerprint_object_store_request(&committed, &identity, &limits())
                .expect("resubmitting an accepted id must refingerprint identically");
        let authority = ExpectedRequestAuthority {
            provider_boundary_id: id.to_string(),
            ..expected_authority()
        };
        let admission = expected_admission();
        let requirements = requirements();
        let prerequisites = FirstSeenPrerequisites {
            expected_authority: &authority,
            expected_cell_admission: Some(&admission),
            reservation_requirements: &requirements,
            put_spool: None,
            database_now_unix_ms: 1_724_999_999_000,
            max_request_deadline_horizon_ms: 2_000,
            cell_allocation_hard_expiry_unix_ms: 1_725_000_001_000,
            dispatch_authority_hard_expiry_unix_ms: 1_725_000_001_000,
        };

        assert!(
            matches!(
                validate_first_seen_prerequisites(
                    &committed,
                    &committed_validated,
                    &prerequisites,
                    &limits()
                ),
                Ok(FirstSeenIdentityDecision::Admit { .. })
            ),
            "an id fingerprint accepts must also be accepted by first-seen: {id:?}"
        );
    }
}

fn elevated_identity_limits() -> RequestFingerprintLimits {
    let mut limits = limits();
    limits.identity.max_identity_bytes = 300;
    limits
}

#[test]
fn validate_authority_revision_bounds_are_independent_of_the_caller_limit() {
    // `validate_authority_revision`'s nonempty/256-byte/control-character/NFC bounds are the checks
    // the removed `authority.rs` applied and the `request.rs` fold restored. The 256-byte bound in
    // particular is `MAX_CANONICAL_ID_BYTES`, deliberately independent of the caller's
    // `max_identity_bytes` -- so this pins it with a caller limit set above 256 to prove the
    // validator holds on its own rather than being subsumed by the caller's limit.
    let mut request = base_request(head_bucket());
    let computed = fingerprint(&request);
    request.canonical_fingerprint = computed.canonical_fingerprint().to_vec().into();
    let validated = fingerprint(&request);
    let admission = expected_admission();
    let requirements = requirements();

    let run = |protocol_revision: String| {
        let authority = ExpectedRequestAuthority {
            protocol_revision,
            ..expected_authority()
        };
        let prerequisites = FirstSeenPrerequisites {
            expected_authority: &authority,
            expected_cell_admission: Some(&admission),
            reservation_requirements: &requirements,
            put_spool: None,
            database_now_unix_ms: 1_724_999_999_000,
            max_request_deadline_horizon_ms: 2_000,
            cell_allocation_hard_expiry_unix_ms: 1_725_000_001_000,
            dispatch_authority_hard_expiry_unix_ms: 1_725_000_001_000,
        };
        validate_first_seen_prerequisites(
            &request,
            &validated,
            &prerequisites,
            &elevated_identity_limits(),
        )
    };

    assert_eq!(
        run(String::new()),
        Err(RequestContractError::InvalidCanonicalText),
        "empty revision"
    );
    assert_eq!(
        run("a".repeat(257)),
        Err(RequestContractError::InvalidCanonicalText),
        "257-byte revision, under the caller's 300-byte limit but over MAX_CANONICAL_ID_BYTES"
    );
    assert_eq!(
        run(format!("revision{}", '\u{0001}')),
        Err(RequestContractError::InvalidCanonicalText),
        "control character, which validate_canonical_text alone would not catch"
    );
    assert_eq!(
        run("e\u{301}".to_string()),
        Err(RequestContractError::InvalidCanonicalText),
        "non-NFC (combining accent)"
    );
    // The equality check in `validate_expected_authority` runs after the revision-validity
    // check, so the positive case needs its own fixture whose request actually carries the
    // precomposed NFC revision (`run`'s shared `request`/`validated` fix `protocol_revision` at
    // "protocol-1" and would otherwise fail on `AuthorityMismatch`, not prove NFC acceptance).
    let mut nfc_request = base_request(head_bucket());
    nfc_request.protocol_revision = "r\u{00e9}vision-1".to_string();
    let nfc_computed = fingerprint(&nfc_request);
    nfc_request.canonical_fingerprint = nfc_computed.canonical_fingerprint().to_vec().into();
    let nfc_validated = fingerprint(&nfc_request);
    let nfc_authority = ExpectedRequestAuthority {
        protocol_revision: "r\u{00e9}vision-1".to_string(),
        ..expected_authority()
    };
    let nfc_prerequisites = FirstSeenPrerequisites {
        expected_authority: &nfc_authority,
        expected_cell_admission: Some(&admission),
        reservation_requirements: &requirements,
        put_spool: None,
        database_now_unix_ms: 1_724_999_999_000,
        max_request_deadline_horizon_ms: 2_000,
        cell_allocation_hard_expiry_unix_ms: 1_725_000_001_000,
        dispatch_authority_hard_expiry_unix_ms: 1_725_000_001_000,
    };
    assert!(
        matches!(
            validate_first_seen_prerequisites(
                &nfc_request,
                &nfc_validated,
                &nfc_prerequisites,
                &elevated_identity_limits()
            ),
            Ok(FirstSeenIdentityDecision::Admit { .. })
        ),
        "precomposed NFC revision must be accepted"
    );
}

#[test]
fn classify_idempotency_treats_a_budget_pin_rotation_as_exact_replay() {
    // CR-033 D3's 2026-08-28 amendment: `allocation_revision`/`allocation_fence` are excluded from
    // the replay preimage precisely so a routine budget retune (which rotates both) does not turn
    // an exact retry into a forever-failing identity-reuse conflict. Rotate the revision alone, the
    // fence alone, and both together, and require every rotation to fingerprint identically to the
    // original and to classify as `ExactReplay` against the original's stored fingerprint.
    let original = base_request(head_bucket());
    let original_validated = fingerprint(&original);
    let stored = ExistingFingerprint::Full(*original_validated.canonical_fingerprint());

    let rotations: [(&str, &str, u64); 3] = [
        ("revision alone", "allocation-2", 7),
        ("fence alone", "allocation-1", 9),
        ("both", "allocation-2", 9),
    ];

    for (label, revision, fence) in rotations {
        let mut rotated = base_request(head_bucket());
        rotated.allocation_revision = revision.to_string();
        rotated.allocation_fence = fence;
        let rotated_validated = fingerprint(&rotated);
        rotated.canonical_fingerprint = rotated_validated.canonical_fingerprint().to_vec().into();

        assert_eq!(
            rotated_validated.canonical_fingerprint(),
            original_validated.canonical_fingerprint(),
            "{label}: rotated budget pin must not change the fingerprint"
        );
        assert_eq!(
            rotated_validated.canonical_preimage(),
            original_validated.canonical_preimage(),
            "{label}: rotated budget pin must not change the preimage"
        );
        assert_eq!(
            classify_idempotency(&rotated, &rotated_validated, stored),
            Ok(IdempotencyDecision::ExactReplay),
            "{label}: a rotated budget pin must classify as an exact replay of the original request"
        );
    }
}

#[test]
fn preimage_and_replay_still_bind_every_field_the_amendment_did_not_touch() {
    // The exclusion removed exactly two fields. Every other field the preimage still writes must
    // keep discriminating replay identity: a request differing only in that field must fingerprint
    // differently and classify as `IdentityReuseConflict` against the original stored fingerprint.
    let original = base_request(head_bucket());
    let original_validated = fingerprint(&original);
    let stored = ExistingFingerprint::Full(*original_validated.canonical_fingerprint());

    type Mutation = fn(&mut ObjectStoreRequestV1);
    let mutations: [(&str, Mutation); 5] = [
        ("policy_revision", |request| {
            request.policy_revision = "policy-2".to_string();
        }),
        ("cell_admission_id", |request| {
            request.cell_admission_id = "admission-2".to_string();
        }),
        ("cell_admission_fence", |request| {
            request.cell_admission_fence = 9;
        }),
        ("deadline_unix_ms", |request| {
            request.deadline_unix_ms += 1;
        }),
        ("reservation.units", |request| {
            request.reservations[0].units = 3;
        }),
    ];

    for (label, mutate) in mutations {
        let mut mutated = base_request(head_bucket());
        mutate(&mut mutated);
        let mutated_validated = fingerprint(&mutated);
        mutated.canonical_fingerprint = mutated_validated.canonical_fingerprint().to_vec().into();

        assert_ne!(
            mutated_validated.canonical_fingerprint(),
            original_validated.canonical_fingerprint(),
            "{label} must still change the fingerprint"
        );
        assert_eq!(
            classify_idempotency(&mutated, &mutated_validated, stored),
            Ok(IdempotencyDecision::IdentityReuseConflict),
            "{label} must classify as an identity reuse conflict against the original stored fingerprint"
        );
    }
}

#[test]
fn first_seen_prerequisites_reject_a_stale_allocation_revision_pin_despite_an_unchanged_fingerprint()
 {
    // The preimage exclusion does not widen first-seen admission: `validate_expected_authority`
    // still exact-matches `allocation_revision` against the cell's current pin. Prove the field is
    // absent from replay identity (fingerprint unchanged) but not absent from admission (still
    // fails closed) in the same test.
    let canonical = fingerprint(&base_request(head_bucket()));

    let mut request = base_request(head_bucket());
    request.allocation_revision = "allocation-stale".to_string();
    let computed = fingerprint(&request);
    request.canonical_fingerprint = computed.canonical_fingerprint().to_vec().into();
    let validated = fingerprint(&request);

    assert_eq!(
        validated.canonical_fingerprint(),
        canonical.canonical_fingerprint(),
        "a stale allocation_revision must not change the fingerprint"
    );

    let authority = expected_authority();
    let admission = expected_admission();
    let requirements = requirements();
    let prerequisites = FirstSeenPrerequisites {
        expected_authority: &authority,
        expected_cell_admission: Some(&admission),
        reservation_requirements: &requirements,
        put_spool: None,
        database_now_unix_ms: 1_724_999_999_000,
        max_request_deadline_horizon_ms: 2_000,
        cell_allocation_hard_expiry_unix_ms: 1_725_000_001_000,
        dispatch_authority_hard_expiry_unix_ms: 1_725_000_001_000,
    };

    assert_eq!(
        validate_first_seen_prerequisites(&request, &validated, &prerequisites, &limits()),
        Err(RequestContractError::AuthorityMismatch)
    );
}

#[test]
fn first_seen_prerequisites_reject_a_stale_allocation_fence_pin_despite_an_unchanged_fingerprint() {
    // Companion to the revision-only case above: `allocation_fence` alone must also still be
    // exact-matched by first-seen admission even though it no longer participates in the fingerprint.
    let canonical = fingerprint(&base_request(head_bucket()));

    let mut request = base_request(head_bucket());
    request.allocation_fence = 99;
    let computed = fingerprint(&request);
    request.canonical_fingerprint = computed.canonical_fingerprint().to_vec().into();
    let validated = fingerprint(&request);

    assert_eq!(
        validated.canonical_fingerprint(),
        canonical.canonical_fingerprint(),
        "a stale allocation_fence must not change the fingerprint"
    );

    let authority = expected_authority();
    let admission = expected_admission();
    let requirements = requirements();
    let prerequisites = FirstSeenPrerequisites {
        expected_authority: &authority,
        expected_cell_admission: Some(&admission),
        reservation_requirements: &requirements,
        put_spool: None,
        database_now_unix_ms: 1_724_999_999_000,
        max_request_deadline_horizon_ms: 2_000,
        cell_allocation_hard_expiry_unix_ms: 1_725_000_001_000,
        dispatch_authority_hard_expiry_unix_ms: 1_725_000_001_000,
    };

    assert_eq!(
        validate_first_seen_prerequisites(&request, &validated, &prerequisites, &limits()),
        Err(RequestContractError::AuthorityMismatch)
    );
}

#[test]
fn fingerprint_object_store_request_still_enforces_allocation_fence_and_revision_shape() {
    // The exclusion only removes the two fields from the canonical preimage; shape validation on
    // both fields in `fingerprint_object_store_request` itself is unchanged.
    let mut zero_fence = base_request(head_bucket());
    zero_fence.allocation_fence = 0;
    assert_eq!(
        fingerprint_object_store_request(&zero_fence, &identity(), &limits()),
        Err(RequestContractError::AuthorityMismatch),
        "allocation_fence == 0 must still be rejected"
    );

    let mut empty_revision = base_request(head_bucket());
    empty_revision.allocation_revision = String::new();
    assert_eq!(
        fingerprint_object_store_request(&empty_revision, &identity(), &limits()),
        Err(RequestContractError::InvalidCanonicalText),
        "empty allocation_revision must still be rejected"
    );

    let mut overlong_revision = base_request(head_bucket());
    overlong_revision.allocation_revision = "a".repeat(129);
    assert_eq!(
        fingerprint_object_store_request(&overlong_revision, &identity(), &limits()),
        Err(RequestContractError::InvalidCanonicalText),
        "an allocation_revision over max_identity_bytes (128) must still be rejected"
    );

    let mut noncanonical_revision = base_request(head_bucket());
    noncanonical_revision.allocation_revision = "e\u{301}".to_string();
    assert_eq!(
        fingerprint_object_store_request(&noncanonical_revision, &identity(), &limits()),
        Err(RequestContractError::InvalidCanonicalText),
        "a non-NFC allocation_revision must still be rejected"
    );

    let mut control_char_revision = base_request(head_bucket());
    control_char_revision.allocation_revision = "\0".to_string();
    assert_eq!(
        fingerprint_object_store_request(&control_char_revision, &identity(), &limits()),
        Err(RequestContractError::InvalidCanonicalText),
        "a NUL-containing allocation_revision must still be rejected"
    );
}

#[test]
fn golden_preimage_no_longer_contains_the_budget_pins_length_prefixed_bytes() {
    // The regression fence for the removal itself: the golden preimage must never again contain
    // `text("allocation-1") || u64BE(7)`, even though the request that produced it does carry
    // `allocation_revision = "allocation-1"` and `allocation_fence = 7`.
    let request = base_request(head_bucket());
    assert_eq!(request.allocation_revision, "allocation-1");
    assert_eq!(request.allocation_fence, 7);

    let preimage = fingerprint(&request).canonical_preimage().to_vec();
    assert_eq!(preimage, decode_hex(GOLDEN_PREIMAGE_HEX));

    // u32BE(12) || "allocation-1" || u64BE(7)
    let removed_write: [u8; 24] = [
        0x00, 0x00, 0x00, 0x0c, 0x61, 0x6c, 0x6c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2d,
        0x31, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07,
    ];

    assert!(
        !preimage
            .windows(removed_write.len())
            .any(|window| window == removed_write),
        "the removed allocation-revision/allocation-fence write must never reappear in the golden preimage"
    );
}

#[test]
fn request_fingerprint_primitives_remain_effect_free_and_unwired() {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    // CR-033 D1/D6/P2 removed the separate-process service shell entirely; assert that
    // structurally instead of grepping a deleted `src/service.rs` for the wiring it never had.
    for removed in ["src/service.rs", "src/server.rs", "src/main.rs"] {
        assert!(
            !manifest.join(removed).exists(),
            "process-composition surface must stay removed: {removed}"
        );
    }
    let request_source = std::fs::read_to_string(manifest.join("src/request.rs"))
        .expect("request primitive source must be readable");

    for forbidden in [
        "tokio_postgres",
        "std::fs",
        "aws_sdk",
        "lore_aws",
        "lore_postgres",
    ] {
        assert!(
            !request_source.contains(forbidden),
            "pure request primitives must not depend on effect surface {forbidden}"
        );
    }
}

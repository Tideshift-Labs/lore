// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_object_dispatch::TerminalResultLimits;
use lore_object_dispatch::validate_and_encode_terminal_result;
use lore_proto::lore::object_dispatch::v1::BoolResultV1;
use lore_proto::lore::object_dispatch::v1::ByteResultHandleV1;
use lore_proto::lore::object_dispatch::v1::DeleteMarkerV1;
use lore_proto::lore::object_dispatch::v1::DeleteObjectResultV1;
use lore_proto::lore::object_dispatch::v1::HeadObjectResultV1;
use lore_proto::lore::object_dispatch::v1::ListObjectEntryV1;
use lore_proto::lore::object_dispatch::v1::ListObjectVersionsResultV1;
use lore_proto::lore::object_dispatch::v1::ListObjectsV2ResultV1;
use lore_proto::lore::object_dispatch::v1::ObjectMetadataEntryV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreTerminalResultV1;
use lore_proto::lore::object_dispatch::v1::ObjectVersionV1;
use lore_proto::lore::object_dispatch::v1::ProviderErrorClassV1;
use lore_proto::lore::object_dispatch::v1::ProviderErrorV1;
use lore_proto::lore::object_dispatch::v1::PutObjectResultV1;
use lore_proto::lore::object_dispatch::v1::object_store_terminal_result_v1::Result as Payload;

const DIGEST: [u8; 32] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
    26, 27, 28, 29, 30, 31,
];
const BOOL_DIGEST: [u8; 32] = [
    0x16, 0x16, 0x2b, 0x78, 0xc2, 0x03, 0x57, 0xb8, 0xff, 0x6a, 0xd0, 0x78, 0x59, 0x2d, 0xa2, 0xed,
    0x41, 0x94, 0xef, 0xa3, 0xf3, 0x8a, 0x3f, 0x9e, 0x22, 0x3d, 0x86, 0x02, 0xf1, 0xa5, 0x37, 0x20,
];
const EMPTY_DIGEST: [u8; 32] = [
    0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc, 0xc9, 0x49,
    0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca, 0xe4, 0x1f, 0x32, 0x62,
];

fn limits() -> TerminalResultLimits {
    TerminalResultLimits {
        max_canonical_result_bytes: 16_384,
        max_list_entries: 8,
        max_key_bytes: 64,
        max_metadata_entries: 4,
        max_metadata_key_bytes: 32,
        max_metadata_value_bytes: 64,
        max_metadata_aggregate_bytes: 128,
        max_opaque_value_bytes: 64,
        max_result_handle_bytes: 128,
        max_provider_code_bytes: 32,
        max_provider_request_id_bytes: 64,
        max_retry_after_ms: 60_000,
    }
}

fn envelope(terminal_result_id: &str, result: Option<Payload>) -> ObjectStoreTerminalResultV1 {
    ObjectStoreTerminalResultV1 {
        terminal_result_id: terminal_result_id.to_string(),
        canonical_result_blake3: vec![0xff; 32].into(),
        canonical_result_size: u64::MAX,
        result,
    }
}

fn encode(result: Payload) -> lore_object_dispatch::CanonicalTerminalResult {
    validate_and_encode_terminal_result(&envelope("terminal-1", Some(result)), &limits())
        .expect("canonical test result must validate")
}

fn varint(mut value: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        bytes.push(byte);
        if value == 0 {
            return bytes;
        }
    }
}

fn scalar_field(field: u32, value: u64, include_default: bool) -> Vec<u8> {
    if value == 0 && !include_default {
        return Vec::new();
    }
    let mut bytes = varint(u64::from(field << 3));
    bytes.extend(varint(value));
    bytes
}

fn bytes_field(field: u32, value: &[u8]) -> Vec<u8> {
    let mut bytes = varint(u64::from((field << 3) | 2));
    bytes.extend(varint(value.len() as u64));
    bytes.extend_from_slice(value);
    bytes
}

fn string_field(field: u32, value: &str) -> Vec<u8> {
    bytes_field(field, value.as_bytes())
}

fn concat(parts: &[Vec<u8>]) -> Vec<u8> {
    parts.iter().flatten().copied().collect()
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn metadata(key: &str, value: &str) -> ObjectMetadataEntryV1 {
    ObjectMetadataEntryV1 {
        key: key.to_string(),
        value: value.to_string(),
    }
}

#[test]
fn bool_result_pins_selected_payload_bytes_size_and_independent_digest() {
    let encoded = encode(Payload::BoolResult(BoolResultV1 { value: true }));

    assert_eq!(encoded.canonical_result_bytes(), [0x08, 0x01]);
    assert_eq!(encoded.canonical_result_size(), 2);
    assert_eq!(encoded.canonical_result_blake3(), &BOOL_DIGEST);
    assert_eq!(blake3::hash(&[0x08, 0x01]).as_bytes(), &BOOL_DIGEST);
}

#[test]
fn selected_payload_is_independent_of_terminal_id_and_supplied_envelope_fields() {
    let first_input = envelope(
        "terminal-1",
        Some(Payload::BoolResult(BoolResultV1 { value: false })),
    );
    let mut second_input = envelope(
        "terminal-2",
        Some(Payload::BoolResult(BoolResultV1 { value: false })),
    );
    second_input.canonical_result_blake3 = vec![0x55; 32].into();
    second_input.canonical_result_size = 7;

    let first = validate_and_encode_terminal_result(&first_input, &limits()).expect("valid result");
    let second =
        validate_and_encode_terminal_result(&second_input, &limits()).expect("valid result");

    assert_eq!(
        second.canonical_result_bytes(),
        first.canonical_result_bytes()
    );
    assert_eq!(
        second.canonical_result_blake3(),
        first.canonical_result_blake3()
    );
    assert_eq!(second.result().terminal_result_id, "terminal-2");
    assert_eq!(second.result().canonical_result_size, 0);
    assert_eq!(
        second.result().canonical_result_blake3.as_ref(),
        EMPTY_DIGEST
    );
}

#[test]
fn all_eight_closed_arms_encode_without_envelope_oneof_discriminator() {
    let payloads = vec![
        Payload::BoolResult(BoolResultV1 { value: false }),
        Payload::HeadObject(HeadObjectResultV1 {
            content_length: 0,
            etag: None,
            last_modified_unix_ms: None,
            version_id: None,
            metadata: Vec::new(),
        }),
        Payload::PutObject(PutObjectResultV1 {
            etag: None,
            version_id: None,
        }),
        Payload::DeleteObject(DeleteObjectResultV1 {
            delete_marker: false,
            version_id: None,
        }),
        Payload::ListObjectsV2(ListObjectsV2ResultV1 {
            entries: Vec::new(),
            common_prefixes: Vec::new(),
            is_truncated: false,
            next_continuation_token: None,
        }),
        Payload::ListObjectVersions(ListObjectVersionsResultV1 {
            versions: Vec::new(),
            delete_markers: Vec::new(),
            common_prefixes: Vec::new(),
            is_truncated: false,
            next_key_marker: None,
            next_version_id_marker: None,
        }),
        Payload::ByteResult(ByteResultHandleV1 {
            handle: "result/body-1".to_string(),
            size: 0,
            blake3: DIGEST.to_vec().into(),
            content_length: 0,
            metadata: Vec::new(),
            etag: None,
            version_id: None,
        }),
        Payload::ProviderError(ProviderErrorV1 {
            error_class: ProviderErrorClassV1::ProviderErrorClassPermanent as i32,
            http_status: 418,
            provider_code: None,
            provider_request_id: None,
            retry_after_ms: None,
            provider_message_blake3: DIGEST.to_vec().into(),
        }),
    ];

    let encoded: Vec<_> = payloads.into_iter().map(encode).collect();
    assert!(
        encoded[..6]
            .iter()
            .all(|value| value.canonical_result_bytes().is_empty())
    );
    assert!(hex(encoded[6].canonical_result_bytes()).starts_with("0a0d726573756c742f626f64792d31"));
    assert!(hex(encoded[7].canonical_result_bytes()).starts_with("080510a203"));
    assert!(validate_and_encode_terminal_result(&envelope("terminal-1", None), &limits()).is_err());

    let debug = format!("{:?}", encoded[6]);
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("result/body-1"));
    assert!(!debug.contains(&hex(&DIGEST)));
}

#[test]
fn terminal_id_and_all_positive_policy_limits_are_validated() {
    for invalid_id in ["", "bad\0id", "e\u{301}"] {
        assert!(
            validate_and_encode_terminal_result(
                &envelope(
                    invalid_id,
                    Some(Payload::BoolResult(BoolResultV1 { value: true }))
                ),
                &limits()
            )
            .is_err()
        );
    }
    assert!(
        validate_and_encode_terminal_result(
            &envelope(
                &"x".repeat(65),
                Some(Payload::BoolResult(BoolResultV1 { value: true }))
            ),
            &limits()
        )
        .is_err()
    );

    let mut mutations = Vec::new();
    macro_rules! zero_limit {
        ($field:ident) => {{
            let mut value = limits();
            value.$field = 0;
            mutations.push(value);
        }};
    }
    zero_limit!(max_canonical_result_bytes);
    zero_limit!(max_list_entries);
    zero_limit!(max_key_bytes);
    zero_limit!(max_metadata_entries);
    zero_limit!(max_metadata_key_bytes);
    zero_limit!(max_metadata_value_bytes);
    zero_limit!(max_metadata_aggregate_bytes);
    zero_limit!(max_opaque_value_bytes);
    zero_limit!(max_result_handle_bytes);
    zero_limit!(max_provider_code_bytes);
    zero_limit!(max_provider_request_id_bytes);

    let input = envelope(
        "terminal-1",
        Some(Payload::BoolResult(BoolResultV1 { value: true })),
    );
    assert!(
        mutations
            .iter()
            .all(|policy| validate_and_encode_terminal_result(&input, policy).is_err())
    );
}

#[test]
fn canonical_result_byte_limit_is_inclusive() {
    let payload = Payload::PutObject(PutObjectResultV1 {
        etag: Some("etag".to_string()),
        version_id: Some("v1".to_string()),
    });
    let size = encode(payload.clone()).canonical_result_size() as u32;
    let mut exact = limits();
    exact.max_canonical_result_bytes = size;
    let mut short = exact;
    short.max_canonical_result_bytes -= 1;

    assert_eq!(
        validate_and_encode_terminal_result(&envelope("terminal-1", Some(payload.clone())), &exact)
            .expect("exact byte limit must validate")
            .canonical_result_size(),
        u64::from(size)
    );
    assert!(
        validate_and_encode_terminal_result(&envelope("terminal-1", Some(payload)), &short)
            .is_err()
    );
}

#[test]
fn version_list_pins_nested_repeated_messages_and_optional_i64_wire_presence() {
    let version = concat(&[
        string_field(1, "asset"),
        string_field(2, "v1"),
        scalar_field(3, 1, false),
        scalar_field(4, 300, false),
        string_field(5, "etag"),
        scalar_field(6, 0, true),
    ]);
    let delete_marker = concat(&[
        string_field(1, "gone"),
        string_field(2, "v0"),
        scalar_field(3, 0, false),
        scalar_field(4, u64::MAX, true),
    ]);
    let expected = concat(&[
        bytes_field(1, &version),
        bytes_field(2, &delete_marker),
        string_field(3, "dir/"),
        scalar_field(4, 1, false),
        string_field(5, "next"),
        string_field(6, "v2"),
    ]);
    let encoded = encode(Payload::ListObjectVersions(ListObjectVersionsResultV1 {
        versions: vec![ObjectVersionV1 {
            key: "asset".to_string(),
            version_id: "v1".to_string(),
            is_latest: true,
            size: 300,
            etag: Some("etag".to_string()),
            last_modified_unix_ms: Some(0),
        }],
        delete_markers: vec![DeleteMarkerV1 {
            key: "gone".to_string(),
            version_id: "v0".to_string(),
            is_latest: false,
            last_modified_unix_ms: Some(-1),
        }],
        common_prefixes: vec!["dir/".to_string()],
        is_truncated: true,
        next_key_marker: Some("next".to_string()),
        next_version_id_marker: Some("v2".to_string()),
    }));

    assert_eq!(encoded.canonical_result_bytes(), expected);
    assert_eq!(
        hex(&expected),
        "0a180a05617373657412027631180120ac022a0465746167300012150a04676f6e651202763020ffffffffffffffffff011a046469722f20012a046e65787432027632"
    );
    assert_eq!(
        encoded.canonical_result_blake3(),
        blake3::hash(&expected).as_bytes()
    );
}

#[test]
fn optional_i64_present_zero_is_distinct_from_absent_default_scalars() {
    let absent = encode(Payload::HeadObject(HeadObjectResultV1 {
        content_length: 0,
        etag: None,
        last_modified_unix_ms: None,
        version_id: None,
        metadata: Vec::new(),
    }));
    let present = encode(Payload::HeadObject(HeadObjectResultV1 {
        content_length: 0,
        etag: None,
        last_modified_unix_ms: Some(0),
        version_id: None,
        metadata: Vec::new(),
    }));

    assert!(absent.canonical_result_bytes().is_empty());
    assert_eq!(absent.canonical_result_blake3(), &EMPTY_DIGEST);
    assert_eq!(present.canonical_result_bytes(), [0x18, 0x00]);
    assert_ne!(
        present.canonical_result_blake3(),
        absent.canonical_result_blake3()
    );
}

#[test]
fn metadata_is_sorted_rejects_duplicates_and_is_detached_from_input() {
    let mut input = envelope(
        "terminal-1",
        Some(Payload::ByteResult(ByteResultHandleV1 {
            handle: "result/body-1".to_string(),
            size: 3,
            blake3: DIGEST.to_vec().into(),
            content_length: 3,
            metadata: vec![metadata("z-key", "last"), metadata("a-key", "first")],
            etag: None,
            version_id: None,
        })),
    );
    let encoded =
        validate_and_encode_terminal_result(&input, &limits()).expect("valid byte result");

    let Some(Payload::ByteResult(source)) = input.result.as_mut() else {
        panic!("test input must remain a byte result")
    };
    source.blake3 = vec![0xff; 32].into();
    source.metadata[0] = metadata("mutated", "mutated");

    let Some(Payload::ByteResult(result)) = encoded.result().result.as_ref() else {
        panic!("canonical result must remain a byte result")
    };
    assert_eq!(result.blake3.as_ref(), DIGEST);
    assert_eq!(
        result.metadata,
        [metadata("a-key", "first"), metadata("z-key", "last")]
    );

    let duplicate = Payload::HeadObject(HeadObjectResultV1 {
        content_length: 1,
        etag: None,
        last_modified_unix_ms: None,
        version_id: None,
        metadata: vec![metadata("same", "a"), metadata("same", "b")],
    });
    assert!(
        validate_and_encode_terminal_result(&envelope("terminal-1", Some(duplicate)), &limits())
            .is_err()
    );
    for key in ["Upper", "bad key", ""] {
        let payload = Payload::HeadObject(HeadObjectResultV1 {
            content_length: 1,
            etag: None,
            last_modified_unix_ms: None,
            version_id: None,
            metadata: vec![metadata(key, "v")],
        });
        assert!(
            validate_and_encode_terminal_result(&envelope("terminal-1", Some(payload)), &limits())
                .is_err()
        );
    }
}

#[test]
fn metadata_component_count_and_aggregate_bounds_are_inclusive() {
    let payload = Payload::HeadObject(HeadObjectResultV1 {
        content_length: 1,
        etag: None,
        last_modified_unix_ms: None,
        version_id: None,
        metadata: vec![metadata("abcd", "wxyz")],
    });
    let mut exact = limits();
    exact.max_metadata_entries = 1;
    exact.max_metadata_key_bytes = 4;
    exact.max_metadata_value_bytes = 4;
    exact.max_metadata_aggregate_bytes = 8;
    assert!(
        validate_and_encode_terminal_result(&envelope("terminal-1", Some(payload.clone())), &exact)
            .is_ok()
    );

    for (field, value) in [("count", 0), ("key", 3), ("value", 3), ("aggregate", 7)] {
        let mut policy = exact;
        match field {
            "count" => policy.max_metadata_entries = value,
            "key" => policy.max_metadata_key_bytes = value,
            "value" => policy.max_metadata_value_bytes = value,
            "aggregate" => policy.max_metadata_aggregate_bytes = value,
            _ => unreachable!(),
        }
        assert!(
            validate_and_encode_terminal_result(
                &envelope("terminal-1", Some(payload.clone())),
                &policy
            )
            .is_err()
        );
    }
}

#[test]
fn list_objects_preserves_order_presence_count_and_truncation_contract() {
    let full_payload = Payload::ListObjectsV2(ListObjectsV2ResultV1 {
        entries: vec![
            ListObjectEntryV1 {
                key: "z".to_string(),
                size: 2,
                etag: Some("etag".to_string()),
                last_modified_unix_ms: Some(i64::MIN),
            },
            ListObjectEntryV1 {
                key: "a".to_string(),
                size: 1,
                etag: None,
                last_modified_unix_ms: Some(i64::MAX),
            },
        ],
        common_prefixes: vec!["z/".to_string(), "a/".to_string()],
        is_truncated: true,
        next_continuation_token: Some("next".to_string()),
    });
    let full = encode(full_payload);
    let Some(Payload::ListObjectsV2(value)) = full.result().result.as_ref() else {
        panic!("canonical result must remain a list")
    };
    assert_eq!(
        value
            .entries
            .iter()
            .map(|entry| entry.key.as_str())
            .collect::<Vec<_>>(),
        ["z", "a"]
    );
    assert_eq!(value.common_prefixes, ["z/", "a/"]);

    let invalid = [
        ListObjectsV2ResultV1 {
            entries: Vec::new(),
            common_prefixes: Vec::new(),
            is_truncated: true,
            next_continuation_token: None,
        },
        ListObjectsV2ResultV1 {
            entries: Vec::new(),
            common_prefixes: Vec::new(),
            is_truncated: false,
            next_continuation_token: Some("next".to_string()),
        },
        ListObjectsV2ResultV1 {
            entries: vec![ListObjectEntryV1 {
                key: "a".to_string(),
                size: 1,
                etag: None,
                last_modified_unix_ms: None,
            }],
            common_prefixes: vec!["a/".to_string()],
            is_truncated: false,
            next_continuation_token: None,
        },
    ];
    let mut one_entry = limits();
    one_entry.max_list_entries = 1;
    assert!(invalid.into_iter().all(|value| {
        validate_and_encode_terminal_result(
            &envelope("terminal-1", Some(Payload::ListObjectsV2(value))),
            &one_entry,
        )
        .is_err()
    }));
}

#[test]
fn version_list_requires_both_markers_exactly_when_truncated() {
    let value =
        |is_truncated, next_key_marker: Option<&str>, next_version_id_marker: Option<&str>| {
            Payload::ListObjectVersions(ListObjectVersionsResultV1 {
                versions: Vec::new(),
                delete_markers: Vec::new(),
                common_prefixes: Vec::new(),
                is_truncated,
                next_key_marker: next_key_marker.map(str::to_string),
                next_version_id_marker: next_version_id_marker.map(str::to_string),
            })
        };
    assert!(
        validate_and_encode_terminal_result(
            &envelope(
                "terminal-1",
                Some(value(true, Some("key"), Some("version")))
            ),
            &limits()
        )
        .is_ok()
    );
    for payload in [
        value(true, None, None),
        value(true, Some("key"), None),
        value(true, None, Some("version")),
        value(false, Some("key"), Some("version")),
    ] {
        assert!(
            validate_and_encode_terminal_result(&envelope("terminal-1", Some(payload)), &limits())
                .is_err()
        );
    }
}

#[test]
fn byte_result_requires_handle_digest_and_exact_content_length() {
    let value = |handle: &str, size: u64, digest: Vec<u8>, content_length: u64| {
        Payload::ByteResult(ByteResultHandleV1 {
            handle: handle.to_string(),
            size,
            blake3: digest.into(),
            content_length,
            metadata: Vec::new(),
            etag: None,
            version_id: None,
        })
    };
    assert!(
        validate_and_encode_terminal_result(
            &envelope(
                "terminal-1",
                Some(value("result/body", u64::MAX, DIGEST.to_vec(), u64::MAX))
            ),
            &limits()
        )
        .is_ok()
    );
    for payload in [
        value("", u64::MAX, DIGEST.to_vec(), u64::MAX),
        value("result/body", u64::MAX, vec![0; 31], u64::MAX),
        value("result/body", u64::MAX, vec![0; 33], u64::MAX),
        value("result/body", u64::MAX, DIGEST.to_vec(), u64::MAX - 1),
    ] {
        assert!(
            validate_and_encode_terminal_result(&envelope("terminal-1", Some(payload)), &limits())
                .is_err()
        );
    }
}

#[test]
fn provider_error_accepts_closed_classes_and_rejects_status_digest_and_retry_violations() {
    let classes = [
        ProviderErrorClassV1::ProviderErrorClassNotFound,
        ProviderErrorClassV1::ProviderErrorClassAuthorization,
        ProviderErrorClassV1::ProviderErrorClassThrottled,
        ProviderErrorClassV1::ProviderErrorClassRetryableDecisive,
        ProviderErrorClassV1::ProviderErrorClassPermanent,
        ProviderErrorClassV1::ProviderErrorClassMalformedResult,
        ProviderErrorClassV1::ProviderErrorClassOversizedResult,
    ];
    let value = |error_class: i32,
                 http_status: u32,
                 retry_after_ms: Option<u64>,
                 digest: Vec<u8>,
                 provider_code: Option<String>,
                 provider_request_id: Option<String>| {
        Payload::ProviderError(ProviderErrorV1 {
            error_class,
            http_status,
            provider_code,
            provider_request_id,
            retry_after_ms,
            provider_message_blake3: digest.into(),
        })
    };
    assert!(classes.into_iter().all(|class| {
        validate_and_encode_terminal_result(
            &envelope(
                "terminal-1",
                Some(value(
                    class as i32,
                    if class == ProviderErrorClassV1::ProviderErrorClassNotFound {
                        404
                    } else {
                        503
                    },
                    Some(60_000),
                    DIGEST.to_vec(),
                    Some("SlowDown".to_string()),
                    Some("request-1".to_string()),
                )),
            ),
            &limits(),
        )
        .is_ok()
    }));

    let invalid = [
        value(0, 503, None, DIGEST.to_vec(), None, None),
        value(8, 503, None, DIGEST.to_vec(), None, None),
        value(99, 503, None, DIGEST.to_vec(), None, None),
        value(3, 99, None, DIGEST.to_vec(), None, None),
        value(3, 600, None, DIGEST.to_vec(), None, None),
        value(3, 503, Some(60_001), DIGEST.to_vec(), None, None),
        value(3, 503, None, vec![0; 31], None, None),
        value(3, 503, None, vec![0; 33], None, None),
        value(3, 503, None, DIGEST.to_vec(), Some("x".repeat(33)), None),
        value(3, 503, None, DIGEST.to_vec(), None, Some("x".repeat(65))),
    ];
    assert!(invalid.into_iter().all(|payload| {
        validate_and_encode_terminal_result(&envelope("terminal-1", Some(payload)), &limits())
            .is_err()
    }));
}

#[test]
fn optional_text_presence_is_byte_distinct() {
    let absent = encode(Payload::PutObject(PutObjectResultV1 {
        etag: None,
        version_id: None,
    }));
    let present = encode(Payload::PutObject(PutObjectResultV1 {
        etag: Some("etag".to_string()),
        version_id: Some("version".to_string()),
    }));

    assert!(present.canonical_result_size() > absent.canonical_result_size());
    assert_ne!(
        present.canonical_result_blake3(),
        absent.canonical_result_blake3()
    );
}

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_object_dispatch::AuthenticatedConsumerIdentity;
use lore_object_dispatch::ObjectStoreResultAckAuthority;
use lore_object_dispatch::RequestIdentityLimits;
use lore_object_dispatch::ResultAckError;
use lore_object_dispatch::ResultAckLimits;
use lore_object_dispatch::ResultAckReceiptInput;
use lore_object_dispatch::TerminalResultLimits;
use lore_object_dispatch::build_object_store_result_ack_receipt;
use lore_object_dispatch::validate_and_encode_terminal_result;
use lore_object_dispatch::validate_object_store_result_ack;
use lore_proto::lore::object_dispatch::v1::BoolResultV1;
use lore_proto::lore::object_dispatch::v1::ByteResultHandleV1;
use lore_proto::lore::object_dispatch::v1::DurableConsumerContextV1;
use lore_proto::lore::object_dispatch::v1::DurableConsumerKindV1;
use lore_proto::lore::object_dispatch::v1::DurableConsumerResultAckProofV1;
use lore_proto::lore::object_dispatch::v1::FragmentLifecycleConsumerContextV1;
use lore_proto::lore::object_dispatch::v1::FragmentLifecycleResultAckProofV1;
use lore_proto::lore::object_dispatch::v1::GetObjectV1;
use lore_proto::lore::object_dispatch::v1::HeadBucketV1;
use lore_proto::lore::object_dispatch::v1::ListObjectsV2v1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultAckStateV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultAckV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreTerminalResultV1;
use lore_proto::lore::object_dispatch::v1::ResultConsumerContextV1;
use lore_proto::lore::object_dispatch::v1::StartupAdmissionConsumerContextV1;
use lore_proto::lore::object_dispatch::v1::StartupAdmissionResultAckProofV1;
use lore_proto::lore::object_dispatch::v1::object_store_request_v1;
use lore_proto::lore::object_dispatch::v1::object_store_result_ack_v1;
use lore_proto::lore::object_dispatch::v1::object_store_terminal_result_v1;
use lore_proto::lore::object_dispatch::v1::result_consumer_context_v1;

const DIGEST: [u8; 32] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32,
];
const LOGICAL_ID: &str = "018f3e12-a456-7abc-8def-0123456789ab";
const ATTEMPT_ID: &str = "018f3e12-a457-7abc-8def-0123456789ab";
const SCOPE: &str =
    "urn:lore:object-dispatch:Ym91bmRhcnktMQ:Y2VsbC0x:dGVuYW50LTE:job:Y29uc3VtZXItMQ";

fn limits() -> ResultAckLimits {
    ResultAckLimits {
        identity: RequestIdentityLimits {
            max_identity_bytes: 256,
            max_authenticated_scope_bytes: 1_024,
        },
        max_terminal_result_id_bytes: 64,
        max_result_handle_bytes: 128,
        max_fingerprint_preimage_bytes: 4_096,
    }
}

fn terminal_limits() -> TerminalResultLimits {
    TerminalResultLimits {
        max_canonical_result_bytes: 4_096,
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

fn identity() -> AuthenticatedConsumerIdentity {
    AuthenticatedConsumerIdentity {
        provider_boundary_id: "boundary-1".to_string(),
        authenticated_cell_id: "cell-1".to_string(),
        authenticated_tenant_id: "tenant-1".to_string(),
        principal_id: "consumer-1".to_string(),
    }
}

fn fragment_context() -> ResultConsumerContextV1 {
    ResultConsumerContextV1 {
        consumer: Some(result_consumer_context_v1::Consumer::FragmentLifecycle(
            FragmentLifecycleConsumerContextV1 {
                fragment_id: vec![42; 32].into(),
                repository_id: Some("repo-1".to_string()),
                association_context: Some("main".to_string()),
                repository_generation: Some(3),
                association_epoch: Some(4),
                lifecycle_generation: 5,
                fragment_epoch: 6,
                lifecycle_fence: 7,
                reader_lease_id: Some("reader-1".to_string()),
                reader_fence: Some(8),
            },
        )),
    }
}

fn startup_context() -> ResultConsumerContextV1 {
    ResultConsumerContextV1 {
        consumer: Some(result_consumer_context_v1::Consumer::StartupAdmission(
            StartupAdmissionConsumerContextV1 {
                policy_revision: "policy-1".to_string(),
                allocation_revision: "allocation-1".to_string(),
                config_revision: "config-1".to_string(),
                startup_attempt_id: "startup-1".to_string(),
                readiness_generation: 3,
            },
        )),
    }
}

fn durable_context(kind: i32) -> ResultConsumerContextV1 {
    ResultConsumerContextV1 {
        consumer: Some(result_consumer_context_v1::Consumer::DurableConsumer(
            DurableConsumerContextV1 {
                consumer_kind: kind,
                authenticated_scope: SCOPE.to_string(),
                operation_id: "job-1".to_string(),
                checkpoint_revision: 9,
                checkpoint_fence: 10,
            },
        )),
    }
}

fn get_operation() -> object_store_request_v1::Operation {
    object_store_request_v1::Operation::GetObject(GetObjectV1::default())
}

fn startup_operation() -> object_store_request_v1::Operation {
    object_store_request_v1::Operation::HeadBucket(HeadBucketV1::default())
}

fn durable_operation() -> object_store_request_v1::Operation {
    object_store_request_v1::Operation::ListObjectsV2(ListObjectsV2v1::default())
}

fn byte_terminal() -> lore_object_dispatch::CanonicalTerminalResult {
    validate_and_encode_terminal_result(
        &ObjectStoreTerminalResultV1 {
            terminal_result_id: "terminal-1".to_string(),
            result: Some(object_store_terminal_result_v1::Result::ByteResult(
                ByteResultHandleV1 {
                    handle: "result/body-1".to_string(),
                    size: 3,
                    blake3: DIGEST.to_vec().into(),
                    content_length: 3,
                    metadata: Vec::new(),
                    etag: None,
                    version_id: None,
                },
            )),
            canonical_result_blake3: Default::default(),
            canonical_result_size: 0,
        },
        &terminal_limits(),
    )
    .expect("byte terminal result must be valid")
}

fn bool_terminal() -> lore_object_dispatch::CanonicalTerminalResult {
    validate_and_encode_terminal_result(
        &ObjectStoreTerminalResultV1 {
            terminal_result_id: "terminal-1".to_string(),
            result: Some(object_store_terminal_result_v1::Result::BoolResult(
                BoolResultV1 { value: true },
            )),
            canonical_result_blake3: Default::default(),
            canonical_result_size: 0,
        },
        &terminal_limits(),
    )
    .expect("bool terminal result must be valid")
}

fn proof_for(
    context: &ResultConsumerContextV1,
    digest: &[u8; 32],
) -> object_store_result_ack_v1::Proof {
    match context.consumer.as_ref().expect("test context has an arm") {
        result_consumer_context_v1::Consumer::FragmentLifecycle(value) => {
            object_store_result_ack_v1::Proof::FragmentLifecycle(
                FragmentLifecycleResultAckProofV1 {
                    fragment_id: value.fragment_id.clone(),
                    repository_id: value.repository_id.clone(),
                    association_context: value.association_context.clone(),
                    repository_generation: value.repository_generation,
                    association_epoch: value.association_epoch,
                    lifecycle_generation: value.lifecycle_generation,
                    fragment_epoch: value.fragment_epoch,
                    lifecycle_fence: value.lifecycle_fence,
                    reader_lease_id: value.reader_lease_id.clone(),
                    reader_fence: value.reader_fence,
                    terminal_result_blake3: digest.to_vec().into(),
                },
            )
        }
        result_consumer_context_v1::Consumer::StartupAdmission(value) => {
            object_store_result_ack_v1::Proof::StartupAdmission(StartupAdmissionResultAckProofV1 {
                policy_revision: value.policy_revision.clone(),
                allocation_revision: value.allocation_revision.clone(),
                config_revision: value.config_revision.clone(),
                startup_attempt_id: value.startup_attempt_id.clone(),
                readiness_generation: value.readiness_generation,
                terminal_result_blake3: digest.to_vec().into(),
            })
        }
        result_consumer_context_v1::Consumer::DurableConsumer(value) => {
            object_store_result_ack_v1::Proof::DurableConsumer(DurableConsumerResultAckProofV1 {
                consumer_kind: value.consumer_kind,
                authenticated_scope: value.authenticated_scope.clone(),
                operation_id: value.operation_id.clone(),
                checkpoint_revision: value.checkpoint_revision,
                checkpoint_fence: value.checkpoint_fence,
                terminal_result_blake3: digest.to_vec().into(),
            })
        }
    }
}

fn ack_for(
    context: &ResultConsumerContextV1,
    terminal: &lore_object_dispatch::CanonicalTerminalResult,
) -> ObjectStoreResultAckV1 {
    let byte_result_handle = match terminal.result().result.as_ref() {
        Some(object_store_terminal_result_v1::Result::ByteResult(result)) => {
            Some(result.handle.clone())
        }
        _ => None,
    };
    ObjectStoreResultAckV1 {
        protocol_revision: "protocol-1".to_string(),
        provider_boundary_id: "boundary-1".to_string(),
        authenticated_cell_id: "cell-1".to_string(),
        authenticated_tenant_id: "tenant-1".to_string(),
        logical_request_id: LOGICAL_ID.to_string(),
        attempt_id: ATTEMPT_ID.to_string(),
        terminal_result_id: "terminal-1".to_string(),
        canonical_result_size: terminal.canonical_result_size(),
        canonical_result_blake3: terminal.canonical_result_blake3().to_vec().into(),
        byte_result_handle,
        proof: Some(proof_for(context, terminal.canonical_result_blake3())),
    }
}

fn validate(
    operation: &object_store_request_v1::Operation,
    context: &ResultConsumerContextV1,
    terminal: &lore_object_dispatch::CanonicalTerminalResult,
    ack: &ObjectStoreResultAckV1,
    policy: &ResultAckLimits,
) -> Result<lore_object_dispatch::ValidatedObjectStoreResultAck, ResultAckError> {
    let identity = identity();
    validate_object_store_result_ack(
        ack,
        &ObjectStoreResultAckAuthority {
            operation,
            consumer_context: context,
            authenticated_identity: &identity,
            protocol_revision: "protocol-1",
            provider_boundary_id: "boundary-1",
            authenticated_cell_id: "cell-1",
            authenticated_tenant_id: "tenant-1",
            logical_request_id: LOGICAL_ID,
            attempt_id: ATTEMPT_ID,
            terminal_result: terminal,
        },
        policy,
    )
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

#[test]
fn fragment_proof_pins_cross_language_canonical_preimage_and_fingerprint() {
    let operation = get_operation();
    let context = fragment_context();
    let terminal = byte_terminal();
    let ack = ack_for(&context, &terminal);
    let validated = validate(&operation, &context, &terminal, &ack, &limits()).expect("valid ACK");
    let expected = decode_hex(concat!(
        "6f626a6563742d64697370617463682d61636b2d763100",
        "0000000a70726f746f636f6c2d310000000a626f756e646172792d31",
        "0000000663656c6c2d310000000874656e616e742d31",
        "0000002430313866336531322d613435362d376162632d386465662d303132333435363738396162",
        "0000002430313866336531322d613435372d376162632d386465662d303132333435363738396162",
        "0000000a7465726d696e616c2d310000000000000035",
        "e87c2c240a531806f9ae187bff62485611de0a2c4cf2bac0323eb75e820899a9",
        "010000000d726573756c742f626f64792d3100000014",
        "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a",
        "01000000067265706f2d3101000000046d61696e",
        "010000000000000003010000000000000004",
        "000000000000000500000000000000060000000000000007",
        "01000000087265616465722d31010000000000000008",
        "e87c2c240a531806f9ae187bff62485611de0a2c4cf2bac0323eb75e820899a9"
    ));

    assert_eq!(validated.canonical_ack_bytes(), expected);
    assert_eq!(validated.canonical_ack_bytes().len(), 377);
    assert_eq!(
        validated.ack_fingerprint(),
        decode_hex("fe757e1ceaebcbd1ec78756caba62bb2e11d918e2d322f56f67ba56ac11ba6dc").as_slice()
    );
}

#[test]
fn startup_and_durable_proof_arms_pin_tags_framing_sizes_and_fingerprints() {
    let terminal = byte_terminal();
    let startup = startup_context();
    let startup_ack = ack_for(&startup, &terminal);
    let startup_validated = validate(
        &startup_operation(),
        &startup,
        &terminal,
        &startup_ack,
        &limits(),
    )
    .expect("startup proof must validate");
    let startup_proof = decode_hex(concat!(
        "00000015",
        "00000008706f6c6963792d31",
        "0000000c616c6c6f636174696f6e2d31",
        "00000008636f6e6669672d31",
        "00000009737461727475702d31",
        "0000000000000003",
        "e87c2c240a531806f9ae187bff62485611de0a2c4cf2bac0323eb75e820899a9"
    ));
    assert_eq!(startup_validated.canonical_ack_bytes().len(), 322);
    assert!(
        startup_validated
            .canonical_ack_bytes()
            .ends_with(&startup_proof)
    );
    assert_eq!(
        startup_validated.ack_fingerprint(),
        decode_hex("e0af2f0e4399ef1bc9083d7f43dbe98c81b75f0d9d2fdd126a82e7596d1e5728").as_slice()
    );

    let durable = durable_context(DurableConsumerKindV1::DurableConsumerKindJob as i32);
    let durable_ack = ack_for(&durable, &terminal);
    let durable_validated = validate(
        &durable_operation(),
        &durable,
        &terminal,
        &durable_ack,
        &limits(),
    )
    .expect("durable proof must validate");
    let durable_proof = decode_hex(concat!(
        "00000016",
        "00000001",
        "0000004f",
        "75726e3a6c6f72653a6f626a6563742d64697370617463683a596d3931626d5268636e6b744d513a",
        "59325673624330783a64475675595735304c54453a6a6f623a59323975633356745a5849744d51",
        "000000056a6f622d31",
        "0000000000000009",
        "000000000000000a",
        "e87c2c240a531806f9ae187bff62485611de0a2c4cf2bac0323eb75e820899a9"
    ));
    assert_eq!(durable_validated.canonical_ack_bytes().len(), 373);
    assert!(
        durable_validated
            .canonical_ack_bytes()
            .ends_with(&durable_proof)
    );
    assert_eq!(
        durable_validated.ack_fingerprint(),
        decode_hex("014b0b53c943f5a2ddfd8e5f7e607aacee2eb583a2330b844ac55d1c632c9791").as_slice()
    );
}

#[test]
fn missing_mismatched_and_future_proof_or_consumer_arms_fail_closed() {
    let terminal = byte_terminal();
    let fragment = fragment_context();
    let operation = get_operation();
    let mut missing = ack_for(&fragment, &terminal);
    missing.proof = None;
    assert_eq!(
        validate(&operation, &fragment, &terminal, &missing, &limits()),
        Err(ResultAckError::InvalidProof)
    );

    let mut wrong_arm = ack_for(&fragment, &terminal);
    wrong_arm.proof = Some(proof_for(
        &startup_context(),
        terminal.canonical_result_blake3(),
    ));
    assert_eq!(
        validate(&operation, &fragment, &terminal, &wrong_arm, &limits()),
        Err(ResultAckError::InvalidProof)
    );

    let future = durable_context(4);
    let future_ack = ack_for(&future, &terminal);
    assert_eq!(
        validate(
            &durable_operation(),
            &future,
            &terminal,
            &future_ack,
            &limits()
        ),
        Err(ResultAckError::InvalidConsumerContext)
    );

    let valid_durable = durable_context(DurableConsumerKindV1::DurableConsumerKindJob as i32);
    let mut future_proof = ack_for(&valid_durable, &terminal);
    let Some(object_store_result_ack_v1::Proof::DurableConsumer(proof)) =
        future_proof.proof.as_mut()
    else {
        panic!("fixture must contain durable proof")
    };
    proof.consumer_kind = 4;
    assert_eq!(
        validate(
            &durable_operation(),
            &valid_durable,
            &terminal,
            &future_proof,
            &limits()
        ),
        Err(ResultAckError::InvalidProof)
    );
}

#[test]
fn startup_and_durable_proofs_bind_each_context_field() {
    let terminal = byte_terminal();
    let startup = startup_context();
    let startup_operation = startup_operation();
    let startup_base = ack_for(&startup, &terminal);
    let Some(object_store_result_ack_v1::Proof::StartupAdmission(startup_proof)) =
        startup_base.proof.as_ref()
    else {
        panic!("fixture must contain startup proof")
    };
    let mut startup_proofs = Vec::new();
    macro_rules! mutate_startup_proof {
        ($field:ident, $value:expr) => {{
            let mut candidate = startup_proof.clone();
            candidate.$field = $value;
            startup_proofs.push(candidate);
        }};
    }
    mutate_startup_proof!(policy_revision, "policy-2".to_string());
    mutate_startup_proof!(allocation_revision, "allocation-2".to_string());
    mutate_startup_proof!(config_revision, "config-2".to_string());
    mutate_startup_proof!(startup_attempt_id, "startup-2".to_string());
    mutate_startup_proof!(readiness_generation, 4);
    mutate_startup_proof!(terminal_result_blake3, vec![0; 32].into());
    assert!(startup_proofs.into_iter().all(|proof| {
        let mut ack = startup_base.clone();
        ack.proof = Some(object_store_result_ack_v1::Proof::StartupAdmission(proof));
        validate(&startup_operation, &startup, &terminal, &ack, &limits())
            == Err(ResultAckError::InvalidProof)
    }));

    let durable = durable_context(DurableConsumerKindV1::DurableConsumerKindJob as i32);
    let durable_operation = durable_operation();
    let durable_base = ack_for(&durable, &terminal);
    let Some(object_store_result_ack_v1::Proof::DurableConsumer(durable_proof)) =
        durable_base.proof.as_ref()
    else {
        panic!("fixture must contain durable proof")
    };
    let mut durable_proofs = Vec::new();
    macro_rules! mutate_durable_proof {
        ($field:ident, $value:expr) => {{
            let mut candidate = durable_proof.clone();
            candidate.$field = $value;
            durable_proofs.push(candidate);
        }};
    }
    mutate_durable_proof!(
        consumer_kind,
        DurableConsumerKindV1::DurableConsumerKindOperator as i32
    );
    mutate_durable_proof!(authenticated_scope, "urn:lore:other".to_string());
    mutate_durable_proof!(operation_id, "job-2".to_string());
    mutate_durable_proof!(checkpoint_revision, 10);
    mutate_durable_proof!(checkpoint_fence, 11);
    mutate_durable_proof!(terminal_result_blake3, vec![0; 32].into());
    assert!(durable_proofs.into_iter().all(|proof| {
        let mut ack = durable_base.clone();
        ack.proof = Some(object_store_result_ack_v1::Proof::DurableConsumer(proof));
        validate(&durable_operation, &durable, &terminal, &ack, &limits())
            == Err(ResultAckError::InvalidProof)
    }));
}

#[test]
fn every_outer_authority_and_terminal_tuple_component_is_exact() {
    let operation = get_operation();
    let context = fragment_context();
    let terminal = byte_terminal();
    let base = ack_for(&context, &terminal);
    let mut mutations = Vec::new();
    macro_rules! mutate {
        ($field:ident, $value:expr) => {{
            let mut candidate = base.clone();
            candidate.$field = $value;
            mutations.push(candidate);
        }};
    }
    mutate!(protocol_revision, "protocol-2".to_string());
    mutate!(provider_boundary_id, "boundary-2".to_string());
    mutate!(authenticated_cell_id, "cell-2".to_string());
    mutate!(authenticated_tenant_id, "tenant-2".to_string());
    mutate!(logical_request_id, ATTEMPT_ID.to_string());
    mutate!(attempt_id, LOGICAL_ID.to_string());
    mutate!(terminal_result_id, "terminal-2".to_string());
    mutate!(canonical_result_size, terminal.canonical_result_size() + 1);
    mutate!(canonical_result_blake3, vec![0; 32].into());
    mutate!(canonical_result_blake3, vec![0; 31].into());
    mutate!(byte_result_handle, None);
    mutate!(byte_result_handle, Some("result/other".to_string()));

    assert!(
        mutations.iter().all(|candidate| validate(
            &operation,
            &context,
            &terminal,
            candidate,
            &limits()
        )
        .is_err())
    );
}

#[test]
fn uuidv7_and_fragment_optional_presence_are_validated_before_fingerprinting() {
    let operation = get_operation();
    let terminal = byte_terminal();
    let context = fragment_context();
    let mut invalid_uuid = ack_for(&context, &terminal);
    invalid_uuid.logical_request_id = "not-a-uuid".to_string();
    let identity = identity();
    let result = validate_object_store_result_ack(
        &invalid_uuid,
        &ObjectStoreResultAckAuthority {
            operation: &operation,
            consumer_context: &context,
            authenticated_identity: &identity,
            protocol_revision: "protocol-1",
            provider_boundary_id: "boundary-1",
            authenticated_cell_id: "cell-1",
            authenticated_tenant_id: "tenant-1",
            logical_request_id: "not-a-uuid",
            attempt_id: ATTEMPT_ID,
            terminal_result: &terminal,
        },
        &limits(),
    );
    assert_eq!(result, Err(ResultAckError::InvalidUuidV7));

    let mut malformed_context = fragment_context();
    let Some(result_consumer_context_v1::Consumer::FragmentLifecycle(value)) =
        malformed_context.consumer.as_mut()
    else {
        panic!("fixture must contain fragment context")
    };
    value.repository_id = None;
    let ack = ack_for(&malformed_context, &terminal);
    assert_eq!(
        validate(&operation, &malformed_context, &terminal, &ack, &limits()),
        Err(ResultAckError::InvalidConsumerContext)
    );
}

#[test]
fn fragment_proof_binds_every_field_and_optional_presence() {
    let operation = get_operation();
    let context = fragment_context();
    let terminal = byte_terminal();
    let base = ack_for(&context, &terminal);
    let Some(object_store_result_ack_v1::Proof::FragmentLifecycle(proof)) = base.proof.as_ref()
    else {
        panic!("fixture must contain fragment proof")
    };
    let mut proofs = Vec::new();
    macro_rules! mutate_proof {
        ($field:ident, $value:expr) => {{
            let mut candidate = proof.clone();
            candidate.$field = $value;
            proofs.push(candidate);
        }};
    }
    mutate_proof!(fragment_id, vec![0; 32].into());
    mutate_proof!(repository_id, None);
    mutate_proof!(association_context, Some("other".to_string()));
    mutate_proof!(repository_generation, Some(4));
    mutate_proof!(association_epoch, Some(5));
    mutate_proof!(lifecycle_generation, 6);
    mutate_proof!(fragment_epoch, 7);
    mutate_proof!(lifecycle_fence, 8);
    mutate_proof!(reader_lease_id, None);
    mutate_proof!(reader_fence, Some(9));
    mutate_proof!(terminal_result_blake3, vec![0; 32].into());
    mutate_proof!(terminal_result_blake3, vec![0; 31].into());

    assert!(proofs.into_iter().all(|proof| {
        let mut candidate = base.clone();
        candidate.proof = Some(object_store_result_ack_v1::Proof::FragmentLifecycle(proof));
        validate(&operation, &context, &terminal, &candidate, &limits())
            == Err(ResultAckError::InvalidProof)
    }));
}

#[test]
fn byte_result_handle_is_present_if_and_only_if_terminal_payload_is_bytes() {
    let operation = get_operation();
    let context = fragment_context();
    let byte_result = byte_terminal();
    let mut missing = ack_for(&context, &byte_result);
    missing.byte_result_handle = None;
    assert_eq!(
        validate(&operation, &context, &byte_result, &missing, &limits()),
        Err(ResultAckError::InvalidByteResultHandle)
    );

    let inline = bool_terminal();
    let valid = ack_for(&context, &inline);
    assert!(validate(&operation, &context, &inline, &valid, &limits()).is_ok());
    let mut extra = valid;
    extra.byte_result_handle = Some("result/body-1".to_string());
    assert_eq!(
        validate(&operation, &context, &inline, &extra, &limits()),
        Err(ResultAckError::InvalidByteResultHandle)
    );
}

#[test]
fn fingerprint_preimage_bound_is_inclusive_and_all_limits_are_positive() {
    let operation = get_operation();
    let context = fragment_context();
    let terminal = byte_terminal();
    let ack = ack_for(&context, &terminal);
    let size = validate(&operation, &context, &terminal, &ack, &limits())
        .expect("baseline ACK")
        .canonical_ack_bytes()
        .len() as u32;
    let mut exact = limits();
    exact.max_fingerprint_preimage_bytes = size;
    assert_eq!(
        validate(&operation, &context, &terminal, &ack, &exact)
            .expect("exact preimage bound is inclusive")
            .canonical_ack_bytes()
            .len() as u32,
        size
    );
    exact.max_fingerprint_preimage_bytes -= 1;
    assert_eq!(
        validate(&operation, &context, &terminal, &ack, &exact),
        Err(ResultAckError::PreimageTooLarge)
    );

    for field in 0..5 {
        let mut invalid = limits();
        match field {
            0 => invalid.identity.max_identity_bytes = 0,
            1 => invalid.identity.max_authenticated_scope_bytes = 0,
            2 => invalid.max_terminal_result_id_bytes = 0,
            3 => invalid.max_result_handle_bytes = 0,
            4 => invalid.max_fingerprint_preimage_bytes = 0,
            _ => unreachable!(),
        }
        assert_eq!(
            validate(&operation, &context, &terminal, &ack, &invalid),
            Err(ResultAckError::InvalidLimits)
        );
    }
}

#[test]
fn receipt_preserves_optional_purge_presence_and_detaches_the_fingerprint() {
    let mut fingerprint = DIGEST.to_vec();
    let receipt = build_object_store_result_ack_receipt(
        &ResultAckReceiptInput {
            terminal_result_id: "terminal-1",
            ack_fingerprint: &fingerprint,
            acked_at_unix_ms: 10,
            payload_purge_after_unix_ms: Some(10),
        },
        &limits(),
    )
    .expect("valid receipt");
    fingerprint[0] = 0xff;
    assert_eq!(
        receipt.state,
        ObjectStoreResultAckStateV1::ObjectStoreResultAckStateAcked as i32
    );
    assert_eq!(receipt.terminal_result_id, "terminal-1");
    assert_eq!(receipt.ack_fingerprint.as_ref(), DIGEST);
    assert_eq!(receipt.acked_at_unix_ms, 10);
    assert_eq!(receipt.payload_purge_after_unix_ms, Some(10));

    let absent = build_object_store_result_ack_receipt(
        &ResultAckReceiptInput {
            terminal_result_id: "terminal-1",
            ack_fingerprint: &DIGEST,
            acked_at_unix_ms: 10,
            payload_purge_after_unix_ms: None,
        },
        &limits(),
    )
    .expect("receipt without purge time");
    assert_eq!(absent.payload_purge_after_unix_ms, None);

    let maximum = build_object_store_result_ack_receipt(
        &ResultAckReceiptInput {
            terminal_result_id: "terminal-1",
            ack_fingerprint: &DIGEST,
            acked_at_unix_ms: i64::MAX,
            payload_purge_after_unix_ms: Some(i64::MAX),
        },
        &limits(),
    )
    .expect("inclusive nonnegative i64 maximum");
    assert_eq!(maximum.payload_purge_after_unix_ms, Some(i64::MAX));
}

#[test]
fn receipt_rejects_invalid_digest_negative_time_and_purge_ordering() {
    let short = [0_u8; 31];
    for input in [
        ResultAckReceiptInput {
            terminal_result_id: "terminal-1",
            ack_fingerprint: &short,
            acked_at_unix_ms: 0,
            payload_purge_after_unix_ms: None,
        },
        ResultAckReceiptInput {
            terminal_result_id: "terminal-1",
            ack_fingerprint: &DIGEST,
            acked_at_unix_ms: -1,
            payload_purge_after_unix_ms: None,
        },
        ResultAckReceiptInput {
            terminal_result_id: "terminal-1",
            ack_fingerprint: &DIGEST,
            acked_at_unix_ms: 10,
            payload_purge_after_unix_ms: Some(9),
        },
    ] {
        assert_eq!(
            build_object_store_result_ack_receipt(&input, &limits()),
            Err(ResultAckError::InvalidReceipt)
        );
    }
}

// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_object_dispatch::AuthenticatedConsumerIdentity;
use lore_object_dispatch::ObjectStoreResultAckAuthority;
use lore_object_dispatch::RequestIdentityLimits;
use lore_object_dispatch::ResultAckLimits;
use lore_object_dispatch::ResultDiscardError;
use lore_object_dispatch::ResultDiscardLimits;
use lore_object_dispatch::ResultDiscardReceiptInput;
use lore_object_dispatch::TerminalResultLimits;
use lore_object_dispatch::build_object_store_result_discard_receipt;
use lore_object_dispatch::validate_and_encode_terminal_result;
use lore_object_dispatch::validate_object_store_result_discard;
use lore_proto::lore::object_dispatch::v1::BoolResultV1;
use lore_proto::lore::object_dispatch::v1::ByteResultHandleV1;
use lore_proto::lore::object_dispatch::v1::DurableConsumerCancellationKindV1;
use lore_proto::lore::object_dispatch::v1::DurableConsumerCancelledProofV1;
use lore_proto::lore::object_dispatch::v1::DurableConsumerContextV1;
use lore_proto::lore::object_dispatch::v1::DurableConsumerKindV1;
use lore_proto::lore::object_dispatch::v1::FragmentLifecycleConsumerContextV1;
use lore_proto::lore::object_dispatch::v1::FragmentLifecycleSupersededProofV1;
use lore_proto::lore::object_dispatch::v1::FragmentLifecycleSupersessionKindV1;
use lore_proto::lore::object_dispatch::v1::HeadBucketV1;
use lore_proto::lore::object_dispatch::v1::ListObjectsV2v1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultDiscardStateV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreResultDiscardV1;
use lore_proto::lore::object_dispatch::v1::ObjectStoreTerminalResultV1;
use lore_proto::lore::object_dispatch::v1::PutObjectV1;
use lore_proto::lore::object_dispatch::v1::ResultConsumerContextV1;
use lore_proto::lore::object_dispatch::v1::StartupAdmissionConsumerContextV1;
use lore_proto::lore::object_dispatch::v1::StartupSupersededProofV1;
use lore_proto::lore::object_dispatch::v1::object_store_request_v1;
use lore_proto::lore::object_dispatch::v1::object_store_result_discard_v1;
use lore_proto::lore::object_dispatch::v1::object_store_terminal_result_v1;
use lore_proto::lore::object_dispatch::v1::result_consumer_context_v1;

const LOGICAL_ID: &str = "018f3e12-a456-7abc-8def-0123456789ab";
const ATTEMPT_ID: &str = "018f3e12-a457-7abc-8def-0123456789ab";
const SCOPE: &str =
    "urn:lore:object-dispatch:Ym91bmRhcnktMQ:Y2VsbC0x:dGVuYW50LTE:job:Y29uc3VtZXItMQ";
const RECEIPT_DIGEST: [u8; 32] = [9; 32];
const COMMON_PREIMAGE_HEX: &str = concat!(
    "6f626a6563742d64697370617463682d646973636172642d763100",
    "0000000a70726f746f636f6c2d310000000a626f756e646172792d31",
    "0000000663656c6c2d310000000874656e616e742d31",
    "0000002430313866336531322d613435362d376162632d386465662d303132333435363738396162",
    "0000002430313866336531322d613435372d376162632d386465662d303132333435363738396162",
    "0000000a7465726d696e616c2d310000000000000002",
    "16162b78c20357b8ff6ad078592da2ed4194efa3f38a3f9e223d8602f1a53720",
    "00"
);

fn limits() -> ResultDiscardLimits {
    ResultDiscardLimits {
        ack: ResultAckLimits {
            identity: RequestIdentityLimits {
                max_identity_bytes: 256,
                max_authenticated_scope_bytes: 1_024,
            },
            max_terminal_result_id_bytes: 64,
            max_result_handle_bytes: 128,
            max_fingerprint_preimage_bytes: 4_096,
        },
        max_checkpoint_id_bytes: 64,
        max_operation_id_bytes: 64,
        max_revision_id_bytes: 64,
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
                reader_lease_id: None,
                reader_fence: None,
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
    let kind_text = match DurableConsumerKindV1::try_from(kind) {
        Ok(DurableConsumerKindV1::DurableConsumerKindJob) => "job",
        Ok(DurableConsumerKindV1::DurableConsumerKindOperator) => "operator",
        Ok(DurableConsumerKindV1::DurableConsumerKindMigrator) => "migrator",
        _ => "invalid",
    };
    ResultConsumerContextV1 {
        consumer: Some(result_consumer_context_v1::Consumer::DurableConsumer(
            DurableConsumerContextV1 {
                consumer_kind: kind,
                authenticated_scope: SCOPE.replace(":job:", &format!(":{kind_text}:")),
                operation_id: "job-1".to_string(),
                checkpoint_revision: 9,
                checkpoint_fence: 10,
            },
        )),
    }
}

fn fragment_operation() -> object_store_request_v1::Operation {
    object_store_request_v1::Operation::PutObject(PutObjectV1::default())
}

fn startup_operation() -> object_store_request_v1::Operation {
    object_store_request_v1::Operation::HeadBucket(HeadBucketV1::default())
}

fn durable_operation() -> object_store_request_v1::Operation {
    object_store_request_v1::Operation::ListObjectsV2(ListObjectsV2v1::default())
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

fn byte_terminal() -> lore_object_dispatch::CanonicalTerminalResult {
    validate_and_encode_terminal_result(
        &ObjectStoreTerminalResultV1 {
            terminal_result_id: "terminal-1".to_string(),
            result: Some(object_store_terminal_result_v1::Result::ByteResult(
                ByteResultHandleV1 {
                    handle: "result/body-1".to_string(),
                    size: 3,
                    blake3: RECEIPT_DIGEST.to_vec().into(),
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

fn fragment_proof(
    terminal_digest: &[u8; 32],
    kind: FragmentLifecycleSupersessionKindV1,
) -> FragmentLifecycleSupersededProofV1 {
    let mut proof = FragmentLifecycleSupersededProofV1 {
        fragment_id: vec![42; 32].into(),
        repository_id: Some("repo-1".to_string()),
        association_context: Some("main".to_string()),
        repository_generation: Some(3),
        association_epoch: Some(4),
        lifecycle_generation: 5,
        fragment_epoch: 6,
        lifecycle_fence: 7,
        reader_lease_id: None,
        reader_fence: None,
        supersession_kind: kind as i32,
        superseding_lifecycle_generation: None,
        superseding_fragment_epoch: None,
        superseding_lifecycle_fence: None,
        no_exposure_checkpoint_id: "no-exposure-1".to_string(),
        no_exposure_checkpoint_revision: 11,
        no_exposure_checkpoint_fence: 12,
        terminal_result_blake3: terminal_digest.to_vec().into(),
        successor_repository_generation: None,
        successor_association_epoch: None,
        repository_tombstone_revision: None,
    };
    match kind {
        FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindSuccessor => {
            proof.superseding_lifecycle_generation = Some(6);
            proof.superseding_fragment_epoch = Some(7);
            proof.superseding_lifecycle_fence = Some(8);
        }
        FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindRemoved => {
            proof.superseding_lifecycle_generation = Some(6);
            proof.superseding_fragment_epoch = Some(6);
            proof.superseding_lifecycle_fence = Some(8);
        }
        FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindAssociationTombstoned => {
            proof.successor_repository_generation = Some(4);
            proof.successor_association_epoch = Some(5);
        }
        FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindRepositoryTombstoned => {
            proof.repository_tombstone_revision = Some(4);
        }
        FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindUnspecified => {}
    }
    proof
}

fn startup_proof(terminal_digest: &[u8; 32]) -> StartupSupersededProofV1 {
    StartupSupersededProofV1 {
        policy_revision: "policy-1".to_string(),
        allocation_revision: "allocation-1".to_string(),
        config_revision: "config-1".to_string(),
        startup_attempt_id: "startup-1".to_string(),
        readiness_generation: 3,
        superseding_policy_revision: "policy-2".to_string(),
        superseding_allocation_revision: "allocation-2".to_string(),
        superseding_config_revision: "config-2".to_string(),
        superseding_startup_attempt_id: "startup-2".to_string(),
        superseding_readiness_generation: 4,
        no_exposure_checkpoint_id: "no-exposure-1".to_string(),
        no_exposure_checkpoint_revision: 11,
        no_exposure_checkpoint_fence: 12,
        terminal_result_blake3: terminal_digest.to_vec().into(),
    }
}

fn durable_proof(
    terminal_digest: &[u8; 32],
    cancellation: DurableConsumerCancellationKindV1,
) -> DurableConsumerCancelledProofV1 {
    DurableConsumerCancelledProofV1 {
        consumer_kind: DurableConsumerKindV1::DurableConsumerKindJob as i32,
        authenticated_scope: SCOPE.to_string(),
        operation_id: "job-1".to_string(),
        checkpoint_revision: 9,
        checkpoint_fence: 10,
        cancellation_kind: cancellation as i32,
        disposition_checkpoint_id: "disposition-1".to_string(),
        disposition_checkpoint_revision: 10,
        disposition_checkpoint_fence: 10,
        superseding_operation_id: (cancellation
            == DurableConsumerCancellationKindV1::DurableConsumerCancellationKindSuperseded)
            .then(|| "job-2".to_string()),
        no_exposure_checkpoint_id: "no-exposure-1".to_string(),
        no_exposure_checkpoint_revision: 10,
        no_exposure_checkpoint_fence: 10,
        terminal_result_blake3: terminal_digest.to_vec().into(),
    }
}

fn discard(
    terminal: &lore_object_dispatch::CanonicalTerminalResult,
    proof: object_store_result_discard_v1::Proof,
) -> ObjectStoreResultDiscardV1 {
    let byte_result_handle = match terminal.result().result.as_ref() {
        Some(object_store_terminal_result_v1::Result::ByteResult(value)) => {
            Some(value.handle.clone())
        }
        _ => None,
    };
    ObjectStoreResultDiscardV1 {
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
        proof: Some(proof),
    }
}

fn validate(
    operation: &object_store_request_v1::Operation,
    context: &ResultConsumerContextV1,
    terminal: &lore_object_dispatch::CanonicalTerminalResult,
    input: &ObjectStoreResultDiscardV1,
    policy: &ResultDiscardLimits,
) -> Result<lore_object_dispatch::ValidatedObjectStoreResultDiscard, ResultDiscardError> {
    let identity = identity();
    validate_object_store_result_discard(
        input,
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

fn full_preimage(proof_hex: &str) -> Vec<u8> {
    decode_hex(&format!("{COMMON_PREIMAGE_HEX}{proof_hex}"))
}

#[test]
fn every_proof_arm_pins_an_independent_full_preimage_and_digest() {
    let terminal = bool_terminal();
    let cases = [
        (
            fragment_operation(),
            fragment_context(),
            object_store_result_discard_v1::Proof::FragmentLifecycleSuperseded(fragment_proof(
                terminal.canonical_result_blake3(),
                FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindSuccessor,
            )),
            concat!(
                "00000014",
                "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a",
                "01000000067265706f2d3101000000046d61696e",
                "010000000000000003010000000000000004",
                "0000000000000005000000000000000600000000000000070000",
                "00000001",
                "010000000000000006010000000000000007010000000000000008",
                "0000000d6e6f2d6578706f737572652d31",
                "000000000000000b000000000000000c",
                "16162b78c20357b8ff6ad078592da2ed4194efa3f38a3f9e223d8602f1a53720",
                "000000"
            ),
            411,
            "0070b5a2d4e75e8e3826785230e22f7b6e1aff3ee5d0084d13ed5a5e42625fcd",
        ),
        (
            fragment_operation(),
            fragment_context(),
            object_store_result_discard_v1::Proof::FragmentLifecycleSuperseded(fragment_proof(
                terminal.canonical_result_blake3(),
                FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindRemoved,
            )),
            concat!(
                "00000014",
                "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a",
                "01000000067265706f2d3101000000046d61696e",
                "010000000000000003010000000000000004",
                "0000000000000005000000000000000600000000000000070000",
                "00000002",
                "010000000000000006010000000000000006010000000000000008",
                "0000000d6e6f2d6578706f737572652d31",
                "000000000000000b000000000000000c",
                "16162b78c20357b8ff6ad078592da2ed4194efa3f38a3f9e223d8602f1a53720",
                "000000"
            ),
            411,
            "880dc5d8c0bf2ad3dd6bed06a9c3657049db92f9cfc0ddb56b8d7b1e3df4bc01",
        ),
        (
            fragment_operation(),
            fragment_context(),
            object_store_result_discard_v1::Proof::FragmentLifecycleSuperseded(fragment_proof(
                terminal.canonical_result_blake3(),
                FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindAssociationTombstoned,
            )),
            concat!(
                "00000014",
                "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a",
                "01000000067265706f2d3101000000046d61696e",
                "010000000000000003010000000000000004",
                "0000000000000005000000000000000600000000000000070000",
                "00000003000000",
                "0000000d6e6f2d6578706f737572652d31",
                "000000000000000b000000000000000c",
                "16162b78c20357b8ff6ad078592da2ed4194efa3f38a3f9e223d8602f1a53720",
                "01000000000000000401000000000000000500"
            ),
            403,
            "69f16d732d57017c00897ebdd9218e1a282132a6ae364e1b22cfa6db8a03eca5",
        ),
        (
            fragment_operation(),
            fragment_context(),
            object_store_result_discard_v1::Proof::FragmentLifecycleSuperseded(fragment_proof(
                terminal.canonical_result_blake3(),
                FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindRepositoryTombstoned,
            )),
            concat!(
                "00000014",
                "2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a",
                "01000000067265706f2d3101000000046d61696e",
                "010000000000000003010000000000000004",
                "0000000000000005000000000000000600000000000000070000",
                "00000004000000",
                "0000000d6e6f2d6578706f737572652d31",
                "000000000000000b000000000000000c",
                "16162b78c20357b8ff6ad078592da2ed4194efa3f38a3f9e223d8602f1a53720",
                "0000010000000000000004"
            ),
            395,
            "15ea5fd1466cab1198e1fb0ea7043a4e67249311ba25fb8c1f4a31a6ba15a7ca",
        ),
        (
            startup_operation(),
            startup_context(),
            object_store_result_discard_v1::Proof::StartupSuperseded(startup_proof(
                terminal.canonical_result_blake3(),
            )),
            concat!(
                "00000015",
                "00000008706f6c6963792d310000000c616c6c6f636174696f6e2d31",
                "00000008636f6e6669672d3100000009737461727475702d31",
                "0000000000000003",
                "00000008706f6c6963792d320000000c616c6c6f636174696f6e2d32",
                "00000008636f6e6669672d3200000009737461727475702d32",
                "0000000000000004",
                "0000000d6e6f2d6578706f737572652d31",
                "000000000000000b000000000000000c",
                "16162b78c20357b8ff6ad078592da2ed4194efa3f38a3f9e223d8602f1a53720"
            ),
            403,
            "d6cee5774821fc943455e3fa283eab6a24ff22fb7efd1e16802154816d9685cd",
        ),
        (
            durable_operation(),
            durable_context(DurableConsumerKindV1::DurableConsumerKindJob as i32),
            object_store_result_discard_v1::Proof::DurableConsumerCancelled(durable_proof(
                terminal.canonical_result_blake3(),
                DurableConsumerCancellationKindV1::DurableConsumerCancellationKindCancelled,
            )),
            concat!(
                "00000016",
                "00000001",
                "0000004f",
                "75726e3a6c6f72653a6f626a6563742d64697370617463683a596d3931626d5268636e6b744d513a",
                "59325673624330783a64475675595735304c54453a6a6f623a59323975633356745a5849744d51",
                "000000056a6f622d31",
                "0000000000000009000000000000000a00000001",
                "0000000d646973706f736974696f6e2d31",
                "000000000000000a000000000000000a00",
                "0000000d6e6f2d6578706f737572652d31",
                "000000000000000a000000000000000a",
                "16162b78c20357b8ff6ad078592da2ed4194efa3f38a3f9e223d8602f1a53720"
            ),
            431,
            "3922270d8a7417369e1dc32e45fd5711a08f437169f5ea5711e6cb8d3fef380d",
        ),
        (
            durable_operation(),
            durable_context(DurableConsumerKindV1::DurableConsumerKindJob as i32),
            object_store_result_discard_v1::Proof::DurableConsumerCancelled(durable_proof(
                terminal.canonical_result_blake3(),
                DurableConsumerCancellationKindV1::DurableConsumerCancellationKindSuperseded,
            )),
            concat!(
                "00000016",
                "00000001",
                "0000004f",
                "75726e3a6c6f72653a6f626a6563742d64697370617463683a596d3931626d5268636e6b744d513a",
                "59325673624330783a64475675595735304c54453a6a6f623a59323975633356745a5849744d51",
                "000000056a6f622d31",
                "0000000000000009000000000000000a00000002",
                "0000000d646973706f736974696f6e2d31",
                "000000000000000a000000000000000a",
                "01000000056a6f622d32",
                "0000000d6e6f2d6578706f737572652d31",
                "000000000000000a000000000000000a",
                "16162b78c20357b8ff6ad078592da2ed4194efa3f38a3f9e223d8602f1a53720"
            ),
            440,
            "721194568e16b29ca0f45fe567452c28509e4bc734b4b5ff5d207919d6463e46",
        ),
    ];

    for (operation, context, proof, proof_hex, size, fingerprint) in cases {
        let input = discard(&terminal, proof);
        let validated = validate(&operation, &context, &terminal, &input, &limits())
            .expect("proof arm must validate");
        assert_eq!(
            validated.canonical_discard_bytes(),
            full_preimage(proof_hex)
        );
        assert_eq!(validated.canonical_discard_bytes().len(), size);
        assert_eq!(
            validated.discard_fingerprint(),
            decode_hex(fingerprint).as_slice()
        );
    }
}

#[test]
fn fragment_accepts_exactly_the_four_closed_supersession_forms() {
    let terminal = bool_terminal();
    let operation = fragment_operation();
    let context = fragment_context();
    for kind in [
        FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindSuccessor,
        FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindRemoved,
        FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindAssociationTombstoned,
        FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindRepositoryTombstoned,
    ] {
        let input = discard(
            &terminal,
            object_store_result_discard_v1::Proof::FragmentLifecycleSuperseded(fragment_proof(
                terminal.canonical_result_blake3(),
                kind,
            )),
        );
        assert!(validate(&operation, &context, &terminal, &input, &limits()).is_ok());
    }

    for raw in [0, 5, 99] {
        let mut proof = fragment_proof(
            terminal.canonical_result_blake3(),
            FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindSuccessor,
        );
        proof.supersession_kind = raw;
        let input = discard(
            &terminal,
            object_store_result_discard_v1::Proof::FragmentLifecycleSuperseded(proof),
        );
        assert_eq!(
            validate(&operation, &context, &terminal, &input, &limits()),
            Err(ResultDiscardError::InvalidProof)
        );
    }
}

#[test]
fn physical_successor_and_removed_algebra_is_strict_and_shape_closed() {
    let terminal = bool_terminal();
    let operation = fragment_operation();
    let context = fragment_context();
    let base = fragment_proof(
        terminal.canonical_result_blake3(),
        FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindSuccessor,
    );
    let mut invalid = Vec::new();
    macro_rules! mutate {
        ($field:ident, $value:expr) => {{
            let mut candidate = base.clone();
            candidate.$field = $value;
            invalid.push(candidate);
        }};
    }
    mutate!(superseding_lifecycle_generation, Some(5));
    mutate!(superseding_fragment_epoch, Some(6));
    mutate!(superseding_lifecycle_fence, Some(7));
    mutate!(superseding_lifecycle_generation, None);
    mutate!(successor_repository_generation, Some(4));
    mutate!(successor_association_epoch, Some(5));
    mutate!(repository_tombstone_revision, Some(4));
    assert!(invalid.into_iter().all(|proof| {
        let input = discard(
            &terminal,
            object_store_result_discard_v1::Proof::FragmentLifecycleSuperseded(proof),
        );
        validate(&operation, &context, &terminal, &input, &limits())
            == Err(ResultDiscardError::InvalidProof)
    }));

    let removed = fragment_proof(
        terminal.canonical_result_blake3(),
        FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindRemoved,
    );
    let input = discard(
        &terminal,
        object_store_result_discard_v1::Proof::FragmentLifecycleSuperseded(removed),
    );
    assert!(validate(&operation, &context, &terminal, &input, &limits()).is_ok());
}

#[test]
fn association_and_repository_tombstone_algebra_rejects_incomplete_or_mixed_evidence() {
    let terminal = bool_terminal();
    let operation = fragment_operation();
    let context = fragment_context();
    let association = fragment_proof(
        terminal.canonical_result_blake3(),
        FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindAssociationTombstoned,
    );
    let mut association_invalid = Vec::new();
    for (repository, epoch, tombstone) in [
        (None, Some(5), None),
        (Some(4), None, None),
        (Some(3), Some(5), None),
        (Some(4), Some(4), None),
        (Some(4), Some(5), Some(9)),
    ] {
        let mut proof = association.clone();
        proof.successor_repository_generation = repository;
        proof.successor_association_epoch = epoch;
        proof.repository_tombstone_revision = tombstone;
        association_invalid.push(proof);
    }

    let repository = fragment_proof(
        terminal.canonical_result_blake3(),
        FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindRepositoryTombstoned,
    );
    let mut repository_invalid = Vec::new();
    for (revision, successor_repository, successor_epoch) in [
        (None, None, None),
        (Some(3), None, None),
        (Some(4), Some(9), None),
        (Some(4), None, Some(9)),
    ] {
        let mut proof = repository.clone();
        proof.repository_tombstone_revision = revision;
        proof.successor_repository_generation = successor_repository;
        proof.successor_association_epoch = successor_epoch;
        repository_invalid.push(proof);
    }

    assert!(
        association_invalid
            .into_iter()
            .chain(repository_invalid)
            .all(|proof| {
                let input = discard(
                    &terminal,
                    object_store_result_discard_v1::Proof::FragmentLifecycleSuperseded(proof),
                );
                validate(&operation, &context, &terminal, &input, &limits())
                    == Err(ResultDiscardError::InvalidProof)
            })
    );
}

#[test]
fn fragment_proof_binds_context_no_exposure_and_terminal_digest_fields() {
    let terminal = bool_terminal();
    let operation = fragment_operation();
    let context = fragment_context();
    let base = fragment_proof(
        terminal.canonical_result_blake3(),
        FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindSuccessor,
    );
    let mut invalid = Vec::new();
    macro_rules! mutate {
        ($field:ident, $value:expr) => {{
            let mut candidate = base.clone();
            candidate.$field = $value;
            invalid.push(candidate);
        }};
    }
    mutate!(fragment_id, vec![0; 32].into());
    mutate!(repository_id, None);
    mutate!(association_context, Some("other".to_string()));
    mutate!(repository_generation, Some(4));
    mutate!(association_epoch, Some(5));
    mutate!(lifecycle_generation, 6);
    mutate!(fragment_epoch, 7);
    mutate!(lifecycle_fence, 8);
    mutate!(reader_lease_id, Some("reader".to_string()));
    mutate!(reader_fence, Some(8));
    mutate!(no_exposure_checkpoint_id, String::new());
    mutate!(no_exposure_checkpoint_revision, 0);
    mutate!(no_exposure_checkpoint_fence, 0);
    mutate!(terminal_result_blake3, vec![0; 32].into());
    mutate!(terminal_result_blake3, vec![0; 31].into());
    assert!(invalid.into_iter().all(|proof| {
        let input = discard(
            &terminal,
            object_store_result_discard_v1::Proof::FragmentLifecycleSuperseded(proof),
        );
        validate(&operation, &context, &terminal, &input, &limits()).is_err()
    }));
}

#[test]
fn startup_requires_exact_context_distinct_successor_and_advanced_generation() {
    let terminal = bool_terminal();
    let operation = startup_operation();
    let context = startup_context();
    let base = startup_proof(terminal.canonical_result_blake3());
    let mut invalid = Vec::new();
    macro_rules! mutate {
        ($field:ident, $value:expr) => {{
            let mut candidate = base.clone();
            candidate.$field = $value;
            invalid.push(candidate);
        }};
    }
    mutate!(policy_revision, "policy-x".to_string());
    mutate!(allocation_revision, "allocation-x".to_string());
    mutate!(config_revision, "config-x".to_string());
    mutate!(startup_attempt_id, "startup-x".to_string());
    mutate!(readiness_generation, 4);
    mutate!(superseding_policy_revision, String::new());
    mutate!(superseding_allocation_revision, String::new());
    mutate!(superseding_config_revision, String::new());
    mutate!(superseding_startup_attempt_id, "startup-1".to_string());
    mutate!(superseding_readiness_generation, 3);
    mutate!(no_exposure_checkpoint_id, String::new());
    mutate!(no_exposure_checkpoint_revision, 0);
    mutate!(no_exposure_checkpoint_fence, 0);
    mutate!(terminal_result_blake3, vec![0; 32].into());
    assert!(invalid.into_iter().all(|proof| {
        let input = discard(
            &terminal,
            object_store_result_discard_v1::Proof::StartupSuperseded(proof),
        );
        validate(&operation, &context, &terminal, &input, &limits()).is_err()
    }));
}

#[test]
fn durable_cancellation_algebra_and_closed_enums_fail_closed() {
    let terminal = bool_terminal();
    let operation = durable_operation();
    let context = durable_context(DurableConsumerKindV1::DurableConsumerKindJob as i32);
    for cancellation in [
        DurableConsumerCancellationKindV1::DurableConsumerCancellationKindCancelled,
        DurableConsumerCancellationKindV1::DurableConsumerCancellationKindSuperseded,
    ] {
        let input = discard(
            &terminal,
            object_store_result_discard_v1::Proof::DurableConsumerCancelled(durable_proof(
                terminal.canonical_result_blake3(),
                cancellation,
            )),
        );
        assert!(validate(&operation, &context, &terminal, &input, &limits()).is_ok());
    }

    for (kind, kind_text) in [
        (DurableConsumerKindV1::DurableConsumerKindJob, "job"),
        (
            DurableConsumerKindV1::DurableConsumerKindOperator,
            "operator",
        ),
        (
            DurableConsumerKindV1::DurableConsumerKindMigrator,
            "migrator",
        ),
    ] {
        let context = durable_context(kind as i32);
        let mut proof = durable_proof(
            terminal.canonical_result_blake3(),
            DurableConsumerCancellationKindV1::DurableConsumerCancellationKindCancelled,
        );
        proof.consumer_kind = kind as i32;
        proof.authenticated_scope = SCOPE.replace(":job:", &format!(":{kind_text}:"));
        let input = discard(
            &terminal,
            object_store_result_discard_v1::Proof::DurableConsumerCancelled(proof),
        );
        assert!(validate(&operation, &context, &terminal, &input, &limits()).is_ok());
    }

    let base = durable_proof(
        terminal.canonical_result_blake3(),
        DurableConsumerCancellationKindV1::DurableConsumerCancellationKindCancelled,
    );
    let mut invalid = Vec::new();
    macro_rules! mutate {
        ($field:ident, $value:expr) => {{
            let mut candidate = base.clone();
            candidate.$field = $value;
            invalid.push(candidate);
        }};
    }
    mutate!(consumer_kind, 0);
    mutate!(consumer_kind, 4);
    mutate!(authenticated_scope, "urn:lore:other".to_string());
    mutate!(operation_id, "job-x".to_string());
    mutate!(checkpoint_revision, 10);
    mutate!(checkpoint_fence, 11);
    mutate!(cancellation_kind, 0);
    mutate!(cancellation_kind, 3);
    mutate!(disposition_checkpoint_id, String::new());
    mutate!(disposition_checkpoint_revision, 9);
    mutate!(disposition_checkpoint_fence, 9);
    mutate!(superseding_operation_id, Some("job-2".to_string()));
    mutate!(no_exposure_checkpoint_id, String::new());
    mutate!(no_exposure_checkpoint_revision, 9);
    mutate!(no_exposure_checkpoint_fence, 9);
    mutate!(terminal_result_blake3, vec![0; 32].into());
    assert!(invalid.into_iter().all(|proof| {
        let input = discard(
            &terminal,
            object_store_result_discard_v1::Proof::DurableConsumerCancelled(proof),
        );
        validate(&operation, &context, &terminal, &input, &limits()).is_err()
    }));

    let superseded = durable_proof(
        terminal.canonical_result_blake3(),
        DurableConsumerCancellationKindV1::DurableConsumerCancellationKindSuperseded,
    );
    for successor in [None, Some("job-1".to_string())] {
        let mut proof = superseded.clone();
        proof.superseding_operation_id = successor;
        let input = discard(
            &terminal,
            object_store_result_discard_v1::Proof::DurableConsumerCancelled(proof),
        );
        assert_eq!(
            validate(&operation, &context, &terminal, &input, &limits()),
            Err(ResultDiscardError::InvalidProof)
        );
    }
}

#[test]
fn proof_arm_consumer_context_and_outer_terminal_tuple_are_exact() {
    let terminal = bool_terminal();
    let operation = fragment_operation();
    let context = fragment_context();
    let proof = fragment_proof(
        terminal.canonical_result_blake3(),
        FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindSuccessor,
    );
    let base = discard(
        &terminal,
        object_store_result_discard_v1::Proof::FragmentLifecycleSuperseded(proof),
    );
    let mut missing = base.clone();
    missing.proof = None;
    assert_eq!(
        validate(&operation, &context, &terminal, &missing, &limits()),
        Err(ResultDiscardError::InvalidProof)
    );
    let mut wrong_arm = base.clone();
    wrong_arm.proof = Some(object_store_result_discard_v1::Proof::StartupSuperseded(
        startup_proof(terminal.canonical_result_blake3()),
    ));
    assert_eq!(
        validate(&operation, &context, &terminal, &wrong_arm, &limits()),
        Err(ResultDiscardError::InvalidProof)
    );

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
    mutate!(
        byte_result_handle,
        Some("forbidden-inline-handle".to_string())
    );
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

    let malformed = durable_context(4);
    let malformed_input = discard(
        &terminal,
        object_store_result_discard_v1::Proof::DurableConsumerCancelled(durable_proof(
            terminal.canonical_result_blake3(),
            DurableConsumerCancellationKindV1::DurableConsumerCancellationKindCancelled,
        )),
    );
    assert_eq!(
        validate(
            &durable_operation(),
            &malformed,
            &terminal,
            &malformed_input,
            &limits()
        ),
        Err(ResultDiscardError::InvalidConsumerContext)
    );
}

#[test]
fn byte_result_handle_is_required_exactly_for_byte_terminal_results() {
    let terminal = byte_terminal();
    let operation = fragment_operation();
    let context = fragment_context();
    let proof = fragment_proof(
        terminal.canonical_result_blake3(),
        FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindSuccessor,
    );
    let valid = discard(
        &terminal,
        object_store_result_discard_v1::Proof::FragmentLifecycleSuperseded(proof),
    );
    assert!(validate(&operation, &context, &terminal, &valid, &limits()).is_ok());
    for handle in [None, Some("result/other".to_string())] {
        let mut invalid = valid.clone();
        invalid.byte_result_handle = handle;
        assert_eq!(
            validate(&operation, &context, &terminal, &invalid, &limits()),
            Err(ResultDiscardError::InvalidByteResultHandle)
        );
    }
}

#[test]
fn checkpoint_operation_revision_and_scope_bounds_are_inclusive() {
    let terminal = bool_terminal();

    let fragment_context = fragment_context();
    let fragment_input = discard(
        &terminal,
        object_store_result_discard_v1::Proof::FragmentLifecycleSuperseded(fragment_proof(
            terminal.canonical_result_blake3(),
            FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindSuccessor,
        )),
    );
    let mut fragment_exact = limits();
    fragment_exact.max_checkpoint_id_bytes = 13;
    assert!(
        validate(
            &fragment_operation(),
            &fragment_context,
            &terminal,
            &fragment_input,
            &fragment_exact,
        )
        .is_ok()
    );
    fragment_exact.max_checkpoint_id_bytes = 12;
    assert!(
        validate(
            &fragment_operation(),
            &fragment_context,
            &terminal,
            &fragment_input,
            &fragment_exact,
        )
        .is_err()
    );

    let startup_context = startup_context();
    let startup_input = discard(
        &terminal,
        object_store_result_discard_v1::Proof::StartupSuperseded(startup_proof(
            terminal.canonical_result_blake3(),
        )),
    );
    let mut startup_exact = limits();
    startup_exact.max_revision_id_bytes = 12;
    assert!(
        validate(
            &startup_operation(),
            &startup_context,
            &terminal,
            &startup_input,
            &startup_exact,
        )
        .is_ok()
    );
    startup_exact.max_revision_id_bytes = 11;
    assert!(
        validate(
            &startup_operation(),
            &startup_context,
            &terminal,
            &startup_input,
            &startup_exact,
        )
        .is_err()
    );

    let durable_context = durable_context(DurableConsumerKindV1::DurableConsumerKindJob as i32);
    let durable_input = discard(
        &terminal,
        object_store_result_discard_v1::Proof::DurableConsumerCancelled(durable_proof(
            terminal.canonical_result_blake3(),
            DurableConsumerCancellationKindV1::DurableConsumerCancellationKindCancelled,
        )),
    );
    let mut durable_exact = limits();
    durable_exact.max_checkpoint_id_bytes = 13;
    durable_exact.max_operation_id_bytes = 5;
    durable_exact.ack.identity.max_authenticated_scope_bytes = 79;
    assert!(
        validate(
            &durable_operation(),
            &durable_context,
            &terminal,
            &durable_input,
            &durable_exact,
        )
        .is_ok()
    );
    durable_exact.max_operation_id_bytes = 4;
    assert!(
        validate(
            &durable_operation(),
            &durable_context,
            &terminal,
            &durable_input,
            &durable_exact,
        )
        .is_err()
    );
    durable_exact.max_operation_id_bytes = 5;
    durable_exact.ack.identity.max_authenticated_scope_bytes = 78;
    assert!(
        validate(
            &durable_operation(),
            &durable_context,
            &terminal,
            &durable_input,
            &durable_exact,
        )
        .is_err()
    );
}

#[test]
fn uuid_limits_preimage_bound_and_debug_redaction_are_closed_and_deterministic() {
    let terminal = bool_terminal();
    let operation = fragment_operation();
    let context = fragment_context();
    let proof = fragment_proof(
        terminal.canonical_result_blake3(),
        FragmentLifecycleSupersessionKindV1::FragmentLifecycleSupersessionKindSuccessor,
    );
    let input = discard(
        &terminal,
        object_store_result_discard_v1::Proof::FragmentLifecycleSuperseded(proof),
    );
    let original = input.clone();
    let first = validate(&operation, &context, &terminal, &input, &limits()).expect("valid");
    let second =
        validate(&operation, &context, &terminal, &input, &limits()).expect("valid replay");
    assert_eq!(first, second);
    assert_eq!(input, original);
    let debug = format!("{first:?}");
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("terminal-1"));
    assert!(!debug.contains("no-exposure-1"));
    assert!(!debug.contains("0070b5a2d4e75e8e"));

    let size = first.canonical_discard_bytes().len() as u32;
    let mut exact = limits();
    exact.ack.max_fingerprint_preimage_bytes = size;
    assert!(validate(&operation, &context, &terminal, &input, &exact).is_ok());
    exact.ack.max_fingerprint_preimage_bytes -= 1;
    assert_eq!(
        validate(&operation, &context, &terminal, &input, &exact),
        Err(ResultDiscardError::PreimageTooLarge)
    );

    for field in 0..8 {
        let mut invalid = limits();
        match field {
            0 => invalid.ack.identity.max_identity_bytes = 0,
            1 => invalid.ack.identity.max_authenticated_scope_bytes = 0,
            2 => invalid.ack.max_terminal_result_id_bytes = 0,
            3 => invalid.ack.max_result_handle_bytes = 0,
            4 => invalid.ack.max_fingerprint_preimage_bytes = 0,
            5 => invalid.max_checkpoint_id_bytes = 0,
            6 => invalid.max_operation_id_bytes = 0,
            7 => invalid.max_revision_id_bytes = 0,
            _ => unreachable!(),
        }
        assert_eq!(
            validate(&operation, &context, &terminal, &input, &invalid),
            Err(ResultDiscardError::InvalidLimits)
        );
    }

    let mut invalid_uuid = input.clone();
    invalid_uuid.logical_request_id = "not-a-uuid".to_string();
    let identity = identity();
    assert_eq!(
        validate_object_store_result_discard(
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
        ),
        Err(ResultDiscardError::InvalidUuidV7)
    );
}

#[test]
fn discard_receipt_preserves_presence_detaches_digest_and_checks_time_ordering() {
    let mut fingerprint = RECEIPT_DIGEST.to_vec();
    let receipt = build_object_store_result_discard_receipt(
        &ResultDiscardReceiptInput {
            terminal_result_id: "terminal-1",
            discard_fingerprint: &fingerprint,
            discarded_at_unix_ms: 10,
            payload_purge_after_unix_ms: Some(11),
        },
        &limits(),
    )
    .expect("valid receipt");
    fingerprint[0] = 0xff;
    assert_eq!(
        receipt.state,
        ObjectStoreResultDiscardStateV1::ObjectStoreResultDiscardStateDiscarded as i32
    );
    assert_eq!(receipt.discard_fingerprint.as_ref(), RECEIPT_DIGEST);
    assert_eq!(receipt.discarded_at_unix_ms, 10);
    assert_eq!(receipt.payload_purge_after_unix_ms, Some(11));

    let absent = build_object_store_result_discard_receipt(
        &ResultDiscardReceiptInput {
            terminal_result_id: "terminal-1",
            discard_fingerprint: &RECEIPT_DIGEST,
            discarded_at_unix_ms: i64::MAX,
            payload_purge_after_unix_ms: None,
        },
        &limits(),
    )
    .expect("i64 maximum and absent purge are valid");
    assert_eq!(absent.payload_purge_after_unix_ms, None);

    let short = [0_u8; 31];
    for invalid in [
        ResultDiscardReceiptInput {
            terminal_result_id: "terminal-1",
            discard_fingerprint: &short,
            discarded_at_unix_ms: 0,
            payload_purge_after_unix_ms: None,
        },
        ResultDiscardReceiptInput {
            terminal_result_id: "terminal-1",
            discard_fingerprint: &RECEIPT_DIGEST,
            discarded_at_unix_ms: -1,
            payload_purge_after_unix_ms: None,
        },
        ResultDiscardReceiptInput {
            terminal_result_id: "terminal-1",
            discard_fingerprint: &RECEIPT_DIGEST,
            discarded_at_unix_ms: 10,
            payload_purge_after_unix_ms: Some(9),
        },
    ] {
        assert_eq!(
            build_object_store_result_discard_receipt(&invalid, &limits()),
            Err(ResultDiscardError::InvalidReceipt)
        );
    }
}

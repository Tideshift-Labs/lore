// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_base::types::Context;
use lore_base::types::FRAGMENT_SIZE_THRESHOLD;
use lore_revision::fragment;
use lore_server::protocol::replication_store::header::ReplicationHeader;
use lore_server::protocol::replication_store::put::*;
use lore_server::protocol::storage::messages::MessageParseError;
use lore_server::quic::replication_store_service::MAX_CHUNK_SIZE;
use lore_server::quic::tests::collapse_bytes_without_header;
use lore_transport::quic::command_header::CommandHeader;
use rand::random;
use uuid::Uuid;

#[test]
fn is_under_max_chunk_size() {
    // base request plus max payload size
    let max_request_size = BASE_REQUEST_SIZE + FRAGMENT_SIZE_THRESHOLD;
    assert!(max_request_size + size_of::<CommandHeader>() <= MAX_CHUNK_SIZE);
}

#[test]
fn parsing_without_payload_works() {
    let repository = random::<Context>();
    let (fragment, address, _) = fragment::generate_random();

    let input = Put {
        header: ReplicationHeader {
            correlation_id: Uuid::new_v4(),
            repository,
        },
        address,
        fragment,
        flags: 0,
        payload: None,
    };
    let input_bytes = collapse_bytes_without_header(&input.clone().to_quic_chunks());
    let output = parse(input_bytes).expect("parse should work");

    assert_eq!(input, output);
}

#[test]
fn parsing_with_payload_works() {
    let repository = random::<Context>();
    let (fragment, address, payload) = fragment::generate_random();

    let input = Put {
        header: ReplicationHeader {
            correlation_id: Uuid::new_v4(),
            repository,
        },
        address,
        fragment,
        flags: 1,
        payload: Some(payload),
    };
    let input_bytes = collapse_bytes_without_header(&input.clone().to_quic_chunks());
    let output = parse(input_bytes).expect("parse should work");

    assert_eq!(input, output);
}

#[test]
fn parsing_fails_if_too_small() {
    let repository = random::<Context>();
    let (fragment, address, _) = fragment::generate_random();

    let input = Put {
        header: ReplicationHeader {
            correlation_id: Uuid::new_v4(),
            repository,
        },
        address,
        fragment,
        flags: 0,
        payload: None,
    };
    let input_bytes = collapse_bytes_without_header(&input.to_quic_chunks());
    let output = parse(input_bytes.slice(0..input_bytes.len() - 1)).expect_err("parse should fail");

    assert_eq!(output, MessageParseError::InvalidFieldLength);
}

#[test]
fn set_flags_are_parsed() {
    let input = PutFlags { force: true };
    let data: u8 = input.clone().into();
    let output: PutFlags = data.into();

    assert_eq!(input, output);
}

#[test]
fn no_flags_are_parsed() {
    let input = PutFlags { force: false };
    let data: u8 = input.clone().into();
    let output: PutFlags = data.into();

    assert_eq!(input, output);
}

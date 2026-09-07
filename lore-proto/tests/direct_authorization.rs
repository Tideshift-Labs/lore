// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use lore_proto::rebac::AuthorizeDirectRepositoryOperationResponse;
use prost::Message;

#[test]
fn direct_authorization_repository_echo_uses_bytes_tag_fourteen() {
    let response = AuthorizeDirectRepositoryOperationResponse {
        repository_id: vec![0x33; 16].into(),
        ..Default::default()
    };
    let mut expected = vec![0x72, 0x10]; // field 14, wire type 2, length 16
    expected.extend_from_slice(&[0x33; 16]);
    assert_eq!(response.encode_to_vec(), expected);
    assert_eq!(
        AuthorizeDirectRepositoryOperationResponse::decode(expected.as_slice()).unwrap(),
        response
    );
}

#[test]
fn old_direct_authorization_response_decodes_with_no_repository_evidence() {
    let response = AuthorizeDirectRepositoryOperationResponse::decode(&[][..]).unwrap();
    assert!(response.repository_id.is_empty());
}

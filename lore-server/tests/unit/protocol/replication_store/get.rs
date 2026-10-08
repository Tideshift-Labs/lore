// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
use lore_base::types::Address;
use lore_base::types::Context;
use lore_revision::fragment;
use lore_server::protocol::replication_store::get::*;
use lore_server::protocol::replication_store::header::ReplicationHeader;
use lore_server::protocol::storage::messages::MessageParseError;
use lore_server::quic::tests::collapse_bytes;
use lore_server::quic::tests::collapse_bytes_without_header;
use lore_storage::StoreGetData;
use lore_storage::StoreMatch;
use rand::random;
use uuid::Uuid;

mod request {
    use super::*;

    #[test]
    fn parsing_works() {
        let repository = random::<Context>();
        let (_, address, _) = fragment::generate_random();

        let input = Get {
            header: ReplicationHeader {
                correlation_id: Uuid::new_v4(),
                repository,
            },
            address,
        };
        let input_bytes = collapse_bytes_without_header(&input.clone().to_quic_chunks());

        let output = Get::parse(input_bytes).expect("parse should work");
        assert_eq!(input, output);
    }

    #[test]
    fn parsing_fails_if_too_small() {
        let repository = random::<Context>();

        let input = Get {
            header: ReplicationHeader {
                correlation_id: Uuid::new_v4(),
                repository,
            },
            address: Address::default(),
        };
        let input_bytes = collapse_bytes_without_header(&input.to_quic_chunks());

        let output =
            Get::parse(input_bytes.slice(0..input_bytes.len() - 1)).expect_err("parse should fail");
        assert_eq!(output, MessageParseError::InvalidFieldLength);
    }
}

mod response {
    use super::*;

    #[test]
    fn serialize_response_has_four_chunks() {
        let (fragment, _, payload) = fragment::generate_random();
        let data = StoreGetData {
            fragment,
            match_made: StoreMatch::MatchFull,
            partition: random::<lore_base::types::Partition>(),
            payload: Some(payload),
        };
        assert_eq!(serialize_response(data).len(), 4);
    }

    #[test]
    fn response_roundtrips() {
        let (fragment, _, payload) = fragment::generate_random();
        let original = StoreGetData {
            fragment,
            match_made: StoreMatch::MatchFull,
            partition: random::<lore_base::types::Partition>(),
            payload: Some(payload),
        };
        let bytes = serialize_response(original.clone());
        let reparsed = parse_response(collapse_bytes(&bytes)).expect("parse should work");
        assert_eq!(reparsed.fragment, original.fragment);
        assert_eq!(reparsed.match_made, original.match_made);
        assert_eq!(reparsed.partition, original.partition);
        assert_eq!(reparsed.payload, original.payload);
    }
}

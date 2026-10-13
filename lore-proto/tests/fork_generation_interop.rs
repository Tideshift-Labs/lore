// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Wire interop for the WP-120 fork-local generation fields.
//!
//! Each upstream message gained one optional field at tag 1001. The `old` module
//! holds hand-copied definitions identical to the pre-change generated structs
//! (`git show HEAD:lore-proto/src/grpc/<file>.rs`), standing in for a peer that
//! predates the field. The tests prove new-to-old decode, old-to-new decode,
//! new-to-new round trip, and that the field is encoded under tag 1001.

use lore_proto::lock::Lock;
use lore_proto::lock::LockNamespaceGeneration;
use lore_proto::lock::QueryResponse;
use lore_proto::lore::model::v1::Branch;
use lore_proto::lore::model::v1::Repository;
use lore_proto::lore::repository::v1::RepositoryGetResponse;
use lore_proto::lore::revision::v1::BranchGetResponse;
use prost::Message;

/// Pre-change shapes of the three responses.
mod old {
    use lore_proto::lock::Lock;
    use lore_proto::lore::model::v1::Branch;
    use lore_proto::lore::model::v1::Repository;

    #[derive(Clone, PartialEq, Eq, Hash, ::prost::Message)]
    pub struct RepositoryGetResponse {
        #[prost(message, optional, tag = "1")]
        pub repository: ::core::option::Option<Repository>,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct BranchGetResponse {
        #[prost(message, optional, tag = "1")]
        pub branch: ::core::option::Option<Branch>,
    }

    #[derive(Clone, PartialEq, ::prost::Message)]
    pub struct QueryResponse {
        #[prost(message, repeated, tag = "1")]
        pub result: ::prost::alloc::vec::Vec<Lock>,
    }
}

/// Field key for tag 1001 with wire type 0 (varint): (1001 << 3) | 0 = 8008.
const KEY_1001_VARINT: [u8; 2] = [0xC8, 0x3E];
/// Field key for tag 1001 with wire type 2 (length-delimited): 8010.
const KEY_1001_LEN: [u8; 2] = [0xCA, 0x3E];

fn repository() -> Repository {
    Repository {
        id: prost::bytes::Bytes::from_static(&[1, 2, 3, 4]),
        name: "interop-repo".to_string(),
        ..Default::default()
    }
}

fn branch() -> Branch {
    Branch {
        id: prost::bytes::Bytes::from_static(&[9, 8, 7]),
        name: "interop-branch".to_string(),
        ..Default::default()
    }
}

fn lock() -> Lock {
    Lock {
        owner: "interop-owner".to_string(),
        ..Default::default()
    }
}

fn generation() -> LockNamespaceGeneration {
    LockNamespaceGeneration {
        repository_lock_generation: 1,
        branch_lock_generation: 2,
        last_applied_fence: 3,
    }
}

#[test]
fn repository_get_response_generation_interop() {
    let new = RepositoryGetResponse {
        repository: Some(repository()),
        repository_generation: Some(7),
    };
    let bytes = new.encode_to_vec();

    // Tag 1001, varint, value 7, the highest tag so it is last on the wire.
    assert!(bytes.ends_with(&[KEY_1001_VARINT[0], KEY_1001_VARINT[1], 7]));

    // New server -> old client: unknown field skipped, known fields intact.
    let as_old = old::RepositoryGetResponse::decode(bytes.as_slice()).expect("old decodes new");
    assert_eq!(as_old.repository, new.repository);

    // Old server -> new client: the field is absent, not a placeholder zero.
    let old_bytes = old::RepositoryGetResponse {
        repository: Some(repository()),
    }
    .encode_to_vec();
    let as_new = RepositoryGetResponse::decode(old_bytes.as_slice()).expect("new decodes old");
    assert_eq!(as_new.repository_generation, None);
    assert_eq!(as_new.repository, Some(repository()));

    // New -> new round trip.
    let round = RepositoryGetResponse::decode(bytes.as_slice()).expect("round trip");
    assert_eq!(round, new);
    assert_eq!(round.repository_generation, Some(7));
}

#[test]
fn branch_get_response_generation_interop() {
    let new = BranchGetResponse {
        branch: Some(branch()),
        branch_generation: Some(11),
    };
    let bytes = new.encode_to_vec();

    assert!(bytes.ends_with(&[KEY_1001_VARINT[0], KEY_1001_VARINT[1], 11]));

    let as_old = old::BranchGetResponse::decode(bytes.as_slice()).expect("old decodes new");
    assert_eq!(as_old.branch, new.branch);

    let old_bytes = old::BranchGetResponse {
        branch: Some(branch()),
    }
    .encode_to_vec();
    let as_new = BranchGetResponse::decode(old_bytes.as_slice()).expect("new decodes old");
    assert_eq!(as_new.branch_generation, None);
    assert_eq!(as_new.branch, Some(branch()));

    let round = BranchGetResponse::decode(bytes.as_slice()).expect("round trip");
    assert_eq!(round, new);
    assert_eq!(round.branch_generation, Some(11));
}

#[test]
fn lock_query_response_namespace_generation_interop() {
    let new = QueryResponse {
        result: vec![lock()],
        namespace_generation: Some(generation()),
    };
    let bytes = new.encode_to_vec();

    // Tag 1001, length-delimited, 6-byte body: fields 1, 2, 3 each (key, value).
    assert!(bytes.ends_with(&[
        KEY_1001_LEN[0],
        KEY_1001_LEN[1],
        6,
        0x08,
        1,
        0x10,
        2,
        0x18,
        3
    ]));

    let as_old = old::QueryResponse::decode(bytes.as_slice()).expect("old decodes new");
    assert_eq!(as_old.result, new.result);

    let old_bytes = old::QueryResponse {
        result: vec![lock()],
    }
    .encode_to_vec();
    let as_new = QueryResponse::decode(old_bytes.as_slice()).expect("new decodes old");
    assert_eq!(as_new.namespace_generation, None);
    assert_eq!(as_new.result, vec![lock()]);

    let round = QueryResponse::decode(bytes.as_slice()).expect("round trip");
    assert_eq!(round, new);
    assert_eq!(round.namespace_generation, Some(generation()));
}

#[test]
fn absent_generation_encodes_nothing() {
    // Unset must stay off the wire so an old peer sees a byte-identical frame.
    let repo = RepositoryGetResponse {
        repository: Some(repository()),
        repository_generation: None,
    };
    let old_repo = old::RepositoryGetResponse {
        repository: Some(repository()),
    };
    assert_eq!(repo.encode_to_vec(), old_repo.encode_to_vec());

    let lock_resp = QueryResponse {
        result: vec![lock()],
        namespace_generation: None,
    };
    let old_lock = old::QueryResponse {
        result: vec![lock()],
    };
    assert_eq!(lock_resp.encode_to_vec(), old_lock.encode_to_vec());
}

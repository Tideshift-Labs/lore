// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! A fragment list and a plain fragment can share a hash: the list's hash is over its reference
//! bytes, and the same bytes stored plain hash the same. The store must therefore refuse a put
//! whose content size or structure differs from the entry already stored under the hash, while
//! still accepting the same content stored with a different compression.
use std::sync::Arc;

use bytes::Bytes;
use lore_storage::Address;
use lore_storage::CompressionMode;
use lore_storage::Fragment;
use lore_storage::FragmentFlags;
use lore_storage::FragmentReference;
use lore_storage::Partition;
use lore_storage::compress;
use lore_storage::hash;
use lore_storage::immutable_store::ImmutableStore;
use lore_storage::local::immutable_store::ImmutableStoreSettings;
use lore_storage::local::immutable_store::LocalImmutableStore;
use zerocopy::IntoBytes;

async fn store() -> Arc<dyn ImmutableStore> {
    LocalImmutableStore::new(None, ImmutableStoreSettings::default())
        .await
        .expect("create store")
}

fn partition() -> Partition {
    rand::random::<Partition>()
}

fn plain(content: &[u8]) -> (Address, Fragment, Bytes) {
    let address = Address {
        hash: hash::hash_slice(content),
        context: Default::default(),
    };
    let fragment = Fragment {
        flags: 0,
        size_payload: content.len() as u32,
        size_content: content.len() as u64,
    };
    (address, fragment, Bytes::copy_from_slice(content))
}

/// Reference bytes over two 40-byte children, so the list is 80 bytes of references that cover
/// 80 bytes of content. Returns the bytes and the list's address.
fn same_size_list_bytes() -> (Vec<u8>, Address) {
    let references = [
        FragmentReference {
            hash: hash::hash_slice(&[1u8; 40]),
            offset_content: 0,
        },
        FragmentReference {
            hash: hash::hash_slice(&[2u8; 40]),
            offset_content: 40,
        },
    ];
    let bytes = references.as_bytes().to_vec();
    let address = Address {
        hash: hash::hash_slice(&bytes),
        context: Default::default(),
    };
    (bytes, address)
}

fn list_fragment(bytes: &[u8], size_content: u64) -> Fragment {
    Fragment {
        flags: FragmentFlags::PayloadFragmented.into(),
        size_payload: bytes.len() as u32,
        size_content,
    }
}

fn assert_collision(result: Result<(), lore_storage::StoreError>) {
    let error = result.expect_err("the put must be refused as a collision");
    assert!(
        error.to_string().contains("Hash collision"),
        "expected a hash collision refusal, got {error:?}"
    );
}

/// The attack in its large form: the list covers far more content than its reference bytes, and
/// the plain copy of those bytes is much smaller, so the sizes differ.
#[tokio::test]
async fn a_put_whose_content_size_differs_from_the_stored_entry_is_refused() {
    let store = store().await;
    let partition = partition();
    let (bytes, address) = same_size_list_bytes();

    store
        .clone()
        .put(
            partition,
            address,
            Fragment {
                flags: 0,
                size_payload: bytes.len() as u32,
                size_content: bytes.len() as u64,
            },
            Some(Bytes::from(bytes.clone())),
            false,
        )
        .await
        .expect("the plain copy is stored first");

    // A list over the same reference bytes that declares a bigger covered size.
    assert_collision(
        store
            .clone()
            .put(
                partition,
                address,
                list_fragment(&bytes, 4096),
                Some(Bytes::from(bytes.clone())),
                false,
            )
            .await,
    );
}

/// The same-size flip: both representations declare 80 bytes of content, so only the structure
/// bit tells them apart.
#[tokio::test]
async fn a_list_put_over_a_stored_plain_copy_of_its_bytes_is_refused() {
    let store = store().await;
    let partition = partition();
    let (bytes, address) = same_size_list_bytes();

    let (_, plain_fragment, payload) = plain(&bytes);
    store
        .clone()
        .put(partition, address, plain_fragment, Some(payload), false)
        .await
        .expect("the plain copy is stored first");

    assert_collision(
        store
            .clone()
            .put(
                partition,
                address,
                list_fragment(&bytes, 80),
                Some(Bytes::from(bytes.clone())),
                false,
            )
            .await,
    );
}

#[tokio::test]
async fn a_plain_put_over_a_stored_list_of_the_same_size_is_refused() {
    let store = store().await;
    let partition = partition();
    let (bytes, address) = same_size_list_bytes();

    store
        .clone()
        .put(
            partition,
            address,
            list_fragment(&bytes, 80),
            Some(Bytes::from(bytes.clone())),
            false,
        )
        .await
        .expect("the list is stored first");

    let (_, plain_fragment, payload) = plain(&bytes);
    assert_collision(
        store
            .clone()
            .put(partition, address, plain_fragment, Some(payload), false)
            .await,
    );
}

/// The refusal holds for a payload-less put too: a caller that asks only to associate a hash
/// must not alias the other structure.
#[tokio::test]
async fn a_payloadless_put_declaring_the_other_structure_is_refused() {
    let store = store().await;
    let partition = partition();
    let (bytes, address) = same_size_list_bytes();

    let (_, plain_fragment, payload) = plain(&bytes);
    store
        .clone()
        .put(partition, address, plain_fragment, Some(payload), false)
        .await
        .expect("the plain copy is stored first");

    assert_collision(
        store
            .clone()
            .put(partition, address, list_fragment(&bytes, 80), None, false)
            .await,
    );
}

#[tokio::test]
async fn repeating_the_same_plain_or_list_put_is_accepted() {
    let store = store().await;
    let partition = partition();

    let (address, fragment, payload) = plain(&[7u8; 100]);
    for _ in 0..3 {
        store
            .clone()
            .put(partition, address, fragment, Some(payload.clone()), false)
            .await
            .expect("repeating a plain put is idempotent");
    }

    let (bytes, list_address) = same_size_list_bytes();
    for _ in 0..3 {
        store
            .clone()
            .put(
                partition,
                list_address,
                list_fragment(&bytes, 80),
                Some(Bytes::from(bytes.clone())),
                false,
            )
            .await
            .expect("repeating a list put is idempotent");
    }
}

/// Compression is how the bytes are stored, not what they are, so it must not count as a
/// different representation. This pins that the structure comparison did not widen to all flags.
#[tokio::test]
async fn the_same_content_with_a_different_compression_is_accepted() {
    for mode in [CompressionMode::Lz4, CompressionMode::Zstd] {
        let store = store().await;
        let partition = partition();
        let content = vec![b'a'; 4000];
        let (address, fragment, payload) = plain(&content);

        store
            .clone()
            .put(partition, address, fragment, Some(payload.clone()), false)
            .await
            .expect("the uncompressed copy is stored first");

        let (compressed_fragment, compressed_payload) =
            compress(fragment, payload.as_ref(), mode).expect("compress");
        assert_ne!(
            compressed_fragment.flags & FragmentFlags::PayloadCompressed,
            0,
            "{mode:?} must have compressed the content for this to test anything"
        );
        store
            .clone()
            .put(
                partition,
                address,
                compressed_fragment,
                Some(compressed_payload),
                false,
            )
            .await
            .unwrap_or_else(|error| {
                panic!("{mode:?}: the compressed copy must be accepted: {error:?}")
            });
    }
}

#[tokio::test]
async fn a_hash_stored_once_still_reads_back_its_first_representation() {
    let store = store().await;
    let partition = partition();
    let (bytes, address) = same_size_list_bytes();

    let (_, plain_fragment, payload) = plain(&bytes);
    store
        .clone()
        .put(partition, address, plain_fragment, Some(payload), false)
        .await
        .expect("the plain copy is stored first");
    let _ = store
        .clone()
        .put(
            partition,
            address,
            list_fragment(&bytes, 80),
            Some(Bytes::from(bytes.clone())),
            false,
        )
        .await;

    let stored = store
        .clone()
        .get_metadata(partition, address)
        .await
        .expect("metadata");
    assert_eq!(
        stored.fragment.flags & FragmentFlags::PayloadFragmented,
        0,
        "the refused put must not have flipped the stored structure"
    );
    assert_eq!(stored.fragment.size_content, 80);
}

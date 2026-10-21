// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! Live tests for the Postgres immutable store's compare-on-existing rule (legacy route).
//!
//! A fragment list's address is the hash of its reference bytes R, and a plain fragment's address
//! is the hash of its content, so plain R and a list over R share an address. The store must
//! refuse a put whose decoded size or structure (`PayloadFragmented`) differs from the
//! representation already stored under the hash, in the same repository and from another one,
//! while a difference in compression alone is accepted.
//!
//! The coordinated and staged routes compare through `witness_representation`; they need the
//! BLAKE3 fixture and Linux roots and are covered by the adapter fixture, not here.
//!
//! # Running
//!
//! Needs a disposable Postgres and S3-compatible store, never a shared development database:
//!
//! ```sh
//! LORE_TEST_PG_URL=postgres://postgres@localhost:<port>/<fresh db> \
//! LORE_TEST_S3_ENDPOINT=http://localhost:<port> \
//! LORE_TEST_S3_BUCKET=<bucket> AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... \
//! cargo test -p lore-postgres --test immutable_store_representation -- --ignored
//! ```
//!
//! Every test is `#[ignore]`d, and a run with the environment unset fails loudly instead of
//! returning early, so an `--ignored` run can never report green over nothing.

use std::sync::Arc;

use bytes::Bytes;
use lore_postgres::store::immutable_store::ObjectStoreSettings;
use lore_postgres::store::immutable_store::PostgresImmutableStore;
use lore_storage::Address;
use lore_storage::CompressionMode;
use lore_storage::Context;
use lore_storage::Fragment;
use lore_storage::FragmentFlags;
use lore_storage::ImmutableStore;
use lore_storage::Partition;
use lore_storage::StoreError;
use lore_storage::compress;
use lore_storage::hash::hash_slice;
use serial_test::serial;

async fn store() -> Arc<PostgresImmutableStore> {
    let var = |name: &str| {
        std::env::var(name)
            .unwrap_or_else(|_| panic!("{name} must be set to run this ignored live test"))
    };
    let settings = ObjectStoreSettings {
        bucket: var("LORE_TEST_S3_BUCKET"),
        endpoint_url: Some(var("LORE_TEST_S3_ENDPOINT")),
        region: Some(
            std::env::var("LORE_TEST_S3_REGION").unwrap_or_else(|_| "us-east-1".to_string()),
        ),
        force_path_style: true,
        slow_operation_threshold_millis: u64::MAX,
        timeout_millis: 30_000,
        validate_bucket_on_startup: false,
    };
    Arc::new(
        PostgresImmutableStore::connect(
            &var("LORE_TEST_PG_URL"),
            5,
            &lore_postgres::pool::TlsConfig::default(),
            settings,
        )
        .await
        .expect("connect + schema + S3 client"),
    )
}

/// Reference bytes over two children of `child_size` bytes each, and the address they hash to.
/// The children are random so every test owns its hash.
fn reference_bytes() -> (Vec<u8>, Address) {
    let mut bytes = Vec::new();
    for offset_content in [0u64, 100] {
        let hash: lore_storage::Hash = rand::random();
        bytes.extend_from_slice(hash.data());
        bytes.extend_from_slice(&offset_content.to_le_bytes());
    }
    assert_eq!(
        bytes.len(),
        size_of::<lore_storage::FragmentReference>() * 2
    );
    let address = Address {
        hash: hash_slice(&bytes),
        context: rand::random(),
    };
    (bytes, address)
}

fn plain_fragment(bytes: &[u8]) -> Fragment {
    Fragment {
        flags: 0,
        size_payload: bytes.len() as u32,
        size_content: bytes.len() as u64,
    }
}

fn list_fragment(bytes: &[u8], size_content: u64) -> Fragment {
    Fragment {
        flags: FragmentFlags::PayloadFragmented.bits(),
        size_payload: bytes.len() as u32,
        size_content,
    }
}

async fn put(
    store: &Arc<PostgresImmutableStore>,
    partition: Partition,
    address: Address,
    fragment: Fragment,
    bytes: &[u8],
) -> Result<(), StoreError> {
    store
        .clone()
        .put(
            partition,
            address,
            fragment,
            Some(Bytes::copy_from_slice(bytes)),
            false,
        )
        .await
}

#[track_caller]
fn refused(result: Result<(), StoreError>, what: &str) {
    match result {
        Ok(()) => panic!("{what}: the put must be refused as a hash collision"),
        Err(error) => assert!(
            error.to_string().contains("Hash collision"),
            "{what}: expected a hash collision refusal, got {error:?}"
        ),
    }
}

/// Which repository the second put lands in, relative to the first.
#[derive(Clone, Copy, Debug)]
enum Second {
    SameRepository,
    OtherRepository,
}

impl Second {
    fn partition(self, first: Partition) -> Partition {
        match self {
            Second::SameRepository => first,
            Second::OtherRepository => rand::random(),
        }
    }
}

const BOTH: [Second; 2] = [Second::SameRepository, Second::OtherRepository];

/// The attack: plain R stored first, then the honest list over the same address. The list
/// covers 200 bytes (size differs) or 80 (the structure bit alone tells them apart).
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn a_list_put_over_a_stored_plain_copy_of_its_bytes_is_refused() {
    let store = store().await;
    for second in BOTH {
        for covered in [200u64, 80] {
            let (bytes, address) = reference_bytes();
            let first: Partition = rand::random();
            put(&store, first, address, plain_fragment(&bytes), &bytes)
                .await
                .expect("the plain copy is the known race and is stored");

            refused(
                put(
                    &store,
                    second.partition(first),
                    address,
                    list_fragment(&bytes, covered),
                    &bytes,
                )
                .await,
                &format!("{second:?} covering {covered}"),
            );
        }
    }
}

/// The reverse order: the honest list is stored, then plain R.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn a_plain_put_over_a_stored_list_of_its_bytes_is_refused() {
    let store = store().await;
    for second in BOTH {
        for covered in [200u64, 80] {
            let (bytes, address) = reference_bytes();
            let first: Partition = rand::random();
            put(
                &store,
                first,
                address,
                list_fragment(&bytes, covered),
                &bytes,
            )
            .await
            .expect("the list is stored first");

            refused(
                put(
                    &store,
                    second.partition(first),
                    address,
                    plain_fragment(&bytes),
                    &bytes,
                )
                .await,
                &format!("{second:?} covering {covered}"),
            );
        }
    }
}

#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn repeating_the_same_plain_or_list_put_is_accepted() {
    let store = store().await;
    let (bytes, address) = reference_bytes();
    let first: Partition = rand::random();
    let other: Partition = rand::random();
    for partition in [first, first, other] {
        put(&store, partition, address, plain_fragment(&bytes), &bytes)
            .await
            .expect("an identical plain put is idempotent, in either repository");
    }

    let (bytes, address) = reference_bytes();
    for partition in [first, first, other] {
        put(
            &store,
            partition,
            address,
            list_fragment(&bytes, 200),
            &bytes,
        )
        .await
        .expect("an identical list put is idempotent, in either repository");
    }
}

/// Compression is how the bytes are stored, not what they are.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn the_same_content_with_a_different_compression_is_accepted() {
    let store = store().await;
    for second in BOTH {
        for mode in [CompressionMode::Lz4, CompressionMode::Zstd] {
            let mut content = vec![b'a'; 4000];
            content[..16].copy_from_slice(&rand::random::<[u8; 16]>());
            let address = Address {
                hash: hash_slice(&content),
                context: rand::random::<Context>(),
            };
            let plain = plain_fragment(&content);
            let (compressed, payload) = compress(plain, &content, mode).expect("compress");
            assert_ne!(compressed.flags & FragmentFlags::PayloadCompressed, 0);

            let first: Partition = rand::random();
            put(&store, first, address, plain, &content)
                .await
                .expect("the uncompressed copy is stored first");
            put(
                &store,
                second.partition(first),
                address,
                compressed,
                &payload,
            )
            .await
            .unwrap_or_else(|error| {
                panic!("{second:?} {mode:?}: the compressed copy must be accepted: {error:?}")
            });
        }
    }
}

/// After the poison, a repository that never uploaded the list (the upload is skipped when the
/// server reports the hash present) gets the hash through a copy, and reads back the poison's
/// size, not the file size. That is the fact push verification relies on to refuse the push.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn a_copied_poison_reports_the_plain_size_not_the_file_size() {
    let store = store().await;
    let (bytes, address) = reference_bytes();
    let attacker: Partition = rand::random();
    put(&store, attacker, address, plain_fragment(&bytes), &bytes)
        .await
        .expect("the plain copy is stored first");

    let victim: Partition = rand::random();
    let victim_context: Context = rand::random();
    store
        .clone()
        .copy(
            attacker,
            address,
            victim,
            victim_context,
            lore_storage::immutable_store::CopyBehavior::default(),
        )
        .await
        .expect("copy into the victim repository");

    let stored = store
        .clone()
        .get_metadata(
            victim,
            Address {
                hash: address.hash,
                context: victim_context,
            },
        )
        .await
        .expect("metadata in the victim repository");
    assert_eq!(stored.fragment.size_content, bytes.len() as u64);
    assert_eq!(stored.fragment.flags & FragmentFlags::PayloadFragmented, 0);
    // The honest list would have covered 200 bytes; the store reports 80.
    assert_ne!(stored.fragment.size_content, 200);
}

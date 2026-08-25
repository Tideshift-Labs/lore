// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Integration tests for the Postgres-backed immutable store (CR-007).
//!
//! Fragment payload metadata and bytes live atomically on the S3-compatible
//! object (MinIO / LocalStack / DO Spaces). Postgres keeps repository/context
//! associations, mutable obliteration state, and a rebuildable metering
//! projection.
//!
//! # Running
//!
//! Requires Postgres + an S3-compatible store. Quickstart with Docker:
//!
//! ```sh
//! docker run -d -p 5433:5432 -e POSTGRES_PASSWORD=test -e POSTGRES_DB=lore postgres:16
//! docker run -d -p 9000:9000 -p 9001:9001 minio/minio server /data
//! # Create the bucket (replace "local" with your mc alias):
//! # mc alias set local http://localhost:9000 minioadmin minioadmin
//! # mc mb local/lore-test
//! ```
//!
//! Then run:
//!
//! ```sh
//! LORE_TEST_PG_URL=postgres://postgres:test@localhost:5433/lore \
//! LORE_TEST_S3_ENDPOINT=http://localhost:9000 \
//! LORE_TEST_S3_BUCKET=lore-test \
//! LORE_TEST_S3_REGION=us-east-1 \
//! AWS_ACCESS_KEY_ID=minioadmin \
//! AWS_SECRET_ACCESS_KEY=minioadmin \
//! cargo test -p lore-postgres --test immutable_store -- --ignored
//! ```
//!
//! Every test here is `#[ignore]`d, so plain `cargo test` needs no running
//! infra — and, more importantly, never claims to have covered this code when it
//! hasn't. Run them with `-- --ignored` once the env below is set.
//!
//! That attribute is doing real work. These were previously plain `#[test]`s
//! that printed a notice and returned when the env was unset — which Rust's
//! harness reports as `test result: ok. 15 passed`, with the notice swallowed by
//! output capture. A suite that asserts coverage it does not have is worse than
//! no suite: CR-016's SQL reached staging unexecuted precisely because this file
//! said it was green, and two real defects (a `now()`-vs-`clock_timestamp()`
//! age and a `greatest(0, NULL)` that ate a null) were then found by hand rather
//! than here. `ignored` and `passed` must not look alike.
//!
//! Env gate: `LORE_TEST_PG_URL`, `LORE_TEST_S3_ENDPOINT`, `LORE_TEST_S3_BUCKET`
//! (+ optional `LORE_TEST_S3_REGION`). Still checked at runtime, so a run with
//! `--ignored` but no env exits early rather than failing confusingly.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use aws_sdk_s3::types::BucketVersioningStatus;
use aws_sdk_s3::types::VersioningConfiguration;
use bytes::Bytes;
use bytes::BytesMut;
use lore_aws::clients::AwsClientBuilder;
use lore_aws::clients::HttpClientSettings;
use lore_aws::clients::TimeoutConfig;
use lore_aws::s3::S3Impl;
use lore_aws::store::object_metadata::from_object_metadata;
use lore_aws::store::object_metadata::to_object_metadata;
use lore_postgres::store::immutable_store::ObjectStoreSettings;
use lore_postgres::store::immutable_store::PostgresImmutableStore;
use lore_storage::Address;
use lore_storage::Context;
use lore_storage::Fragment;
use lore_storage::FragmentFlags;
use lore_storage::FragmentReference;
use lore_storage::Hash;
use lore_storage::ImmutableStore;
use lore_storage::Partition;
use lore_storage::StoreError;
use lore_storage::StoreMatch;
use lore_storage::StoreMatchResult;
use lore_storage::StoreObliterateStats;
use lore_storage::StoreRepositoryStats;
use lore_storage::TypedBytesMut;
use serial_test::serial;

// ─── env helpers ─────────────────────────────────────────────────────────────

/// Returns `(pg_url, s3_endpoint, s3_bucket, s3_region)` or `None` when any
/// required gate variable is unset.
fn env_config() -> Option<(String, String, String, String)> {
    let pg_url = std::env::var("LORE_TEST_PG_URL").ok()?;
    let s3_endpoint = std::env::var("LORE_TEST_S3_ENDPOINT").ok()?;
    let s3_bucket = std::env::var("LORE_TEST_S3_BUCKET").ok()?;
    let s3_region =
        std::env::var("LORE_TEST_S3_REGION").unwrap_or_else(|_| "us-east-1".to_string());
    Some((pg_url, s3_endpoint, s3_bucket, s3_region))
}

async fn pg_client(pg_url: &str) -> tokio_postgres::Client {
    let (client, connection) = tokio_postgres::connect(pg_url, tokio_postgres::NoTls)
        .await
        .expect("connect for direct test setup");
    lore_base::lore_spawn!(async move {
        if let Err(e) = connection.await {
            eprintln!("direct postgres connection error: {e}");
        }
    });
    client
}

/// Delete one rebuildable metering row while leaving its association and S3
/// object intact. This simulates projection loss without corrupting the
/// authoritative representation.
async fn delete_metering_row(pg_url: &str, hash: Hash) {
    let client = pg_client(pg_url).await;
    client
        .execute(
            "DELETE FROM lore_fragment_metering WHERE hash = $1",
            &[&hash.data().as_slice()],
        )
        .await
        .expect("delete metering row");
}

/// Remove every Postgres row for a deliberately corrupted object fixture so
/// global reconciliation tests remain independent of test execution order.
async fn delete_hash_rows(pg_url: &str, hash: Hash) {
    let mut client = pg_client(pg_url).await;
    let transaction = client.transaction().await.expect("begin fixture cleanup");
    for table in [
        "lore_fragments",
        "lore_fragment_state",
        "lore_fragment_metering",
    ] {
        transaction
            .execute(
                &format!("DELETE FROM {table} WHERE hash = $1"),
                &[&hash.data().as_slice()],
            )
            .await
            .expect("delete corrupted fixture rows");
    }
    transaction.commit().await.expect("commit fixture cleanup");
}

async fn metering_fragment(pg_url: &str, hash: Hash) -> Option<Fragment> {
    let client = pg_client(pg_url).await;
    client
        .query_opt(
            "SELECT payload_flags, size_payload, size_content \
             FROM lore_fragment_metering WHERE hash = $1",
            &[&hash.data().as_slice()],
        )
        .await
        .expect("query metering row")
        .map(|row| Fragment {
            flags: row.get::<_, i64>("payload_flags") as u32,
            size_payload: row.get::<_, i64>("size_payload") as u32,
            size_content: row.get::<_, i64>("size_content") as u64,
        })
}

async fn make_s3(s3_endpoint: &str, s3_region: &str) -> S3Impl {
    let builder = Box::pin(
        AwsClientBuilder::builder()
            .with_http_settings(&HttpClientSettings::default())
            .maybe_endpoint(Some(s3_endpoint.to_string()))
            .maybe_region(Some(s3_region.to_string()))
            .with_timeout_config(
                TimeoutConfig::builder()
                    .operation_timeout(Duration::from_secs(30))
                    .build(),
            )
            .build_config(),
    )
    .await
    .with_slow_operation_threshold(u64::MAX)
    .s3_with_path_style(true);

    Box::pin(builder.build())
        .await
        .expect("build direct test S3 client")
}

fn object_key(hash: Hash) -> String {
    let mut destination = [0u8; 64];
    lore_revision::util::to_hex_str(hash.data(), &mut destination).to_string()
}

// ─── shared test helpers ──────────────────────────────────────────────────────

/// Build and connect a `PostgresImmutableStore` with test-friendly settings.
async fn make_store(
    pg_url: &str,
    s3_endpoint: &str,
    s3_bucket: &str,
    s3_region: &str,
) -> Arc<PostgresImmutableStore> {
    make_store_with_pool_max(pg_url, s3_endpoint, s3_bucket, s3_region, 5).await
}

async fn make_store_with_pool_max(
    pg_url: &str,
    s3_endpoint: &str,
    s3_bucket: &str,
    s3_region: &str,
    pool_max_size: u32,
) -> Arc<PostgresImmutableStore> {
    let settings = ObjectStoreSettings {
        bucket: s3_bucket.to_string(),
        endpoint_url: Some(s3_endpoint.to_string()),
        region: Some(s3_region.to_string()),
        force_path_style: true,
        slow_operation_threshold_millis: u64::MAX,
        timeout_millis: 30_000,
        // Bucket may be pre-created by the harness; don't fail construction
        // on a HEAD if it doesn't exist yet — the test creates it via mc/aws-cli.
        validate_bucket_on_startup: false,
    };
    Arc::new(
        PostgresImmutableStore::connect(
            pg_url,
            pool_max_size,
            &lore_postgres::pool::TlsConfig::default(),
            settings,
        )
        .await
        .expect("connect + schema + S3 client"),
    )
}

async fn seed_fragment_state(pg_url: &str, partition: Partition, address: Address, state: i64) {
    let repository: Context = partition.into();
    let mut client = pg_client(pg_url).await;
    let transaction = client.transaction().await.expect("begin lifecycle fixture");
    transaction
        .execute(
            "DELETE FROM lore_fragments WHERE repository = $1 AND context = $2 AND hash = $3",
            &[
                &repository.data().as_slice(),
                &address.context.data().as_slice(),
                &address.hash.data().as_slice(),
            ],
        )
        .await
        .expect("remove target association");
    transaction
        .execute(
            "INSERT INTO lore_fragment_state (hash, state) VALUES ($1, $2) \
             ON CONFLICT (hash) DO UPDATE SET state = EXCLUDED.state",
            &[&address.hash.data().as_slice(), &state],
        )
        .await
        .expect("seed lifecycle state");
    transaction
        .commit()
        .await
        .expect("commit lifecycle fixture");
}

async fn fragment_state(pg_url: &str, hash: Hash) -> Option<i64> {
    pg_client(pg_url)
        .await
        .query_opt(
            "SELECT state FROM lore_fragment_state WHERE hash = $1",
            &[&hash.data().as_slice()],
        )
        .await
        .expect("query lifecycle state")
        .map(|row| row.get("state"))
}

async fn put_fragment_chain(
    store: Arc<PostgresImmutableStore>,
    partition: Partition,
    depth: usize,
) -> Vec<Address> {
    let leaf: Address = rand::random();
    put_fragment(store.clone(), partition, leaf, 1024).await;
    let mut addresses = vec![leaf];
    let mut child = leaf;

    for _ in 0..depth {
        let parent = Address {
            hash: rand::random(),
            context: leaf.context,
        };
        let reference = FragmentReference {
            hash: child.hash,
            offset_content: 0,
        };
        let mut payload = BytesMut::zeroed(std::mem::size_of::<FragmentReference>());
        payload.as_type_slice_mut::<FragmentReference>()[0] = reference;
        let payload = payload.freeze();
        let fragment = Fragment {
            flags: FragmentFlags::PayloadFragmented.bits(),
            size_payload: payload.len() as u32,
            size_content: 1024,
        };
        store
            .clone()
            .put(partition, parent, fragment, Some(payload), false)
            .await
            .expect("put fragmented parent");
        addresses.push(parent);
        child = parent;
    }
    addresses
}

/// Build an uncompressed `Fragment` + payload for the given byte size.
///
/// `flags = 0`, `size_content = size_payload as u64` (uncompressed, unfragmented).
/// The payload bytes are a repeating `0xAB` pattern — content is arbitrary since
/// the store does not verify the hash against the bytes.
fn make_fragment_and_payload(size_payload: u32) -> (Fragment, Bytes) {
    let fragment = Fragment {
        flags: 0,
        size_payload,
        size_content: size_payload as u64,
    };
    let payload = Bytes::from(vec![0xABu8; size_payload as usize]);
    (fragment, payload)
}

fn stored_durable(mut fragment: Fragment) -> Fragment {
    fragment.flags |= FragmentFlags::PayloadStoredDurable.bits();
    fragment
}

/// Put `size_payload` bytes under `(partition, address)` and return the stored
/// `(Fragment, Bytes)` pair. Panics on error so callers stay concise.
async fn put_fragment(
    store: Arc<PostgresImmutableStore>,
    partition: Partition,
    address: Address,
    size_payload: u32,
) -> (Fragment, Bytes) {
    let (frag, payload) = make_fragment_and_payload(size_payload);
    store
        .clone()
        .put(partition, address, frag, Some(payload.clone()), false)
        .await
        .expect("put_fragment helper");
    (frag, payload)
}

async fn get_payload(
    store: Arc<PostgresImmutableStore>,
    partition: Partition,
    address: Address,
) -> Result<(Fragment, Bytes), StoreError> {
    store.get(partition, address).await?.into_payload()
}

async fn query_addresses(
    store: Arc<PostgresImmutableStore>,
    partition: Partition,
    addresses: &[Address],
) -> Result<Vec<StoreMatchResult>, StoreError> {
    let mut results = vec![StoreMatchResult::default(); addresses.len()];
    store.query(partition, addresses, &mut results).await?;
    Ok(results)
}

async fn query_one(
    store: Arc<PostgresImmutableStore>,
    partition: Partition,
    address: Address,
) -> Result<StoreMatchResult, StoreError> {
    let mut results = query_addresses(store, partition, &[address]).await?;
    Ok(results.remove(0))
}

// ─── tests ────────────────────────────────────────────────────────────────────

/// 1. Round-trip / byte-perfect: `put` then `get` returns an identical
///    `Fragment` and byte-exact payload.
///
/// Uses a 200 KB payload to exercise the S3 streaming read path while staying
/// under the 256 KB `FRAGMENT_SIZE_THRESHOLD`.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn round_trip_byte_perfect() {
    let Some((pg, ep, bucket, region)) = env_config() else {
        eprintln!(
            "LORE_TEST_PG_URL / LORE_TEST_S3_ENDPOINT / LORE_TEST_S3_BUCKET unset; \
             skipping Postgres immutable-store test"
        );
        return;
    };
    let s = make_store(&pg, &ep, &bucket, &region).await;

    let partition: Partition = rand::random();
    let address: Address = rand::random();
    // 200 KB: exercises the streaming read path, stays under 256 KB threshold.
    let (frag_in, payload_in) = put_fragment(s.clone(), partition, address, 200 * 1024).await;

    let object = make_s3(&ep, &region)
        .await
        .head_object(&bucket, &object_key(address.hash))
        .await
        .expect("head object written by put");
    assert_eq!(
        from_object_metadata(object.metadata()),
        Ok(frag_in),
        "the S3 object must carry the authoritative fragment metadata"
    );

    let (frag_out, payload_out) = get_payload(s.clone(), partition, address)
        .await
        .expect("get after put");

    assert_eq!(
        stored_durable(frag_in),
        frag_out,
        "Fragment metadata must round-trip unchanged"
    );
    assert_eq!(
        payload_in, payload_out,
        "Payload bytes must be bit-for-bit identical after round-trip"
    );
}

/// `get_metadata` spends a `HeadObject` to return the authoritative stored
/// representation and an exact partition/context match without reading bytes.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn get_metadata_returns_the_stored_fragment_and_full_match() {
    let Some((pg, ep, bucket, region)) = env_config() else {
        eprintln!(
            "LORE_TEST_PG_URL / LORE_TEST_S3_ENDPOINT / LORE_TEST_S3_BUCKET unset; \
             skipping Postgres immutable-store test"
        );
        return;
    };
    let store = make_store(&pg, &ep, &bucket, &region).await;
    let partition: Partition = rand::random();
    let address: Address = rand::random();
    let (fragment, _) = put_fragment(store.clone(), partition, address, 1024).await;

    let result = store
        .get_metadata(partition, address)
        .await
        .expect("get_metadata after put");

    assert_eq!(result.fragment, stored_durable(fragment));
    assert_eq!(result.match_made, StoreMatch::MatchFull);
}

/// Query stays S3-free and reports only lifecycle/durability state, while
/// metadata-only and full reads recover representation from the object. None
/// of the three trusts the rebuildable Postgres metering projection.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn reads_ignore_a_corrupted_metering_projection() {
    let Some((pg, ep, bucket, region)) = env_config() else {
        eprintln!(
            "LORE_TEST_PG_URL / LORE_TEST_S3_ENDPOINT / LORE_TEST_S3_BUCKET unset; \
             skipping Postgres immutable-store test"
        );
        return;
    };
    let store = make_store(&pg, &ep, &bucket, &region).await;
    let partition: Partition = rand::random();
    let address: Address = rand::random();
    let (fragment, payload) = put_fragment(store.clone(), partition, address, 1536).await;

    let client = pg_client(&pg).await;
    client
        .execute(
            "UPDATE lore_fragment_metering \
             SET payload_flags = $1, size_payload = $2, size_content = $3 WHERE hash = $4",
            &[&7_i64, &1_i64, &2_i64, &address.hash.data().as_slice()],
        )
        .await
        .expect("corrupt metering projection");

    let query = query_one(store.clone(), partition, address)
        .await
        .expect("query with corrupted projection");
    let metadata = store
        .clone()
        .get_metadata(partition, address)
        .await
        .expect("get_metadata with corrupted projection");
    let (read_fragment, read_payload) = get_payload(store.clone(), partition, address)
        .await
        .expect("get with corrupted projection");

    assert_eq!(
        query.match_made,
        StoreMatch::MatchFull,
        "query must remain S3-free and report the exact association"
    );
    assert!(query.stored_durable, "query must report durable storage");
    assert_eq!(
        metadata.fragment,
        stored_durable(fragment),
        "get_metadata must use S3 metadata"
    );
    assert_eq!(
        read_fragment,
        stored_durable(fragment),
        "get must use S3 metadata"
    );
    assert_eq!(
        read_payload, payload,
        "get must still return the object bytes"
    );
}

/// An associated object without Lore metadata cannot fall back to Postgres.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn object_without_fragment_metadata_is_an_error() {
    let Some((pg, ep, bucket, region)) = env_config() else {
        eprintln!(
            "LORE_TEST_PG_URL / LORE_TEST_S3_ENDPOINT / LORE_TEST_S3_BUCKET unset; \
             skipping Postgres immutable-store test"
        );
        return;
    };
    let store = make_store(&pg, &ep, &bucket, &region).await;
    let partition: Partition = rand::random();
    let address: Address = rand::random();
    let (_, payload) = put_fragment(store.clone(), partition, address, 384).await;

    make_s3(&ep, &region)
        .await
        .put_object(&bucket, &object_key(address.hash), payload, None)
        .await
        .expect("replace object without metadata");

    let error = store
        .get_metadata(partition, address)
        .await
        .expect_err("missing object metadata must not fall back to Postgres");
    delete_hash_rows(&pg, address.hash).await;
    assert!(error.is_internal(), "expected Internal, got {error:?}");
}

/// Malformed Lore metadata is a corrupt authoritative object, not absence and
/// not a signal to consult the metering projection.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn malformed_object_fragment_metadata_is_an_error() {
    let Some((pg, ep, bucket, region)) = env_config() else {
        eprintln!(
            "LORE_TEST_PG_URL / LORE_TEST_S3_ENDPOINT / LORE_TEST_S3_BUCKET unset; \
             skipping Postgres immutable-store test"
        );
        return;
    };
    let store = make_store(&pg, &ep, &bucket, &region).await;
    let partition: Partition = rand::random();
    let address: Address = rand::random();
    let (_, payload) = put_fragment(store.clone(), partition, address, 384).await;
    let malformed = std::collections::HashMap::from([(
        "lore-fragment".to_string(),
        "not:a:fragment".to_string(),
    )]);

    make_s3(&ep, &region)
        .await
        .put_object(&bucket, &object_key(address.hash), payload, Some(malformed))
        .await
        .expect("replace object with malformed metadata");

    let error = store
        .get_metadata(partition, address)
        .await
        .expect_err("malformed object metadata must not fall back to Postgres");
    delete_hash_rows(&pg, address.hash).await;
    assert!(error.is_internal(), "expected Internal, got {error:?}");
}

/// An exact already-associated Stored put is a pure idempotent hot path. It
/// succeeds without payload proof and without consulting an object that has
/// disappeared after the original write.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn exact_associated_put_without_payload_is_s3_free() {
    let Some((pg, ep, bucket, region)) = env_config() else {
        eprintln!(
            "LORE_TEST_PG_URL / LORE_TEST_S3_ENDPOINT / LORE_TEST_S3_BUCKET unset; \
             skipping Postgres immutable-store test"
        );
        return;
    };
    let store = make_store(&pg, &ep, &bucket, &region).await;
    let partition: Partition = rand::random();
    let address: Address = rand::random();
    let (fragment, _) = put_fragment(store.clone(), partition, address, 512).await;
    make_s3(&ep, &region)
        .await
        .delete_object(&bucket, &object_key(address.hash), None)
        .await
        .expect("remove object after initial put");

    let result = store.put(partition, address, fragment, None, false).await;
    delete_hash_rows(&pg, address.hash).await;

    result.expect("exact associated put must not consult S3");
}

/// A payload-bearing first association overwrites any row-less orphan object,
/// even if that orphan predates object metadata or carries malformed metadata.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn payload_put_overwrites_untrusted_rowless_orphan_objects() {
    let Some((pg, ep, bucket, region)) = env_config() else {
        eprintln!(
            "LORE_TEST_PG_URL / LORE_TEST_S3_ENDPOINT / LORE_TEST_S3_BUCKET unset; \
             skipping Postgres immutable-store test"
        );
        return;
    };
    let store = make_store(&pg, &ep, &bucket, &region).await;
    let s3 = make_s3(&ep, &region).await;
    let malformed = std::collections::HashMap::from([(
        "lore-fragment".to_string(),
        "not:a:fragment".to_string(),
    )]);

    for orphan_metadata in [None, Some(malformed)] {
        let partition: Partition = rand::random();
        let address: Address = rand::random();
        let (fragment, payload) = make_fragment_and_payload(640);
        s3.put_object(
            &bucket,
            &object_key(address.hash),
            Bytes::from(vec![0xEE; 17]),
            orphan_metadata,
        )
        .await
        .expect("seed row-less orphan object");

        store
            .clone()
            .put(partition, address, fragment, Some(payload.clone()), false)
            .await
            .expect("payload put must overwrite untrusted orphan");
        let (read_fragment, read_payload) = get_payload(store.clone(), partition, address)
            .await
            .expect("read overwritten orphan");

        assert_eq!(read_fragment, stored_durable(fragment));
        assert_eq!(read_payload, payload);
        assert_eq!(metering_fragment(&pg, address.hash).await, Some(fragment));
        delete_hash_rows(&pg, address.hash).await;
        s3.delete_object(&bucket, &object_key(address.hash), None)
            .await
            .expect("remove overwritten orphan fixture");
    }
}

/// 2. Query match levels.
///
/// After a full put:
/// - `query` on the exact address reports `MatchFull`.
/// - `query` for the same hash under a DIFFERENT partition reports `MatchHash`
///   (global dedup: hash is visible across partitions via the index on `hash` alone).
/// - `query` for a random never-put hash reports `MatchNone`.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn existence_levels() {
    let Some((pg, ep, bucket, region)) = env_config() else {
        eprintln!(
            "LORE_TEST_PG_URL / LORE_TEST_S3_ENDPOINT / LORE_TEST_S3_BUCKET unset; \
             skipping Postgres immutable-store test"
        );
        return;
    };
    let s = make_store(&pg, &ep, &bucket, &region).await;

    let partition: Partition = rand::random();
    let address: Address = rand::random();
    put_fragment(s.clone(), partition, address, 1024).await;

    // Full match on the exact address.
    let m = query_one(s.clone(), partition, address)
        .await
        .expect("query exact association");
    assert_eq!(
        m.match_made,
        StoreMatch::MatchFull,
        "exact address must be MatchFull"
    );

    // The hash is globally visible — a different partition with MatchHash finds it.
    let other_partition: Partition = rand::random();
    let m_hash = query_one(s.clone(), other_partition, address)
        .await
        .expect("query cross-partition hash");
    assert_eq!(
        m_hash.match_made,
        StoreMatch::MatchHash,
        "same hash under different partition must be MatchHash (global dedup)"
    );

    // A never-put hash is absent at every level.
    let absent = Address {
        hash: rand::random(),
        context: rand::random(),
    };
    let m_absent = query_one(s.clone(), partition, absent)
        .await
        .expect("query absent address");
    assert_eq!(
        m_absent.match_made,
        StoreMatch::MatchNone,
        "never-put hash must be MatchNone"
    );
    assert!(m.stored_durable, "query must report durable storage");
}

/// 3. Dedup behavior — same partition, same hash, different context.
///
/// A new association to an existing global hash still requires the caller to
/// supply a payload as proof of the logical content it is associating:
/// - Same partition, same hash, different context, NO payload → error.
/// - Same partition, same hash, different context, WITH payload → succeeds
///   after validating the authoritative object, without rewriting it.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn dedup_same_partition_requires_payload() {
    let Some((pg, ep, bucket, region)) = env_config() else {
        eprintln!(
            "LORE_TEST_PG_URL / LORE_TEST_S3_ENDPOINT / LORE_TEST_S3_BUCKET unset; \
             skipping Postgres immutable-store test"
        );
        return;
    };
    let s = make_store(&pg, &ep, &bucket, &region).await;

    let partition: Partition = rand::random();
    let addr1: Address = rand::random();
    let (frag, payload) = put_fragment(s.clone(), partition, addr1, 1024).await;

    // Same partition, same hash, new context — WITHOUT payload proof.
    let addr2 = Address {
        hash: addr1.hash,
        context: rand::random(),
    };
    let no_payload_result = s.clone().put(partition, addr2, frag, None, false).await;
    assert!(
        no_payload_result.is_err(),
        "same-partition same-hash no-payload put must error (MatchPartition path unreachable)"
    );
    let err_str = format!("{:?}", no_payload_result.unwrap_err());
    assert!(
        err_str.contains("Payload buffer required"),
        "expected 'Payload buffer required' in error, got: {err_str}"
    );

    // Same partition, same hash, new context WITH payload proof → succeeds
    // after validating the existing self-describing object.
    s.clone()
        .put(partition, addr2, frag, Some(payload.clone()), false)
        .await
        .expect("same-partition same-hash different-context put WITH payload must succeed");

    let (_, payload_out) = get_payload(s.clone(), partition, addr2)
        .await
        .expect("get addr2 after dedup-with-payload put");
    assert_eq!(
        payload, payload_out,
        "dedup put with payload must return the original bytes"
    );
}

/// 3 (continued). Cross-partition put without payload errors with
/// "Payload buffer required".
///
/// The hash exists globally, but a new repository/context association still
/// requires payload proof.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn dedup_cross_partition_no_payload_errors() {
    let Some((pg, ep, bucket, region)) = env_config() else {
        eprintln!(
            "LORE_TEST_PG_URL / LORE_TEST_S3_ENDPOINT / LORE_TEST_S3_BUCKET unset; \
             skipping Postgres immutable-store test"
        );
        return;
    };
    let s = make_store(&pg, &ep, &bucket, &region).await;

    let p1: Partition = rand::random();
    let addr: Address = rand::random();
    let (frag, _payload) = put_fragment(s.clone(), p1, addr, 512).await;

    // Different partition, same hash, no payload → "Payload buffer required".
    let p2: Partition = rand::random();
    let addr_p2 = Address {
        hash: addr.hash,
        context: rand::random(),
    };
    let result = s.clone().put(p2, addr_p2, frag, None, false).await;
    assert!(result.is_err(), "cross-partition no-payload put must error");
    let err_str = format!("{:?}", result.unwrap_err());
    assert!(
        err_str.contains("Payload buffer required"),
        "expected 'Payload buffer required', got: {err_str}"
    );
}

/// Two valid physical representations of the same logical hash may race. Both
/// associations succeed and converge on whichever complete S3 object version
/// wins; both repositories are metered from that actual representation.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn concurrent_same_hash_first_writes_converge_object_and_projection() {
    let Some((pg, ep, bucket, region)) = env_config() else {
        eprintln!(
            "LORE_TEST_PG_URL / LORE_TEST_S3_ENDPOINT / LORE_TEST_S3_BUCKET unset; \
             skipping Postgres immutable-store test"
        );
        return;
    };
    let store = make_store(&pg, &ep, &bucket, &region).await;
    let hash: Hash = rand::random();
    let partition_a: Partition = rand::random();
    let partition_b: Partition = rand::random();
    let address_a = Address {
        hash,
        context: rand::random(),
    };
    let address_b = Address {
        hash,
        context: rand::random(),
    };
    let fragment_a = Fragment {
        flags: FragmentFlags::PayloadCompressedZstd.bits(),
        size_payload: 1024,
        size_content: 8192,
    };
    let fragment_b = Fragment {
        flags: FragmentFlags::PayloadCompressedLZ4.bits(),
        size_payload: 1536,
        size_content: 8192,
    };
    let payload_a = Bytes::from(vec![0xA1; fragment_a.size_payload as usize]);
    let payload_b = Bytes::from(vec![0xB2; fragment_b.size_payload as usize]);
    let barrier = Arc::new(tokio::sync::Barrier::new(2));

    let write_a = {
        let store = store.clone();
        let barrier = barrier.clone();
        async move {
            barrier.wait().await;
            store
                .put(partition_a, address_a, fragment_a, Some(payload_a), false)
                .await
        }
    };
    let write_b = {
        let store = store.clone();
        let barrier = barrier.clone();
        async move {
            barrier.wait().await;
            store
                .put(partition_b, address_b, fragment_b, Some(payload_b), false)
                .await
        }
    };
    let (result_a, result_b) = tokio::join!(write_a, write_b);

    assert!(
        result_a.is_ok() && result_b.is_ok(),
        "both valid representations must associate: A={result_a:?}, B={result_b:?}"
    );
    let object = make_s3(&ep, &region)
        .await
        .head_object(&bucket, &object_key(hash))
        .await
        .expect("head winning object");
    let winner_fragment = from_object_metadata(object.metadata())
        .expect("winning object must carry valid fragment metadata");
    assert!(
        winner_fragment == fragment_a || winner_fragment == fragment_b,
        "object must contain one complete submitted representation: {winner_fragment:?}"
    );

    let metadata_a = store
        .clone()
        .get_metadata(partition_a, address_a)
        .await
        .expect("read representation through association A");
    let metadata_b = store
        .clone()
        .get_metadata(partition_b, address_b)
        .await
        .expect("read representation through association B");
    assert_eq!(metadata_a.fragment, stored_durable(winner_fragment));
    assert_eq!(metadata_b.fragment, stored_durable(winner_fragment));
    assert_eq!(
        metering_fragment(&pg, hash).await,
        Some(winner_fragment),
        "projection must describe the winning S3 object version"
    );
    assert_eq!(
        store
            .clone()
            .repository_stats(partition_a)
            .await
            .expect("repository A stats"),
        StoreRepositoryStats {
            fragment_count: 1,
            payload_bytes: u64::from(winner_fragment.size_payload),
            content_bytes: winner_fragment.size_content,
        },
        "repository A must be metered from the winning representation"
    );
    assert_eq!(
        store
            .clone()
            .repository_stats(partition_b)
            .await
            .expect("repository B stats"),
        StoreRepositoryStats {
            fragment_count: 1,
            payload_bytes: u64::from(winner_fragment.size_payload),
            content_bytes: winner_fragment.size_content,
        },
        "repository B must be metered from the winning representation"
    );
}

/// Reusing a hash for different logical content remains a collision: the
/// second association is rejected and cannot disturb the existing object or
/// projection.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn same_hash_with_different_logical_size_is_rejected() {
    let Some((pg, ep, bucket, region)) = env_config() else {
        eprintln!(
            "LORE_TEST_PG_URL / LORE_TEST_S3_ENDPOINT / LORE_TEST_S3_BUCKET unset; \
             skipping Postgres immutable-store test"
        );
        return;
    };
    let store = make_store(&pg, &ep, &bucket, &region).await;
    let hash: Hash = rand::random();
    let partition_a: Partition = rand::random();
    let partition_b: Partition = rand::random();
    let address_a = Address {
        hash,
        context: rand::random(),
    };
    let address_b = Address {
        hash,
        context: rand::random(),
    };
    let fragment_a = Fragment {
        flags: FragmentFlags::PayloadCompressedZstd.bits(),
        size_payload: 512,
        size_content: 4096,
    };
    let fragment_b = Fragment {
        flags: FragmentFlags::PayloadCompressedLZ4.bits(),
        size_payload: 768,
        size_content: 8192,
    };
    store
        .clone()
        .put(
            partition_a,
            address_a,
            fragment_a,
            Some(Bytes::from(vec![0xA1; 512])),
            false,
        )
        .await
        .expect("put original logical content");

    let error = store
        .clone()
        .put(
            partition_b,
            address_b,
            fragment_b,
            Some(Bytes::from(vec![0xB2; 768])),
            false,
        )
        .await
        .expect_err("different logical size for one hash must be rejected");

    assert!(
        error.is_internal(),
        "expected collision Internal, got {error:?}"
    );
    assert_eq!(metering_fragment(&pg, hash).await, Some(fragment_a));
    assert_eq!(
        query_one(store, partition_b, address_b)
            .await
            .expect("check rejected association")
            .match_made,
        StoreMatch::MatchNone
    );
}

/// 4. `query` over a mix of present and absent addresses returns the
///    per-index matches in the correct order.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn query_batch_mixed() {
    let Some((pg, ep, bucket, region)) = env_config() else {
        eprintln!(
            "LORE_TEST_PG_URL / LORE_TEST_S3_ENDPOINT / LORE_TEST_S3_BUCKET unset; \
             skipping Postgres immutable-store test"
        );
        return;
    };
    let s = make_store(&pg, &ep, &bucket, &region).await;

    let partition: Partition = rand::random();
    let present1: Address = rand::random();
    let present2: Address = rand::random();
    let absent: Address = rand::random();

    put_fragment(s.clone(), partition, present1, 512).await;
    put_fragment(s.clone(), partition, present2, 512).await;

    // Order: [present, absent, present] — confirms index ordering is preserved.
    let addresses = [present1, absent, present2];
    let results = query_addresses(s.clone(), partition, &addresses)
        .await
        .expect("batch query");

    assert_eq!(results.len(), 3, "result count must match address count");
    assert_eq!(
        results[0].match_made,
        StoreMatch::MatchFull,
        "present1 → MatchFull"
    );
    assert_eq!(
        results[1].match_made,
        StoreMatch::MatchNone,
        "absent → MatchNone"
    );
    assert_eq!(
        results[2].match_made,
        StoreMatch::MatchFull,
        "present2 → MatchFull"
    );
}

/// 5. `copy`: put a fragment, copy it to a new (partition, context), then
///    confirm `get` on the destination returns the same bytes.
///
/// Copy is a pure association write — the bytes and metadata are already in
/// the shared bucket and Postgres keyed by hash; only the `lore_fragments`
/// row for the destination is added.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn copy_fragment() {
    let Some((pg, ep, bucket, region)) = env_config() else {
        eprintln!(
            "LORE_TEST_PG_URL / LORE_TEST_S3_ENDPOINT / LORE_TEST_S3_BUCKET unset; \
             skipping Postgres immutable-store test"
        );
        return;
    };
    let s = make_store(&pg, &ep, &bucket, &region).await;

    let src_partition: Partition = rand::random();
    let src_addr: Address = rand::random();
    let (_, payload) = put_fragment(s.clone(), src_partition, src_addr, 2048).await;

    let dst_partition: Partition = rand::random();
    let dst_context: Context = rand::random();

    s.clone()
        .copy(src_partition, src_addr, dst_partition, dst_context, false)
        .await
        .expect("copy");

    let dst_addr = Address {
        hash: src_addr.hash,
        context: dst_context,
    };
    let (_, payload_out) = get_payload(s.clone(), dst_partition, dst_addr)
        .await
        .expect("get after copy");
    assert_eq!(
        payload, payload_out,
        "copied fragment bytes must be identical to the original"
    );
    assert_eq!(
        s.clone()
            .repository_stats(dst_partition)
            .await
            .expect("destination repository stats after copy"),
        StoreRepositoryStats {
            fragment_count: 1,
            payload_bytes: 2048,
            content_bytes: 2048,
        },
        "copy must associate the existing projection with the destination repository"
    );

    // A zero source context is the partition-match form: any association of
    // this hash in the source partition is sufficient.
    let wildcard_dst_partition: Partition = rand::random();
    let wildcard_dst_context: Context = rand::random();
    let unassociated_partition: Partition = rand::random();
    let cross_partition_error = s
        .clone()
        .copy(
            unassociated_partition,
            Address {
                hash: src_addr.hash,
                context: Context::default(),
            },
            wildcard_dst_partition,
            wildcard_dst_context,
            false,
        )
        .await
        .expect_err("partition-match copy must not cross source partitions");
    assert!(cross_partition_error.is_address_not_found());

    s.clone()
        .copy(
            src_partition,
            Address {
                hash: src_addr.hash,
                context: Context::default(),
            },
            wildcard_dst_partition,
            wildcard_dst_context,
            false,
        )
        .await
        .expect("copy from partition match");
    let wildcard_dst_addr = Address {
        hash: src_addr.hash,
        context: wildcard_dst_context,
    };
    let (_, wildcard_payload) = get_payload(s, wildcard_dst_partition, wildcard_dst_addr)
        .await
        .expect("get after partition-match copy");
    assert_eq!(payload, wildcard_payload);
}

/// 6a. `obliterate` with a single association: after obliteration, `get` errors
///     and `query` returns `MatchNone`. Stats record one fragment and one payload
///     deleted.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn obliterate_single_association() {
    let Some((pg, ep, bucket, region)) = env_config() else {
        eprintln!(
            "LORE_TEST_PG_URL / LORE_TEST_S3_ENDPOINT / LORE_TEST_S3_BUCKET unset; \
             skipping Postgres immutable-store test"
        );
        return;
    };
    let s = make_store(&pg, &ep, &bucket, &region).await;

    let partition: Partition = rand::random();
    let address: Address = rand::random();
    put_fragment(s.clone(), partition, address, 1024).await;

    let stats = Arc::new(StoreObliterateStats::default());
    s.clone()
        .obliterate(partition, address, stats.clone())
        .await
        .expect("obliterate");

    // Association row deleted → get must error.
    assert!(
        get_payload(s.clone(), partition, address).await.is_err(),
        "get after obliterate must error"
    );

    // query must return MatchNone (association gone).
    let q = query_one(s.clone(), partition, address)
        .await
        .expect("query after obliterate must not panic");
    assert_eq!(
        q.match_made,
        StoreMatch::MatchNone,
        "query after obliterate must return MatchNone"
    );

    // Stats: one association and one payload deleted.
    assert_eq!(
        stats.num_fragments.load(Ordering::Relaxed),
        1,
        "obliterate must record 1 fragment association"
    );
    assert_eq!(
        stats.num_payloads.load(Ordering::Relaxed),
        1,
        "obliterate must record 1 payload deleted (sole association)"
    );
    assert_eq!(
        metering_fragment(&pg, address.hash).await,
        None,
        "last-association obliteration must remove the metering projection"
    );
}

/// 6b. `obliterate` with refcount: two associations to the same hash —
///     obliterating one leaves the other's bytes intact and still gettable.
///     The payload is NOT deleted because the refcount > 0.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn obliterate_refcount_keeps_other_association() {
    let Some((pg, ep, bucket, region)) = env_config() else {
        eprintln!(
            "LORE_TEST_PG_URL / LORE_TEST_S3_ENDPOINT / LORE_TEST_S3_BUCKET unset; \
             skipping Postgres immutable-store test"
        );
        return;
    };
    let s = make_store(&pg, &ep, &bucket, &region).await;

    let partition: Partition = rand::random();
    // Two addresses share the same hash but different contexts.
    let hash: Hash = rand::random();
    let addr1 = Address {
        hash,
        context: rand::random(),
    };
    let addr2 = Address {
        hash,
        context: rand::random(),
    };

    // Both puts supply payload proof. The second validates the existing object
    // and adds only the new association.
    let (frag, payload) = make_fragment_and_payload(1024);
    s.clone()
        .put(partition, addr1, frag, Some(payload.clone()), false)
        .await
        .expect("put addr1");
    s.clone()
        .put(partition, addr2, frag, Some(payload.clone()), false)
        .await
        .expect("put addr2 (same hash, different context)");

    // Obliterate only the first association.
    let stats = Arc::new(StoreObliterateStats::default());
    s.clone()
        .obliterate(partition, addr1, stats.clone())
        .await
        .expect("obliterate addr1");

    // addr1 gone.
    assert!(
        get_payload(s.clone(), partition, addr1).await.is_err(),
        "get addr1 after obliterate must error"
    );

    // addr2 still has its bytes intact.
    let (_, payload_out) = get_payload(s.clone(), partition, addr2)
        .await
        .expect("get addr2 after partial obliterate must succeed");
    assert_eq!(
        payload, payload_out,
        "addr2 bytes must be intact after obliteration of addr1"
    );

    // Payload NOT deleted (refcount > 0 after addr1 removed).
    assert_eq!(
        stats.num_fragments.load(Ordering::Relaxed),
        1,
        "one fragment association must be recorded as removed"
    );
    assert_eq!(
        stats.num_payloads.load(Ordering::Relaxed),
        0,
        "payload must NOT be deleted when other associations remain"
    );
    assert_eq!(
        metering_fragment(&pg, hash).await,
        Some(frag),
        "shared payloads retain their metering projection"
    );
}

/// Recursive obliteration must not retain a Postgres checkout while descending.
/// A chain much deeper than a one-connection pool completes instead of waiting
/// forever for its own connection.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn obliterate_deep_fragment_chain_with_one_connection_does_not_deadlock() {
    let Some((pg, ep, bucket, region)) = env_config() else {
        return;
    };
    let store = make_store_with_pool_max(&pg, &ep, &bucket, &region, 1).await;
    let partition: Partition = rand::random();
    let addresses = put_fragment_chain(store.clone(), partition, 3).await;
    let root = *addresses.last().expect("chain has a root");
    let stats = Arc::new(StoreObliterateStats::default());

    tokio::time::timeout(
        Duration::from_secs(15),
        store.clone().obliterate(partition, root, stats.clone()),
    )
    .await
    .expect("recursive obliteration self-deadlocked with a one-connection pool")
    .expect("obliterate deep fragment chain");

    assert_eq!(stats.num_fragments.load(Ordering::Relaxed), addresses.len());
    assert_eq!(stats.num_payloads.load(Ordering::Relaxed), addresses.len());
    for address in addresses {
        assert_eq!(fragment_state(&pg, address.hash).await, Some(256));
        assert_eq!(metering_fragment(&pg, address.hash).await, None);
    }
}

/// A process restart after publishing `Obliterating` must resume child
/// traversal from the still-present parent object and finish both payloads.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn obliterate_retry_from_obliterating_resumes_child_traversal() {
    let Some((pg, ep, bucket, region)) = env_config() else {
        return;
    };
    let store = make_store(&pg, &ep, &bucket, &region).await;
    let partition: Partition = rand::random();
    let addresses = put_fragment_chain(store.clone(), partition, 1).await;
    let child = addresses[0];
    let parent = addresses[1];
    seed_fragment_state(&pg, partition, parent, 512).await;
    let stats = Arc::new(StoreObliterateStats::default());

    store
        .clone()
        .obliterate(partition, parent, stats.clone())
        .await
        .expect("retry from Obliterating");

    assert_eq!(fragment_state(&pg, parent.hash).await, Some(256));
    assert_eq!(fragment_state(&pg, child.hash).await, Some(256));
    assert_eq!(metering_fragment(&pg, parent.hash).await, None);
    assert_eq!(metering_fragment(&pg, child.hash).await, None);
    assert_eq!(stats.num_fragments.load(Ordering::Relaxed), 1);
    assert_eq!(stats.num_payloads.load(Ordering::Relaxed), 2);
}

/// A process restart after child traversal must skip that traversal, resume
/// payload deletion, remove the projection, and publish `Obliterated`.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn obliterate_retry_from_payload_deleting_finishes_finalization() {
    let Some((pg, ep, bucket, region)) = env_config() else {
        return;
    };
    let store = make_store(&pg, &ep, &bucket, &region).await;
    let partition: Partition = rand::random();
    let address: Address = rand::random();
    put_fragment(store.clone(), partition, address, 1024).await;
    seed_fragment_state(&pg, partition, address, 1).await;
    let stats = Arc::new(StoreObliterateStats::default());

    store
        .clone()
        .obliterate(partition, address, stats.clone())
        .await
        .expect("retry from PayloadDeleting");

    assert_eq!(fragment_state(&pg, address.hash).await, Some(256));
    assert_eq!(metering_fragment(&pg, address.hash).await, None);
    assert!(
        make_s3(&ep, &region)
            .await
            .head_object(&bucket, &object_key(address.hash))
            .await
            .is_err(),
        "payload must be absent after finalization"
    );
    assert_eq!(stats.num_fragments.load(Ordering::Relaxed), 0);
    assert_eq!(stats.num_payloads.load(Ordering::Relaxed), 1);
}

/// Version deletion must drain more than one `ListObjectVersions` page and
/// leave neither historical versions nor delete markers behind.
#[tokio::test]
#[ignore = "needs live Postgres + version-capable S3 env; run with -- --ignored"]
#[serial]
async fn obliterate_deletes_more_than_one_thousand_object_versions() {
    let Some((pg, ep, _shared_bucket, region)) = env_config() else {
        return;
    };
    let s3 = make_s3(&ep, &region).await;
    let isolated_bucket = format!(
        "lore-versions-{}",
        &object_key(rand::random::<Hash>())[..20]
    );
    s3.sdk_client()
        .create_bucket()
        .bucket(&isolated_bucket)
        .send()
        .await
        .expect("create isolated versioning bucket");
    let versioning_enabled = VersioningConfiguration::builder()
        .status(BucketVersioningStatus::Enabled)
        .build();
    s3.sdk_client()
        .put_bucket_versioning()
        .bucket(&isolated_bucket)
        .versioning_configuration(versioning_enabled)
        .send()
        .await
        .expect("enable bucket versioning");
    let store = make_store(&pg, &ep, &isolated_bucket, &region).await;

    let partition: Partition = rand::random();
    let address: Address = rand::random();
    let (fragment, payload) = put_fragment(store.clone(), partition, address, 64).await;
    let key = object_key(address.hash);
    for _ in 0..1000 {
        s3.put_object(
            &isolated_bucket,
            &key,
            payload.clone(),
            Some(to_object_metadata(&fragment)),
        )
        .await
        .expect("append object version");
    }

    let before = s3
        .sdk_client()
        .list_object_versions()
        .bucket(&isolated_bucket)
        .prefix(&key)
        .send()
        .await
        .expect("list first version page");
    assert_eq!(before.versions().len(), 1000, "first page must be full");
    assert!(before.is_truncated().unwrap_or(false));

    let result = store
        .clone()
        .obliterate(
            partition,
            address,
            Arc::new(StoreObliterateStats::default()),
        )
        .await;
    let after = s3
        .sdk_client()
        .list_object_versions()
        .bucket(&isolated_bucket)
        .prefix(&key)
        .send()
        .await
        .expect("list versions after obliteration");
    let cleanup = s3
        .sdk_client()
        .delete_bucket()
        .bucket(&isolated_bucket)
        .send()
        .await;

    result.expect("obliterate versioned payload");
    assert!(after.versions().is_empty(), "historical versions remain");
    assert!(after.delete_markers().is_empty(), "delete markers remain");
    if let Err(error) = cleanup {
        eprintln!("best-effort isolated bucket cleanup failed: {error}");
    }
}

/// A new association racing the old association's obliteration must either
/// preserve or resurrect the shared object atomically. The new association is
/// never allowed to point at deleted bytes.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn put_racing_last_association_obliterate_preserves_a_complete_payload() {
    let Some((pg, ep, bucket, region)) = env_config() else {
        eprintln!(
            "LORE_TEST_PG_URL / LORE_TEST_S3_ENDPOINT / LORE_TEST_S3_BUCKET unset; \
             skipping Postgres immutable-store test"
        );
        return;
    };
    let store = make_store(&pg, &ep, &bucket, &region).await;
    let source_partition: Partition = rand::random();
    let destination_partition: Partition = rand::random();
    let source_address: Address = rand::random();
    let destination_address = Address {
        hash: source_address.hash,
        context: rand::random(),
    };
    let (fragment, payload) =
        put_fragment(store.clone(), source_partition, source_address, 1024).await;
    let expected_payload = payload.clone();
    let barrier = Arc::new(tokio::sync::Barrier::new(2));

    let put = {
        let store = store.clone();
        let barrier = barrier.clone();
        async move {
            barrier.wait().await;
            store
                .put(
                    destination_partition,
                    destination_address,
                    fragment,
                    Some(payload),
                    false,
                )
                .await
        }
    };
    let obliterate = {
        let store = store.clone();
        let barrier = barrier.clone();
        async move {
            barrier.wait().await;
            store
                .obliterate(
                    source_partition,
                    source_address,
                    Arc::new(StoreObliterateStats::default()),
                )
                .await
        }
    };
    let (put_result, obliterate_result) = tokio::join!(put, obliterate);

    obliterate_result.expect("source obliteration");
    if let Err(error) = put_result {
        assert!(
            error.is_slow_down(),
            "racing put may only fail transiently, got {error:?}"
        );
        store
            .clone()
            .put(
                destination_partition,
                destination_address,
                fragment,
                Some(expected_payload.clone()),
                false,
            )
            .await
            .expect("put retry after obliteration must resurrect the payload");
    }
    assert_eq!(
        query_one(store.clone(), source_partition, source_address)
            .await
            .expect("check source association")
            .match_made,
        StoreMatch::MatchNone
    );
    let (stored_fragment, stored_payload) =
        get_payload(store.clone(), destination_partition, destination_address)
            .await
            .expect("new association must have complete bytes");
    assert_eq!(stored_fragment, stored_durable(fragment));
    assert_eq!(stored_payload, expected_payload);
    assert_eq!(
        metering_fragment(&pg, source_address.hash).await,
        Some(fragment)
    );
}

/// Copy racing the source's last-association obliteration has two valid
/// serializations: copy wins and preserves the object, or obliterate wins and
/// copy reports absence. Neither may leave a destination association to
/// deleted bytes.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn copy_racing_last_association_obliterate_never_dangles() {
    let Some((pg, ep, bucket, region)) = env_config() else {
        eprintln!(
            "LORE_TEST_PG_URL / LORE_TEST_S3_ENDPOINT / LORE_TEST_S3_BUCKET unset; \
             skipping Postgres immutable-store test"
        );
        return;
    };
    let store = make_store(&pg, &ep, &bucket, &region).await;
    let source_partition: Partition = rand::random();
    let destination_partition: Partition = rand::random();
    let source_address: Address = rand::random();
    let destination_context: Context = rand::random();
    let destination_address = Address {
        hash: source_address.hash,
        context: destination_context,
    };
    let (fragment, _) = put_fragment(store.clone(), source_partition, source_address, 1024).await;
    let barrier = Arc::new(tokio::sync::Barrier::new(2));

    let copy = {
        let store = store.clone();
        let barrier = barrier.clone();
        async move {
            barrier.wait().await;
            store
                .copy(
                    source_partition,
                    source_address,
                    destination_partition,
                    destination_context,
                    false,
                )
                .await
        }
    };
    let obliterate = {
        let store = store.clone();
        let barrier = barrier.clone();
        async move {
            barrier.wait().await;
            store
                .obliterate(
                    source_partition,
                    source_address,
                    Arc::new(StoreObliterateStats::default()),
                )
                .await
        }
    };
    let (copy_result, obliterate_result) = tokio::join!(copy, obliterate);
    obliterate_result.expect("source obliteration");

    let destination_match = query_one(store.clone(), destination_partition, destination_address)
        .await
        .expect("check destination association");
    if copy_result.is_ok() {
        assert_eq!(destination_match.match_made, StoreMatch::MatchFull);
        let (stored_fragment, _) =
            get_payload(store.clone(), destination_partition, destination_address)
                .await
                .expect("successful copy must retain bytes");
        assert_eq!(stored_fragment, stored_durable(fragment));
        assert_eq!(
            metering_fragment(&pg, source_address.hash).await,
            Some(fragment)
        );
    } else {
        assert_eq!(destination_match.match_made, StoreMatch::MatchNone);
        assert_eq!(metering_fragment(&pg, source_address.hash).await, None);
    }
}

/// 7. `get` on a never-put address returns an error (AddressNotFound-style),
///    not a panic.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn get_never_put_address_errors() {
    let Some((pg, ep, bucket, region)) = env_config() else {
        eprintln!(
            "LORE_TEST_PG_URL / LORE_TEST_S3_ENDPOINT / LORE_TEST_S3_BUCKET unset; \
             skipping Postgres immutable-store test"
        );
        return;
    };
    let s = make_store(&pg, &ep, &bucket, &region).await;

    let partition: Partition = rand::random();
    let address: Address = rand::random();

    let result = get_payload(s, partition, address).await;
    assert!(
        result.is_err(),
        "get on a never-put address must return an error, not Ok"
    );
}

/// 8. Batched `query` (B3) — order preservation and correctness.
///
/// The B3 rewrite collapses N per-address probes into a single
/// `hash = ANY($1)` query and reconstructs the per-index result from a
/// `HashSet`. This test verifies that the reconstruction preserves input order
/// even when present and absent addresses are interleaved, and that the empty
/// input short-circuit works.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn query_batch_order_preservation() {
    let Some((pg, ep, bucket, region)) = env_config() else {
        eprintln!(
            "LORE_TEST_PG_URL / LORE_TEST_S3_ENDPOINT / LORE_TEST_S3_BUCKET unset; \
             skipping Postgres immutable-store test"
        );
        return;
    };
    let s = make_store(&pg, &ep, &bucket, &region).await;

    let partition: Partition = rand::random();

    // Three distinct present addresses.
    let present0: Address = rand::random();
    let present1: Address = rand::random();
    let present2: Address = rand::random();
    // Two addresses never put.
    let absent0: Address = rand::random();
    let absent1: Address = rand::random();

    put_fragment(s.clone(), partition, present0, 256).await;
    put_fragment(s.clone(), partition, present1, 256).await;
    put_fragment(s.clone(), partition, present2, 256).await;

    // Interleaved slice: [present0, absent0, present1, absent1, present2].
    let addresses = [present0, absent0, present1, absent1, present2];

    // Exact associations report the best match rather than confirming a requested level.
    let results = query_addresses(s.clone(), partition, &addresses)
        .await
        .expect("batch query");

    assert_eq!(
        results.len(),
        5,
        "result length must equal address slice length"
    );
    assert_eq!(
        results[0].match_made,
        StoreMatch::MatchFull,
        "present0 → MatchFull"
    );
    assert_eq!(
        results[1].match_made,
        StoreMatch::MatchNone,
        "absent0 → MatchNone"
    );
    assert_eq!(
        results[2].match_made,
        StoreMatch::MatchFull,
        "present1 → MatchFull"
    );
    assert_eq!(
        results[3].match_made,
        StoreMatch::MatchNone,
        "absent1 → MatchNone"
    );
    assert_eq!(
        results[4].match_made,
        StoreMatch::MatchFull,
        "present2 → MatchFull"
    );

    // --- empty input short-circuit ---
    let empty_results = query_addresses(s.clone(), partition, &[])
        .await
        .expect("empty batch query");
    assert!(
        empty_results.is_empty(),
        "empty address slice must return empty Vec"
    );

    // --- MatchFull batch: same hash, different context ---
    // put at (hash, ctxA); query over [(hash,ctxA), (hash,ctxB)].
    // Only the exact (hash, context) pair matches; the other context returns MatchNone.
    let hash: Hash = rand::random();
    let ctx_a: Context = rand::random();
    let ctx_b: Context = rand::random();
    let addr_a = Address {
        hash,
        context: ctx_a,
    };
    let addr_b = Address {
        hash,
        context: ctx_b,
    };
    put_fragment(s.clone(), partition, addr_a, 256).await;

    let full_results = query_addresses(s.clone(), partition, &[addr_a, addr_b])
        .await
        .expect("exact batch query");

    assert_eq!(full_results.len(), 2, "MatchFull result length must be 2");
    assert_eq!(
        full_results[0].match_made,
        StoreMatch::MatchFull,
        "addr_a (exact match) → MatchFull"
    );
    assert_eq!(
        full_results[1].match_made,
        StoreMatch::MatchNone,
        "addr_b (same hash, different context) → MatchNone"
    );
}

/// 9. `repository_stats` on a repository with no fragment associations
///    reports all-zero stats, not an error — an unknown repository has no
///    associations, which is the intended CR-016 semantic, not a bug.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn repository_stats_unknown_repository_reports_zeroes() {
    let Some((pg, ep, bucket, region)) = env_config() else {
        eprintln!(
            "LORE_TEST_PG_URL / LORE_TEST_S3_ENDPOINT / LORE_TEST_S3_BUCKET unset; \
             skipping Postgres immutable-store test"
        );
        return;
    };
    let s = make_store(&pg, &ep, &bucket, &region).await;

    let partition: Partition = rand::random();
    let stats = s
        .clone()
        .repository_stats(partition)
        .await
        .expect("repository_stats on an unknown repository must not error");

    assert_eq!(
        stats,
        StoreRepositoryStats::default(),
        "an unknown repository must report all-zero stats"
    );
}

/// 10. `repository_stats` sums `fragment_count` / `payload_bytes` /
///     `content_bytes` over several distinct fragments put into one
///     repository.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn repository_stats_sums_multiple_fragments() {
    let Some((pg, ep, bucket, region)) = env_config() else {
        eprintln!(
            "LORE_TEST_PG_URL / LORE_TEST_S3_ENDPOINT / LORE_TEST_S3_BUCKET unset; \
             skipping Postgres immutable-store test"
        );
        return;
    };
    let s = make_store(&pg, &ep, &bucket, &region).await;

    let partition: Partition = rand::random();
    let sizes = [512u32, 1024, 4096];
    for &size in &sizes {
        let address: Address = rand::random();
        put_fragment(s.clone(), partition, address, size).await;
    }

    let stats = s
        .clone()
        .repository_stats(partition)
        .await
        .expect("repository_stats over a populated repository");

    let expected_total: u64 = sizes.iter().map(|&size| size as u64).sum();
    assert_eq!(stats.fragment_count, 3, "one distinct hash per put");
    assert_eq!(
        stats.payload_bytes, expected_total,
        "payload_bytes must sum the put sizes"
    );
    assert_eq!(
        stats.content_bytes, expected_total,
        "content_bytes must sum the put sizes (uncompressed fixture: content == payload)"
    );
}

/// 11. Deduplication WITHIN a repository: the same hash associated under two
///     different contexts in the same repository is counted ONCE — this is
///     what the query's `SELECT DISTINCT hash` subquery exists for, and the
///     assertion most likely to catch a regression if that subquery is
///     "simplified" away.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn repository_stats_deduplicates_same_hash_multiple_contexts() {
    let Some((pg, ep, bucket, region)) = env_config() else {
        eprintln!(
            "LORE_TEST_PG_URL / LORE_TEST_S3_ENDPOINT / LORE_TEST_S3_BUCKET unset; \
             skipping Postgres immutable-store test"
        );
        return;
    };
    let s = make_store(&pg, &ep, &bucket, &region).await;

    let partition: Partition = rand::random();
    let (frag, payload) = make_fragment_and_payload(2048);
    let addr1: Address = rand::random();
    let addr2 = Address {
        hash: addr1.hash,
        context: rand::random(),
    };

    s.clone()
        .put(partition, addr1, frag, Some(payload.clone()), false)
        .await
        .expect("put addr1");
    // Same partition, same hash, different context, WITH payload — the only
    // reachable path for a second association to an existing hash in this
    // implementation (see `dedup_same_partition_requires_payload` above).
    s.clone()
        .put(partition, addr2, frag, Some(payload), false)
        .await
        .expect("put addr2 (dedup within the same repository)");

    let stats = s
        .clone()
        .repository_stats(partition)
        .await
        .expect("repository_stats");

    assert_eq!(
        stats.fragment_count, 1,
        "the same hash under two contexts must count once, not twice"
    );
    assert_eq!(
        stats.payload_bytes, 2048,
        "bytes must not be double-counted for the deduped hash"
    );
    assert_eq!(
        stats.content_bytes, 2048,
        "bytes must not be double-counted for the deduped hash"
    );
}

/// 12. Cross-repository isolation, alongside the intended global-dedup
///     metering semantic (CR-016 requirement 3): a hash shared by two
///     repositories is counted IN FULL for each one, so summing across
///     repositories exceeds the bytes actually held in the bucket. That is
///     the intended metering semantic, asserted here rather than treated as
///     a bug.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn repository_stats_isolates_repositories_but_double_counts_a_shared_hash() {
    let Some((pg, ep, bucket, region)) = env_config() else {
        eprintln!(
            "LORE_TEST_PG_URL / LORE_TEST_S3_ENDPOINT / LORE_TEST_S3_BUCKET unset; \
             skipping Postgres immutable-store test"
        );
        return;
    };
    let s = make_store(&pg, &ep, &bucket, &region).await;

    let partition_a: Partition = rand::random();
    let partition_b: Partition = rand::random();
    let (shared_frag, shared_payload) = make_fragment_and_payload(1024);
    let addr_a: Address = rand::random();
    let addr_b = Address {
        hash: addr_a.hash,
        context: rand::random(),
    };

    s.clone()
        .put(
            partition_a,
            addr_a,
            shared_frag,
            Some(shared_payload.clone()),
            false,
        )
        .await
        .expect("put shared hash into repo A");
    // Cross-partition, same hash, WITH payload proof — validates the existing
    // object and adds a new association scoped to repo B. See
    // `dedup_cross_partition_no_payload_errors` for the no-payload counterpart.
    s.clone()
        .put(
            partition_b,
            addr_b,
            shared_frag,
            Some(shared_payload),
            false,
        )
        .await
        .expect("put shared hash into repo B");

    // A fragment unique to repo B, to prove it does not leak into repo A's numbers.
    let extra_address: Address = rand::random();
    put_fragment(s.clone(), partition_b, extra_address, 2048).await;

    let stats_a = s
        .clone()
        .repository_stats(partition_a)
        .await
        .expect("repository_stats A");
    let stats_b = s
        .clone()
        .repository_stats(partition_b)
        .await
        .expect("repository_stats B");

    assert_eq!(
        stats_a.fragment_count, 1,
        "repo A must see only the hash it shares with repo B, not repo B's extra fragment"
    );
    assert_eq!(stats_a.payload_bytes, 1024);
    assert_eq!(stats_a.content_bytes, 1024);

    assert_eq!(
        stats_b.fragment_count, 2,
        "repo B must see the shared hash plus its own extra fragment"
    );
    assert_eq!(
        stats_b.payload_bytes,
        1024 + 2048,
        "repo B's sum includes the shared hash in full, not half"
    );
    assert_eq!(stats_b.content_bytes, 1024 + 2048);
}

/// 13. A missing metering projection row is repaired from authoritative S3
///     metadata before repository statistics are aggregated.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn repository_stats_repairs_a_missing_metering_row_from_s3() {
    let Some((pg, ep, bucket, region)) = env_config() else {
        eprintln!(
            "LORE_TEST_PG_URL / LORE_TEST_S3_ENDPOINT / LORE_TEST_S3_BUCKET unset; \
             skipping Postgres immutable-store test"
        );
        return;
    };
    let s = make_store(&pg, &ep, &bucket, &region).await;

    let partition: Partition = rand::random();
    let address: Address = rand::random();
    let (fragment, _) = put_fragment(s.clone(), partition, address, 2048).await;
    delete_metering_row(&pg, address.hash).await;
    assert_eq!(
        metering_fragment(&pg, address.hash).await,
        None,
        "test setup must remove only the projection row"
    );

    let stats = s
        .clone()
        .repository_stats(partition)
        .await
        .expect("repository_stats must repair projection loss");

    assert_eq!(
        stats,
        StoreRepositoryStats {
            fragment_count: 1,
            payload_bytes: 2048,
            content_bytes: 2048,
        },
        "stats must be exact after self-healing"
    );
    assert_eq!(
        metering_fragment(&pg, address.hash).await,
        Some(fragment),
        "the repaired projection must match authoritative object metadata"
    );
}

/// A full rebuild reconciles every distinct associated hash and removes
/// projection rows that no repository/context association references.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn rebuild_metering_projection_repairs_missing_and_removes_orphans() {
    let Some((pg, ep, bucket, region)) = env_config() else {
        eprintln!(
            "LORE_TEST_PG_URL / LORE_TEST_S3_ENDPOINT / LORE_TEST_S3_BUCKET unset; \
             skipping Postgres immutable-store test"
        );
        return;
    };
    let store = make_store(&pg, &ep, &bucket, &region).await;
    let partition: Partition = rand::random();
    let address_a: Address = rand::random();
    let address_b: Address = rand::random();
    let (fragment_a, _) = put_fragment(store.clone(), partition, address_a, 1024).await;
    let (fragment_b, _) = put_fragment(store.clone(), partition, address_b, 4096).await;
    delete_metering_row(&pg, address_a.hash).await;

    let orphan_hash: Hash = rand::random();
    let client = pg_client(&pg).await;
    client
        .execute(
            "INSERT INTO lore_fragment_metering (hash, payload_flags, size_payload, size_content) \
             VALUES ($1, 0, 9, 9)",
            &[&orphan_hash.data().as_slice()],
        )
        .await
        .expect("insert orphan metering row");
    let expected_reconciled: i64 = client
        .query_one("SELECT COUNT(DISTINCT hash) FROM lore_fragments", &[])
        .await
        .expect("count associated hashes before rebuild")
        .get(0);

    let reconciled = store
        .rebuild_metering_projection()
        .await
        .expect("rebuild metering projection");

    assert_eq!(
        reconciled, expected_reconciled as u64,
        "the rebuild result must equal all distinct currently associated hashes"
    );
    assert_eq!(
        metering_fragment(&pg, address_a.hash).await,
        Some(fragment_a)
    );
    assert_eq!(
        metering_fragment(&pg, address_b.hash).await,
        Some(fragment_b)
    );
    assert_eq!(
        metering_fragment(&pg, orphan_hash).await,
        None,
        "unassociated projection rows must be removed"
    );
}

/// Rebuild is one transaction: if a later authoritative object is malformed,
/// projection rows repaired earlier in hash order must roll back too.
#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
#[serial]
async fn rebuild_metering_projection_rolls_back_on_malformed_object() {
    let Some((pg, ep, bucket, region)) = env_config() else {
        eprintln!(
            "LORE_TEST_PG_URL / LORE_TEST_S3_ENDPOINT / LORE_TEST_S3_BUCKET unset; \
             skipping Postgres immutable-store test"
        );
        return;
    };
    let store = make_store(&pg, &ep, &bucket, &region).await;
    let partition: Partition = rand::random();
    let address_a: Address = rand::random();
    let address_b: Address = rand::random();
    let (_, payload_a) = put_fragment(store.clone(), partition, address_a, 1024).await;
    let (_, payload_b) = put_fragment(store.clone(), partition, address_b, 1024).await;
    let (valid_address, corrupt_address, corrupt_payload) =
        if address_a.hash.data() < address_b.hash.data() {
            (address_a, address_b, payload_b)
        } else {
            (address_b, address_a, payload_a)
        };
    delete_metering_row(&pg, valid_address.hash).await;
    delete_metering_row(&pg, corrupt_address.hash).await;
    let malformed = std::collections::HashMap::from([(
        "lore-fragment".to_string(),
        "not:a:fragment".to_string(),
    )]);
    make_s3(&ep, &region)
        .await
        .put_object(
            &bucket,
            &object_key(corrupt_address.hash),
            corrupt_payload,
            Some(malformed),
        )
        .await
        .expect("corrupt later authoritative object");

    let rebuild = store.rebuild_metering_projection().await;
    let valid_projection = metering_fragment(&pg, valid_address.hash).await;
    let corrupt_projection = metering_fragment(&pg, corrupt_address.hash).await;
    delete_hash_rows(&pg, valid_address.hash).await;
    delete_hash_rows(&pg, corrupt_address.hash).await;

    let error = rebuild.expect_err("malformed object must fail rebuild");
    assert!(error.is_internal(), "expected Internal, got {error:?}");
    assert_eq!(
        valid_projection, None,
        "earlier projection repair must roll back"
    );
    assert_eq!(corrupt_projection, None);
}

/// Fresh schema carries only association, lifecycle, and metering tables. The
/// former authoritative Postgres metadata table must not be recreated.
#[tokio::test]
#[ignore = "needs a fresh live Postgres schema (see module docs); run with -- --ignored"]
#[serial]
async fn fresh_schema_does_not_create_the_old_fragment_metadata_table() {
    let Some((pg, ep, bucket, region)) = env_config() else {
        eprintln!(
            "LORE_TEST_PG_URL / LORE_TEST_S3_ENDPOINT / LORE_TEST_S3_BUCKET unset; \
             skipping Postgres immutable-store test"
        );
        return;
    };
    let client = pg_client(&pg).await;
    client
        .execute("DROP TABLE IF EXISTS lore_fragment_metadata", &[])
        .await
        .expect("remove legacy table before fresh-schema bootstrap");
    let _store = make_store(&pg, &ep, &bucket, &region).await;
    let row = client
        .query_one(
            "SELECT to_regclass('public.lore_fragment_metadata')::text AS old_table, \
                    to_regclass('public.lore_fragment_state')::text AS state_table, \
                    to_regclass('public.lore_fragment_metering')::text AS metering_table",
            &[],
        )
        .await
        .expect("inspect fresh immutable schema");

    let old_table: Option<String> = row.get("old_table");
    let state_table: Option<String> = row.get("state_table");
    let metering_table: Option<String> = row.get("metering_table");
    assert_eq!(
        old_table, None,
        "old authoritative PG metadata table remains"
    );
    assert_eq!(state_table.as_deref(), Some("lore_fragment_state"));
    assert_eq!(metering_table.as_deref(), Some("lore_fragment_metering"));
}

// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Integration tests for the Postgres-backed immutable store (CR-007).
//!
//! Fragment **metadata** lives in Postgres (`lore_fragments` +
//! `lore_fragment_metadata`); fragment **bytes** live in an S3-compatible
//! object store (MinIO / LocalStack / DO Spaces).
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
//! cargo test -p lore-postgres --test immutable_store
//! ```
//!
//! Gated on `LORE_TEST_PG_URL`, `LORE_TEST_S3_ENDPOINT`, and
//! `LORE_TEST_S3_BUCKET`. If any is unset, each test prints a skip line and
//! returns immediately so plain `cargo test` needs no running infra.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use bytes::Bytes;
use lore_postgres::store::immutable_store::ObjectStoreSettings;
use lore_postgres::store::immutable_store::PostgresImmutableStore;
use lore_storage::Address;
use lore_storage::Context;
use lore_storage::Fragment;
use lore_storage::Hash;
use lore_storage::ImmutableStore;
use lore_storage::Partition;
use lore_storage::StoreMatch;
use lore_storage::StoreObliterateStats;
use lore_storage::StoreRepositoryStats;
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

/// Delete a fragment's `lore_fragment_metadata` row directly over a
/// throwaway connection, bypassing `PostgresImmutableStore`'s own API (which
/// never leaves an association without its metadata row on its own — `put`
/// writes both in one transaction). Used to construct an "association
/// present, metadata absent" state for the inner-join test below; that state
/// can arise operationally (e.g. a partial/aborted cleanup) even though this
/// store never produces it itself.
async fn delete_metadata_row(pg_url: &str, hash: Hash) {
    let (client, connection) = tokio_postgres::connect(pg_url, tokio_postgres::NoTls)
        .await
        .expect("connect for direct metadata delete");
    lore_base::lore_spawn!(async move {
        if let Err(e) = connection.await {
            eprintln!("direct postgres connection error: {e}");
        }
    });
    client
        .execute(
            "DELETE FROM lore_fragment_metadata WHERE hash = $1",
            &[&hash.data().as_slice()],
        )
        .await
        .expect("delete metadata row");
}

// ─── shared test helpers ──────────────────────────────────────────────────────

/// Build and connect a `PostgresImmutableStore` with test-friendly settings.
async fn make_store(
    pg_url: &str,
    s3_endpoint: &str,
    s3_bucket: &str,
    s3_region: &str,
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
            5,
            &lore_postgres::pool::TlsConfig::default(),
            settings,
        )
        .await
        .expect("connect + schema + S3 client"),
    )
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

// ─── tests ────────────────────────────────────────────────────────────────────

/// 1. Round-trip / byte-perfect: `put` then `get` returns an identical
///    `Fragment` and byte-exact payload.
///
/// Uses a 200 KB payload to exercise the S3 streaming read path while staying
/// under the 256 KB `FRAGMENT_SIZE_THRESHOLD`.
#[tokio::test]
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

    let (frag_out, payload_out) = s
        .clone()
        .get(partition, address, StoreMatch::MatchFull)
        .await
        .expect("get after put");

    assert_eq!(
        frag_in, frag_out,
        "Fragment metadata must round-trip unchanged"
    );
    assert_eq!(
        payload_in, payload_out,
        "Payload bytes must be bit-for-bit identical after round-trip"
    );
}

/// 2. Existence levels.
///
/// After a full put:
/// - `exist(MatchFull)` on the exact address → `MatchFull`.
/// - `exist(MatchHash)` for the same hash under a DIFFERENT partition → `MatchHash`
///   (global dedup: hash is visible across partitions via the index on `hash` alone).
/// - `exist(MatchFull)` for a random never-put hash → `MatchNone`.
/// - `query` returns the stored `Fragment` with `match_made == MatchFull`.
#[tokio::test]
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
    let m = s
        .clone()
        .exist(partition, address, StoreMatch::MatchFull)
        .await
        .expect("exist MatchFull");
    assert_eq!(m, StoreMatch::MatchFull, "exact address must be MatchFull");

    // The hash is globally visible — a different partition with MatchHash finds it.
    let other_partition: Partition = rand::random();
    let m_hash = s
        .clone()
        .exist(other_partition, address, StoreMatch::MatchHash)
        .await
        .expect("exist MatchHash cross-partition");
    assert_eq!(
        m_hash,
        StoreMatch::MatchHash,
        "same hash under different partition must be MatchHash (global dedup)"
    );

    // A never-put hash is absent at every level.
    let absent = Address {
        hash: rand::random(),
        context: rand::random(),
    };
    let m_absent = s
        .clone()
        .exist(partition, absent, StoreMatch::MatchFull)
        .await
        .expect("exist absent MatchFull");
    assert_eq!(
        m_absent,
        StoreMatch::MatchNone,
        "never-put hash must be MatchNone"
    );

    // query returns the correct fragment with the right match_made.
    let q = s
        .clone()
        .query(partition, address, StoreMatch::MatchFull)
        .await
        .expect("query");
    assert_eq!(q.match_made, StoreMatch::MatchFull, "query match_made");
    assert_eq!(q.fragment.size_payload, 1024, "query fragment size_payload");
    assert_eq!(q.fragment.size_content, 1024, "query fragment size_content");
    assert_eq!(q.fragment.flags, 0, "query fragment flags");
}

/// 3. Dedup behavior — same partition, same hash, different context.
///
/// IMPLEMENTATION FINDING: The `lookup` in this Postgres implementation calls
/// `do_query` with `MatchFull` and short-circuits a `MatchFull` miss to
/// `MatchNone` (the comment reads: "there is no partial-upload support, so
/// there is no benefit to probing coarser granularities"). This means the
/// `MatchPartition` arm of `put`'s match is unreachable: even if the hash
/// exists in the same partition under a different context, `lookup` returns
/// `MatchNone`, which with `payload = None` hits the `Err("Payload buffer
/// required")` arm.
///
/// The test below documents the actual behavior:
/// - Same partition, same hash, different context, NO payload → error.
/// - Same partition, same hash, different context, WITH payload → succeeds
///   (re-uploads to S3 idempotently, records the new association).
///
/// This finding is reported to the main session; the spec's "MatchPartition
/// path" description does not match the current implementation.
#[tokio::test]
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

    // Same partition, same hash, new context — WITHOUT payload. The MatchPartition
    // arm is unreachable so this must error with "Payload buffer required".
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

    // Same partition, same hash, new context WITH payload → succeeds
    // (re-uploads the same S3 key idempotently, adds the new association row).
    s.clone()
        .put(partition, addr2, frag, Some(payload.clone()), false)
        .await
        .expect("same-partition same-hash different-context put WITH payload must succeed");

    let (_, payload_out) = s
        .clone()
        .get(partition, addr2, StoreMatch::MatchFull)
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
/// The hash exists globally (MatchHash level) but `lookup(MatchFull)` returns
/// `MatchNone` on a full-miss, so `put` with `payload = None` errors.
#[tokio::test]
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

/// 4. `exist_batch` over a mix of present and absent addresses returns the
///    per-index matches in the correct order.
#[tokio::test]
#[serial]
async fn exist_batch_mixed() {
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
    let results = s
        .clone()
        .exist_batch(partition, &addresses, StoreMatch::MatchFull)
        .await
        .expect("exist_batch");

    assert_eq!(results.len(), 3, "result count must match address count");
    assert_eq!(results[0], StoreMatch::MatchFull, "present1 → MatchFull");
    assert_eq!(results[1], StoreMatch::MatchNone, "absent → MatchNone");
    assert_eq!(results[2], StoreMatch::MatchFull, "present2 → MatchFull");
}

/// 5. `copy`: put a fragment, copy it to a new (partition, context), then
///    confirm `get` on the destination returns the same bytes.
///
/// Copy is a pure association write — the bytes and metadata are already in
/// the shared bucket and Postgres keyed by hash; only the `lore_fragments`
/// row for the destination is added.
#[tokio::test]
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
    let (_, payload_out) = s
        .clone()
        .get(dst_partition, dst_addr, StoreMatch::MatchFull)
        .await
        .expect("get after copy");
    assert_eq!(
        payload, payload_out,
        "copied fragment bytes must be identical to the original"
    );
}

/// 6a. `obliterate` with a single association: after obliteration, `get` errors
///     and `query` returns `MatchNone`. Stats record one fragment and one payload
///     deleted.
#[tokio::test]
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
        s.clone()
            .get(partition, address, StoreMatch::MatchFull)
            .await
            .is_err(),
        "get after obliterate must error"
    );

    // query must return MatchNone (association gone).
    let q = s
        .clone()
        .query(partition, address, StoreMatch::MatchFull)
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
}

/// 6b. `obliterate` with refcount: two associations to the same hash —
///     obliterating one leaves the other's bytes intact and still gettable.
///     The payload is NOT deleted because the refcount > 0.
#[tokio::test]
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

    // Both puts require payload (MatchPartition path unreachable).
    // The second S3 upload is idempotent — same key, same bytes.
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
        s.clone()
            .get(partition, addr1, StoreMatch::MatchFull)
            .await
            .is_err(),
        "get addr1 after obliterate must error"
    );

    // addr2 still has its bytes intact.
    let (_, payload_out) = s
        .clone()
        .get(partition, addr2, StoreMatch::MatchFull)
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
}

/// 7. `get` on a never-put address returns an error (AddressNotFound-style),
///    not a panic.
#[tokio::test]
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

    let result = s
        .clone()
        .get(partition, address, StoreMatch::MatchFull)
        .await;
    assert!(
        result.is_err(),
        "get on a never-put address must return an error, not Ok"
    );
}

/// 8. `exist_batch` (B3 batched query) — order preservation and correctness.
///
/// The B3 rewrite collapses N per-address probes into a single
/// `hash = ANY($1)` query and reconstructs the per-index result from a
/// `HashSet`. This test verifies that the reconstruction preserves input order
/// even when present and absent addresses are interleaved, and that the empty
/// input short-circuit works.
#[tokio::test]
#[serial]
async fn exist_batch_order_preservation() {
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

    // --- MatchHash batch ---
    // MatchHash is global (no partition filter) so any put hash in the DB
    // returns MatchHash regardless of which partition it was stored under.
    let results = s
        .clone()
        .exist_batch(partition, &addresses, StoreMatch::MatchHash)
        .await
        .expect("exist_batch MatchHash");

    assert_eq!(
        results.len(),
        5,
        "result length must equal address slice length"
    );
    assert_eq!(results[0], StoreMatch::MatchHash, "present0 → MatchHash");
    assert_eq!(results[1], StoreMatch::MatchNone, "absent0 → MatchNone");
    assert_eq!(results[2], StoreMatch::MatchHash, "present1 → MatchHash");
    assert_eq!(results[3], StoreMatch::MatchNone, "absent1 → MatchNone");
    assert_eq!(results[4], StoreMatch::MatchHash, "present2 → MatchHash");

    // --- empty input short-circuit ---
    let empty_results = s
        .clone()
        .exist_batch(partition, &[], StoreMatch::MatchHash)
        .await
        .expect("exist_batch empty MatchHash");
    assert!(
        empty_results.is_empty(),
        "empty address slice must return empty Vec"
    );

    // --- MatchFull batch: same hash, different context ---
    // put at (hash, ctxA); exist_batch MatchFull over [(hash,ctxA), (hash,ctxB)].
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

    let full_results = s
        .clone()
        .exist_batch(partition, &[addr_a, addr_b], StoreMatch::MatchFull)
        .await
        .expect("exist_batch MatchFull");

    assert_eq!(full_results.len(), 2, "MatchFull result length must be 2");
    assert_eq!(
        full_results[0],
        StoreMatch::MatchFull,
        "addr_a (exact match) → MatchFull"
    );
    assert_eq!(
        full_results[1],
        StoreMatch::MatchNone,
        "addr_b (same hash, different context) → MatchNone"
    );
}

/// 9. `repository_stats` on a repository with no fragment associations
///    reports all-zero stats, not an error — an unknown repository has no
///    associations, which is the intended CR-016 semantic, not a bug.
#[tokio::test]
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
    // Cross-partition, same hash, WITH payload — succeeds (idempotent
    // re-upload to the same S3 key, plus a new association row scoped to
    // repo B; see `dedup_cross_partition_no_payload_errors` for the
    // no-payload counterpart that errors instead).
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

/// 13. Inner-join semantic: an association row (`lore_fragments`) with no
///     matching `lore_fragment_metadata` row is excluded from the aggregate
///     entirely — not just from the byte sums but from `fragment_count` too.
///     The query's `JOIN … USING (hash)` (not a `LEFT JOIN`) drops the whole
///     row rather than leaving a null-sized entry, so the three returned
///     figures stay internally consistent (a `fragment_count` that doesn't
///     match what its own sums account for would be worse than an
///     under-count).
#[tokio::test]
#[serial]
async fn repository_stats_excludes_an_association_with_no_metadata_row() {
    let Some((pg, ep, bucket, region)) = env_config() else {
        eprintln!(
            "LORE_TEST_PG_URL / LORE_TEST_S3_ENDPOINT / LORE_TEST_S3_BUCKET unset; \
             skipping Postgres immutable-store test"
        );
        return;
    };
    let s = make_store(&pg, &ep, &bucket, &region).await;

    let partition: Partition = rand::random();
    // A normal fragment, present in both tables.
    let normal_address: Address = rand::random();
    put_fragment(s.clone(), partition, normal_address, 1024).await;

    // A second fragment, associated in `lore_fragments` but with its
    // `lore_fragment_metadata` row removed out from under it.
    let orphan_address: Address = rand::random();
    put_fragment(s.clone(), partition, orphan_address, 2048).await;
    delete_metadata_row(&pg, orphan_address.hash).await;

    let stats = s
        .clone()
        .repository_stats(partition)
        .await
        .expect("repository_stats must not error on an orphaned association");

    assert_eq!(
        stats.fragment_count, 1,
        "the orphaned association (no metadata row) must be excluded, not counted"
    );
    assert_eq!(
        stats.payload_bytes, 1024,
        "only the normal fragment's bytes may be summed"
    );
    assert_eq!(
        stats.content_bytes, 1024,
        "only the normal fragment's bytes may be summed"
    );
}

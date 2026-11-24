// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Integration tests for the Postgres mutable (branch-tip CAS) store (CR-007).
//!
//! Gated on `LORE_TEST_PG_URL`; skipped when unset. Isolated by a random
//! `Partition` since `lore_mutable` is shared.

use std::sync::Arc;

use lore_base::types::KeyType;
use lore_postgres::store::mutable_store::PostgresMutableStore;
use lore_storage::Hash;
use lore_storage::MutableStore;
use lore_storage::Partition;

fn pg_url() -> Option<String> {
    std::env::var("LORE_TEST_PG_URL").ok()
}

#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn mutable_store_advisory_lock_accepts_smallint_key_type() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping Postgres mutable-store advisory-lock test");
        return;
    };
    let store = Arc::new(
        PostgresMutableStore::connect(&url, 1, &lore_postgres::pool::TlsConfig::default())
            .await
            .expect("connect + schema"),
    );

    store
        .store(
            rand::random(),
            rand::random(),
            rand::random(),
            KeyType::RepositoryId,
        )
        .await
        .expect("advisory lock must accept the store's i16 key type");
}

#[tokio::test]
#[ignore = "needs live Postgres + S3 env (see module docs); run with -- --ignored"]
async fn mutable_cas_lifecycle() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping Postgres mutable-store test");
        return;
    };
    let store = Arc::new(
        PostgresMutableStore::connect(&url, 5, &lore_postgres::pool::TlsConfig::default())
            .await
            .expect("connect + schema"),
    );

    let part: Partition = rand::random();
    let key: Hash = rand::random();
    let kt = KeyType::RepositoryId;
    let v1: Hash = rand::random();
    let v2: Hash = rand::random();

    // Absent → AddressNotFound.
    assert!(store.clone().load(part, key, kt).await.is_err());

    // store + load.
    store
        .clone()
        .store(part, key, v1, kt)
        .await
        .expect("store v1");
    assert_eq!(
        store.clone().load(part, key, kt).await.expect("load v1"),
        v1
    );

    // CAS with matching expected → swaps, returns expected.
    let prev = store
        .clone()
        .compare_and_swap(part, key, v1, v2, kt)
        .await
        .expect("cas v1->v2");
    assert_eq!(prev, v1);
    assert_eq!(
        store.clone().load(part, key, kt).await.expect("load v2"),
        v2
    );

    // CAS with stale expected → no swap, returns the actual current value.
    let v3: Hash = rand::random();
    let got = store
        .clone()
        .compare_and_swap(part, key, v1, v3, kt)
        .await
        .expect("cas stale");
    assert_eq!(got, v2, "stale CAS returns current");
    assert_eq!(
        store
            .clone()
            .load(part, key, kt)
            .await
            .expect("load unchanged"),
        v2,
        "stale CAS must not modify"
    );

    // store(null) removes the key.
    store
        .clone()
        .store(part, key, Hash::default(), kt)
        .await
        .expect("store null removes");
    assert!(store.clone().load(part, key, kt).await.is_err());

    // CAS on an absent key with a non-zero expectation does not insert and
    // reports the actual current value (zero).
    let v4: Hash = rand::random();
    let exp_absent: Hash = rand::random();
    let r = store
        .clone()
        .compare_and_swap(part, key, exp_absent, v4, kt)
        .await
        .expect("cas absent");
    assert_eq!(r, Hash::default());
    assert!(
        store.clone().load(part, key, kt).await.is_err(),
        "non-zero expected CAS must not create a missing key"
    );

    // Zero is the observed value for an absent key, so zero-expected CAS
    // inserts and reports success.
    let r = store
        .clone()
        .compare_and_swap(part, key, Hash::default(), v4, kt)
        .await
        .expect("zero-expected cas absent");
    assert_eq!(r, Hash::default());
    assert_eq!(
        store.clone().load(part, key, kt).await.expect("load v4"),
        v4
    );

    // list by (partition, key_type) → both keys.
    let key2: Hash = rand::random();
    let v5: Hash = rand::random();
    store
        .clone()
        .store(part, key2, v5, kt)
        .await
        .expect("store key2");
    let mut rx = store.clone().list(part, kt).await.expect("list").channel();
    let mut items = Vec::new();
    while let Some(kv) = rx.recv().await {
        items.push(kv);
    }
    assert_eq!(
        items.len(),
        2,
        "list returns both keys for the partition+type"
    );
}

async fn raw_client(url: &str) -> tokio_postgres::Client {
    let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
        .await
        .expect("connect raw assertion client");
    lore_base::lore_spawn!(async move {
        if let Err(error) = connection.await {
            eprintln!("direct postgres connection error: {error}");
        }
    });
    client
}

/// Rows an older build left: a swap to zero stored a zero row. A mixed-version roll must
/// read them as absent and clear them on a matching swap (v0.14 mutable-store contract).
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn zero_rows_from_an_older_build_read_as_absent() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping Postgres mutable-store zero-row test");
        return;
    };
    let store = Arc::new(
        PostgresMutableStore::connect(&url, 5, &lore_postgres::pool::TlsConfig::default())
            .await
            .expect("connect + schema"),
    );
    let db = raw_client(&url).await;
    let kt = KeyType::RepositoryId;
    let kt_raw = kt as i16;
    let zero = Hash::default();
    let zero_bytes = zero.data().as_slice().to_vec();

    let part: Partition = rand::random();
    let key: Hash = rand::random();
    let other_key: Hash = rand::random();
    let part_bytes = part.data().as_slice().to_vec();
    let key_bytes = key.data().as_slice().to_vec();
    let other_key_bytes = other_key.data().as_slice().to_vec();

    let insert_zero = |key_bytes: Vec<u8>| {
        let db = &db;
        let part_bytes = part_bytes.clone();
        let zero_bytes = zero_bytes.clone();
        async move {
            db.execute(
                "INSERT INTO lore_mutable (partition, key_type, key, value) \
                 VALUES ($1, $2, $3, $4)",
                &[&part_bytes, &kt_raw, &key_bytes, &zero_bytes],
            )
            .await
            .expect("seed a zero row as an older build left it");
        }
    };
    let row_count = |key_bytes: Vec<u8>| {
        let db = &db;
        let part_bytes = part_bytes.clone();
        async move {
            db.query_one(
                "SELECT count(*) FROM lore_mutable \
                 WHERE partition = $1 AND key_type = $2 AND key = $3",
                &[&part_bytes, &kt_raw, &key_bytes],
            )
            .await
            .expect("count rows")
            .get::<_, i64>(0)
        }
    };

    insert_zero(key_bytes.clone()).await;
    insert_zero(other_key_bytes.clone()).await;

    // load: a stored zero reads as absent.
    assert!(
        store.clone().load(part, key, kt).await.is_err(),
        "a stored zero row must load as AddressNotFound"
    );

    // list: the partition listing and the null-partition listing leave it out.
    let mut rx = store.clone().list(part, kt).await.expect("list").channel();
    let mut listed = Vec::new();
    while let Some(kv) = rx.recv().await {
        listed.push(kv);
    }
    assert!(
        listed.is_empty(),
        "zero rows are left out of a partition list"
    );
    let mut rx = store
        .clone()
        .list(Partition::default(), kt)
        .await
        .expect("list null partition")
        .channel();
    while let Some((listed_key, listed_value)) = rx.recv().await {
        assert!(!listed_value.is_zero(), "no zero value is ever listed");
        assert!(
            listed_key != key && listed_key != other_key,
            "the zero rows are left out of the null-partition list"
        );
    }

    // CAS with a non-zero expectation answers zero and changes nothing.
    let expected: Hash = rand::random();
    let wanted: Hash = rand::random();
    let answered = store
        .clone()
        .compare_and_swap(part, key, expected, wanted, kt)
        .await
        .expect("cas mismatch over a zero row");
    assert_eq!(answered, zero);
    assert_eq!(
        row_count(key_bytes.clone()).await,
        1,
        "a mismatch writes nothing"
    );
    let value: Vec<u8> = db
        .query_one(
            "SELECT value FROM lore_mutable WHERE partition = $1 AND key_type = $2 AND key = $3",
            &[&part_bytes, &kt_raw, &key_bytes],
        )
        .await
        .expect("read the row")
        .get(0);
    assert_eq!(
        value, zero_bytes,
        "a mismatch leaves the zero row as it was"
    );

    // CAS zero -> zero answers zero and removes the row.
    let answered = store
        .clone()
        .compare_and_swap(part, key, zero, zero, kt)
        .await
        .expect("cas zero to zero");
    assert_eq!(answered, zero);
    assert_eq!(
        row_count(key_bytes.clone()).await,
        0,
        "a matching zero-to-zero swap removes the zero row"
    );

    // CAS zero -> X installs X over the other zero row.
    let answered = store
        .clone()
        .compare_and_swap(part, other_key, zero, wanted, kt)
        .await
        .expect("cas zero to value over a zero row");
    assert_eq!(answered, zero);
    assert_eq!(
        store
            .clone()
            .load(part, other_key, kt)
            .await
            .expect("load installed"),
        wanted
    );
    assert_eq!(row_count(other_key_bytes).await, 1);
}

/// A swap to the value already held writes nothing: the row is not rewritten.
#[tokio::test]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn a_swap_to_the_held_value_writes_nothing() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping Postgres mutable-store same-value test");
        return;
    };
    let store = Arc::new(
        PostgresMutableStore::connect(&url, 5, &lore_postgres::pool::TlsConfig::default())
            .await
            .expect("connect + schema"),
    );
    let db = raw_client(&url).await;
    let kt = KeyType::RepositoryId;
    let kt_raw = kt as i16;
    let part: Partition = rand::random();
    let key: Hash = rand::random();
    let held: Hash = rand::random();
    let part_bytes = part.data().as_slice().to_vec();
    let key_bytes = key.data().as_slice().to_vec();

    store
        .clone()
        .store(part, key, held, kt)
        .await
        .expect("store held value");
    let xmin = || async {
        db.query_one(
            "SELECT xmin::text FROM lore_mutable \
             WHERE partition = $1 AND key_type = $2 AND key = $3",
            &[&part_bytes, &kt_raw, &key_bytes],
        )
        .await
        .expect("read xmin")
        .get::<_, String>(0)
    };
    let before = xmin().await;

    let answered = store
        .clone()
        .compare_and_swap(part, key, held, held, kt)
        .await
        .expect("cas held to held");
    assert_eq!(answered, held);
    assert_eq!(store.clone().load(part, key, kt).await.expect("load"), held);
    assert_eq!(
        xmin().await,
        before,
        "a swap to the held value must not rewrite the row"
    );
}

// `race_swaps` (ConcurrentSwapsFormOneHistory) requires a multi-thread runtime.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs live Postgres env (see module docs); run with -- --ignored"]
async fn mutable_store_satisfies_shared_conformance_battery() {
    let Some(url) = pg_url() else {
        eprintln!("LORE_TEST_PG_URL unset; skipping Postgres mutable-store conformance test");
        return;
    };
    let store = Arc::new(
        PostgresMutableStore::connect(&url, 5, &lore_postgres::pool::TlsConfig::default())
            .await
            .expect("connect + schema"),
    );

    lore_storage::mutable_conformance::verify_mutable_store(
        store,
        lore_storage::mutable_conformance::Capabilities::new("PostgresMutableStore"),
    )
    .await;
}

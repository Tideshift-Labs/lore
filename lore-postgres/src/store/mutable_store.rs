// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Postgres-backed mutable store (CR-007) — the branch-tip compare-and-swap.
//!
//! Strongly-consistent single-key CAS on a single-primary Postgres: the swap is
//! a single `INSERT … ON CONFLICT … DO UPDATE … WHERE existing.value = expected`
//! statement (atomic), mirroring the DynamoDB conditional-put semantics (INV-H §3).
//! `(partition, key_type, key)` is the primary key; the fragment **bytes** are not
//! here — this store holds only the mutable key→value (e.g. branch tip) mapping.

use std::sync::Arc;

use async_trait::async_trait;
use deadpool_postgres::Manager;
use deadpool_postgres::ManagerConfig;
use deadpool_postgres::Pool;
use deadpool_postgres::RecyclingMethod;
use lore_base::types::Address;
use lore_base::types::KeyType;
use lore_storage::Hash;
use lore_storage::MutableStore;
use lore_storage::Partition;
use lore_storage::errors::AddressNotFound;
use lore_storage::immutable_store::StoreError;
use lore_storage::store_types::KeyValueStream;
use tokio_postgres::NoTls;

const SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS lore_mutable (
    partition bytea    NOT NULL,
    key_type  smallint NOT NULL,
    key       bytea    NOT NULL,
    value     bytea    NOT NULL,
    PRIMARY KEY (partition, key_type, key)
);
";

/// Postgres mutable (key→value, branch-tip CAS) store.
pub struct PostgresMutableStore {
    pool: Pool,
}

impl PostgresMutableStore {
    /// Build the pool and ensure the schema. Async (schema DDL needs a connection).
    pub async fn connect(url: &str, pool_max: u32) -> Result<Self, String> {
        let pg_config = url
            .parse::<tokio_postgres::Config>()
            .map_err(|e| format!("invalid postgres url: {e}"))?;
        let manager = Manager::from_config(
            pg_config,
            NoTls,
            ManagerConfig {
                recycling_method: RecyclingMethod::Fast,
            },
        );
        let pool = Pool::builder(manager)
            .max_size(pool_max as usize)
            .build()
            .map_err(|e| format!("failed to build postgres pool: {e}"))?;
        let client = pool
            .get()
            .await
            .map_err(|e| format!("postgres connect failed: {e}"))?;
        client
            .batch_execute(SCHEMA)
            .await
            .map_err(|e| format!("postgres mutable-store schema failed: {e}"))?;
        Ok(Self { pool })
    }
}

fn db_err<E: std::fmt::Display>(e: E) -> StoreError {
    StoreError::internal(format!("postgres mutable store: {e}"))
}

fn not_found(key: Hash) -> StoreError {
    StoreError::from(AddressNotFound::from(Address::zero_context_hash(key)))
}

#[async_trait]
impl MutableStore for PostgresMutableStore {
    async fn load(
        self: Arc<Self>,
        partition: Partition,
        key: Hash,
        key_type: KeyType,
    ) -> Result<Hash, StoreError> {
        let client = self.pool.get().await.map_err(db_err)?;
        let row = client
            .query_opt(
                "SELECT value FROM lore_mutable \
                 WHERE partition = $1 AND key_type = $2 AND key = $3",
                &[
                    &partition.data().as_slice(),
                    &(key_type as i16),
                    &key.data().as_slice(),
                ],
            )
            .await
            .map_err(db_err)?;
        match row {
            Some(row) => {
                let value: Vec<u8> = row.get("value");
                Ok(Hash::from(value.as_slice()))
            }
            None => Err(not_found(key)),
        }
    }

    async fn store(
        self: Arc<Self>,
        partition: Partition,
        key: Hash,
        value: Hash,
        key_type: KeyType,
    ) -> Result<(), StoreError> {
        let client = self.pool.get().await.map_err(db_err)?;
        let part = partition.data().as_slice();
        let kt = key_type as i16;
        let k = key.data().as_slice();
        if value.is_zero() {
            // Storing the null hash removes the key (trait contract).
            client
                .execute(
                    "DELETE FROM lore_mutable \
                     WHERE partition = $1 AND key_type = $2 AND key = $3",
                    &[&part, &kt, &k],
                )
                .await
                .map_err(db_err)?;
        } else {
            client
                .execute(
                    "INSERT INTO lore_mutable (partition, key_type, key, value) \
                     VALUES ($1, $2, $3, $4) \
                     ON CONFLICT (partition, key_type, key) DO UPDATE SET value = EXCLUDED.value",
                    &[&part, &kt, &k, &value.data().as_slice()],
                )
                .await
                .map_err(db_err)?;
        }
        Ok(())
    }

    async fn compare_and_swap(
        self: Arc<Self>,
        partition: Partition,
        key: Hash,
        expected: Hash,
        value: Hash,
        key_type: KeyType,
    ) -> Result<Hash, StoreError> {
        let client = self.pool.get().await.map_err(db_err)?;
        let part = partition.data().as_slice();
        let kt = key_type as i16;
        let k = key.data().as_slice();

        // Swap iff the key is absent (no conflict → INSERT proceeds) OR the
        // existing value equals `expected` (conflict → DO UPDATE WHERE passes).
        // A returned row ⇒ the swap happened ⇒ return `expected` (matches the
        // DynamoDB store, which returns `expected` on success).
        let swapped = client
            .query_opt(
                "INSERT INTO lore_mutable (partition, key_type, key, value) \
                 VALUES ($1, $2, $3, $4) \
                 ON CONFLICT (partition, key_type, key) \
                 DO UPDATE SET value = EXCLUDED.value \
                 WHERE lore_mutable.value = $5 \
                 RETURNING value",
                &[
                    &part,
                    &kt,
                    &k,
                    &value.data().as_slice(),
                    &expected.data().as_slice(),
                ],
            )
            .await
            .map_err(db_err)?;

        if swapped.is_some() {
            return Ok(expected);
        }

        // Conflict with a different current value — return the actual current so
        // the caller sees `current != expected` and can retry.
        let current = client
            .query_one(
                "SELECT value FROM lore_mutable \
                 WHERE partition = $1 AND key_type = $2 AND key = $3",
                &[&part, &kt, &k],
            )
            .await
            .map_err(db_err)?;
        let current: Vec<u8> = current.get("value");
        Ok(Hash::from(current.as_slice()))
    }

    async fn list(
        self: Arc<Self>,
        partition: Partition,
        key_type: KeyType,
    ) -> Result<KeyValueStream, StoreError> {
        let client = self.pool.get().await.map_err(db_err)?;
        let kt = key_type as i16;
        // A null partition matches all partitions (trait contract).
        let rows = if partition.is_zero() {
            client
                .query(
                    "SELECT key, value FROM lore_mutable WHERE key_type = $1",
                    &[&kt],
                )
                .await
        } else {
            client
                .query(
                    "SELECT key, value FROM lore_mutable WHERE partition = $1 AND key_type = $2",
                    &[&partition.data().as_slice(), &kt],
                )
                .await
        }
        .map_err(db_err)?;

        let (stream, tx) = KeyValueStream::new();
        for row in rows {
            let key: Vec<u8> = row.get("key");
            let value: Vec<u8> = row.get("value");
            // Unbounded channel: send never blocks; receiver drains the stream.
            let _ = tx.send((Hash::from(key.as_slice()), Hash::from(value.as_slice())));
        }
        Ok(stream)
    }

    async fn flush(self: Arc<Self>, _sync_data: bool) -> Result<(), StoreError> {
        // Writes are durable on commit; nothing to flush.
        Ok(())
    }
}

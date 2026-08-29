// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! Postgres-backed mutable store (CR-007) — the branch-tip compare-and-swap.
//!
//! Strongly-consistent single-key CAS on a single-primary Postgres. Store and
//! compare-and-swap share one per-key transactional advisory lock, so the
//! observed prior value, conditional mutation, and returned outcome have one
//! linearization point, mirroring DynamoDB conditional-put semantics (INV-H §3).
//! `(partition, key_type, key)` is the primary key; the fragment **bytes** are not
//! here — this store holds only the mutable key→value (e.g. branch tip) mapping.

use std::sync::Arc;

use async_trait::async_trait;
use deadpool_postgres::Pool;
use deadpool_postgres::PoolError;
use lore_base::types::Address;
use lore_base::types::KeyType;
use lore_storage::Hash;
use lore_storage::MutableStore;
use lore_storage::Partition;
use lore_storage::errors::AddressNotFound;
use lore_storage::errors::SlowDown;
use lore_storage::immutable_store::StoreError;
use lore_storage::store_types::KeyValueStream;
use tokio_postgres::Transaction;

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
    instruments: crate::metrics::Instruments,
    /// CR-029 domain-key bypass fence. Shared with the domain coordinator, so
    /// readiness flips it once rather than every write re-reading the schema
    /// state. Starts disabled and fails closed: a cell that never completes
    /// backfill never turns it on.
    enforcement: crate::domain::bypass::DomainEnforcement,
}

impl PostgresMutableStore {
    /// Build the pool (rustls TLS; see [`crate::pool`]) and ensure the schema.
    /// `tls` carries the CA bundle / verification mode. Async (schema DDL needs a
    /// connection).
    pub async fn connect(
        url: &str,
        pool_max: u32,
        tls: &crate::pool::TlsConfig,
    ) -> Result<Self, String> {
        let pool = crate::pool::build_pool(url, pool_max, tls)?;
        crate::pool::ensure_schema(&pool, SCHEMA).await?;
        Ok(Self {
            pool,
            instruments: crate::metrics::Instruments::new("mutable"),
            enforcement: crate::domain::bypass::DomainEnforcement::disabled(),
        })
    }

    /// Share the domain coordinator's enforcement handle with this store.
    ///
    /// Called during server construction, before the store is published. The
    /// handle is a clone of one flag, so enabling enforcement anywhere enables
    /// it here too.
    pub fn with_domain_enforcement(
        mut self,
        enforcement: crate::domain::bypass::DomainEnforcement,
    ) -> Self {
        self.enforcement = enforcement;
        self
    }

    /// Reject a domain-owned key write while enforcement is on.
    ///
    /// This is the single choke point for all seven generic mutable RPCs — the
    /// v0/v1 gRPC pairs and the two QUIC command families — which pass the wire
    /// `KeyType` through untouched and authorize only repository-level `write`.
    /// Putting the check at the store rather than in the handlers is deliberate:
    /// two of the seven use a different authorization path, so a handler-level
    /// check would have to exist twice and stay in step.
    fn reject_domain_key(&self, key_type: KeyType) -> Result<(), StoreError> {
        if self.enforcement.is_enabled() && crate::domain::bypass::is_domain_owned(key_type) {
            return Err(StoreError::internal(
                crate::domain::bypass::rejection_message(key_type),
            ));
        }
        Ok(())
    }
}

/// Map a query/execute error, surfacing transient failures as `SlowDown` so
/// clients retry rather than treating them as permanent (A2).
fn db_err(e: tokio_postgres::Error) -> StoreError {
    if crate::pool::is_transient_pg(&e) {
        StoreError::from(SlowDown)
    } else {
        StoreError::internal(format!("postgres mutable store: {e}"))
    }
}

/// Map a pool-checkout error (transient ⇒ `SlowDown`).
fn pool_err(e: PoolError) -> StoreError {
    if crate::pool::is_transient_pool(&e) {
        StoreError::from(SlowDown)
    } else {
        StoreError::internal(format!("postgres mutable store pool: {e}"))
    }
}

fn not_found(key: Hash) -> StoreError {
    StoreError::from(AddressNotFound::from(Address::zero_context_hash(key)))
}

/// Serialize every mutable writer for one `(partition, key_type, key)` tuple.
/// The database derives the 64-bit lock ID from the complete tuple, avoiding a
/// process-local lock that would not coordinate active-active loreservers.
async fn lock_key(
    tx: &Transaction<'_>,
    partition: &[u8],
    key_type: i16,
    key: &[u8],
) -> Result<(), StoreError> {
    tx.execute(
        "SELECT pg_advisory_xact_lock( \
             hashtextextended( \
                 encode($1, 'hex') || ':' || $2::smallint::text || ':' || encode($3, 'hex'), \
                 0 \
             ) \
         )",
        &[&partition, &key_type, &key],
    )
    .await
    .map_err(db_err)?;
    Ok(())
}

#[async_trait]
impl MutableStore for PostgresMutableStore {
    #[tracing::instrument(level = "debug", skip_all)]
    async fn load(
        self: Arc<Self>,
        partition: Partition,
        key: Hash,
        key_type: KeyType,
    ) -> Result<Hash, StoreError> {
        let _t = self.instruments.start("load", self.pool.status());
        let client = self.pool.get().await.map_err(pool_err)?;
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

    #[tracing::instrument(level = "debug", skip_all)]
    async fn store(
        self: Arc<Self>,
        partition: Partition,
        key: Hash,
        value: Hash,
        key_type: KeyType,
    ) -> Result<(), StoreError> {
        self.reject_domain_key(key_type)?;
        let _t = self.instruments.start("store", self.pool.status());
        let mut client = self.pool.get().await.map_err(pool_err)?;
        let part = partition.data().as_slice();
        let kt = key_type as i16;
        let k = key.data().as_slice();
        let tx = client.transaction().await.map_err(db_err)?;
        lock_key(&tx, part, kt, k).await?;
        if value.is_zero() {
            // Storing the null hash removes the key (trait contract).
            tx.execute(
                "DELETE FROM lore_mutable \
                     WHERE partition = $1 AND key_type = $2 AND key = $3",
                &[&part, &kt, &k],
            )
            .await
            .map_err(db_err)?;
        } else {
            tx.execute(
                "INSERT INTO lore_mutable (partition, key_type, key, value) \
                     VALUES ($1, $2, $3, $4) \
                     ON CONFLICT (partition, key_type, key) DO UPDATE SET value = EXCLUDED.value",
                &[&part, &kt, &k, &value.data().as_slice()],
            )
            .await
            .map_err(db_err)?;
        }
        tx.commit().await.map_err(db_err)
    }

    #[tracing::instrument(level = "debug", skip_all)]
    async fn compare_and_swap(
        self: Arc<Self>,
        partition: Partition,
        key: Hash,
        expected: Hash,
        value: Hash,
        key_type: KeyType,
    ) -> Result<Hash, StoreError> {
        self.reject_domain_key(key_type)?;
        let _t = self
            .instruments
            .start("compare_and_swap", self.pool.status());
        let mut client = self.pool.get().await.map_err(pool_err)?;
        let part = partition.data().as_slice();
        let kt = key_type as i16;
        let k = key.data().as_slice();
        let tx = client.transaction().await.map_err(db_err)?;
        lock_key(&tx, part, kt, k).await?;

        // Read and decide while holding the same database lock used by every
        // mutable writer. A missing key is the zero value.
        let current = tx
            .query_opt(
                "SELECT value FROM lore_mutable \
                 WHERE partition = $1 AND key_type = $2 AND key = $3 \
                 FOR UPDATE",
                &[&part, &kt, &k],
            )
            .await
            .map_err(db_err)?;
        let current = current
            .map(|row| {
                let current: Vec<u8> = row.get("value");
                Hash::from(current.as_slice())
            })
            .unwrap_or_default();

        if current != expected {
            tx.commit().await.map_err(db_err)?;
            return Ok(current);
        }

        // CAS retains a zero-valued row, matching LocalMutableStore. `load`
        // exposes zero as absence, but a later zero-expected CAS can still use
        // the row as its predecessor.
        tx.execute(
            "INSERT INTO lore_mutable (partition, key_type, key, value) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (partition, key_type, key) DO UPDATE SET value = EXCLUDED.value",
            &[&part, &kt, &k, &value.data().as_slice()],
        )
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        Ok(current)
    }

    #[tracing::instrument(level = "debug", skip_all)]
    async fn list(
        self: Arc<Self>,
        partition: Partition,
        key_type: KeyType,
    ) -> Result<KeyValueStream, StoreError> {
        let _t = self.instruments.start("list", self.pool.status());
        let client = self.pool.get().await.map_err(pool_err)?;
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

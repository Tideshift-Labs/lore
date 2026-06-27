// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Postgres-backed immutable store (CR-007) — fragment **metadata** in Postgres,
//! fragment **bytes** in S3-compatible object storage (e.g. DO Spaces, MinIO).
//!
//! This mirrors `lore-aws`'s immutable store, which couples fragment bytes in S3
//! with fragment metadata + associations in DynamoDB. Here the two DynamoDB
//! tables become two Postgres tables and the byte path reuses `lore-aws`'s S3
//! client (the `aws-sdk-s3` client is the standard S3-compatible client; we do
//! not reimplement object I/O or FastCDC):
//!
//! - `lore_fragments` — one row per `(hash, repository, context)` *association*.
//!   Existence is a primary-key/prefix lookup (the three [`StoreMatch`] levels
//!   are leftmost-prefix reads of the `(hash, repository, context)` PK) and the
//!   global refcount is `EXISTS … WHERE hash = …`.
//! - `lore_fragment_metadata` — one row per `hash` carrying the [`Fragment`]
//!   flags/sizes (`INSERT … ON CONFLICT (hash) DO UPDATE`; consistent reads).
//!
//! Deduplication scope is **global** (content-addressed by hash), matching the
//! `lore-aws` default (`DedupScope::Global`) and a single shared object-storage
//! bucket. Per-repository (partition) dedup + multi-bucket routing are
//! `lore-aws` features that are out of scope for this crate (CR-007 §"Out of
//! scope": the byte target is just "an S3-compatible store").

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;
use bytes::BytesMut;
use deadpool_postgres::Pool;
use deadpool_postgres::PoolError;
use lore_aws::aws_error::AwsError;
use lore_aws::clients::AwsClientBuilder;
use lore_aws::clients::HttpClientSettings;
use lore_aws::clients::TimeoutConfig;
use lore_aws::s3::S3Impl;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::FRAGMENT_SIZE_THRESHOLD;
use lore_base::types::Fragment;
use lore_base::types::FragmentFlags;
use lore_base::types::FragmentReference;
use lore_base::types::Hash;
use lore_base::types::Partition;
use lore_base::types::TypedBytes;
use lore_storage::ImmutableStore;
use lore_storage::StoreError;
use lore_storage::StoreMatch;
use lore_storage::StoreObliterateStats;
use lore_storage::StoreQueryResult;
use lore_storage::errors::AddressNotFound;
use lore_storage::errors::SlowDown;
use lore_storage::immutable_store::sanitise_fragment_behavior_flags;

/// Self-bootstrapping schema. The `(hash, repository, context)` primary key is
/// the association identity; its B-tree also serves the leftmost-prefix
/// existence reads (`hash`, `(hash, repository)`, full) and the by-hash refcount,
/// so no secondary indexes are needed. Metadata is keyed by `hash` alone (global
/// dedup). See [`crate::store::immutable_store`] for the design.
const SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS lore_fragments (
    hash       bytea NOT NULL,
    repository bytea NOT NULL,
    context    bytea NOT NULL,
    PRIMARY KEY (hash, repository, context)
);
CREATE TABLE IF NOT EXISTS lore_fragment_metadata (
    hash         bytea  NOT NULL PRIMARY KEY,
    flags        bigint NOT NULL,
    size_payload bigint NOT NULL,
    size_content bigint NOT NULL
);
";

/// Object-storage (S3-compatible) settings for the fragment-byte path. Mirrors
/// the keys `lore-aws` exposes (endpoint / region / bucket / path-style) so the
/// same config can point at DO Spaces, MinIO, or LocalStack.
#[derive(Debug, Clone)]
pub struct ObjectStoreSettings {
    /// Bucket holding fragment payloads (one shared bucket; global dedup).
    pub bucket: String,
    /// Optional endpoint URL (set for S3-compatible stores like Spaces/MinIO).
    pub endpoint_url: Option<String>,
    /// Optional region.
    pub region: Option<String>,
    /// Force path-style addressing — required for S3-compatible stores reached
    /// by a non-AWS hostname (MinIO in Docker, etc.).
    pub force_path_style: bool,
    /// Slow-operation log threshold (millis).
    pub slow_operation_threshold_millis: u64,
    /// Per-operation timeout (millis).
    pub timeout_millis: u64,
    /// Whether to HEAD the bucket at startup to fail fast on misconfiguration.
    pub validate_bucket_on_startup: bool,
}

/// Postgres-backed immutable store (metadata in Postgres, bytes in S3).
pub struct PostgresImmutableStore {
    pool: Pool,
    s3: S3Impl,
    bucket: String,
    instruments: crate::metrics::Instruments,
}

impl PostgresImmutableStore {
    /// Build the Postgres pool (ensuring the schema) and the S3-compatible byte
    /// client, then return a ready store.
    ///
    /// Async because both the schema DDL and the AWS config load need to run; the
    /// server plugin factory drives this to completion via `block_on` at startup.
    pub async fn connect(
        pg_url: &str,
        pool_max: u32,
        ca_cert: Option<&str>,
        object: ObjectStoreSettings,
    ) -> Result<Self, String> {
        let pool = crate::pool::build_pool(pg_url, pool_max, ca_cert)?;
        crate::pool::ensure_schema(&pool, SCHEMA).await?;

        // Build the S3-compatible byte client via lore-aws's client builder so
        // endpoint / region / path-style handling matches the AWS backend.
        let builder = Box::pin(
            AwsClientBuilder::builder()
                .with_http_settings(&HttpClientSettings::default())
                .maybe_endpoint(object.endpoint_url.clone())
                .maybe_region(object.region.clone())
                .with_timeout_config(
                    TimeoutConfig::builder()
                        .operation_timeout(Duration::from_millis(object.timeout_millis))
                        .build(),
                )
                .build_config(),
        )
        .await
        .with_slow_operation_threshold(object.slow_operation_threshold_millis)
        .s3_with_path_style(object.force_path_style);
        let builder = if object.validate_bucket_on_startup {
            builder.ensure_bucket(&object.bucket)
        } else {
            builder
        };
        let s3 = Box::pin(builder.build())
            .await
            .map_err(|e| format!("failed to build S3 client: {e}"))?;

        Ok(Self {
            pool,
            s3,
            bucket: object.bucket,
            instruments: crate::metrics::Instruments::new("immutable"),
        })
    }

    fn hash_key(hash: Hash) -> String {
        let mut dst = [0u8; 64];
        lore_revision::util::to_hex_str(hash.data(), &mut dst).to_string()
    }

    fn not_found(hash: Hash) -> StoreError {
        StoreError::from(AddressNotFound::from(Address::zero_context_hash(hash)))
    }

    /// Existence at the requested match level (global dedup). The three levels
    /// are leftmost-prefix reads of the `(hash, repository, context)` PK.
    async fn exists(
        &self,
        repository: Context,
        address: Address,
        match_requested: StoreMatch,
    ) -> Result<bool, StoreError> {
        if match_requested == StoreMatch::MatchNone {
            return Ok(false);
        }
        let client = self.pool.get().await.map_err(pool_err)?;
        let hash = address.hash.data().as_slice();
        let row = match match_requested {
            StoreMatch::MatchFull => {
                client
                    .query_opt(
                        "SELECT 1 FROM lore_fragments \
                         WHERE hash = $1 AND repository = $2 AND context = $3 LIMIT 1",
                        &[
                            &hash,
                            &repository.data().as_slice(),
                            &address.context.data().as_slice(),
                        ],
                    )
                    .await
            }
            StoreMatch::MatchPartition => {
                client
                    .query_opt(
                        "SELECT 1 FROM lore_fragments \
                         WHERE hash = $1 AND repository = $2 LIMIT 1",
                        &[&hash, &repository.data().as_slice()],
                    )
                    .await
            }
            StoreMatch::MatchHash => {
                client
                    .query_opt(
                        "SELECT 1 FROM lore_fragments WHERE hash = $1 LIMIT 1",
                        &[&hash],
                    )
                    .await
            }
            StoreMatch::MatchNone => return Ok(false),
        }
        .map_err(db_err)?;
        Ok(row.is_some())
    }

    async fn ensure_exists(
        &self,
        repository: Context,
        address: Address,
        match_required: StoreMatch,
    ) -> Result<(), StoreError> {
        if self.exists(repository, address, match_required).await? {
            Ok(())
        } else {
            Err(Self::not_found(address.hash))
        }
    }

    /// Best match at or below the requested level, walking down the hierarchy —
    /// mirrors `AwsImmutableStore::lookup`.
    async fn lookup(
        &self,
        repository: Context,
        address: Address,
        match_requested: StoreMatch,
    ) -> Result<StoreMatch, StoreError> {
        let mut level = match_requested;
        let mut exists = self.exists(repository, address, level).await?;

        // A full-match miss short-circuits: there is no partial-upload support, so
        // there is no benefit to probing coarser granularities.
        if !exists && level == StoreMatch::MatchFull {
            return Ok(StoreMatch::MatchNone);
        }
        while !exists && level.prev().is_some() {
            level = level.prev().unwrap();
            exists = self.exists(repository, address, level).await?;
        }
        Ok(if exists { level } else { StoreMatch::MatchNone })
    }

    async fn do_query(
        &self,
        repository: Context,
        address: Address,
        match_requested: StoreMatch,
        hide_obliterates: bool,
    ) -> Result<StoreQueryResult, StoreError> {
        let match_made = self.lookup(repository, address, match_requested).await?;
        if match_made == StoreMatch::MatchNone {
            return Ok(StoreQueryResult {
                fragment: Fragment::default(),
                match_made,
            });
        }
        let fragment = self.load_metadata(address.hash).await?;
        if fragment.flags & FragmentFlags::PayloadObliteration.bits() != 0 && hide_obliterates {
            Ok(StoreQueryResult {
                fragment: Fragment::default(),
                match_made: StoreMatch::MatchNone,
            })
        } else {
            Ok(StoreQueryResult {
                fragment,
                match_made,
            })
        }
    }

    async fn load_metadata(&self, hash: Hash) -> Result<Fragment, StoreError> {
        let client = self.pool.get().await.map_err(pool_err)?;
        let row = client
            .query_opt(
                "SELECT flags, size_payload, size_content FROM lore_fragment_metadata \
                 WHERE hash = $1",
                &[&hash.data().as_slice()],
            )
            .await
            .map_err(db_err)?;
        match row {
            Some(row) => Ok(Fragment {
                flags: row.get::<_, i64>("flags") as u32,
                size_payload: row.get::<_, i64>("size_payload") as u32,
                size_content: row.get::<_, i64>("size_content") as u64,
            }),
            None => Err(Self::not_found(hash)),
        }
    }

    /// Conditional metadata update — applies `updated` only if the row still
    /// equals `expected` (the DynamoDB conditional-put used for the obliteration
    /// state machine). A zero rowcount means another writer raced us.
    async fn update_metadata(
        &self,
        hash: Hash,
        updated: Fragment,
        expected: Fragment,
    ) -> Result<(), StoreError> {
        let client = self.pool.get().await.map_err(pool_err)?;
        let affected = client
            .execute(
                "UPDATE lore_fragment_metadata \
                 SET flags = $1, size_payload = $2, size_content = $3 \
                 WHERE hash = $4 AND flags = $5 AND size_payload = $6 AND size_content = $7",
                &[
                    &(updated.flags as i64),
                    &(updated.size_payload as i64),
                    &(updated.size_content as i64),
                    &hash.data().as_slice(),
                    &(expected.flags as i64),
                    &(expected.size_payload as i64),
                    &(expected.size_content as i64),
                ],
            )
            .await
            .map_err(db_err)?;
        if affected == 0 {
            return Err(StoreError::internal(
                "Failed to update metadata due to conflict",
            ));
        }
        Ok(())
    }

    async fn associate_fragment(
        &self,
        repository: Context,
        address: Address,
    ) -> Result<(), StoreError> {
        let client = self.pool.get().await.map_err(pool_err)?;
        client
            .execute(
                "INSERT INTO lore_fragments (hash, repository, context) \
                 VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                &[
                    &address.hash.data().as_slice(),
                    &repository.data().as_slice(),
                    &address.context.data().as_slice(),
                ],
            )
            .await
            .map_err(db_err)?;
        Ok(())
    }

    async fn delete_association(
        &self,
        repository: Context,
        address: Address,
    ) -> Result<(), StoreError> {
        let client = self.pool.get().await.map_err(pool_err)?;
        client
            .execute(
                "DELETE FROM lore_fragments \
                 WHERE hash = $1 AND repository = $2 AND context = $3",
                &[
                    &address.hash.data().as_slice(),
                    &repository.data().as_slice(),
                    &address.context.data().as_slice(),
                ],
            )
            .await
            .map_err(db_err)?;
        Ok(())
    }

    /// Whether any association still references `hash` (global refcount).
    async fn has_associations(&self, hash: Hash) -> Result<bool, StoreError> {
        let client = self.pool.get().await.map_err(pool_err)?;
        let row = client
            .query_opt(
                "SELECT 1 FROM lore_fragments WHERE hash = $1 LIMIT 1",
                &[&hash.data().as_slice()],
            )
            .await
            .map_err(db_err)?;
        Ok(row.is_some())
    }

    async fn write_payload(
        &self,
        repository: Context,
        address: Address,
        fragment: Fragment,
        payload: Bytes,
    ) -> Result<(), StoreError> {
        if payload.len() != fragment.size_payload as usize {
            return Err(StoreError::internal(format!(
                "Failed to store in immutable store for put {}",
                address.hash
            )));
        }
        let key = Self::hash_key(address.hash);
        self.s3
            .put_object(&self.bucket, &key, payload.to_vec())
            .await
            .map_err(|e| s3_err(e, "S3 put object failed"))?;

        // Metadata upsert + association insert run in ONE transaction (B4): the
        // fragment is either fully indexed or not at all, never metadata without
        // its association (or vice versa). Bytes are written first (above); a
        // crash before commit leaves recoverable state — a later query/get treats
        // the fragment as absent and the client re-sends it, as in the AWS store.
        let mut client = self.pool.get().await.map_err(pool_err)?;
        let tx = client.transaction().await.map_err(db_err)?;
        tx.execute(
            "INSERT INTO lore_fragment_metadata (hash, flags, size_payload, size_content) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (hash) DO UPDATE SET \
                 flags = EXCLUDED.flags, \
                 size_payload = EXCLUDED.size_payload, \
                 size_content = EXCLUDED.size_content",
            &[
                &address.hash.data().as_slice(),
                &(fragment.flags as i64),
                &(fragment.size_payload as i64),
                &(fragment.size_content as i64),
            ],
        )
        .await
        .map_err(db_err)?;
        tx.execute(
            "INSERT INTO lore_fragments (hash, repository, context) \
             VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            &[
                &address.hash.data().as_slice(),
                &repository.data().as_slice(),
                &address.context.data().as_slice(),
            ],
        )
        .await
        .map_err(db_err)?;
        tx.commit().await.map_err(db_err)?;
        Ok(())
    }

    async fn delete_payload(&self, hash: Hash) -> Result<(), StoreError> {
        let key = Self::hash_key(hash);
        self.s3
            .delete_object(&self.bucket, &key, None)
            .await
            .map_err(|e| s3_err(e, "S3 delete object failed"))?;
        Ok(())
    }

    /// Fetch the full payload bytes for `hash`. `NoSuchKey` becomes
    /// `AddressNotFound` so a missing payload reads as a self-healing miss.
    async fn get_payload_bytes(&self, hash: Hash) -> Result<Bytes, StoreError> {
        let key = Self::hash_key(hash);
        let mut output =
            self.s3
                .get_object(&self.bucket, &key, None)
                .await
                .map_err(|e| match e {
                    AwsError::AwsSdkError(sdk_error) => match sdk_error.into_service_error() {
                        aws_sdk_s3::operation::get_object::GetObjectError::NoSuchKey(_) => {
                            Self::not_found(hash)
                        }
                        _ => StoreError::from(SlowDown),
                    },
                    other => StoreError::internal(format!("S3 get object failed: {other:?}")),
                })?;

        let mut buffer = BytesMut::with_capacity(FRAGMENT_SIZE_THRESHOLD);
        while let Some(chunk) = output.body.next().await {
            let chunk = chunk.map_err(|e| {
                StoreError::internal(format!("S3 response stream read failed: {e}"))
            })?;
            buffer.extend_from_slice(chunk.as_ref());
        }
        Ok(buffer.freeze())
    }

    async fn load(&self, hash: Hash) -> Result<(Fragment, Bytes), StoreError> {
        // Fetch metadata (Postgres) and bytes (S3) concurrently — on the hot
        // read/clone path this makes per-fragment latency max(meta, bytes)
        // instead of the sum, mirroring the AWS store. Metadata is authoritative:
        // its error/obliteration verdict takes priority over the byte fetch.
        let (meta_res, bytes_res) =
            tokio::join!(self.load_metadata(hash), self.get_payload_bytes(hash));

        let fragment = meta_res?;
        lore_storage::validate_fragment_size(&fragment)?;
        if fragment.flags & FragmentFlags::PayloadObliteration.bits() != 0 {
            return Err(Self::not_found(hash));
        }
        let payload = bytes_res?;
        if payload.len() != fragment.size_payload as usize {
            return Err(StoreError::internal(format!(
                "Failed to load from immutable store, size mismatch (load {}, expected {}) for get {hash}",
                payload.len(),
                fragment.size_payload
            )));
        }
        Ok((fragment, payload))
    }
}

/// Map a query/execute error; transient failures become `SlowDown` so clients
/// retry rather than treat them as permanent (A2).
fn db_err(e: tokio_postgres::Error) -> StoreError {
    if crate::pool::is_transient_pg(&e) {
        StoreError::from(SlowDown)
    } else {
        StoreError::internal(format!("postgres immutable store: {e}"))
    }
}

/// Map a pool-checkout error (transient ⇒ `SlowDown`).
fn pool_err(e: PoolError) -> StoreError {
    if crate::pool::is_transient_pool(&e) {
        StoreError::from(SlowDown)
    } else {
        StoreError::internal(format!("postgres immutable store pool: {e}"))
    }
}

fn s3_err<E: std::fmt::Debug>(e: AwsError<E>, context: &str) -> StoreError {
    match e {
        AwsError::AwsSdkError(_) => StoreError::from(SlowDown),
        other => StoreError::internal(format!("{context}: {other:?}")),
    }
}

#[async_trait]
impl ImmutableStore for PostgresImmutableStore {
    #[tracing::instrument(level = "debug", skip_all)]
    async fn exist(
        self: Arc<Self>,
        partition: Partition,
        address: Address,
        match_requested: StoreMatch,
    ) -> Result<StoreMatch, StoreError> {
        let _t = self.instruments.start("exist", self.pool.status());
        let repository: Context = partition.into();
        if self.exists(repository, address, match_requested).await? {
            Ok(match_requested)
        } else {
            Ok(StoreMatch::MatchNone)
        }
    }

    #[tracing::instrument(level = "debug", skip_all)]
    async fn exist_batch(
        self: Arc<Self>,
        partition: Partition,
        addresses: &[Address],
        match_requested: StoreMatch,
    ) -> Result<Vec<StoreMatch>, StoreError> {
        if addresses.is_empty() || match_requested == StoreMatch::MatchNone {
            return Ok(vec![StoreMatch::MatchNone; addresses.len()]);
        }
        let _t = self.instruments.start("exist_batch", self.pool.status());
        let repository: Context = partition.into();
        let client = self.pool.get().await.map_err(pool_err)?;
        // One query for the whole batch via `hash = ANY($n)` (B3) — a fragment
        // push existence-checks thousands of hashes, so we collapse N round-trips
        // into a single statement instead of probing each address individually.
        let hashes: Vec<&[u8]> = addresses.iter().map(|a| a.hash.data().as_slice()).collect();

        match match_requested {
            StoreMatch::MatchHash => {
                let rows = client
                    .query(
                        "SELECT DISTINCT hash FROM lore_fragments WHERE hash = ANY($1)",
                        &[&hashes],
                    )
                    .await
                    .map_err(db_err)?;
                let present: HashSet<Vec<u8>> =
                    rows.iter().map(|r| r.get::<_, Vec<u8>>("hash")).collect();
                Ok(addresses
                    .iter()
                    .map(|a| {
                        if present.contains(a.hash.data().as_slice()) {
                            StoreMatch::MatchHash
                        } else {
                            StoreMatch::MatchNone
                        }
                    })
                    .collect())
            }
            StoreMatch::MatchPartition => {
                let rows = client
                    .query(
                        "SELECT DISTINCT hash FROM lore_fragments \
                         WHERE repository = $1 AND hash = ANY($2)",
                        &[&repository.data().as_slice(), &hashes],
                    )
                    .await
                    .map_err(db_err)?;
                let present: HashSet<Vec<u8>> =
                    rows.iter().map(|r| r.get::<_, Vec<u8>>("hash")).collect();
                Ok(addresses
                    .iter()
                    .map(|a| {
                        if present.contains(a.hash.data().as_slice()) {
                            StoreMatch::MatchPartition
                        } else {
                            StoreMatch::MatchNone
                        }
                    })
                    .collect())
            }
            StoreMatch::MatchFull => {
                let rows = client
                    .query(
                        "SELECT hash, context FROM lore_fragments \
                         WHERE repository = $1 AND hash = ANY($2)",
                        &[&repository.data().as_slice(), &hashes],
                    )
                    .await
                    .map_err(db_err)?;
                let present: HashSet<(Vec<u8>, Vec<u8>)> = rows
                    .iter()
                    .map(|r| (r.get::<_, Vec<u8>>("hash"), r.get::<_, Vec<u8>>("context")))
                    .collect();
                Ok(addresses
                    .iter()
                    .map(|a| {
                        let key = (a.hash.data().to_vec(), a.context.data().to_vec());
                        if present.contains(&key) {
                            StoreMatch::MatchFull
                        } else {
                            StoreMatch::MatchNone
                        }
                    })
                    .collect())
            }
            StoreMatch::MatchNone => Ok(vec![StoreMatch::MatchNone; addresses.len()]),
        }
    }

    #[tracing::instrument(level = "debug", skip_all)]
    async fn query(
        self: Arc<Self>,
        partition: Partition,
        address: Address,
        match_requested: StoreMatch,
    ) -> Result<StoreQueryResult, StoreError> {
        let _t = self.instruments.start("query", self.pool.status());
        let repository: Context = partition.into();
        self.do_query(repository, address, match_requested, true)
            .await
    }

    #[tracing::instrument(level = "debug", skip_all)]
    async fn get(
        self: Arc<Self>,
        partition: Partition,
        address: Address,
        match_required: StoreMatch,
    ) -> Result<(Fragment, Bytes), StoreError> {
        let _t = self.instruments.start("get", self.pool.status());
        let repository: Context = partition.into();
        self.ensure_exists(repository, address, match_required)
            .await?;
        let (fragment, payload) = self.load(address.hash).await?;
        lore_storage::validate_fragment_payload(&fragment, payload.len())?;
        Ok((fragment, payload))
    }

    #[tracing::instrument(level = "debug", skip_all)]
    async fn put(
        self: Arc<Self>,
        partition: Partition,
        address: Address,
        mut fragment: Fragment,
        payload: Option<Bytes>,
        _force: bool,
    ) -> Result<(), StoreError> {
        let _t = self.instruments.start("put", self.pool.status());
        sanitise_fragment_behavior_flags(&mut fragment);
        if let Some(payload) = payload.as_ref() {
            lore_storage::validate_fragment_payload(&fragment, payload.len())?;
        } else {
            lore_storage::validate_fragment_size(&fragment)?;
        }
        let repository: Context = partition.into();

        let query = self
            .do_query(repository, address, StoreMatch::MatchFull, false)
            .await;

        let match_made = if let Ok(query) = &query {
            if query.fragment.flags & FragmentFlags::PayloadObliterating.bits()
                == FragmentFlags::PayloadObliterating.bits()
                && query.match_made != StoreMatch::MatchNone
            {
                return Err(StoreError::internal(format!(
                    "Failed to obliterate immutable {address}"
                )));
            }
            if query.match_made != StoreMatch::MatchNone
                && fragment.size_content != query.fragment.size_content
                && query.fragment.flags & FragmentFlags::PayloadObliterated.bits()
                    != FragmentFlags::PayloadObliterated.bits()
            {
                return Err(StoreError::internal("Hash collision"));
            }
            query.match_made
        } else {
            StoreMatch::MatchNone
        };

        match match_made {
            // Already present with this exact context — nothing to do.
            StoreMatch::MatchFull => Ok(()),
            // Bytes already present for this repository (or globally); just record
            // the new association for this context.
            StoreMatch::MatchPartition => self.associate_fragment(repository, address).await,
            // Hash exists globally and the client proved the payload — associate.
            StoreMatch::MatchHash if payload.is_some() => {
                self.associate_fragment(repository, address).await
            }
            // No match — the payload must have been provided; store it.
            StoreMatch::MatchNone if payload.is_some() => {
                self.write_payload(repository, address, fragment, payload.unwrap())
                    .await
            }
            StoreMatch::MatchHash | StoreMatch::MatchNone => {
                Err(StoreError::internal("Payload buffer required"))
            }
        }
    }

    #[tracing::instrument(level = "debug", skip_all)]
    async fn obliterate(
        self: Arc<Self>,
        partition: Partition,
        address: Address,
        stats: Arc<StoreObliterateStats>,
    ) -> Result<(), StoreError> {
        let _t = self.instruments.start("obliterate", self.pool.status());
        let repository: Context = partition.into();

        let original = self.load_metadata(address.hash).await?;
        lore_storage::validate_fragment_size(&original)?;

        // Acquire the obliteration lock by flagging the metadata; if it is
        // already flagged, another obliteration is in flight / completed.
        if original.flags & FragmentFlags::PayloadObliteration.bits() != 0 {
            return Ok(());
        }
        let mut obliterating = original;
        obliterating.flags |= FragmentFlags::PayloadObliterating.bits();
        self.update_metadata(address.hash, obliterating, original)
            .await?;

        // A fragmented fragment's payload is a list of child references; obliterate
        // each child first.
        if obliterating.flags & FragmentFlags::PayloadFragmented.bits() != 0 {
            let payload = self.get_payload_bytes(address.hash).await?;
            let aligned = payload.to_aligned::<FragmentReference>();
            let references = aligned.as_type_slice::<FragmentReference>().to_vec();
            for reference in references {
                let child = Address {
                    hash: reference.hash,
                    context: address.context,
                };
                self.clone()
                    .obliterate(partition, child, stats.clone())
                    .await?;
            }
        }

        self.delete_association(repository, address).await?;
        stats
            .num_fragments
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // If other associations remain, leave the shared payload in place and
        // restore the metadata to its pre-obliteration state.
        if self.has_associations(address.hash).await? {
            return self
                .update_metadata(address.hash, original, obliterating)
                .await;
        }

        self.delete_payload(address.hash).await?;
        stats
            .num_payloads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let mut obliterated = obliterating;
        obliterated.flags = FragmentFlags::PayloadObliterated.bits();
        obliterated.size_payload = 0;
        obliterated.size_content = 0;
        self.update_metadata(address.hash, obliterated, obliterating)
            .await
    }

    #[tracing::instrument(level = "debug", skip_all)]
    async fn copy(
        self: Arc<Self>,
        source_partition: Partition,
        source_address: Address,
        destination_partition: Partition,
        destination_context: Context,
        _durable: bool,
    ) -> Result<(), StoreError> {
        let _t = self.instruments.start("copy", self.pool.status());
        let source_repository: Context = source_partition.into();
        let destination_repository: Context = destination_partition.into();
        let destination_address = Address {
            hash: source_address.hash,
            context: destination_context,
        };

        let query = self
            .do_query(
                source_repository,
                source_address,
                StoreMatch::MatchFull,
                false,
            )
            .await?;
        if query.match_made != StoreMatch::MatchFull {
            return Err(StoreError::from(AddressNotFound::from(source_address)));
        }

        // Single shared bucket + global hash-keyed metadata: the bytes and the
        // metadata are already reachable for the destination, so a copy is a pure
        // association write.
        self.associate_fragment(destination_repository, destination_address)
            .await
    }

    async fn evict(
        self: Arc<Self>,
        _max_capacity: usize,
        _sync_data: bool,
        _sink: Option<lore_storage::gc_event::GcEventSinkRef>,
    ) -> Result<usize, StoreError> {
        Ok(0)
    }

    async fn compact(
        self: Arc<Self>,
        _max_size: usize,
        _at: Option<usize>,
        _sync_data: bool,
        _sink: Option<lore_storage::gc_event::GcEventSinkRef>,
    ) -> Result<Option<usize>, StoreError> {
        Ok(None)
    }

    async fn compact_resume_at(self: Arc<Self>) -> Option<usize> {
        None
    }

    async fn compact_stop(self: Arc<Self>) {}

    async fn verify(self: Arc<Self>, _heal: bool) -> Result<(), StoreError> {
        Ok(())
    }

    async fn flush(self: Arc<Self>, _sync_data: bool) -> Result<(), StoreError> {
        Ok(())
    }

    fn max_query_batch(&self) -> Option<usize> {
        None
    }
}

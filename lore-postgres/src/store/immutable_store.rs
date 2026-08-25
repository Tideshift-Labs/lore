// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Khurram Virani
// SPDX-License-Identifier: MIT
//! Postgres-backed immutable store (CR-007): fragment bytes and their authoritative
//! representation metadata live together in S3-compatible object storage (for example DO
//! Spaces or MinIO). Postgres holds associations, mutable lifecycle state, and a rebuildable
//! metering projection.
//!
//! The byte path and object-metadata encoding reuse `lore-aws`; Postgres replaces only the
//! coordination records that the AWS backend keeps in DynamoDB:
//!
//! - `lore_fragments` — one row per `(hash, repository, context)` *association*.
//!   Existence is a primary-key/prefix lookup (the three [`StoreMatch`] levels
//!   are leftmost-prefix reads of the `(hash, repository, context)` PK) and the
//!   global refcount is `EXISTS … WHERE hash = …`.
//! - `lore_fragment_state` — one mutable lifecycle row per hash.
//! - `lore_fragment_metering` — an exact, synchronized, but explicitly non-authoritative
//!   projection used for repository storage statistics.
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
use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::operation::get_object::GetObjectError;
use aws_sdk_s3::operation::head_object::HeadObjectError;
use aws_smithy_types::error::metadata::ProvideErrorMetadata;
use bytes::Bytes;
use bytes::BytesMut;
use deadpool_postgres::Pool;
use deadpool_postgres::PoolError;
use lore_aws::aws_error::AwsError;
use lore_aws::aws_error::is_retryable_sdk_error;
use lore_aws::clients::AwsClientBuilder;
use lore_aws::clients::HttpClientSettings;
use lore_aws::clients::TimeoutConfig;
use lore_aws::s3::S3Impl;
use lore_aws::store::object_metadata::ObjectMetadataError;
use lore_aws::store::object_metadata::PAYLOAD_FLAGS;
use lore_aws::store::object_metadata::from_object_metadata;
use lore_aws::store::object_metadata::to_object_metadata;
use lore_base::types::Address;
use lore_base::types::Context;
use lore_base::types::Fragment;
use lore_base::types::FragmentFlags;
use lore_base::types::FragmentReference;
use lore_base::types::Hash;
use lore_base::types::Partition;
use lore_base::types::TypedBytes;
use lore_storage::ImmutableStore;
use lore_storage::StoreError;
use lore_storage::StoreGetData;
use lore_storage::StoreMatch;
use lore_storage::StoreMatchResult;
use lore_storage::StoreObliterateStats;
use lore_storage::StoreRepositoryStats;
use lore_storage::errors::AddressNotFound;
use lore_storage::errors::SlowDown;
use lore_storage::immutable_store::sanitise_fragment_behavior_flags;
use tokio_postgres::Transaction;

/// Self-bootstrapping schema. The `(hash, repository, context)` primary key is
/// the association identity; its B-tree also serves the leftmost-prefix
/// existence reads (`hash`, `(hash, repository)`, full) and the by-hash refcount.
/// The one secondary index inverts that leading column so a whole repository's
/// fragment set is reachable without a sequential scan — the access path
/// [`ImmutableStore::repository_stats`] needs. Lifecycle and metering rows are keyed by `hash`
/// alone because object identity and deduplication are global within the shared regional bucket.
///
/// This const is the runtime authority (applied by [`crate::pool::ensure_schema`]
/// under an advisory lock at boot); `migrations/0001_init.sql` is the same schema
/// as an out-of-band provisioning artifact. Keep the two in lockstep — an object
/// added here but not there is silently missing from any cell provisioned from
/// the migration file, and vice versa.
const SCHEMA: &str = "\
CREATE TABLE IF NOT EXISTS lore_fragments (
    hash       bytea NOT NULL,
    repository bytea NOT NULL,
    context    bytea NOT NULL,
    PRIMARY KEY (hash, repository, context)
);
CREATE INDEX IF NOT EXISTS lore_fragments_repo_hash ON lore_fragments (repository, hash);
CREATE TABLE IF NOT EXISTS lore_fragment_state (
    hash  bytea  NOT NULL PRIMARY KEY,
    state bigint NOT NULL CHECK (state IN (0, 1, 256, 512))
);
CREATE TABLE IF NOT EXISTS lore_fragment_metering (
    hash          bytea  NOT NULL PRIMARY KEY,
    payload_flags bigint NOT NULL CHECK (payload_flags >= 0 AND payload_flags <= 4294967295),
    size_payload bigint NOT NULL CHECK (size_payload >= 0),
    size_content bigint NOT NULL CHECK (size_content >= 0)
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

/// Postgres-backed immutable store with authoritative fragment representations on S3 objects.
pub struct PostgresImmutableStore {
    pool: Pool,
    s3: S3Impl,
    bucket: String,
    instruments: crate::metrics::Instruments,
}

/// Mutable lifecycle state. Representation flags and sizes never live here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FragmentState {
    Stored,
    Obliterating,
    /// Child traversal completed; object-version deletion may be retried idempotently.
    PayloadDeleting,
    Obliterated,
}

impl FragmentState {
    fn bits(self) -> i64 {
        match self {
            Self::Stored => 0,
            Self::Obliterating => i64::from(FragmentFlags::PayloadObliterating.bits()),
            Self::PayloadDeleting => 1,
            Self::Obliterated => i64::from(FragmentFlags::PayloadObliterated.bits()),
        }
    }

    fn from_bits(bits: i64) -> Result<Self, StoreError> {
        match bits {
            0 => Ok(Self::Stored),
            bits if bits == i64::from(FragmentFlags::PayloadObliterating.bits()) => {
                Ok(Self::Obliterating)
            }
            1 => Ok(Self::PayloadDeleting),
            bits if bits == i64::from(FragmentFlags::PayloadObliterated.bits()) => {
                Ok(Self::Obliterated)
            }
            _ => Err(StoreError::internal(format!(
                "invalid fragment lifecycle state {bits}"
            ))),
        }
    }
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
        tls: &crate::pool::TlsConfig,
        object: ObjectStoreSettings,
    ) -> Result<Self, String> {
        let pool = crate::pool::build_pool(pg_url, pool_max, tls)?;
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

    /// Whether the exact repository/context association exists.
    async fn association_exists(
        &self,
        repository: Context,
        address: Address,
    ) -> Result<bool, StoreError> {
        let client = self.pool.get().await.map_err(pool_err)?;
        let hash = address.hash.data().as_slice();
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
            .map(|row| row.is_some())
            .map_err(db_err)
    }

    async fn load_state(&self, hash: Hash) -> Result<Option<FragmentState>, StoreError> {
        let client = self.pool.get().await.map_err(pool_err)?;
        let row = client
            .query_opt(
                "SELECT state FROM lore_fragment_state WHERE hash = $1",
                &[&hash.data().as_slice()],
            )
            .await
            .map_err(db_err)?;
        row.map(|row| {
            row.try_get::<_, i64>("state")
                .map_err(row_decode_err)
                .and_then(FragmentState::from_bits)
        })
        .transpose()
    }

    fn advisory_key(hash: Hash) -> i64 {
        let mut key = [0_u8; 8];
        key.copy_from_slice(&hash.data()[..8]);
        i64::from_be_bytes(key)
    }

    async fn lock_hash(tx: &Transaction<'_>, hash: Hash) -> Result<(), StoreError> {
        tx.execute(
            "SELECT pg_advisory_xact_lock($1)",
            &[&Self::advisory_key(hash)],
        )
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn load_state_tx(
        tx: &Transaction<'_>,
        hash: Hash,
    ) -> Result<Option<FragmentState>, StoreError> {
        let row = tx
            .query_opt(
                "SELECT state FROM lore_fragment_state WHERE hash = $1",
                &[&hash.data().as_slice()],
            )
            .await
            .map_err(db_err)?;
        row.map(|row| {
            row.try_get::<_, i64>("state")
                .map_err(row_decode_err)
                .and_then(FragmentState::from_bits)
        })
        .transpose()
    }

    async fn set_state_tx(
        tx: &Transaction<'_>,
        hash: Hash,
        state: FragmentState,
    ) -> Result<(), StoreError> {
        tx.execute(
            "INSERT INTO lore_fragment_state (hash, state) VALUES ($1, $2) \
             ON CONFLICT (hash) DO UPDATE SET state = EXCLUDED.state",
            &[&hash.data().as_slice(), &state.bits()],
        )
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn upsert_metering_tx(
        tx: &Transaction<'_>,
        hash: Hash,
        fragment: Fragment,
    ) -> Result<(), StoreError> {
        let size_content = i64::try_from(fragment.size_content).map_err(|error| {
            StoreError::internal_with_context(
                error,
                "fragment size_content exceeds Postgres metering range",
            )
        })?;
        tx.execute(
            "INSERT INTO lore_fragment_metering \
                 (hash, payload_flags, size_payload, size_content) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (hash) DO UPDATE SET \
                 payload_flags = EXCLUDED.payload_flags, \
                 size_payload = EXCLUDED.size_payload, \
                 size_content = EXCLUDED.size_content",
            &[
                &hash.data().as_slice(),
                &i64::from(fragment.flags & PAYLOAD_FLAGS),
                &i64::from(fragment.size_payload),
                &size_content,
            ],
        )
        .await
        .map_err(db_err)?;
        Ok(())
    }

    async fn associate_fragment_tx(
        tx: &Transaction<'_>,
        repository: Context,
        address: Address,
    ) -> Result<(), StoreError> {
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
        Ok(())
    }

    async fn association_exists_tx(
        tx: &Transaction<'_>,
        repository: Context,
        address: Address,
    ) -> Result<bool, StoreError> {
        tx.query_opt(
            "SELECT 1 FROM lore_fragments \
             WHERE hash = $1 AND repository = $2 AND context = $3 LIMIT 1",
            &[
                &address.hash.data().as_slice(),
                &repository.data().as_slice(),
                &address.context.data().as_slice(),
            ],
        )
        .await
        .map(|row| row.is_some())
        .map_err(db_err)
    }

    /// Resolve the source form accepted by [`ImmutableStore::copy`]: an exact
    /// context names one association, while zero context names any association
    /// of the hash in the repository partition.
    async fn copy_source_exists_tx(
        tx: &Transaction<'_>,
        repository: Context,
        address: Address,
    ) -> Result<bool, StoreError> {
        if !address.context.is_zero() {
            return Self::association_exists_tx(tx, repository, address).await;
        }

        tx.query_opt(
            "SELECT 1 FROM lore_fragments \
             WHERE hash = $1 AND repository = $2 LIMIT 1",
            &[
                &address.hash.data().as_slice(),
                &repository.data().as_slice(),
            ],
        )
        .await
        .map(|row| row.is_some())
        .map_err(db_err)
    }

    async fn has_associations_tx(tx: &Transaction<'_>, hash: Hash) -> Result<bool, StoreError> {
        tx.query_opt(
            "SELECT 1 FROM lore_fragments WHERE hash = $1 LIMIT 1",
            &[&hash.data().as_slice()],
        )
        .await
        .map(|row| row.is_some())
        .map_err(db_err)
    }

    async fn delete_association_tx(
        tx: &Transaction<'_>,
        repository: Context,
        address: Address,
    ) -> Result<u64, StoreError> {
        tx.execute(
            "DELETE FROM lore_fragments \
             WHERE hash = $1 AND repository = $2 AND context = $3",
            &[
                &address.hash.data().as_slice(),
                &repository.data().as_slice(),
                &address.context.data().as_slice(),
            ],
        )
        .await
        .map_err(db_err)
    }

    fn decode_object_fragment(
        hash: Hash,
        metadata: Option<&std::collections::HashMap<String, String>>,
    ) -> Result<Fragment, StoreError> {
        from_object_metadata(metadata).map_err(|error| match error {
            ObjectMetadataError::Absent => {
                StoreError::internal(format!("S3 object {hash} carries no fragment metadata"))
            }
            ObjectMetadataError::Malformed(_) => {
                StoreError::internal_with_context(error, "S3 object fragment metadata unusable")
            }
        })
    }

    async fn head_fragment(&self, hash: Hash) -> Result<Fragment, StoreError> {
        let key = Self::hash_key(hash);
        let output = self
            .s3
            .head_object(&self.bucket, &key)
            .await
            .map_err(|error| s3_head_error(error, hash))?;
        let fragment = Self::decode_object_fragment(hash, output.metadata())?;
        lore_storage::validate_fragment_metadata(&fragment)?;

        let content_length = output.content_length().ok_or_else(|| {
            StoreError::internal(format!("S3 object {hash} has no content length"))
        })?;
        if content_length < 0 || content_length as u64 != u64::from(fragment.size_payload) {
            return Err(StoreError::internal(format!(
                "S3 object {hash} content length {content_length} does not match fragment size_payload {}",
                fragment.size_payload
            )));
        }

        Ok(stored_durable(fragment))
    }

    /// Recheck under the same per-hash lock used by writers before clearing a stale Stored claim.
    async fn repair_missing_payload(&self, hash: Hash) -> Result<(), StoreError> {
        let mut client = self.pool.get().await.map_err(pool_err)?;
        let tx = client.transaction().await.map_err(db_err)?;
        Self::lock_hash(&tx, hash).await?;

        match self.head_fragment(hash).await {
            Ok(_) => {}
            Err(error) if error.is_address_not_found() => {
                if Self::load_state_tx(&tx, hash).await? == Some(FragmentState::Stored) {
                    tx.execute(
                        "DELETE FROM lore_fragment_state WHERE hash = $1",
                        &[&hash.data().as_slice()],
                    )
                    .await
                    .map_err(db_err)?;
                    tx.execute(
                        "DELETE FROM lore_fragment_metering WHERE hash = $1",
                        &[&hash.data().as_slice()],
                    )
                    .await
                    .map_err(db_err)?;
                }
            }
            Err(error) => return Err(error),
        }

        tx.commit().await.map_err(db_err)
    }

    /// Fetch the payload and its authoritative fragment from one `GetObject` response.
    async fn load(&self, hash: Hash) -> Result<(Fragment, Bytes), StoreError> {
        let key = Self::hash_key(hash);
        let mut output = self
            .s3
            .get_object(&self.bucket, &key, None)
            .await
            .map_err(|error| s3_payload_load_error(error, hash))?;
        let fragment = Self::decode_object_fragment(hash, output.metadata())?;
        lore_storage::validate_fragment_metadata(&fragment)?;

        let mut buffer = BytesMut::with_capacity(fragment.size_payload as usize);
        while let Some(chunk) = output.body.next().await {
            let chunk = chunk.map_err(|error| {
                StoreError::internal_with_context(error, "S3 response stream read failed")
            })?;
            buffer.extend_from_slice(chunk.as_ref());
        }
        let payload = buffer.freeze();
        lore_storage::validate_fragment_payload(&fragment, payload.len())?;
        Ok((stored_durable(fragment), payload))
    }

    /// Remove every object version, including any current delete-marker-visible history.
    async fn delete_payload(&self, hash: Hash) -> Result<(), StoreError> {
        let key = Self::hash_key(hash);

        // `S3Impl::list_versions` exposes no continuation-token arguments. Repeatedly deleting the
        // first page makes the next page become the first, which exhausts arbitrarily long version
        // histories without widening lore-aws's API. Deleting an exact version id is idempotent,
        // so repeating the loop after a crash is harmless.
        loop {
            let listed = self
                .s3
                .list_versions(&self.bucket, &key)
                .await
                .map_err(|error| s3_operation_error(error, "S3 list object versions failed"))?;

            let object_versions = listed.versions.unwrap_or_default();
            let delete_markers = listed.delete_markers.unwrap_or_default();
            let page_entries = object_versions.len() + delete_markers.len();
            if page_entries == 0 {
                // A versioning-off endpoint may not return an entry here. HEAD before the ordinary
                // delete: after a versioned purge (including a resumed one) HEAD is absent, and an
                // unconditional delete would create a fresh marker that this operation just
                // promised to remove.
                match self.s3.head_object(&self.bucket, &key).await {
                    Ok(_) => {
                        self.s3
                            .delete_object(&self.bucket, &key, None)
                            .await
                            .map_err(|error| {
                                s3_operation_error(error, "S3 delete object failed")
                            })?;
                    }
                    Err(error) => {
                        let error = s3_head_error(error, hash);
                        if !error.is_address_not_found() {
                            return Err(error);
                        }
                    }
                }
                break;
            }

            for version in object_versions {
                self.s3
                    .delete_object(&self.bucket, &key, version.version_id)
                    .await
                    .map_err(|error| {
                        s3_operation_error(error, "S3 delete object version failed")
                    })?;
            }
            for marker in delete_markers {
                self.s3
                    .delete_object(&self.bucket, &key, marker.version_id)
                    .await
                    .map_err(|error| s3_operation_error(error, "S3 delete object marker failed"))?;
            }
        }
        Ok(())
    }

    async fn obliterate_sub_fragments(
        self: Arc<Self>,
        partition: Partition,
        address: Address,
        fragment: Fragment,
        payload: Bytes,
        stats: Arc<StoreObliterateStats>,
    ) -> Result<(), StoreError> {
        if fragment.flags & FragmentFlags::PayloadFragmented.bits() == 0 {
            return Ok(());
        }

        let aligned = payload.to_aligned::<FragmentReference>();
        let references = aligned.as_type_slice::<FragmentReference>().to_vec();
        for reference in references {
            self.clone()
                .obliterate(
                    partition,
                    Address {
                        hash: reference.hash,
                        context: address.context,
                    },
                    stats.clone(),
                )
                .await?;
        }
        Ok(())
    }

    /// Rebuild the non-authoritative metering projection from every associated S3 object.
    ///
    /// Both tables are locked for the transaction. Writers may finish their object upload while
    /// waiting, but cannot publish an association until this complete reconciliation commits. A
    /// missing or malformed object aborts the whole transaction, so a successful count never
    /// describes a partially repaired projection.
    pub async fn rebuild_metering_projection(&self) -> Result<u64, StoreError> {
        let mut client = self.pool.get().await.map_err(pool_err)?;
        let tx = client.transaction().await.map_err(db_err)?;
        tx.batch_execute(
            "LOCK TABLE lore_fragments IN SHARE MODE; \
             LOCK TABLE lore_fragment_state IN SHARE MODE; \
             LOCK TABLE lore_fragment_metering IN SHARE ROW EXCLUSIVE MODE;",
        )
        .await
        .map_err(db_err)?;

        let rows = tx
            .query(
                "SELECT DISTINCT f.hash, s.state \
                 FROM lore_fragments f \
                 LEFT JOIN lore_fragment_state s USING (hash) \
                 ORDER BY f.hash",
                &[],
            )
            .await
            .map_err(db_err)?;
        for row in &rows {
            let bytes: Vec<u8> = row.try_get("hash").map_err(row_decode_err)?;
            if bytes.len() != std::mem::size_of::<Hash>() {
                return Err(StoreError::internal(format!(
                    "invalid fragment hash length {} in Postgres",
                    bytes.len()
                )));
            }
            let hash = Hash::from(bytes.as_slice());
            let state = row
                .try_get::<_, Option<i64>>("state")
                .map_err(row_decode_err)?
                .map(FragmentState::from_bits)
                .transpose()?;
            match state {
                Some(FragmentState::Stored) => {}
                Some(FragmentState::Obliterating | FragmentState::PayloadDeleting) => {
                    return Err(StoreError::from(SlowDown));
                }
                Some(FragmentState::Obliterated) | None => {
                    return Err(StoreError::internal(format!(
                        "associated fragment {hash} is not in Stored lifecycle state"
                    )));
                }
            }
            let fragment = self.head_fragment(hash).await?;
            Self::upsert_metering_tx(&tx, hash, fragment).await?;
        }
        tx.execute(
            "DELETE FROM lore_fragment_metering m \
             WHERE NOT EXISTS ( \
                 SELECT 1 FROM lore_fragments f \
                 JOIN lore_fragment_state s USING (hash) \
                 WHERE f.hash = m.hash AND s.state = 0 \
             )",
            &[],
        )
        .await
        .map_err(db_err)?;

        let count = u64::try_from(rows.len())
            .map_err(|error| StoreError::internal_with_context(error, "fragment count overflow"))?;
        tx.commit().await.map_err(db_err)?;
        Ok(count)
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

/// Row/column shape failures are permanent schema or query-contract bugs, never overload.
fn row_decode_err(error: tokio_postgres::Error) -> StoreError {
    StoreError::internal_with_context(error, "postgres immutable-store row decode failed")
}

/// Map a pool-checkout error (transient ⇒ `SlowDown`).
fn pool_err(e: PoolError) -> StoreError {
    if crate::pool::is_transient_pool(&e) {
        StoreError::from(SlowDown)
    } else {
        StoreError::internal(format!("postgres immutable store pool: {e}"))
    }
}

fn s3_payload_load_error(error: AwsError<SdkError<GetObjectError>>, hash: Hash) -> StoreError {
    match &error {
        AwsError::AwsSdkError(sdk_error)
            if matches!(
                sdk_error.as_service_error(),
                Some(GetObjectError::NoSuchKey(_))
            ) =>
        {
            PostgresImmutableStore::not_found(hash)
        }
        AwsError::AwsSdkError(sdk_error) if is_retryable_sdk_error(sdk_error) => {
            StoreError::from(SlowDown)
        }
        _ => StoreError::internal_with_context(error, "S3 get object failed"),
    }
}

fn s3_head_error(error: AwsError<SdkError<HeadObjectError>>, hash: Hash) -> StoreError {
    match &error {
        AwsError::AwsSdkError(sdk_error)
            if matches!(
                sdk_error.as_service_error(),
                Some(HeadObjectError::NotFound(_))
            ) =>
        {
            PostgresImmutableStore::not_found(hash)
        }
        AwsError::AwsSdkError(sdk_error) if is_retryable_sdk_error(sdk_error) => {
            StoreError::from(SlowDown)
        }
        _ => StoreError::internal_with_context(error, "S3 head object failed"),
    }
}

fn s3_operation_error<E>(error: AwsError<SdkError<E>>, context: &str) -> StoreError
where
    E: ProvideErrorMetadata + std::fmt::Debug + Send + Sync + 'static,
{
    match &error {
        AwsError::AwsSdkError(sdk_error) if is_retryable_sdk_error(sdk_error) => {
            StoreError::from(SlowDown)
        }
        _ => StoreError::internal_with_context(error, context),
    }
}

fn stored_durable(mut fragment: Fragment) -> Fragment {
    fragment.flags |= FragmentFlags::PayloadStoredDurable.bits();
    fragment
}

#[async_trait]
impl ImmutableStore for PostgresImmutableStore {
    /// This process serves every tenant in the cell. Reads therefore require the exact
    /// repository/context association even though the object bytes are globally deduplicated.
    fn isolates_partitions(&self) -> bool {
        true
    }

    #[tracing::instrument(level = "debug", skip_all)]
    async fn query(
        self: Arc<Self>,
        partition: Partition,
        addresses: &[Address],
        results: &mut [StoreMatchResult],
    ) -> Result<(), StoreError> {
        debug_assert_eq!(addresses.len(), results.len());
        if addresses.is_empty() {
            return Ok(());
        }
        let _t = self.instruments.start("query", self.pool.status());
        let repository: Context = partition.into();
        let client = self.pool.get().await.map_err(pool_err)?;

        // A fragment push resolves thousands of hashes at once. Join lifecycle state to the
        // associations so an obliterating/obliterated hash can never be reported as usable.
        let hashes: Vec<&[u8]> = addresses.iter().map(|a| a.hash.data().as_slice()).collect();
        let rows = client
            .query(
                "SELECT f.hash, f.context \
                 FROM lore_fragments f \
                 JOIN lore_fragment_state s USING (hash) \
                 WHERE f.repository = $1 AND f.hash = ANY($2) AND s.state = 0",
                &[&repository.data().as_slice(), &hashes],
            )
            .await
            .map_err(db_err)?;
        let present_hashes: HashSet<Vec<u8>> = rows
            .iter()
            .map(|row| row.get::<_, Vec<u8>>("hash"))
            .collect();
        let present_full: HashSet<(Vec<u8>, Vec<u8>)> = rows
            .iter()
            .map(|row| {
                (
                    row.get::<_, Vec<u8>>("hash"),
                    row.get::<_, Vec<u8>>("context"),
                )
            })
            .collect();

        for (address, result) in addresses.iter().zip(results.iter_mut()) {
            let full_key = (
                address.hash.data().to_vec(),
                address.context.data().to_vec(),
            );
            let match_made = if present_full.contains(&full_key) {
                StoreMatch::MatchFull
            } else if present_hashes.contains(address.hash.data().as_slice()) {
                StoreMatch::MatchPartition
            } else {
                StoreMatch::MatchNone
            };
            *result = if match_made == StoreMatch::MatchNone {
                StoreMatchResult::default()
            } else {
                StoreMatchResult {
                    match_made,
                    partition,
                    context: if match_made == StoreMatch::MatchFull {
                        address.context
                    } else {
                        Context::default()
                    },
                    stored_local: false,
                    stored_durable: true,
                }
            };
        }
        Ok(())
    }

    #[tracing::instrument(level = "debug", skip_all)]
    async fn get_metadata(
        self: Arc<Self>,
        partition: Partition,
        address: Address,
    ) -> Result<StoreGetData, StoreError> {
        let _t = self.instruments.start("get_metadata", self.pool.status());
        let repository: Context = partition.into();
        let (associated, state) = tokio::join!(
            self.association_exists(repository, address),
            self.load_state(address.hash)
        );
        if !associated? || state? != Some(FragmentState::Stored) {
            return Ok(StoreGetData::default());
        }

        match self.head_fragment(address.hash).await {
            Ok(fragment) => Ok(StoreGetData::metadata(
                fragment,
                StoreMatch::MatchFull,
                partition,
            )),
            Err(error) if error.is_address_not_found() => {
                if let Err(repair_error) = self.repair_missing_payload(address.hash).await {
                    tracing::warn!(%address, ?repair_error, "failed to repair missing payload state");
                }
                Ok(StoreGetData::default())
            }
            Err(error) => Err(error),
        }
    }

    #[tracing::instrument(level = "debug", skip_all)]
    async fn get(
        self: Arc<Self>,
        partition: Partition,
        address: Address,
    ) -> Result<StoreGetData, StoreError> {
        let _t = self.instruments.start("get", self.pool.status());
        let repository: Context = partition.into();
        let (associated, state) = tokio::join!(
            self.association_exists(repository, address),
            self.load_state(address.hash)
        );
        if !associated? || state? != Some(FragmentState::Stored) {
            return Err(Self::not_found(address.hash));
        }
        let loaded = self.load(address.hash).await;
        if loaded
            .as_ref()
            .err()
            .is_some_and(StoreError::is_address_not_found)
            && let Err(repair_error) = self.repair_missing_payload(address.hash).await
        {
            tracing::warn!(%address, ?repair_error, "failed to repair missing payload state");
        }
        let (fragment, payload) = loaded?;
        lore_storage::validate_fragment_payload(&fragment, payload.len())?;
        Ok(StoreGetData {
            fragment,
            match_made: StoreMatch::MatchFull,
            partition,
            payload: Some(payload),
        })
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
        lore_storage::validate_fragment_metadata(&fragment)?;
        if let Some(payload) = payload.as_ref() {
            lore_storage::validate_fragment_payload(&fragment, payload.len())?;
        } else {
            lore_storage::validate_fragment_size(&fragment)?;
        }
        i64::try_from(fragment.size_content).map_err(|error| {
            StoreError::internal_with_context(
                error,
                "fragment size_content exceeds Postgres metering range",
            )
        })?;
        let repository: Context = partition.into();
        let mut client = self.pool.get().await.map_err(pool_err)?;
        let tx = client.transaction().await.map_err(db_err)?;
        Self::lock_hash(&tx, address.hash).await?;

        let state = Self::load_state_tx(&tx, address.hash).await?;
        let associated = Self::association_exists_tx(&tx, repository, address).await?;
        match state {
            Some(FragmentState::Obliterating | FragmentState::PayloadDeleting) => {
                return Err(StoreError::from(SlowDown));
            }
            Some(FragmentState::Stored) if associated => {
                return tx.commit().await.map_err(db_err);
            }
            Some(FragmentState::Stored) => {
                if payload.is_none() {
                    return Err(StoreError::internal("Payload buffer required"));
                }
                match self.head_fragment(address.hash).await {
                    Ok(authoritative) => {
                        if authoritative.size_content != fragment.size_content {
                            return Err(StoreError::internal("Hash collision"));
                        }
                        Self::upsert_metering_tx(&tx, address.hash, authoritative).await?;
                        Self::associate_fragment_tx(&tx, repository, address).await?;
                        return tx.commit().await.map_err(db_err);
                    }
                    Err(error) if error.is_address_not_found() => {
                        tx.execute(
                            "DELETE FROM lore_fragment_state WHERE hash = $1",
                            &[&address.hash.data().as_slice()],
                        )
                        .await
                        .map_err(db_err)?;
                        tx.execute(
                            "DELETE FROM lore_fragment_metering WHERE hash = $1",
                            &[&address.hash.data().as_slice()],
                        )
                        .await
                        .map_err(db_err)?;
                    }
                    Err(error) => return Err(error),
                }
            }
            Some(FragmentState::Obliterated) | None => {}
        }

        let Some(payload) = payload else {
            return Err(StoreError::internal("Payload buffer required"));
        };
        let key = Self::hash_key(address.hash);
        self.s3
            .put_object(
                &self.bucket,
                &key,
                payload,
                Some(to_object_metadata(&fragment)),
            )
            .await
            .map_err(|error| s3_operation_error(error, "S3 put object failed"))?;

        Self::set_state_tx(&tx, address.hash, FragmentState::Stored).await?;
        Self::upsert_metering_tx(&tx, address.hash, fragment).await?;
        Self::associate_fragment_tx(&tx, repository, address).await?;
        tx.commit().await.map_err(db_err)
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

        // Phase 1: remove this association and durably publish the child-traversal mark. No object
        // request occurs while a Postgres connection is held. A retry that finds either transient
        // state resumes below instead of treating the half-finished operation as complete.
        let phase = {
            let mut client = self.pool.get().await.map_err(pool_err)?;
            let tx = client.transaction().await.map_err(db_err)?;
            Self::lock_hash(&tx, address.hash).await?;

            match Self::load_state_tx(&tx, address.hash).await? {
                Some(FragmentState::Stored) => {
                    if !Self::association_exists_tx(&tx, repository, address).await? {
                        tx.commit().await.map_err(db_err)?;
                        return Ok(());
                    }

                    let deleted = Self::delete_association_tx(&tx, repository, address).await?;
                    if Self::has_associations_tx(&tx, address.hash).await? {
                        tx.commit().await.map_err(db_err)?;
                        if deleted > 0 {
                            stats
                                .num_fragments
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        return Ok(());
                    }

                    Self::set_state_tx(&tx, address.hash, FragmentState::Obliterating).await?;
                    tx.commit().await.map_err(db_err)?;
                    if deleted > 0 {
                        stats
                            .num_fragments
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    FragmentState::Obliterating
                }
                Some(FragmentState::Obliterating) => {
                    tx.commit().await.map_err(db_err)?;
                    FragmentState::Obliterating
                }
                Some(FragmentState::PayloadDeleting) => {
                    tx.commit().await.map_err(db_err)?;
                    FragmentState::PayloadDeleting
                }
                Some(FragmentState::Obliterated) | None => {
                    tx.commit().await.map_err(db_err)?;
                    return Ok(());
                }
            }
        };

        // Phase 2: read the still-present parent object and recursively finish its children. This
        // is deliberately resumable: an error leaves Obliterating committed, so the next call
        // repeats the idempotent child traversal. Once complete, publish PayloadDeleting.
        if phase == FragmentState::Obliterating {
            let (fragment, payload) = self.load(address.hash).await?;
            self.clone()
                .obliterate_sub_fragments(partition, address, fragment, payload, stats.clone())
                .await?;

            let mut client = self.pool.get().await.map_err(pool_err)?;
            let tx = client.transaction().await.map_err(db_err)?;
            Self::lock_hash(&tx, address.hash).await?;
            if Self::has_associations_tx(&tx, address.hash).await? {
                return Err(StoreError::internal(
                    "fragment gained an association during obliteration",
                ));
            }
            match Self::load_state_tx(&tx, address.hash).await? {
                Some(FragmentState::Obliterating) => {
                    Self::set_state_tx(&tx, address.hash, FragmentState::PayloadDeleting).await?;
                    tx.commit().await.map_err(db_err)?;
                }
                Some(FragmentState::PayloadDeleting) => {
                    tx.commit().await.map_err(db_err)?;
                }
                Some(FragmentState::Obliterated) => {
                    tx.commit().await.map_err(db_err)?;
                    return Ok(());
                }
                Some(FragmentState::Stored) | None => {
                    return Err(StoreError::internal(
                        "fragment lifecycle regressed during obliteration",
                    ));
                }
            }
        }

        // Phase 3: version deletion is idempotent and runs without a database checkout. A crash
        // after this call leaves PayloadDeleting committed; retrying lists/deletes again and then
        // performs the final state/projection transaction.
        self.delete_payload(address.hash).await?;

        let mut client = self.pool.get().await.map_err(pool_err)?;
        let tx = client.transaction().await.map_err(db_err)?;
        Self::lock_hash(&tx, address.hash).await?;
        match Self::load_state_tx(&tx, address.hash).await? {
            Some(FragmentState::PayloadDeleting) => {
                if Self::has_associations_tx(&tx, address.hash).await? {
                    return Err(StoreError::internal(
                        "fragment gained an association while deleting its payload",
                    ));
                }
                tx.execute(
                    "DELETE FROM lore_fragment_metering WHERE hash = $1",
                    &[&address.hash.data().as_slice()],
                )
                .await
                .map_err(db_err)?;
                Self::set_state_tx(&tx, address.hash, FragmentState::Obliterated).await?;
                tx.commit().await.map_err(db_err)?;
                stats
                    .num_payloads
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            }
            Some(FragmentState::Obliterated) => {
                tx.commit().await.map_err(db_err)?;
                Ok(())
            }
            Some(FragmentState::Obliterating) => Err(StoreError::from(SlowDown)),
            Some(FragmentState::Stored) | None => Err(StoreError::internal(
                "fragment lifecycle changed while deleting its payload",
            )),
        }
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

        let mut client = self.pool.get().await.map_err(pool_err)?;
        let tx = client.transaction().await.map_err(db_err)?;
        Self::lock_hash(&tx, source_address.hash).await?;
        if Self::load_state_tx(&tx, source_address.hash).await? != Some(FragmentState::Stored)
            || !Self::copy_source_exists_tx(&tx, source_repository, source_address).await?
        {
            return Err(StoreError::from(AddressNotFound::from(source_address)));
        }

        match self.head_fragment(source_address.hash).await {
            Ok(fragment) => {
                Self::upsert_metering_tx(&tx, source_address.hash, fragment).await?;
                Self::associate_fragment_tx(&tx, destination_repository, destination_address)
                    .await?;
                tx.commit().await.map_err(db_err)
            }
            Err(error) if error.is_address_not_found() => {
                tx.execute(
                    "DELETE FROM lore_fragment_state WHERE hash = $1",
                    &[&source_address.hash.data().as_slice()],
                )
                .await
                .map_err(db_err)?;
                tx.execute(
                    "DELETE FROM lore_fragment_metering WHERE hash = $1",
                    &[&source_address.hash.data().as_slice()],
                )
                .await
                .map_err(db_err)?;
                tx.commit().await.map_err(db_err)?;
                Err(error)
            }
            Err(error) => Err(error),
        }
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

    #[tracing::instrument(level = "debug", skip_all)]
    async fn repository_stats(
        self: Arc<Self>,
        partition: Partition,
    ) -> Result<StoreRepositoryStats, StoreError> {
        let _t = self
            .instruments
            .start("repository_stats", self.pool.status());
        let repository: Context = partition.into();
        let mut client = self.pool.get().await.map_err(pool_err)?;
        let tx = client.transaction().await.map_err(db_err)?;

        // An inner join could return an exact-looking undercount after projection loss. Find every
        // missing row first, acquire hash locks in a stable order, and synchronously reconstruct it
        // from authoritative object metadata. Any failed HEAD rolls the whole repair transaction
        // back and fails this stats call rather than publishing a partial result.
        let incomplete = tx
            .query(
                "SELECT DISTINCT f.hash, s.state \
                 FROM lore_fragments f \
                 LEFT JOIN lore_fragment_state s USING (hash) \
                 LEFT JOIN lore_fragment_metering m USING (hash) \
                 WHERE f.repository = $1 \
                   AND (m.hash IS NULL OR s.hash IS NULL OR s.state <> 0) \
                 ORDER BY f.hash",
                &[&repository.data().as_slice()],
            )
            .await
            .map_err(db_err)?;
        for row in incomplete {
            let bytes: Vec<u8> = row.try_get("hash").map_err(row_decode_err)?;
            if bytes.len() != std::mem::size_of::<Hash>() {
                return Err(StoreError::internal(format!(
                    "invalid fragment hash length {} in Postgres",
                    bytes.len()
                )));
            }
            let hash = Hash::from(bytes.as_slice());
            Self::lock_hash(&tx, hash).await?;

            // The association may have been removed while this transaction waited for its hash.
            // Skip it if so; the aggregate below observes the current committed association set.
            if tx
                .query_opt(
                    "SELECT 1 FROM lore_fragments WHERE repository = $1 AND hash = $2 LIMIT 1",
                    &[&repository.data().as_slice(), &hash.data().as_slice()],
                )
                .await
                .map_err(db_err)?
                .is_none()
            {
                continue;
            }

            match Self::load_state_tx(&tx, hash).await? {
                Some(FragmentState::Stored) => {
                    let fragment = self.head_fragment(hash).await?;
                    Self::upsert_metering_tx(&tx, hash, fragment).await?;
                }
                Some(FragmentState::Obliterating | FragmentState::PayloadDeleting) => {
                    return Err(StoreError::from(SlowDown));
                }
                Some(FragmentState::Obliterated) | None => {
                    return Err(StoreError::internal(format!(
                        "associated fragment {hash} is not in Stored lifecycle state"
                    )));
                }
            }
        }

        // DISTINCT deduplicates contexts within the repository. LEFT JOIN keeps incomplete rows
        // visible so the count comparison can fail closed instead of returning an undercount.
        // `SUM(bigint)` yields numeric, so cast back to bigint.
        let row = tx
            .query_one(
                "SELECT COUNT(*)::bigint AS referenced_count, \
                        COUNT(m.hash)::bigint AS projected_count, \
                        COUNT(s.hash) FILTER (WHERE s.state = 0)::bigint AS stored_count, \
                        COALESCE(SUM(m.size_payload), 0)::bigint AS payload_bytes, \
                        COALESCE(SUM(m.size_content), 0)::bigint AS content_bytes \
                 FROM (SELECT DISTINCT hash FROM lore_fragments WHERE repository = $1) f \
                 LEFT JOIN lore_fragment_metering m USING (hash) \
                 LEFT JOIN lore_fragment_state s USING (hash)",
                &[&repository.data().as_slice()],
            )
            .await
            .map_err(db_err)?;

        // `try_get` rather than `get`: the latter panics on a column or type mismatch.
        let read = |column: &str| -> Result<u64, StoreError> {
            let value: i64 = row.try_get(column).map_err(row_decode_err)?;
            u64::try_from(value).map_err(|error| {
                StoreError::internal_with_context(error, "negative repository storage statistic")
            })
        };

        let referenced_count = read("referenced_count")?;
        if read("projected_count")? != referenced_count || read("stored_count")? != referenced_count
        {
            return Err(StoreError::internal(
                "repository storage projection is incomplete after repair",
            ));
        }

        let result = StoreRepositoryStats {
            fragment_count: referenced_count,
            payload_bytes: read("payload_bytes")?,
            content_bytes: read("content_bytes")?,
        };
        tx.commit().await.map_err(db_err)?;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use aws_sdk_s3::config::http::HttpResponse;
    use aws_sdk_s3::error::ErrorMetadata;
    use aws_sdk_s3::operation::get_object::GetObjectError;
    use aws_sdk_s3::primitives::SdkBody;
    use aws_sdk_s3::types::error::NoSuchKey;
    use rand::random;

    use super::*;

    fn service_error(error: GetObjectError, status: u16) -> AwsError<SdkError<GetObjectError>> {
        AwsError::AwsSdkError(Box::new(SdkError::service_error(
            error,
            HttpResponse::new(status.try_into().unwrap(), SdkBody::empty()),
        )))
    }

    #[test]
    fn s3_payload_load_error_no_such_key_is_address_not_found() {
        let error = service_error(
            GetObjectError::NoSuchKey(
                NoSuchKey::builder()
                    .meta(ErrorMetadata::builder().code("NoSuchKey").build())
                    .build(),
            ),
            404,
        );

        let error = s3_payload_load_error(error, random::<Hash>());

        assert!(
            error.is_address_not_found(),
            "expected AddressNotFound, got {error:?}"
        );
    }

    #[test]
    fn s3_payload_load_error_retryable_timeout_is_slow_down() {
        let error = AwsError::AwsSdkError(Box::new(SdkError::timeout_error(
            std::io::Error::other("injected timeout"),
        )));

        let error = s3_payload_load_error(error, random::<Hash>());

        assert!(error.is_slow_down(), "expected SlowDown, got {error:?}");
    }

    #[test]
    fn s3_payload_load_error_permanent_service_errors_are_internal() {
        for (code, status) in [("AccessDenied", 403), ("NoSuchBucket", 404)] {
            let error = service_error(
                GetObjectError::generic(ErrorMetadata::builder().code(code).build()),
                status,
            );

            let error = s3_payload_load_error(error, random::<Hash>());

            assert!(
                error.is_internal(),
                "expected {code} ({status}) to map to Internal, got {error:?}"
            );
        }
    }

    #[test]
    fn s3_payload_load_error_non_sdk_error_is_internal() {
        let error = s3_payload_load_error(AwsError::JoinError, random::<Hash>());

        assert!(error.is_internal(), "expected Internal, got {error:?}");
    }
}

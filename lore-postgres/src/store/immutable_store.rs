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

use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use std::time::SystemTime;

use async_trait::async_trait;
use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::operation::get_object::GetObjectError;
use aws_sdk_s3::operation::head_object::HeadObjectError;
use aws_smithy_types::error::metadata::ProvideErrorMetadata;
use aws_smithy_types::retry::RetryConfig;
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

use crate::domain::fragments::BeginOutcome;
use crate::domain::fragments::BudgetPin;
use crate::domain::fragments::CONTENT_STRUCTURE_MASK;
use crate::domain::fragments::CellProviderBoundary;
use crate::domain::fragments::CommitVerdict;
use crate::domain::fragments::DecodeSupport;
use crate::domain::fragments::ENCODING_MASK;
use crate::domain::fragments::EpochAuthority;
use crate::domain::fragments::FragmentAttemptLedger;
use crate::domain::fragments::FragmentDirectPutOperation;
use crate::domain::fragments::FragmentDispatchRuntimeConfig;
use crate::domain::fragments::FragmentGetAttempt;
use crate::domain::fragments::FragmentGetOperation;
use crate::domain::fragments::FragmentGetResponse;
use crate::domain::fragments::FragmentManifest;
use crate::domain::fragments::FragmentObliterateBegin;
use crate::domain::fragments::FragmentObliteratePhase;
use crate::domain::fragments::FragmentObliterateRepresentation;
use crate::domain::fragments::FragmentProviderActivationError;
use crate::domain::fragments::FragmentProviderAttempt;
use crate::domain::fragments::FragmentProviderDisposition;
use crate::domain::fragments::FragmentProviderEntry;
use crate::domain::fragments::FragmentProviderError;
use crate::domain::fragments::FragmentPurgeProof;
use crate::domain::fragments::FragmentPurgeTarget;
use crate::domain::fragments::FragmentQueryRequest;
use crate::domain::fragments::FragmentTransportOperation;
use crate::domain::fragments::FragmentTransportResponse;
use crate::domain::fragments::FragmentVerdict;
use crate::domain::fragments::FragmentWriteCapabilityReadiness;
use crate::domain::fragments::FragmentWriteClaimInput;
use crate::domain::fragments::FragmentWriteSettlement;
use crate::domain::fragments::InFlightPutBound;
use crate::domain::fragments::IoObservation;
use crate::domain::fragments::MissingDiagnostic;
use crate::domain::fragments::PostgresFragmentCoordinator;
use crate::domain::fragments::ProviderAttemptClass;
use crate::domain::fragments::ProviderAttemptOutcome;
use crate::domain::fragments::ProviderCapabilities;
use crate::domain::fragments::ProviderTrafficClass;
use crate::domain::fragments::coordinator::DirectWriteKind;
use crate::domain::fragments::decodable_encoding;
use crate::domain::fragments::read_fragment_write_capability;

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

/// Typed runtime inputs that are specific to the governed fragment route.
pub struct FragmentProviderRuntimeSettings {
    capabilities: ProviderCapabilities,
    in_flight_puts: InFlightPutBound,
    late_effect_bound: Duration,
    provider_write_authority_revision: Option<String>,
}

impl FragmentProviderRuntimeSettings {
    pub fn new(
        capabilities: ProviderCapabilities,
        in_flight_puts: InFlightPutBound,
        late_effect_bound: Duration,
        provider_write_authority_revision: Option<String>,
    ) -> Self {
        Self {
            capabilities,
            in_flight_puts,
            late_effect_bound,
            provider_write_authority_revision,
        }
    }
}

/// Provider-independent exact staged-epoch cleanup supplied by WP-114's future
/// write-behind route. Direct provider mode intentionally leaves this absent.
#[async_trait]
pub trait StagedEpochCleanup: Send + Sync {
    /// Read one exact staged path for child discovery. `None` is decisive
    /// absence; uncertainty is an error and keeps the head deleting.
    async fn read_exact(&self, target: &FragmentPurgeTarget) -> Result<Option<Bytes>, StoreError>;

    /// Prove one exact staged path removed.
    async fn purge_exact(&self, target: &FragmentPurgeTarget) -> Result<(), StoreError>;
}

/// Closed configuration refusals from the retry-disabled physical S3 adapter.
///
/// These are startup classifications, not provider outcomes. No variant
/// carries a credential, endpoint, bucket, region, or SDK configuration value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PostgresFragmentTransportConfigError {
    #[error("fragment provider S3 client has no resolved retry configuration")]
    MissingRetryConfiguration,
    #[error("fragment provider S3 client automatic retry is not disabled")]
    RetryEnabled,
    #[error("fragment provider S3 client has no trustworthy resolved region")]
    MissingResolvedRegion,
    #[error("fragment provider target has an invalid normalized region")]
    InvalidTargetRegion,
    #[error("fragment provider target region does not match resolved S3 client")]
    RegionMismatch,
    #[error("fragment provider S3 client has no trustworthy resolved endpoint")]
    MissingResolvedEndpoint,
    #[error("fragment provider target has an invalid normalized endpoint")]
    InvalidTargetEndpoint,
    #[error("fragment provider target endpoint does not match resolved S3 client")]
    EndpointMismatch,
    #[error("fragment provider bucket has versioning enabled")]
    BucketVersioningEnabled,
    #[error("fragment provider bucket has versioning suspended")]
    BucketVersioningSuspended,
    #[error("fragment provider bucket returned an unknown versioning status")]
    BucketVersioningUnknown,
    #[error("fragment provider bucket versioning probe failed")]
    BucketVersioningProbeFailed,
    #[error("fragment provider bucket versioning probe did not issue exactly one request")]
    BucketVersioningAttemptCount,
}

/// Closed startup failures while attaching the governed fragment route.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PostgresFragmentProviderActivationError {
    #[error("fragment provider bucket does not match immutable store bucket")]
    BucketMismatch,
    #[error("fragment provider requires an explicit resolved S3 endpoint")]
    MissingResolvedEndpoint,
    #[error("fragment provider S3 transport configuration failed: {0}")]
    Transport(
        #[from]
        #[source]
        PostgresFragmentTransportConfigError,
    ),
    #[error("fragment provider seam activation failed: {0}")]
    Provider(
        #[from]
        #[source]
        FragmentProviderActivationError,
    ),
}

impl From<PostgresFragmentProviderActivationError> for StoreError {
    fn from(error: PostgresFragmentProviderActivationError) -> Self {
        StoreError::internal_with_context(error, "fragment provider activation failed")
    }
}

/// Postgres-backed immutable store with authoritative fragment representations on S3 objects.
pub struct PostgresImmutableStore {
    pool: Pool,
    s3: S3Impl,
    bucket: String,
    instruments: crate::metrics::Instruments,
    fragment_route: FragmentLifecycleRoute,
    staged_epoch_cleanup: Option<Arc<dyn StagedEpochCleanup>>,
    io_timeout: Duration,
}

enum FragmentLifecycleRoute {
    Legacy,
    Coordinated {
        coordinator: PostgresFragmentCoordinator,
        provider: Arc<FragmentProviderEntry>,
        budget_pin: BudgetPin,
        late_effect_bound: Duration,
        provider_write_authority_revision: Option<String>,
    },
}

#[derive(Clone, Copy)]
struct CoordinatedProvider<'a> {
    entry: &'a FragmentProviderEntry,
    budget_pin: &'a BudgetPin,
    late_effect_bound: Duration,
}

struct CoordinatedDirectPut<'a> {
    intent: &'a crate::domain::fragments::FragmentIntent,
    manifest: &'a FragmentManifest,
    address: Address,
    fragment: Fragment,
    payload: &'a Bytes,
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

        // Build the legacy S3-compatible byte client with its existing retry
        // policy. Coordinated mode derives its separate retry-disabled client
        // from this client's resolved configuration only when that route is
        // selected.
        let http_settings = HttpClientSettings::default();
        let builder = Box::pin(
            AwsClientBuilder::builder()
                .with_http_settings(&http_settings)
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

        let io_timeout = Duration::from_millis(object.timeout_millis);
        Ok(Self {
            pool,
            s3,
            bucket: object.bucket,
            instruments: crate::metrics::Instruments::new("immutable"),
            fragment_route: FragmentLifecycleRoute::Legacy,
            staged_epoch_cleanup: None,
            io_timeout,
        })
    }

    /// Select the coordinator-owned route after server boot has proved the
    /// lifecycle schema complete, enabled, and ready and constructed the one
    /// attested provider entry. Absent or disabled cells never call this.
    pub fn with_fragment_lifecycle(
        mut self,
        coordinator: PostgresFragmentCoordinator,
        provider: Arc<FragmentProviderEntry>,
        budget_pin: BudgetPin,
        late_effect_bound: Duration,
        provider_write_authority_revision: Option<String>,
    ) -> Self {
        self.fragment_route = FragmentLifecycleRoute::Coordinated {
            coordinator,
            provider,
            budget_pin,
            late_effect_bound,
            provider_write_authority_revision,
        };
        self
    }

    /// Attach the staged cleanup collaborator without changing provider or
    /// lifecycle ownership. Direct mode never calls this.
    pub fn with_staged_epoch_cleanup(mut self, cleanup: Arc<dyn StagedEpochCleanup>) -> Self {
        self.staged_epoch_cleanup = Some(cleanup);
        self
    }

    /// Read the durable cell-wide write capability through this store's
    /// existing pool. This grants no write authority and constructs no
    /// provider route.
    pub async fn fragment_write_capability_readiness(
        &self,
    ) -> Result<FragmentWriteCapabilityReadiness, StoreError> {
        read_fragment_write_capability(&self.pool)
            .await
            .map_err(domain_store_err)
    }

    /// Build the one governed provider entry around a distinct SDK client, then
    /// select the coordinator route. The new client clones the legacy client's
    /// resolved configuration and overrides only automatic retry, so credentials,
    /// endpoint, region, timeouts, and path-style behavior cannot drift. Server
    /// boot calls this only after readiness chose complete+enabled lifecycle mode.
    pub async fn with_fragment_provider(
        self,
        coordinator: PostgresFragmentCoordinator,
        budget_pin: BudgetPin,
        dispatch: FragmentDispatchRuntimeConfig,
        boundary: CellProviderBoundary,
        runtime: FragmentProviderRuntimeSettings,
    ) -> Result<Self, PostgresFragmentProviderActivationError> {
        let target = boundary.target().clone();
        if target.bucket != self.bucket {
            return Err(PostgresFragmentProviderActivationError::BucketMismatch);
        }
        let resolved_endpoint_url = self
            .s3
            .resolved_endpoint_url()
            .ok_or(PostgresFragmentProviderActivationError::MissingResolvedEndpoint)?;
        let provider_config = self
            .s3
            .sdk_client()
            .config()
            .to_builder()
            .retry_config(RetryConfig::disabled())
            .build();
        let transport = super::fragment_transport::PostgresFragmentS3Transport::new(
            aws_sdk_s3::Client::from_conf(provider_config),
            target.bucket,
            target.region,
            target.endpoint_host,
            &resolved_endpoint_url,
        )
        .await?;
        let provider = FragmentProviderEntry::connect(
            dispatch,
            boundary,
            runtime.capabilities,
            runtime.in_flight_puts,
            transport,
        )
        .await?;
        Ok(self.with_fragment_lifecycle(
            coordinator,
            Arc::new(provider),
            budget_pin,
            runtime.late_effect_bound,
            runtime.provider_write_authority_revision,
        ))
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

    fn fragment_from_manifest(manifest: &FragmentManifest) -> Result<Fragment, MissingDiagnostic> {
        Ok(Fragment {
            flags: u32::try_from(manifest.payload_flags)
                .map_err(|_| MissingDiagnostic::InvalidStructure)?,
            size_payload: u32::try_from(manifest.size_payload)
                .map_err(|_| MissingDiagnostic::InvalidStructure)?,
            size_content: u64::try_from(manifest.size_content)
                .map_err(|_| MissingDiagnostic::InvalidStructure)?,
        })
    }

    /// Validate a stored representation in the required order: shared
    /// structural validators, supported-decoder selection, decode, then
    /// semantic comparison with the immutable manifest and requested hash.
    fn validate_candidate(
        requested_hash: Hash,
        manifest: &FragmentManifest,
        fragment: Fragment,
        payload: Bytes,
    ) -> Result<(Fragment, Bytes), MissingDiagnostic> {
        lore_storage::validate_fragment_metadata(&fragment)
            .map_err(|_| MissingDiagnostic::InvalidStructure)?;
        if lore_storage::validate_fragment_payload(&fragment, payload.len()).is_err() {
            return Err(if payload.len() < fragment.size_payload as usize {
                MissingDiagnostic::Truncated
            } else {
                MissingDiagnostic::InvalidStructure
            });
        }
        if fragment.flags & FragmentFlags::PayloadFragmented.bits() != 0 {
            lore_storage::validate_fragment_list(&fragment, &payload)
                .map_err(|_| MissingDiagnostic::InvalidStructure)?;
        }

        match decodable_encoding(fragment.flags) {
            DecodeSupport::Supported => {}
            DecodeSupport::RecognizedUnsupported => {
                return Err(MissingDiagnostic::UnrepairableEncoding);
            }
            DecodeSupport::Undefined => return Err(MissingDiagnostic::InvalidStructure),
        }

        let decoded = if fragment.flags & ENCODING_MASK == 0 {
            payload.clone()
        } else {
            lore_storage::decompress(fragment, payload.as_ref())
                .map_err(|_| MissingDiagnostic::Corrupt)?
                .1
                .freeze()
        };
        let persisted_flags = fragment.flags & (CONTENT_STRUCTURE_MASK | ENCODING_MASK);
        let manifest_flags = u32::try_from(manifest.payload_flags)
            .map_err(|_| MissingDiagnostic::InvalidStructure)?;
        let decoded_hash = Hash::hash_buffer(decoded.as_ref());
        if manifest.size_payload != i64::from(fragment.size_payload)
            || manifest.size_content != i64::try_from(fragment.size_content).unwrap_or(i64::MAX)
            || manifest_flags != persisted_flags
            || manifest.decoded_hash.as_slice() != decoded_hash.data()
            || decoded_hash != requested_hash
        {
            return Err(MissingDiagnostic::Corrupt);
        }
        Ok((stored_durable(fragment), payload))
    }

    async fn resolve_one(
        coordinator: &PostgresFragmentCoordinator,
        repository: Context,
        address: Address,
    ) -> Result<crate::domain::fragments::FragmentResolution, StoreError> {
        coordinator
            .resolve(
                repository.data(),
                address.context.data(),
                &[address.hash.data().to_vec()],
            )
            .await
            .map_err(domain_store_err)?
            .into_iter()
            .next()
            .ok_or_else(|| StoreError::internal("fragment resolver omitted its requested hash"))
    }

    async fn mark_coordinated_missing(
        coordinator: &PostgresFragmentCoordinator,
        witness: &crate::domain::fragments::EpochWitness,
        diagnostic: MissingDiagnostic,
    ) -> Result<(), StoreError> {
        coordinator
            .mark_missing(witness, diagnostic)
            .await
            .map_err(domain_store_err)?;
        Ok(())
    }

    async fn load_coordinated(
        &self,
        coordinator: &PostgresFragmentCoordinator,
        provider: &FragmentProviderEntry,
        repository: Context,
        address: Address,
    ) -> Result<(Fragment, Bytes), StoreError> {
        let resolution = Self::resolve_one(coordinator, repository, address).await?;
        let captured_verdict = resolution.verdict.clone();
        let FragmentVerdict::Readable {
            witness, manifest, ..
        } = resolution.verdict
        else {
            return Err(Self::not_found(address.hash));
        };

        let loaded = match manifest.authority {
            EpochAuthority::Remote => {
                let logical_request_id = uuid::Uuid::now_v7().hyphenated().to_string();
                let attempt_id = uuid::Uuid::now_v7().hyphenated().to_string();
                let execution = provider
                    .get(
                        &FragmentGetAttempt {
                            logical_request_id,
                            attempt_id,
                            attempt_ordinal: 1,
                        },
                        &FragmentGetOperation {
                            object_key: manifest.object_key.clone(),
                        },
                    )
                    .await
                    .map_err(provider_store_err)?;
                match (execution.outcome, execution.response) {
                    (
                        ProviderAttemptOutcome::Decisive,
                        FragmentGetResponse::Found { bytes, metadata },
                    ) => {
                        let metadata = metadata.into_iter().collect::<HashMap<_, _>>();
                        let fragment = from_object_metadata(Some(&metadata))
                            .map_err(|_| MissingDiagnostic::InvalidStructure);
                        match fragment.and_then(|fragment| {
                            Self::validate_candidate(
                                address.hash,
                                &manifest,
                                fragment,
                                Bytes::from(bytes),
                            )
                        }) {
                            Ok(loaded) => loaded,
                            Err(diagnostic) => {
                                Self::mark_coordinated_missing(coordinator, &witness, diagnostic)
                                    .await?;
                                return Err(Self::not_found(address.hash));
                            }
                        }
                    }
                    (ProviderAttemptOutcome::Decisive, FragmentGetResponse::NotFound) => {
                        Self::mark_coordinated_missing(
                            coordinator,
                            &witness,
                            MissingDiagnostic::Absent,
                        )
                        .await?;
                        return Err(Self::not_found(address.hash));
                    }
                    (ProviderAttemptOutcome::Decisive, FragmentGetResponse::Throttled)
                    | (ProviderAttemptOutcome::Ambiguous, _) => {
                        return Err(StoreError::from(SlowDown));
                    }
                    (
                        ProviderAttemptOutcome::Decisive,
                        FragmentGetResponse::DefiniteFailure
                        | FragmentGetResponse::AmbiguousFailure,
                    ) => {
                        return Err(StoreError::internal(
                            "fragment provider GET did not return a readable response",
                        ));
                    }
                }
            }
            EpochAuthority::Staged => {
                let deadline = SystemTime::now()
                    .checked_add(self.io_timeout)
                    .ok_or_else(|| StoreError::internal("staged lease deadline overflow"))?;
                let lease_id = *uuid::Uuid::now_v7().as_bytes();
                coordinator
                    .acquire_staged_leases(
                        &lease_id,
                        &[(witness.hash.clone(), witness.epoch)],
                        deadline,
                    )
                    .await
                    .map_err(domain_store_err)?;
                let read =
                    tokio::time::timeout(self.io_timeout, tokio::fs::read(&manifest.object_key))
                        .await;
                let result = match read {
                    Ok(Ok(bytes)) => Self::fragment_from_manifest(&manifest).and_then(|fragment| {
                        Self::validate_candidate(
                            address.hash,
                            &manifest,
                            fragment,
                            Bytes::from(bytes),
                        )
                    }),
                    Ok(Err(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                        Err(MissingDiagnostic::Absent)
                    }
                    Ok(Err(_)) | Err(_) => {
                        coordinator
                            .release_staged_lease(&lease_id)
                            .await
                            .map_err(domain_store_err)?;
                        return Err(StoreError::from(SlowDown));
                    }
                };
                coordinator
                    .release_staged_lease(&lease_id)
                    .await
                    .map_err(domain_store_err)?;
                match result {
                    Ok(loaded) => loaded,
                    Err(diagnostic) => {
                        Self::mark_coordinated_missing(coordinator, &witness, diagnostic).await?;
                        return Err(Self::not_found(address.hash));
                    }
                }
            }
        };

        let revalidated = Self::resolve_one(coordinator, repository, address).await?;
        if revalidated.verdict != captured_verdict {
            return Err(StoreError::from(SlowDown));
        }
        Ok(loaded)
    }

    fn provider_deadline_unix_ms(&self) -> Result<i64, StoreError> {
        let deadline = SystemTime::now()
            .checked_add(self.io_timeout)
            .ok_or_else(|| StoreError::internal("fragment provider deadline overflow"))?;
        let millis = deadline
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|error| {
                StoreError::internal_with_context(error, "fragment provider deadline before epoch")
            })?
            .as_millis();
        i64::try_from(millis).map_err(|error| {
            StoreError::internal_with_context(error, "fragment provider deadline exceeds i64")
        })
    }

    fn validate_head_candidate(
        requested_hash: Hash,
        manifest: &FragmentManifest,
        metadata: Vec<(String, String)>,
        content_length: u64,
    ) -> Result<Fragment, MissingDiagnostic> {
        let metadata = metadata.into_iter().collect::<HashMap<_, _>>();
        let fragment = from_object_metadata(Some(&metadata))
            .map_err(|_| MissingDiagnostic::InvalidStructure)?;
        lore_storage::validate_fragment_metadata(&fragment)
            .map_err(|_| MissingDiagnostic::InvalidStructure)?;

        let manifest_flags = u32::try_from(manifest.payload_flags)
            .map_err(|_| MissingDiagnostic::InvalidStructure)?;
        let persisted_flags = fragment.flags & (CONTENT_STRUCTURE_MASK | ENCODING_MASK);
        if content_length != u64::from(fragment.size_payload)
            || manifest.size_payload != i64::from(fragment.size_payload)
            || manifest.size_content != i64::try_from(fragment.size_content).unwrap_or(i64::MAX)
            || manifest_flags != persisted_flags
            || manifest.decoded_hash.as_slice() != requested_hash.data()
        {
            return Err(MissingDiagnostic::Corrupt);
        }
        Ok(stored_durable(fragment))
    }

    async fn load_metadata_coordinated(
        &self,
        coordinator: &PostgresFragmentCoordinator,
        provider: &FragmentProviderEntry,
        budget_pin: &BudgetPin,
        repository: Context,
        address: Address,
    ) -> Result<Fragment, StoreError> {
        let resolution = Self::resolve_one(coordinator, repository, address).await?;
        let captured_verdict = resolution.verdict.clone();
        let FragmentVerdict::Readable {
            witness, manifest, ..
        } = resolution.verdict
        else {
            return Err(Self::not_found(address.hash));
        };
        if manifest.authority == EpochAuthority::Staged {
            return Self::fragment_from_manifest(&manifest)
                .map(stored_durable)
                .map_err(|_| Self::not_found(address.hash));
        }

        let logical_request_id = uuid::Uuid::now_v7().hyphenated().to_string();
        let attempt_id = uuid::Uuid::now_v7().hyphenated().to_string();
        let mut ledger = FragmentAttemptLedger::new(
            provider.boundary().provider_boundary_id(),
            &logical_request_id,
        )
        .map_err(provider_store_err)?;
        let admitted = provider
            .admit_operation(
                FragmentProviderAttempt {
                    traffic_class: ProviderTrafficClass::Read,
                    attempt_class: ProviderAttemptClass::HeadObject,
                    logical_request_id,
                    attempt_id,
                    attempt_ordinal: 1,
                    deadline_unix_ms: self.provider_deadline_unix_ms()?,
                    budget_pin: budget_pin.clone(),
                    put_body: None,
                },
                FragmentTransportOperation::Head {
                    object_key: manifest.object_key.clone(),
                },
            )
            .await
            .map_err(provider_store_err)?;
        let execution = admitted
            .execute(&mut ledger)
            .await
            .map_err(provider_store_err)?;
        let fragment = match (execution.outcome, execution.response) {
            (
                ProviderAttemptOutcome::Decisive,
                FragmentTransportResponse::Head {
                    metadata,
                    content_length,
                },
            ) => match Self::validate_head_candidate(
                address.hash,
                &manifest,
                metadata,
                content_length,
            ) {
                Ok(fragment) => fragment,
                Err(diagnostic) => {
                    Self::mark_coordinated_missing(coordinator, &witness, diagnostic).await?;
                    return Err(Self::not_found(address.hash));
                }
            },
            (ProviderAttemptOutcome::Decisive, FragmentTransportResponse::NotFound) => {
                Self::mark_coordinated_missing(coordinator, &witness, MissingDiagnostic::Absent)
                    .await?;
                return Err(Self::not_found(address.hash));
            }
            (ProviderAttemptOutcome::Ambiguous, _) => return Err(StoreError::from(SlowDown)),
            (ProviderAttemptOutcome::Decisive, FragmentTransportResponse::DefiniteFailure) => {
                return Err(StoreError::internal(
                    "fragment provider HEAD returned a definite failure",
                ));
            }
            _ => {
                return Err(StoreError::internal(
                    "fragment provider HEAD returned an inconsistent response",
                ));
            }
        };

        let revalidated = Self::resolve_one(coordinator, repository, address).await?;
        if revalidated.verdict != captured_verdict {
            return Err(StoreError::from(SlowDown));
        }
        Ok(fragment)
    }

    fn direct_manifest(
        intent: &crate::domain::fragments::FragmentIntent,
        address: Address,
        fragment: Fragment,
        payload: &Bytes,
    ) -> Result<FragmentManifest, StoreError> {
        let mut identity = blake3::Hasher::new();
        identity.update(b"lore-fragment-manifest-v1\0");
        identity.update(&(intent.object_key.len() as u64).to_le_bytes());
        identity.update(intent.object_key.as_bytes());
        identity.update(&fragment.flags.to_le_bytes());
        identity.update(&fragment.size_payload.to_le_bytes());
        identity.update(&fragment.size_content.to_le_bytes());
        identity.update(address.hash.data());
        identity.update(blake3::hash(payload).as_bytes());
        Ok(FragmentManifest {
            authority: EpochAuthority::Remote,
            object_key: intent.object_key.clone(),
            manifest_id: identity.finalize().as_bytes().to_vec(),
            size_payload: i64::from(fragment.size_payload),
            size_content: i64::try_from(fragment.size_content).map_err(|error| {
                StoreError::internal_with_context(
                    error,
                    "fragment size_content exceeds manifest range",
                )
            })?,
            decoded_hash: address.hash.data().to_vec(),
            payload_flags: i64::from(fragment.flags & (CONTENT_STRUCTURE_MASK | ENCODING_MASK)),
        })
    }

    async fn verify_conditional_put(
        &self,
        provider: &FragmentProviderEntry,
        manifest: &FragmentManifest,
        address: Address,
    ) -> Result<IoObservation, StoreError> {
        let execution = provider
            .get(
                &FragmentGetAttempt {
                    logical_request_id: uuid::Uuid::now_v7().hyphenated().to_string(),
                    attempt_id: uuid::Uuid::now_v7().hyphenated().to_string(),
                    attempt_ordinal: 1,
                },
                &FragmentGetOperation {
                    object_key: manifest.object_key.clone(),
                },
            )
            .await
            .map_err(provider_store_err)?;
        match (execution.outcome, execution.response) {
            (ProviderAttemptOutcome::Decisive, FragmentGetResponse::Found { bytes, metadata }) => {
                let metadata = metadata.into_iter().collect::<HashMap<_, _>>();
                let fragment = match from_object_metadata(Some(&metadata)) {
                    Ok(fragment) => fragment,
                    Err(_) => {
                        return Ok(IoObservation::Unusable(MissingDiagnostic::InvalidStructure));
                    }
                };
                match Self::validate_candidate(address.hash, manifest, fragment, Bytes::from(bytes))
                {
                    Ok(_) => Ok(IoObservation::Valid(manifest.clone())),
                    Err(diagnostic) => Ok(IoObservation::Unusable(diagnostic)),
                }
            }
            (ProviderAttemptOutcome::Decisive, FragmentGetResponse::NotFound) => {
                Ok(IoObservation::Unusable(MissingDiagnostic::Absent))
            }
            (ProviderAttemptOutcome::Decisive, FragmentGetResponse::Throttled)
            | (ProviderAttemptOutcome::Ambiguous, _) => Err(StoreError::from(SlowDown)),
            _ => Err(StoreError::internal(
                "conditional fragment object verification failed",
            )),
        }
    }

    async fn settle_direct_put(
        coordinator: &PostgresFragmentCoordinator,
        claim: &crate::domain::fragments::FragmentWriteClaim,
        settlement: FragmentWriteSettlement,
    ) -> Result<(), StoreError> {
        coordinator
            .settle_write_claim(claim, settlement)
            .await
            .map_err(domain_store_err)
    }

    async fn issue_direct_put(
        &self,
        coordinator: &PostgresFragmentCoordinator,
        provider: CoordinatedProvider<'_>,
        request: CoordinatedDirectPut<'_>,
    ) -> Result<(IoObservation, FragmentWriteSettlement), StoreError> {
        let claim = request.intent.write_claim().ok_or_else(|| {
            StoreError::internal("fragment direct PUT intent has no durable write claim")
        })?;
        let body_blake3 = *blake3::hash(request.payload).as_bytes();
        let binding_matches = claim.hash() == request.address.hash.data()
            && claim.epoch() == request.intent.epoch
            && claim.fence() == request.intent.fence
            && claim.authority() == request.intent.authority
            && claim.object_key() == request.intent.object_key.as_str()
            && claim.body_blake3() == &body_blake3
            && claim.body_size() == request.payload.len() as u64;
        if !binding_matches {
            Self::settle_direct_put(coordinator, claim, FragmentWriteSettlement::NoSend).await?;
            return Err(StoreError::internal(
                "fragment direct PUT does not match its durable write claim",
            ));
        }
        let logical_request_id = uuid::Uuid::from_bytes(*claim.logical_request_id())
            .hyphenated()
            .to_string();
        let attempt_id = uuid::Uuid::from_bytes(*claim.attempt_id())
            .hyphenated()
            .to_string();
        let ledger = FragmentAttemptLedger::new(
            provider.entry.boundary().provider_boundary_id(),
            &logical_request_id,
        );
        let mut ledger = match ledger {
            Ok(ledger) => ledger,
            Err(error) => {
                Self::settle_direct_put(coordinator, claim, FragmentWriteSettlement::NoSend)
                    .await?;
                return Err(provider_store_err(error));
            }
        };
        let traffic_class = match request.intent.direct_write_kind() {
            Some(DirectWriteKind::Normal) => ProviderTrafficClass::DirectFallback,
            Some(DirectWriteKind::Repair) => ProviderTrafficClass::Repair,
            None => {
                Self::settle_direct_put(coordinator, claim, FragmentWriteSettlement::NoSend)
                    .await?;
                return Err(StoreError::internal(
                    "fragment direct PUT intent has no direct-write lineage",
                ));
            }
        };
        let deadline_unix_ms = match system_time_millis(claim.send_not_after()) {
            Ok(deadline) => deadline,
            Err(error) => {
                Self::settle_direct_put(coordinator, claim, FragmentWriteSettlement::NoSend)
                    .await?;
                return Err(error);
            }
        };
        let admitted = provider
            .entry
            .admit_put(
                FragmentProviderAttempt {
                    traffic_class,
                    attempt_class: ProviderAttemptClass::PutObject,
                    logical_request_id,
                    attempt_id,
                    attempt_ordinal: 1,
                    deadline_unix_ms,
                    budget_pin: provider.budget_pin.clone(),
                    put_body: None,
                },
                FragmentDirectPutOperation {
                    object_key: request.intent.object_key.clone(),
                    metadata: to_object_metadata(&request.fragment).into_iter().collect(),
                    declared_size: request.payload.len() as u64,
                    declared_blake3: body_blake3,
                },
            )
            .await;
        let admitted = match admitted {
            Ok(admitted) => admitted,
            Err(error) => {
                Self::settle_direct_put(coordinator, claim, FragmentWriteSettlement::NoSend)
                    .await?;
                return Err(provider_store_err(error));
            }
        };
        let authorized = match coordinator.authorize_write_claim(claim).await {
            Ok(authorized) => authorized,
            Err(error) => {
                Self::settle_direct_put(coordinator, claim, FragmentWriteSettlement::NoSend)
                    .await?;
                return Err(domain_store_err(error));
            }
        };
        if authorized.send_budget().is_zero() {
            Self::settle_direct_put(coordinator, claim, FragmentWriteSettlement::NoSend).await?;
            return Err(StoreError::from(SlowDown));
        }
        let execution = tokio::time::timeout(
            authorized.send_budget(),
            admitted.execute_direct_put(&mut ledger, request.payload),
        )
        .await;
        let execution = match execution {
            Ok(Ok(execution)) => execution,
            Ok(Err(error)) => {
                let settlement = if ledger.attempt_count() == 0
                    && ledger.committed_grant_count() == 0
                    && ledger.ambiguous_count() == 0
                {
                    FragmentWriteSettlement::NoSend
                } else {
                    FragmentWriteSettlement::Ambiguous
                };
                Self::settle_direct_put(coordinator, claim, settlement).await?;
                return Err(provider_store_err(error));
            }
            Err(_) => {
                Self::settle_direct_put(coordinator, claim, FragmentWriteSettlement::Ambiguous)
                    .await?;
                return Err(StoreError::from(SlowDown));
            }
        };
        let settlement = match execution.outcome {
            ProviderAttemptOutcome::Decisive => FragmentWriteSettlement::Decisive,
            ProviderAttemptOutcome::Ambiguous => FragmentWriteSettlement::Ambiguous,
        };
        let observation = match (execution.outcome, execution.response) {
            (ProviderAttemptOutcome::Decisive, FragmentTransportResponse::PutCreated) => {
                Ok(IoObservation::Valid(request.manifest.clone()))
            }
            (
                ProviderAttemptOutcome::Decisive,
                FragmentTransportResponse::PutPreconditionFailed,
            )
            | (ProviderAttemptOutcome::Ambiguous, _) => {
                self.verify_conditional_put(provider.entry, request.manifest, request.address)
                    .await
            }
            (ProviderAttemptOutcome::Decisive, FragmentTransportResponse::DefiniteFailure) => {
                Err(StoreError::internal("fragment provider PUT failed"))
            }
            _ => Err(StoreError::internal(
                "fragment provider PUT returned an inconsistent response",
            )),
        };
        match observation {
            Ok(observation) => Ok((observation, settlement)),
            Err(error) => {
                Self::settle_direct_put(coordinator, claim, settlement).await?;
                Err(error)
            }
        }
    }

    async fn put_coordinated(
        &self,
        coordinator: &PostgresFragmentCoordinator,
        provider: CoordinatedProvider<'_>,
        repository: Context,
        address: Address,
        fragment: Fragment,
        payload: Option<Bytes>,
    ) -> Result<(), StoreError> {
        let Some(payload) = payload else {
            return match Self::resolve_one(coordinator, repository, address)
                .await?
                .verdict
            {
                FragmentVerdict::Readable { .. } => Ok(()),
                FragmentVerdict::Absent => Err(StoreError::internal(
                    "fragment direct PUT requires payload bytes",
                )),
            };
        };
        let preflight_manifest = FragmentManifest {
            authority: EpochAuthority::Remote,
            object_key: String::new(),
            manifest_id: vec![0; 32],
            size_payload: i64::from(fragment.size_payload),
            size_content: i64::try_from(fragment.size_content).map_err(|error| {
                StoreError::internal_with_context(
                    error,
                    "fragment size_content exceeds manifest range",
                )
            })?,
            decoded_hash: address.hash.data().to_vec(),
            payload_flags: i64::from(fragment.flags & (CONTENT_STRUCTURE_MASK | ENCODING_MASK)),
        };
        Self::validate_candidate(address.hash, &preflight_manifest, fragment, payload.clone())
            .map_err(|diagnostic| {
                StoreError::internal(format!(
                    "fragment direct PUT semantic validation failed: {diagnostic:?}"
                ))
            })?;
        let legacy_key = Self::hash_key(address.hash);
        let logical_request_id = uuid::Uuid::now_v7();
        let attempt_id = uuid::Uuid::now_v7();
        let write_claim = FragmentWriteClaimInput::new(
            *logical_request_id.as_bytes(),
            *attempt_id.as_bytes(),
            *blake3::hash(&payload).as_bytes(),
            payload.len() as u64,
            self.io_timeout,
            provider.late_effect_bound,
        )
        .map_err(domain_store_err)?;
        let begin = coordinator
            .begin_direct_write(address.hash.data(), &legacy_key, write_claim)
            .await
            .map_err(domain_store_err)?;
        let intent = match begin {
            BeginOutcome::AlreadyReadable(witness) => {
                return match coordinator
                    .create_association_if_current(
                        &witness,
                        repository.data(),
                        address.context.data(),
                    )
                    .await
                    .map_err(domain_store_err)?
                {
                    CommitVerdict::Published => Ok(()),
                    CommitVerdict::Fenced | CommitVerdict::Abandoned => {
                        Err(StoreError::from(SlowDown))
                    }
                };
            }
            BeginOutcome::Fenced(_) => return Err(StoreError::from(SlowDown)),
            BeginOutcome::WriteClaimBlocked { .. } => {
                return Err(StoreError::from(SlowDown));
            }
            BeginOutcome::Admitted(intent) => intent,
        };
        let manifest = Self::direct_manifest(&intent, address, fragment, &payload)?;

        let (observation, settlement) = self
            .issue_direct_put(
                coordinator,
                provider,
                CoordinatedDirectPut {
                    intent: &intent,
                    manifest: &manifest,
                    address,
                    fragment,
                    payload: &payload,
                },
            )
            .await?;
        let published_readable = matches!(observation, IoObservation::Valid(_));
        match coordinator
            .commit_remote(&intent, observation, settlement)
            .await
            .map_err(domain_store_err)?
        {
            CommitVerdict::Published => {}
            CommitVerdict::Fenced | CommitVerdict::Abandoned => {
                return Err(StoreError::from(SlowDown));
            }
        }
        if !published_readable {
            return Err(StoreError::from(SlowDown));
        }
        match coordinator
            .create_association(
                address.hash.data(),
                repository.data(),
                address.context.data(),
            )
            .await
            .map_err(domain_store_err)?
        {
            CommitVerdict::Published => Ok(()),
            CommitVerdict::Fenced | CommitVerdict::Abandoned => Err(StoreError::from(SlowDown)),
        }
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

    fn validate_obliterate_child_candidate(
        address: Address,
        manifest: &FragmentManifest,
        candidate: Option<(Fragment, Bytes)>,
    ) -> Result<Option<(Fragment, Bytes)>, StoreError> {
        let Some((fragment, bytes)) = candidate else {
            return Err(StoreError::internal(
                "exact fragmented representation is absent during child discovery",
            ));
        };
        Self::validate_candidate(address.hash, manifest, fragment, bytes)
            .map(Some)
            .map_err(|diagnostic| {
                StoreError::internal(format!(
                    "exact fragment child-discovery payload is invalid: {diagnostic:?}"
                ))
            })
    }

    fn record_owned_obliterate_completion(stats: &StoreObliterateStats) {
        stats
            .num_fragments
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        stats
            .num_payloads
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    async fn load_obliterate_representation(
        &self,
        provider: &FragmentProviderEntry,
        cleanup: Option<&Arc<dyn StagedEpochCleanup>>,
        address: Address,
        representation: &FragmentObliterateRepresentation,
    ) -> Result<Option<(Fragment, Bytes)>, StoreError> {
        let Some(manifest) = representation.manifest() else {
            return Ok(None);
        };
        let payload_flags = u32::try_from(manifest.payload_flags).map_err(|error| {
            StoreError::internal_with_context(error, "fragment purge payload flags exceed u32")
        })?;
        if payload_flags & FragmentFlags::PayloadFragmented.bits() == 0 {
            return Ok(None);
        }
        let candidate = match representation.target().authority() {
            EpochAuthority::Remote => {
                let execution = provider
                    .get(
                        &FragmentGetAttempt {
                            logical_request_id: uuid::Uuid::now_v7().hyphenated().to_string(),
                            attempt_id: uuid::Uuid::now_v7().hyphenated().to_string(),
                            attempt_ordinal: 1,
                        },
                        &FragmentGetOperation {
                            object_key: representation.target().object_key().to_owned(),
                        },
                    )
                    .await
                    .map_err(provider_store_err)?;
                match (execution.outcome, execution.response) {
                    (
                        ProviderAttemptOutcome::Decisive,
                        FragmentGetResponse::Found { bytes, metadata },
                    ) => {
                        let metadata = metadata.into_iter().collect::<HashMap<_, _>>();
                        let fragment = from_object_metadata(Some(&metadata)).map_err(|error| {
                            StoreError::internal_with_context(
                                error,
                                "exact fragment child-discovery metadata is invalid",
                            )
                        })?;
                        Some((fragment, Bytes::from(bytes)))
                    }
                    (ProviderAttemptOutcome::Decisive, FragmentGetResponse::NotFound) => None,
                    (ProviderAttemptOutcome::Decisive, FragmentGetResponse::Throttled)
                    | (ProviderAttemptOutcome::Ambiguous, _) => {
                        return Err(StoreError::from(SlowDown));
                    }
                    (
                        ProviderAttemptOutcome::Decisive,
                        FragmentGetResponse::DefiniteFailure
                        | FragmentGetResponse::AmbiguousFailure,
                    ) => {
                        return Err(StoreError::internal(
                            "exact fragment child-discovery GET failed",
                        ));
                    }
                }
            }
            EpochAuthority::Staged => {
                let cleanup = cleanup.ok_or_else(|| {
                    StoreError::internal(
                        "coordinated obliterate encountered staged authority without cleanup",
                    )
                })?;
                cleanup
                    .read_exact(representation.target())
                    .await?
                    .map(|bytes| {
                        Self::fragment_from_manifest(manifest)
                            .map(|fragment| (fragment, bytes))
                            .map_err(|diagnostic| {
                                StoreError::internal(format!(
                                    "exact staged child-discovery manifest is invalid: {diagnostic:?}"
                                ))
                            })
                    })
                    .transpose()?
            }
        };
        Self::validate_obliterate_child_candidate(address, manifest, candidate)
    }

    async fn purge_obliterate_target(
        &self,
        provider: CoordinatedProvider<'_>,
        cleanup: Option<&Arc<dyn StagedEpochCleanup>>,
        target: &FragmentPurgeTarget,
    ) -> Result<FragmentPurgeProof, StoreError> {
        match target.authority() {
            EpochAuthority::Staged => {
                let cleanup = cleanup.ok_or_else(|| {
                    StoreError::internal(
                        "coordinated obliterate encountered staged authority without cleanup",
                    )
                })?;
                cleanup.purge_exact(target).await?;
            }
            EpochAuthority::Remote => {
                let logical_request_id = uuid::Uuid::now_v7().hyphenated().to_string();
                let attempt_id = uuid::Uuid::now_v7().hyphenated().to_string();
                let mut ledger = FragmentAttemptLedger::new(
                    provider.entry.boundary().provider_boundary_id(),
                    &logical_request_id,
                )
                .map_err(provider_store_err)?;
                let admitted = provider
                    .entry
                    .admit_operation(
                        FragmentProviderAttempt {
                            traffic_class: ProviderTrafficClass::Operator,
                            attempt_class: ProviderAttemptClass::DeleteObject,
                            logical_request_id,
                            attempt_id,
                            attempt_ordinal: 1,
                            deadline_unix_ms: self.provider_deadline_unix_ms()?,
                            budget_pin: provider.budget_pin.clone(),
                            put_body: None,
                        },
                        FragmentTransportOperation::DeleteExact {
                            object_key: target.object_key().to_owned(),
                        },
                    )
                    .await
                    .map_err(provider_store_err)?;
                let execution =
                    tokio::time::timeout(self.io_timeout, admitted.execute(&mut ledger))
                        .await
                        .map_err(|_| StoreError::from(SlowDown))?
                        .map_err(provider_store_err)?;
                match (execution.outcome, execution.response) {
                    (ProviderAttemptOutcome::Decisive, FragmentTransportResponse::Deleted) => {}
                    (ProviderAttemptOutcome::Ambiguous, _) => {
                        return Err(StoreError::from(SlowDown));
                    }
                    _ => {
                        return Err(StoreError::internal(
                            "exact unversioned fragment delete failed",
                        ));
                    }
                }
            }
        }
        Ok(FragmentPurgeProof::new(target.clone()))
    }

    async fn obliterate_coordinated(
        self: Arc<Self>,
        coordinator: &PostgresFragmentCoordinator,
        provider: CoordinatedProvider<'_>,
        provider_write_authority_revision: &str,
        partition: Partition,
        address: Address,
        stats: Arc<StoreObliterateStats>,
    ) -> Result<(), StoreError> {
        let repository: Context = partition.into();
        loop {
            let begin = coordinator
                .begin_obliterate(
                    address.hash.data(),
                    repository.data(),
                    address.context.data(),
                    provider_write_authority_revision,
                )
                .await
                .map_err(domain_store_err)?;
            let intent = match begin {
                FragmentObliterateBegin::NoOp => return Ok(()),
                FragmentObliterateBegin::AssociationOnly => {
                    stats
                        .num_fragments
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    return Ok(());
                }
                FragmentObliterateBegin::Blocked { blocked_until, .. } => {
                    if let Ok(delay) = blocked_until.duration_since(SystemTime::now())
                        && !delay.is_zero()
                    {
                        tokio::time::sleep(delay).await;
                    }
                    continue;
                }
                FragmentObliterateBegin::Ready(intent) => intent,
            };
            let cleanup = self.staged_epoch_cleanup.as_ref();
            if intent
                .purge_targets()
                .iter()
                .any(|target| target.authority() == EpochAuthority::Staged)
                && cleanup.is_none()
            {
                return Err(StoreError::internal(
                    "coordinated obliterate requires staged epoch cleanup",
                ));
            }
            match intent.phase() {
                FragmentObliteratePhase::Children => {
                    if let Some(current) = intent.current()
                        && let Some((fragment, payload)) = self
                            .load_obliterate_representation(
                                provider.entry,
                                cleanup,
                                address,
                                current,
                            )
                            .await?
                    {
                        self.clone()
                            .obliterate_sub_fragments(
                                partition,
                                address,
                                fragment,
                                payload,
                                stats.clone(),
                            )
                            .await?;
                    }
                    match coordinator
                        .commit_obliterate_children(&intent)
                        .await
                        .map_err(domain_store_err)?
                    {
                        CommitVerdict::Published => continue,
                        CommitVerdict::Fenced | CommitVerdict::Abandoned => {
                            return Err(StoreError::from(SlowDown));
                        }
                    }
                }
                FragmentObliteratePhase::Payload => {
                    let mut proofs = Vec::with_capacity(intent.purge_targets().len());
                    for target in intent.purge_targets() {
                        proofs.push(
                            self.purge_obliterate_target(provider, cleanup, target)
                                .await?,
                        );
                    }
                    match coordinator
                        .commit_obliterate_payload(&intent, &proofs)
                        .await
                        .map_err(domain_store_err)?
                    {
                        CommitVerdict::Published => {
                            Self::record_owned_obliterate_completion(&stats);
                            return Ok(());
                        }
                        CommitVerdict::Fenced | CommitVerdict::Abandoned => {
                            return Err(StoreError::from(SlowDown));
                        }
                    }
                }
            }
        }
    }

    /// Rebuild the non-authoritative metering projection for the active lifecycle route.
    ///
    /// The coordinated route delegates to lifecycle authority and performs no provider I/O. The
    /// legacy route below retains its existing S3 metadata reconstruction: both legacy tables are
    /// locked for the transaction, and a missing or malformed object aborts the reconciliation.
    pub async fn rebuild_metering_projection(&self) -> Result<u64, StoreError> {
        if let FragmentLifecycleRoute::Coordinated { coordinator, .. } = &self.fragment_route {
            return coordinator
                .rebuild_metering_projection()
                .await
                .map_err(domain_store_err);
        }

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
fn domain_store_err(error: crate::domain::errors::DomainError) -> StoreError {
    if error.is_retryable() {
        StoreError::from(SlowDown)
    } else {
        StoreError::internal_with_context(error, "fragment lifecycle coordinator failed")
    }
}

fn provider_store_err(error: FragmentProviderError) -> StoreError {
    match error.disposition() {
        FragmentProviderDisposition::Transient => StoreError::from(SlowDown),
        FragmentProviderDisposition::InvalidInput
        | FragmentProviderDisposition::NotReady
        | FragmentProviderDisposition::OutcomeUnknown
        | FragmentProviderDisposition::Internal => {
            StoreError::internal_with_context(error, "fragment provider seam failed")
        }
    }
}

fn system_time_millis(value: SystemTime) -> Result<i64, StoreError> {
    let millis = value
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|error| {
            StoreError::internal_with_context(error, "fragment write send deadline before epoch")
        })?
        .as_millis();
    i64::try_from(millis).map_err(|error| {
        StoreError::internal_with_context(error, "fragment write send deadline exceeds i64")
    })
}

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
        if let FragmentLifecycleRoute::Coordinated { coordinator, .. } = &self.fragment_route {
            let requested = addresses
                .iter()
                .map(|address| FragmentQueryRequest {
                    hash: address.hash.data().to_vec(),
                    context: address.context.data().to_vec(),
                })
                .collect::<Vec<_>>();
            let matches = coordinator
                .resolve_query_matches(repository.data(), &requested)
                .await
                .map_err(domain_store_err)?;
            if matches.len() != results.len() {
                return Err(StoreError::internal(
                    "fragment query resolver returned the wrong result count",
                ));
            }
            for ((address, resolved), result) in
                addresses.iter().zip(matches).zip(results.iter_mut())
            {
                if resolved.hash.as_slice() != address.hash.data() {
                    return Err(StoreError::internal(
                        "fragment query resolver changed request order",
                    ));
                }
                let match_made = if resolved.exact_context_readable {
                    StoreMatch::MatchFull
                } else if resolved.partition_readable {
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
            return Ok(());
        }
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
        if let FragmentLifecycleRoute::Coordinated {
            coordinator,
            provider,
            budget_pin,
            ..
        } = &self.fragment_route
        {
            return match self
                .load_metadata_coordinated(coordinator, provider, budget_pin, repository, address)
                .await
            {
                Ok(fragment) => Ok(StoreGetData::metadata(
                    fragment,
                    StoreMatch::MatchFull,
                    partition,
                )),
                Err(error) if error.is_address_not_found() => Ok(StoreGetData::default()),
                Err(error) => Err(error),
            };
        }
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
        if let FragmentLifecycleRoute::Coordinated {
            coordinator,
            provider,
            ..
        } = &self.fragment_route
        {
            let (fragment, payload) = self
                .load_coordinated(coordinator, provider, repository, address)
                .await?;
            return Ok(StoreGetData {
                fragment,
                match_made: StoreMatch::MatchFull,
                partition,
                payload: Some(payload),
            });
        }
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
        if let FragmentLifecycleRoute::Coordinated {
            coordinator,
            provider,
            budget_pin,
            late_effect_bound,
            ..
        } = &self.fragment_route
        {
            return self
                .put_coordinated(
                    coordinator,
                    CoordinatedProvider {
                        entry: provider,
                        budget_pin,
                        late_effect_bound: *late_effect_bound,
                    },
                    repository,
                    address,
                    fragment,
                    payload,
                )
                .await;
        }
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

        if let FragmentLifecycleRoute::Coordinated {
            coordinator,
            provider,
            budget_pin,
            late_effect_bound,
            provider_write_authority_revision,
        } = &self.fragment_route
        {
            let revision = provider_write_authority_revision.as_deref().ok_or_else(|| {
                StoreError::internal(
                    "coordinated obliterate requires an activated provider write-authority revision",
                )
            })?;
            return self
                .clone()
                .obliterate_coordinated(
                    coordinator,
                    CoordinatedProvider {
                        entry: provider,
                        budget_pin,
                        late_effect_bound: *late_effect_bound,
                    },
                    revision,
                    partition,
                    address,
                    stats,
                )
                .await;
        }

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

        if let FragmentLifecycleRoute::Coordinated { coordinator, .. } = &self.fragment_route {
            let hashes = [source_address.hash.data().to_vec()];
            let resolution = if source_address.context.is_zero() {
                coordinator
                    .resolve_partition(source_repository.data(), &hashes)
                    .await
            } else {
                coordinator
                    .resolve(
                        source_repository.data(),
                        source_address.context.data(),
                        &hashes,
                    )
                    .await
            }
            .map_err(domain_store_err)?
            .into_iter()
            .next()
            .ok_or_else(|| StoreError::internal("copy resolver omitted its requested hash"))?;
            let FragmentVerdict::Readable { witness, .. } = resolution.verdict else {
                return Err(StoreError::from(AddressNotFound::from(source_address)));
            };
            return match coordinator
                .create_association_if_current(
                    &witness,
                    destination_repository.data(),
                    destination_context.data(),
                )
                .await
                .map_err(domain_store_err)?
            {
                crate::domain::fragments::CommitVerdict::Published => Ok(()),
                crate::domain::fragments::CommitVerdict::Fenced
                | crate::domain::fragments::CommitVerdict::Abandoned => {
                    Err(StoreError::from(SlowDown))
                }
            };
        }

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
        if let FragmentLifecycleRoute::Coordinated { coordinator, .. } = &self.fragment_route {
            let stats = coordinator
                .repository_stats(repository.data())
                .await
                .map_err(domain_store_err)?;
            return Ok(StoreRepositoryStats {
                fragment_count: stats.fragment_count,
                payload_bytes: stats.payload_bytes,
                content_bytes: stats.content_bytes,
            });
        }
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
    use std::time::Duration;

    use aws_sdk_s3::config::http::HttpResponse;
    use aws_sdk_s3::error::ErrorMetadata;
    use aws_sdk_s3::operation::get_object::GetObjectError;
    use aws_sdk_s3::primitives::SdkBody;
    use aws_sdk_s3::types::error::NoSuchKey;
    use rand::random;
    use uuid::Uuid;

    use super::*;
    use crate::domain::PostgresDomainStore;
    use crate::domain::errors::DomainError;
    use crate::domain::fragments::BeginOutcome;
    use crate::domain::fragments::CommitVerdict;
    use crate::domain::fragments::FragmentLifecycleState;
    use crate::domain::fragments::FragmentObliterateBegin;
    use crate::domain::fragments::FragmentObliteratePhase;
    use crate::domain::fragments::FragmentWriteCapabilityCutover;
    use crate::domain::fragments::FragmentWriteClaimInput;
    use crate::domain::fragments::FragmentWriteSettlement;
    use crate::domain::fragments::IoObservation;
    use crate::domain::fragments::schema;
    use crate::pool::TlsConfig;

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

    /// CR-031/WP-118: the fragment lifecycle schema lives under
    /// `domain/fragments/schema.rs`, migration-owned and mirrored into
    /// `migrations/0001_init.sql`. It must never be added to this legacy
    /// auto-bootstrap `SCHEMA` const, because that would make a legacy-only
    /// cell (one that never runs the CR-031 migration, e.g. an old binary or a
    /// deployment that intentionally stays on the pre-WP-118 lifecycle path)
    /// silently start creating fragment-coordinator relations it has no
    /// coordinator to read them with. A name collision here is a real defect,
    /// not a naming coincidence -- every one of these tables/sequences is a
    /// CR-031 contract name, not a word that could appear in this legacy
    /// schema by accident.
    #[test]
    fn legacy_bootstrap_schema_does_not_contain_the_fragment_lifecycle_relations() {
        const FRAGMENT_LIFECYCLE_RELATIONS: [&str; 7] = [
            "lore_fragment_lifecycle",
            "lore_fragment_epochs",
            "lore_fragment_associations",
            "lore_fragment_lifecycle_metering",
            "lore_fragment_staged_leases",
            "lore_fragment_schema_state",
            "lore_fragment_fence_seq",
        ];
        for relation in FRAGMENT_LIFECYCLE_RELATIONS {
            assert!(
                !SCHEMA.contains(relation),
                "the legacy immutable-store SCHEMA const must not create the \
                 CR-031 fragment lifecycle relation {relation}; that DDL \
                 belongs only to domain/fragments/schema.rs and \
                 migrations/0001_init.sql"
            );
        }
    }

    fn fragmented_obliterate_manifest(authority: EpochAuthority) -> FragmentManifest {
        FragmentManifest {
            authority,
            object_key: "exact-fragment-key".to_owned(),
            manifest_id: vec![0x41; 32],
            size_payload: 1,
            size_content: 1,
            decoded_hash: vec![0x42; 32],
            payload_flags: i64::from(FragmentFlags::PayloadFragmented.bits()),
        }
    }

    #[test]
    fn fragmented_remote_not_found_fails_closed_before_children_commit() {
        let error = PostgresImmutableStore::validate_obliterate_child_candidate(
            Address::default(),
            &fragmented_obliterate_manifest(EpochAuthority::Remote),
            None,
        )
        .expect_err("a missing exact remote representation cannot advance child deletion");

        assert!(error.is_internal(), "expected Internal, got {error:?}");
        assert!(
            format!("{error:?}")
                .contains("exact fragmented representation is absent during child discovery")
        );
    }

    #[test]
    fn fragmented_staged_none_fails_closed_before_children_commit() {
        let error = PostgresImmutableStore::validate_obliterate_child_candidate(
            Address::default(),
            &fragmented_obliterate_manifest(EpochAuthority::Staged),
            None,
        )
        .expect_err("a missing exact staged representation cannot advance child deletion");

        assert!(error.is_internal(), "expected Internal, got {error:?}");
        assert!(
            format!("{error:?}")
                .contains("exact fragmented representation is absent during child discovery")
        );
    }

    #[test]
    fn owned_obliterate_completion_counts_fragment_and_payload_once() {
        let stats = StoreObliterateStats::default();

        PostgresImmutableStore::record_owned_obliterate_completion(&stats);

        assert_eq!(
            stats
                .num_fragments
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
        assert_eq!(
            stats
                .num_payloads
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    #[ignore = "run with tests/run-fragment-lifecycle-live.ps1"]
    async fn exact_purge_proofs_are_required_before_payload_tombstone() {
        let url = std::env::var("LORE_TEST_PG_URL").expect("runner must provide LORE_TEST_PG_URL");
        let store = PostgresDomainStore::connect(&url, 4, &TlsConfig::default())
            .await
            .expect("connect domain store");
        let coordinator = store.fragment_coordinator();
        coordinator
            .bootstrap()
            .await
            .expect("install isolated fragment schema");
        let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .expect("connect assertion client");
        lore_base::lore_spawn!(async move {
            let _ = connection.await;
        });
        client
            .execute(
                "UPDATE lore_fragment_schema_state \
                    SET backfill_state = $1, cutover_at = clock_timestamp(), \
                        residue_classified = true, sequence_headroom_fence = 1 \
                  WHERE id = 1",
                &[&schema::BACKFILL_CUTOVER],
            )
            .await
            .expect("stage lifecycle cutover");
        coordinator
            .enable_lifecycle()
            .await
            .expect("enable lifecycle");
        let revision = "write-claims-v1";
        coordinator
            .require_write_claims(
                &FragmentWriteCapabilityCutover::new(revision)
                    .expect("canonical provider authority revision"),
            )
            .await
            .expect("require claims");

        let repository_id = random::<[u8; 16]>();
        let default_branch_id = random::<[u8; 16]>();
        client
            .execute(
                "INSERT INTO lore_domain_repositories ( \
                    repository_id, state, generation, name, metadata_hash, \
                    default_branch_id, creation_fingerprint_version, \
                    creation_fingerprint, created_at \
                 ) VALUES ($1, 0, 1, $2, $3, $4, 1, $5, clock_timestamp())",
                &[
                    &repository_id.as_slice(),
                    &format!("purge-proof-{:016x}", random::<u64>()),
                    &random::<[u8; 32]>().as_slice(),
                    &default_branch_id.as_slice(),
                    &random::<[u8; 32]>().as_slice(),
                ],
            )
            .await
            .expect("insert repository fixture");

        let hash = random::<[u8; 32]>();
        let object_key = hash
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let claim = FragmentWriteClaimInput::new(
            *Uuid::now_v7().as_bytes(),
            *Uuid::now_v7().as_bytes(),
            [0x91; 32],
            1,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .expect("valid claim");
        let BeginOutcome::Admitted(write) = coordinator
            .begin_direct_write(&hash, &object_key, claim)
            .await
            .expect("begin publication")
        else {
            panic!("fresh hash must admit");
        };
        coordinator
            .authorize_write_claim(write.write_claim().expect("durable claim"))
            .await
            .expect("authorize send");
        assert_eq!(
            coordinator
                .commit_remote(
                    &write,
                    IoObservation::Valid(FragmentManifest {
                        authority: EpochAuthority::Remote,
                        object_key: object_key.clone(),
                        manifest_id: vec![0x92; 32],
                        size_payload: 1,
                        size_content: 1,
                        decoded_hash: vec![0x93; 32],
                        payload_flags: 0,
                    }),
                    FragmentWriteSettlement::Decisive,
                )
                .await
                .expect("publish"),
            CommitVerdict::Published
        );
        let context = random::<[u8; 16]>();
        assert_eq!(
            coordinator
                .create_association(&hash, &repository_id, &context)
                .await
                .expect("associate"),
            CommitVerdict::Published
        );

        let FragmentObliterateBegin::Ready(children) = coordinator
            .begin_obliterate(&hash, &repository_id, &context, revision)
            .await
            .expect("begin obliterate")
        else {
            panic!("last association must own deletion");
        };
        assert_eq!(children.phase(), FragmentObliteratePhase::Children);
        assert_eq!(
            coordinator
                .commit_obliterate_children(&children)
                .await
                .expect("commit children"),
            CommitVerdict::Published
        );
        let FragmentObliterateBegin::Ready(payload) = coordinator
            .begin_obliterate(&hash, &repository_id, &context, revision)
            .await
            .expect("resume payload phase")
        else {
            panic!("owning retry must resume payload phase");
        };
        assert_eq!(payload.phase(), FragmentObliteratePhase::Payload);
        let missing = coordinator
            .commit_obliterate_payload(&payload, &[])
            .await
            .expect_err("no proof cannot tombstone a nonempty target set");
        assert!(matches!(missing, DomainError::PreconditionRejected { .. }));
        let state_after_missing_proof: i16 = client
            .query_one(
                "SELECT state FROM lore_fragment_lifecycle WHERE hash = $1",
                &[&hash.as_slice()],
            )
            .await
            .expect("read head after missing proof")
            .get(0);
        assert_eq!(
            state_after_missing_proof,
            FragmentLifecycleState::DeletingPayload.bits(),
            "a failed or ambiguous physical deletion must not tombstone"
        );
        let FragmentObliterateBegin::Ready(retry) = coordinator
            .begin_obliterate(&hash, &repository_id, &context, revision)
            .await
            .expect("resume after physical deletion uncertainty")
        else {
            panic!("owning retry must remain recoverable");
        };
        assert_eq!(retry.phase(), FragmentObliteratePhase::Payload);
        assert_eq!(retry.ownership(), payload.ownership());
        assert_eq!(retry.purge_targets(), payload.purge_targets());

        let proofs = retry
            .purge_targets()
            .iter()
            .cloned()
            .map(FragmentPurgeProof::new)
            .collect::<Vec<_>>();
        assert_eq!(
            coordinator
                .commit_obliterate_payload(&retry, &proofs)
                .await
                .expect("commit exact proofs"),
            CommitVerdict::Published
        );
        let state: i16 = client
            .query_one(
                "SELECT state FROM lore_fragment_lifecycle WHERE hash = $1",
                &[&hash.as_slice()],
            )
            .await
            .expect("read final head")
            .get(0);
        assert_eq!(state, FragmentLifecycleState::Tombstoned.bits());
    }
}

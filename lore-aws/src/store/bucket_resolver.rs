// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
// Copyright 2026 Khurram Virani
//! Pluggable resolution of the S3 bucket a repository's fragments live in.
//!
//! By default the AWS immutable store writes every fragment to a single,
//! statically configured bucket ([`StaticBucketResolver`]). Deployments that
//! host many repositories (for example a multi-tenant platform built on Lore)
//! can supply their own [`BucketResolver`] to route different repositories'
//! fragments to different buckets, giving each repository physically isolated
//! storage.
//!
//! Two resolvers ship with `lore-aws`:
//!
//! - [`StaticBucketResolver`] — the default. Every repository maps to one
//!   configured bucket; preserves the historical single-bucket behaviour
//!   exactly and never does I/O.
//! - [`DynamoBucketResolver`] — resolves a repository's bucket from a DynamoDB
//!   routing table, read-through cached. A hosting platform provisions the
//!   table (one row per repository) and the resolver looks the bucket up on the
//!   first reference to each repository, then serves it from memory thereafter.
//!
//! Lore deliberately stays in its own vocabulary here: a resolver is handed a
//! [`Context`] (the repository identifier) and returns a bucket name. Any
//! notion of tenants, orgs or accounts lives entirely in the caller that
//! constructs the resolver — the store only ever sees repositories and buckets.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use aws_sdk_dynamodb::types::AttributeValue;
use dashmap::DashMap;
use lore_base::error::SlowDown;
use lore_base::types::Context;
use lore_storage::StoreError;
use tracing::warn;

use crate::aws_error::AwsError;
use crate::dynamodb::DynamoDb;

/// Resolves the S3 bucket that should hold a given repository's fragments.
///
/// Implementations must be deterministic: the same repository must always
/// resolve to the same bucket, otherwise previously written fragments would
/// become unreachable.
///
/// `bucket_for` is **async** and **fallible**: a real resolver may need to do
/// I/O on a cache miss (for example a DynamoDB read) and must be able to fail
/// rather than guess. The store calls it on every S3 read, write and delete, so
/// resolvers are expected to cache aggressively — repository→bucket mappings are
/// immutable, so a cached entry never needs invalidation.
///
/// The trait is object-safe: the store holds an `Arc<dyn BucketResolver>`. The
/// async method is desugared (via [`async_trait`]) to a boxed future, which
/// costs one small heap allocation per call even on the static path — negligible
/// next to the S3 round-trip each call already precedes.
#[async_trait]
pub trait BucketResolver: Send + Sync {
    /// Returns the bucket name for `repository`, or an error if it cannot be
    /// resolved. Implementations must **not** invent a default on failure: the
    /// store would otherwise write a repository's bytes into the wrong bucket.
    async fn bucket_for(&self, repository: &Context) -> Result<String, StoreError>;
}

/// The default resolver: every repository maps to the same configured bucket.
///
/// This preserves the historical single-bucket behaviour of the AWS immutable
/// store exactly, and is what the store uses when no per-repository routing is
/// configured. It never does I/O and never fails.
#[derive(Debug, Clone)]
pub struct StaticBucketResolver {
    bucket: String,
}

impl StaticBucketResolver {
    /// Creates a resolver that always returns `bucket`.
    pub fn new(bucket: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
        }
    }

    /// Returns the single bucket this resolver is pinned to.
    pub fn bucket(&self) -> &str {
        &self.bucket
    }
}

#[async_trait]
impl BucketResolver for StaticBucketResolver {
    async fn bucket_for(&self, _repository: &Context) -> Result<String, StoreError> {
        Ok(self.bucket.clone())
    }
}

/// DynamoDB attribute holding the repository identifier on a routing-table row
/// (the table's partition key). Encoded as a DynamoDB **string** (`S`) using
/// Lore's canonical [`Context`] representation — see [`DynamoBucketResolver`].
pub const ROUTING_TABLE_REPOSITORY_ATTRIBUTE: &str = "repository";

/// DynamoDB attribute holding the destination bucket name on a routing-table
/// row. Read as a DynamoDB **string** (`S`); all other attributes are ignored.
pub const ROUTING_TABLE_BUCKET_ATTRIBUTE: &str = "bucket";

/// Resolves a repository's bucket from a DynamoDB routing table, read-through
/// cached.
///
/// A hosting platform provisions a routing table — one row per repository,
/// mapping the repository to the bucket that should physically hold its
/// fragments — and injects this resolver via
/// [`AwsImmutableStore::with_bucket_resolver`]. Creating or populating the table
/// is the host's responsibility; this resolver only reads it.
///
/// [`AwsImmutableStore::with_bucket_resolver`]: crate::store::immutable_store::AwsImmutableStore::with_bucket_resolver
///
/// ## Table contract
///
/// - **Partition key** `repository` (string): Lore's canonical [`Context`]
///   string — `Context`'s [`Display`]/[`ToString`], i.e. the lowercase,
///   unseparated hex of its 16 raw bytes (32 hex characters). For example the
///   `Context` with bytes `01 23 45 67 89 ab cd ef 01 23 45 67 89 ab cd ef`
///   encodes to the key `"0123456789abcdef0123456789abcdef"`. This is Lore's
///   own representation, not a hand-rolled UUID/hex format.
/// - **Attribute** `bucket` (string): the destination bucket. Any other
///   attributes on the row are ignored.
///
/// [`Display`]: std::fmt::Display
/// [`ToString`]: std::string::ToString
///
/// ## Lookup semantics
///
/// - **Cache hit** → returned from memory, no network call. Repository→bucket
///   mappings are immutable, so cached entries never expire or invalidate.
/// - **Cache miss** → a `GetItem` with `ConsistentRead = true`, so a freshly
///   provisioned route is observed immediately. A found row is cached and its
///   `bucket` returned.
/// - **No row found** → a **fail-closed error**. The resolver never falls back
///   to a default or shared bucket: writing a repository's bytes into the wrong
///   bucket would be a storage-isolation (security) failure, so an unrouted
///   repository fails the operation instead.
///
/// The resolver needs only `dynamodb:GetItem` on the routing table (read-only).
pub struct DynamoBucketResolver {
    dynamodb: DynamoDb,
    table_name: Arc<str>,
    // Immutable repository→bucket mappings; never invalidated (see type docs).
    cache: DashMap<Context, String>,
}

impl DynamoBucketResolver {
    /// Creates a resolver backed by `dynamodb`, looking routes up in
    /// `table_name`. The table itself must already exist and be populated by the
    /// host; this resolver only issues read-only `GetItem`s against it.
    pub fn new(dynamodb: DynamoDb, table_name: impl Into<Arc<str>>) -> Self {
        Self {
            dynamodb,
            table_name: table_name.into(),
            cache: DashMap::new(),
        }
    }

    /// The routing table this resolver reads from.
    pub fn table_name(&self) -> &str {
        &self.table_name
    }

    /// Builds the primary key for `repository`'s routing row: the canonical
    /// [`Context`] string under the `repository` partition-key attribute.
    fn routing_key(repository: &Context) -> HashMap<String, AttributeValue> {
        HashMap::from([(
            ROUTING_TABLE_REPOSITORY_ATTRIBUTE.to_string(),
            AttributeValue::S(repository.to_string()),
        )])
    }
}

#[async_trait]
impl BucketResolver for DynamoBucketResolver {
    async fn bucket_for(&self, repository: &Context) -> Result<String, StoreError> {
        if let Some(bucket) = self.cache.get(repository) {
            return Ok(bucket.clone());
        }

        let output = self
            .dynamodb
            .get_item(
                &self.table_name,
                Self::routing_key(repository),
                true, /* consistent read: observe freshly provisioned routes */
            )
            .await
            .map_err(|e| {
                warn!("DynamoDB bucket routing lookup failed for repository {repository}: {e:?}");
                if matches!(&e, AwsError::AwsSdkError(_)) {
                    StoreError::from(SlowDown)
                } else {
                    StoreError::internal_with_context(e, "DynamoDB bucket routing lookup failed")
                }
            })?;

        // Fail closed: a repository with no routing row must NOT fall back to any
        // default/shared bucket. Returning an error here is what keeps each
        // repository's bytes confined to its own bucket.
        let Some(item) = output.item else {
            return Err(StoreError::internal(format!(
                "No bucket route for repository {repository} in routing table {} \
                 (fail-closed: the resolver never uses a default bucket)",
                self.table_name
            )));
        };

        // Read only the `bucket` string attribute; ignore everything else.
        let bucket = match item.get(ROUTING_TABLE_BUCKET_ATTRIBUTE) {
            Some(AttributeValue::S(bucket)) => bucket.clone(),
            _ => {
                return Err(StoreError::internal(format!(
                    "Routing row for repository {repository} in table {} is missing a string \
                     `{ROUTING_TABLE_BUCKET_ATTRIBUTE}` attribute",
                    self.table_name
                )));
            }
        };

        // Cache the immutable mapping so subsequent calls skip the network.
        self.cache.insert(*repository, bucket.clone());

        Ok(bucket)
    }
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use aws_sdk_dynamodb::operation::get_item::GetItemOutput;
    use aws_sdk_dynamodb::types::AttributeValue;
    use mockall::predicate::eq;
    use rand::random;

    use super::*;
    use crate::dynamodb::MockDynamoDb;

    const ROUTING_TABLE: &str = "repository-bucket-routing";

    /// The canonical `Context` key encoding the routing table depends on: the
    /// lowercase, unseparated hex of the 16 raw bytes, exactly `Context`'s
    /// `Display`/`to_string`. This is the contract a downstream writer that
    /// provisions the table must follow.
    #[test]
    fn context_key_encoding_is_canonical_hex() {
        let repository = Context::from([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef,
        ]);

        // The exact Context → key string the routing table is keyed by.
        assert_eq!(repository.to_string(), "0123456789abcdef0123456789abcdef");

        let key = DynamoBucketResolver::routing_key(&repository);
        assert_eq!(
            key,
            HashMap::from([(
                "repository".to_string(),
                AttributeValue::S("0123456789abcdef0123456789abcdef".to_string()),
            )])
        );
    }

    #[tokio::test]
    async fn static_resolver_ignores_repository() {
        let resolver = StaticBucketResolver::new("only-bucket");
        let a = random::<Context>();
        let b = random::<Context>();

        assert_eq!(resolver.bucket_for(&a).await.unwrap(), "only-bucket");
        assert_eq!(resolver.bucket_for(&b).await.unwrap(), "only-bucket");
    }

    /// A cold miss issues a single `ConsistentRead` `GetItem` keyed by the
    /// canonical `Context` string, caches the result, and serves every
    /// subsequent call from memory — so a second lookup does no DynamoDB call.
    #[tokio::test]
    async fn cold_miss_reads_consistently_then_caches() {
        let repository = random::<Context>();
        let expected_key = DynamoBucketResolver::routing_key(&repository);

        let mut dynamodb = MockDynamoDb::default();
        dynamodb
            .expect_get_item()
            .with(
                eq(Arc::<str>::from(ROUTING_TABLE)),
                eq(expected_key),
                eq(true), /* consistent read */
            )
            .times(1) // exactly one network call across both lookups below
            .return_once(|_, _, _| {
                Ok(GetItemOutput::builder()
                    .set_item(Some(HashMap::from([
                        (
                            "bucket".to_string(),
                            AttributeValue::S("routed-bucket".to_string()),
                        ),
                        // An unrelated attribute the resolver must ignore.
                        (
                            "created_at".to_string(),
                            AttributeValue::N("42".to_string()),
                        ),
                    ])))
                    .build())
            });

        let resolver = DynamoBucketResolver::new(dynamodb, ROUTING_TABLE);

        // Cold miss: hits DynamoDB.
        assert_eq!(
            resolver.bucket_for(&repository).await.unwrap(),
            "routed-bucket"
        );
        // Cache hit: no second DynamoDB call (the mock would panic on a second
        // call thanks to `.times(1)`).
        assert_eq!(
            resolver.bucket_for(&repository).await.unwrap(),
            "routed-bucket"
        );
    }

    /// A repository with no routing row fails closed: the resolver returns an
    /// error and never substitutes any default/shared bucket.
    #[tokio::test]
    async fn missing_route_fails_closed_with_no_default() {
        let repository = random::<Context>();

        let mut dynamodb = MockDynamoDb::default();
        dynamodb
            .expect_get_item()
            .with(
                eq(Arc::<str>::from(ROUTING_TABLE)),
                eq(DynamoBucketResolver::routing_key(&repository)),
                eq(true),
            )
            .return_once(|_, _, _| Ok(GetItemOutput::builder().build())); // no item

        let resolver = DynamoBucketResolver::new(dynamodb, ROUTING_TABLE);

        let result = resolver.bucket_for(&repository).await;
        // There is NO fallback: an unrouted repository is an error, full stop.
        assert!(
            result.is_err(),
            "expected fail-closed error, got bucket {result:?}"
        );
    }

    /// A row whose `bucket` attribute is absent (or not a string) is treated as
    /// no route — still fail-closed, never a default.
    #[tokio::test]
    async fn malformed_route_fails_closed() {
        let repository = random::<Context>();

        let mut dynamodb = MockDynamoDb::default();
        dynamodb
            .expect_get_item()
            .with(
                eq(Arc::<str>::from(ROUTING_TABLE)),
                eq(DynamoBucketResolver::routing_key(&repository)),
                eq(true),
            )
            .return_once(|_, _, _| {
                Ok(GetItemOutput::builder()
                    // Wrong type for `bucket`, and no string bucket present.
                    .set_item(Some(HashMap::from([(
                        "bucket".to_string(),
                        AttributeValue::N("1".to_string()),
                    )])))
                    .build())
            });

        let resolver = DynamoBucketResolver::new(dynamodb, ROUTING_TABLE);

        assert!(resolver.bucket_for(&repository).await.is_err());
    }
}

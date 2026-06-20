// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
//! Pluggable resolution of the S3 bucket a repository's fragments live in.
//!
//! By default the AWS immutable store writes every fragment to a single,
//! statically configured bucket ([`StaticBucketResolver`]). Deployments that
//! host many repositories (for example a multi-tenant platform built on Lore)
//! can supply their own [`BucketResolver`] to route different repositories'
//! fragments to different buckets, giving each repository physically isolated
//! storage.
//!
//! Lore deliberately stays in its own vocabulary here: a resolver is handed a
//! [`Context`] (the repository identifier) and returns a bucket name. Any
//! notion of tenants, orgs or accounts lives entirely in the caller that
//! constructs the resolver — the store only ever sees repositories and buckets.

use std::borrow::Cow;

use lore_base::types::Context;

/// Resolves the S3 bucket that should hold a given repository's fragments.
///
/// Implementations must be deterministic: the same repository must always
/// resolve to the same bucket, otherwise previously written fragments would
/// become unreachable. They must also be cheap to call — `bucket_for` is
/// invoked on every S3 read, write and delete.
///
/// The returned [`Cow`] lets the common case (a single static bucket) avoid an
/// allocation by borrowing, while dynamic resolvers can return an owned,
/// freshly computed bucket name.
pub trait BucketResolver: Send + Sync {
    /// Returns the bucket name for `repository`.
    fn bucket_for(&self, repository: &Context) -> Cow<'_, str>;
}

/// The default resolver: every repository maps to the same configured bucket.
///
/// This preserves the historical single-bucket behaviour of the AWS immutable
/// store exactly, and is what the store uses when no per-repository routing is
/// configured.
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

impl BucketResolver for StaticBucketResolver {
    fn bucket_for(&self, _repository: &Context) -> Cow<'_, str> {
        Cow::Borrowed(&self.bucket)
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use rand::random;

    use super::*;

    #[test]
    fn static_resolver_ignores_repository() {
        let resolver = StaticBucketResolver::new("only-bucket");
        let a = random::<Context>();
        let b = random::<Context>();

        assert_eq!(resolver.bucket_for(&a), "only-bucket");
        assert_eq!(resolver.bucket_for(&b), "only-bucket");
    }

    /// A test-only resolver that maps each distinct repository to a stable,
    /// repository-specific bucket name. Mirrors the shape a hosting platform's
    /// own resolver would take.
    struct PerRepositoryResolver {
        prefix: String,
        assigned: Mutex<HashMap<Context, String>>,
    }

    impl BucketResolver for PerRepositoryResolver {
        fn bucket_for(&self, repository: &Context) -> Cow<'_, str> {
            let mut assigned = self.assigned.lock().unwrap();
            let next = assigned.len();
            let bucket = assigned
                .entry(*repository)
                .or_insert_with(|| format!("{}-{next}", self.prefix))
                .clone();
            Cow::Owned(bucket)
        }
    }

    #[test]
    fn dynamic_resolver_is_deterministic_per_repository() {
        let resolver = PerRepositoryResolver {
            prefix: "tenant".to_string(),
            assigned: Mutex::new(HashMap::new()),
        };

        let a = random::<Context>();
        let b = random::<Context>();

        let a_bucket = resolver.bucket_for(&a).into_owned();
        let b_bucket = resolver.bucket_for(&b).into_owned();

        // Different repositories route to different buckets...
        assert_ne!(a_bucket, b_bucket);
        // ...and the same repository always routes to the same bucket.
        assert_eq!(resolver.bucket_for(&a), a_bucket);
        assert_eq!(resolver.bucket_for(&b), b_bucket);
    }
}

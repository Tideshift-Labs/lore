// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! One MinIO bucket per case, shared by both coordinator sets.
//!
//! # Why a bucket and not a key prefix
//!
//! WP-109 requires each case to own "a unique bucket/object-prefix namespace".
//! The prefix arm is not expressible from a test: `PostgresImmutableStore`
//! derives its object key from the content hash alone
//! (`object_key = hex(hash)`), with no configurable prefix, and WP-109 forbids
//! changing production behaviour. `CaseNamespace::object_prefix` exists for a
//! consumer that can apply one; this crate's S3 path is not it.
//!
//! So this harness takes the other arm the rule allows and mints a bucket per
//! case. Both sets share it — which is the property under test, one bucket
//! behind two replicas — while two cases can never collide, and cleanup is one
//! bounded delete of a known key set rather than a scan of a shared bucket.
//! `immutable_store.rs`'s versioning case already creates a per-case bucket
//! this way, so it is an established shape here rather than a new dependency.
//!
//! # Cleanup, and its recorded disposition
//!
//! [`CaseBucket::release`] lists and deletes every object, then the bucket, and
//! prints what it removed. A case that panics unwinds past `release`, and
//! [`Drop`] then prints a `retained for debug` line naming the bucket — WP-109's
//! required disposition for a cleanup that could not complete, and the same
//! convention `CaseNamespace` uses for a schema.

#![allow(dead_code)]

use std::time::Duration;

use lore_aws::clients::AwsClientBuilder;
use lore_aws::clients::HttpClientSettings;
use lore_aws::clients::TimeoutConfig;
use lore_aws::s3::S3Impl;
use uuid::Uuid;

use super::env::ObjectStoreEnv;

/// Build an S3 client against the case's endpoint, path-style addressed the way
/// MinIO needs.
pub async fn s3_client(env: &ObjectStoreEnv) -> S3Impl {
    let builder = Box::pin(
        AwsClientBuilder::builder()
            .with_http_settings(&HttpClientSettings::default())
            .maybe_endpoint(Some(env.endpoint.clone()))
            .maybe_region(Some(env.region.clone()))
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
        .expect("build the case's S3 client")
}

/// One case's owned bucket.
pub struct CaseBucket {
    name: String,
    s3: S3Impl,
    released: bool,
}

impl CaseBucket {
    /// Create a bucket named from the case label and a fresh unique suffix.
    ///
    /// The name is lowercase, dot-free, and under 63 bytes, because S3 bucket
    /// naming is stricter than PostgreSQL identifier naming and MinIO enforces
    /// it.
    ///
    /// The suffix is **not** the case's identity seed, deliberately. Replaying
    /// a failed case with the same `LORE_TEST_SEED` is the point of the seed,
    /// and a seed-derived bucket name would make that replay collide with the
    /// bucket the failed run retained for debug — the replay would die in
    /// `create_bucket` before running the case it was meant to reproduce. The
    /// bucket's name carries no evidence, so it costs nothing to make it unique
    /// per attempt.
    pub async fn create(env: &ObjectStoreEnv, case_label: &str, _seed: u64) -> Self {
        let sanitised: String = case_label
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '-'
                }
            })
            .take(20)
            .collect();
        // UUIDv7, like `CaseNamespace`'s schema name: the timestamp prefix makes
        // a retained bucket's creation order readable from its name.
        let name = format!("wp109-{sanitised}-{}", Uuid::now_v7().simple());
        assert!(
            name.len() <= 63
                && name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
            "minted bucket name must satisfy S3 naming, got {name:?}"
        );
        let s3 = s3_client(env).await;
        s3.sdk_client()
            .create_bucket()
            .bucket(&name)
            .send()
            .await
            .unwrap_or_else(|error| panic!("create case bucket {name}: {error}"));
        // WP-109 requires namespace creation to be recorded, not merely to
        // happen. This line is that record, matching `CaseNamespace`'s.
        println!("case object namespace created: bucket={name}");
        Self {
            name,
            s3,
            released: false,
        }
    }

    /// The bucket both sets are configured against.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The client, for direct object-store readback.
    pub fn s3(&self) -> &S3Impl {
        &self.s3
    }

    /// Every key currently in the bucket, sorted.
    ///
    /// This is the authoritative object-store readback a race asserts against:
    /// "one object, not two" is a statement about this list, not about what a
    /// store method returned.
    pub async fn keys(&self) -> Vec<String> {
        let mut keys: Vec<String> = self
            .s3
            .sdk_client()
            .list_objects_v2()
            .bucket(&self.name)
            .send()
            .await
            .unwrap_or_else(|error| panic!("list case bucket {}: {error}", self.name))
            .contents()
            .iter()
            .filter_map(|object| object.key().map(str::to_owned))
            .collect();
        keys.sort();
        keys
    }

    /// Delete every object and then the bucket, printing what was removed.
    pub async fn release(mut self) {
        let keys = self.keys().await;
        for key in &keys {
            self.s3
                .sdk_client()
                .delete_object()
                .bucket(&self.name)
                .key(key)
                .send()
                .await
                .unwrap_or_else(|error| {
                    panic!(
                        "delete object {key} from case bucket {}: {error}",
                        self.name
                    )
                });
        }
        self.s3
            .sdk_client()
            .delete_bucket()
            .bucket(&self.name)
            .send()
            .await
            .unwrap_or_else(|error| panic!("drop case bucket {}: {error}", self.name));
        self.released = true;
        println!(
            "case object namespace released: bucket={} objects={}",
            self.name,
            keys.len()
        );
    }
}

impl Drop for CaseBucket {
    fn drop(&mut self) {
        if !self.released {
            println!(
                "case object namespace retained for debug (not released): bucket={}",
                self.name
            );
        }
    }
}

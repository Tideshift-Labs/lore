// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-License-Identifier: MIT
pub mod copy;
pub mod get;
pub mod get_metadata;
pub mod mutable_compare_and_swap;
pub mod mutable_load;
pub mod mutable_store;
pub mod put;
pub mod query;
pub mod service;
pub mod verify;

#[cfg(test)]
pub(crate) mod test_utils;

/// Backpressure limit for streaming storage handlers — matches the QUIC public stream handler's 500 per stream × 8 streams = 4000 per connection so gRPC (single stream per connection) gets equivalent per-connection parallelism.
pub(crate) const STREAM_PROCESS_LIMIT: usize = 4000;

/// Max concurrent fragment PUT tasks (each an S3 `put_object`) processed per Put
/// stream. Defaults to [`STREAM_PROCESS_LIMIT`], but is overridable via the
/// `LORE_STORAGE_PUT_CONCURRENCY` env var (positive integer). A slow S3-compatible
/// backend — e.g. LocalStack in the Lorehub dev/CI harness — is saturated by a
/// 4000-connection upload fan-out (every stream stalls at 0 B/s and the AWS SDK's
/// StalledStreamProtection aborts it, livelocking a large import); capping the
/// concurrency lets the gateway service each PUT. Real S3 scales, so prod leaves the
/// var unset and keeps the 4000 default. Tideshift fork change CR-013. Read once.
pub(crate) fn put_task_concurrency() -> usize {
    static LIMIT: std::sync::LazyLock<usize> = std::sync::LazyLock::new(|| {
        std::env::var("LORE_STORAGE_PUT_CONCURRENCY")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|&n| n > 0)
            .unwrap_or(STREAM_PROCESS_LIMIT)
    });
    *LIMIT
}

// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Tideshift Labs
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
        parse_put_concurrency(std::env::var("LORE_STORAGE_PUT_CONCURRENCY").ok())
    });
    *LIMIT
}

/// Parse the `LORE_STORAGE_PUT_CONCURRENCY` override, falling back to
/// [`STREAM_PROCESS_LIMIT`]. A value that is PRESENT but invalid (non-numeric or
/// zero) is warned about and falls back — otherwise a dev misconfig would silently
/// re-manifest as the very 0 B/s LocalStack livelock CR-013 exists to prevent,
/// rather than surfacing. Absent = the normal prod path, no warning.
fn parse_put_concurrency(raw: Option<String>) -> usize {
    let Some(value) = raw else {
        return STREAM_PROCESS_LIMIT;
    };
    match value.parse::<usize>() {
        Ok(n) if n > 0 => n,
        _ => {
            tracing::warn!(
                value = %value,
                default = STREAM_PROCESS_LIMIT,
                "LORE_STORAGE_PUT_CONCURRENCY is not a positive integer; using default",
            );
            STREAM_PROCESS_LIMIT
        }
    }
}

#[cfg(test)]
mod tests {
    use super::STREAM_PROCESS_LIMIT;
    use super::parse_put_concurrency;

    #[test]
    fn parses_a_positive_override() {
        assert_eq!(parse_put_concurrency(Some("32".to_string())), 32);
    }

    #[test]
    fn absent_falls_back_to_default() {
        assert_eq!(parse_put_concurrency(None), STREAM_PROCESS_LIMIT);
    }

    #[test]
    fn invalid_present_values_fall_back_to_default() {
        // zero, negative, non-numeric, and empty all revert to the default.
        assert_eq!(
            parse_put_concurrency(Some("0".to_string())),
            STREAM_PROCESS_LIMIT
        );
        assert_eq!(
            parse_put_concurrency(Some("-4".to_string())),
            STREAM_PROCESS_LIMIT
        );
        assert_eq!(
            parse_put_concurrency(Some("nope".to_string())),
            STREAM_PROCESS_LIMIT
        );
        assert_eq!(
            parse_put_concurrency(Some(String::new())),
            STREAM_PROCESS_LIMIT
        );
    }
}

// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use std::sync::Arc;
use std::time::Duration;

use aws_config::meta::region::ProvideRegion;
use aws_sdk_dynamodb::config::ProvideCredentials;
use aws_sdk_dynamodb::operation::describe_table::DescribeTableError;
use aws_sdk_s3::operation::head_bucket::HeadBucketError;
use aws_smithy_http_client::Builder as HttpClientBuilder;
use aws_smithy_http_client::Connector;
use aws_smithy_http_client::tls;
use aws_smithy_http_client::tls::rustls_provider::CryptoMode;
use aws_smithy_runtime_api::client::behavior_version::BehaviorVersion;
use aws_smithy_types::retry::RetryConfig;
use opentelemetry::KeyValue;
use serde::Deserialize;
use thiserror::Error;
use tokio::sync::Semaphore;
use tracing::debug;
use tracing::warn;

use crate::aws_error::AwsError;
use crate::dynamodb::DynamoDb;
use crate::net_http_client::NetHttpClient;
use crate::s3::S3;

#[derive(Debug, Error, PartialEq)]
pub enum AwsClientError<E> {
    #[error("DynamoDB table not found: {0}")]
    DynamoTableNotFound(String),
    #[error("S3 bucket not found: {0}")]
    BucketNotFound(String),
    /// Boxed for the reason on [`AwsError::AwsSdkError`].
    #[error("AWS SDK error: {0:?}")]
    SdkError(#[from] Box<E>),
    #[error("Unknown error")]
    Unknown,
}

pub const DEFAULT_POOL_IDLE_TIMEOUT_SECONDS: u64 = 30;

fn default_idle_timeout() -> u64 {
    DEFAULT_POOL_IDLE_TIMEOUT_SECONDS
}

/// Total attempts per request, including the first. Two more than the SDK's
/// own default of three, while still costing less worst-case delay than that
/// default does, because [`DEFAULT_RETRY_INITIAL_BACKOFF_MILLIS`] is lower.
pub const DEFAULT_RETRY_MAX_ATTEMPTS: u32 = 5;
/// Base of the exponential backoff. The SDK's own default is one second.
pub const DEFAULT_RETRY_INITIAL_BACKOFF_MILLIS: u64 = 100;
/// Ceiling on any single computed backoff. Not reached by the defaults here —
/// five attempts from 100ms peak below one second — so it only binds when
/// `max_attempts` is raised.
pub const DEFAULT_RETRY_MAX_BACKOFF_SECONDS: u64 = 20;

fn default_retry_max_attempts() -> u32 {
    DEFAULT_RETRY_MAX_ATTEMPTS
}

fn default_retry_initial_backoff_millis() -> u64 {
    DEFAULT_RETRY_INITIAL_BACKOFF_MILLIS
}

fn default_retry_max_backoff_seconds() -> u64 {
    DEFAULT_RETRY_MAX_BACKOFF_SECONDS
}

/// How the SDK should retry a request it classifies as retryable.
#[derive(Clone, Copy, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RetryMode {
    /// Exponential backoff with jitter, no rate limiter. The default.
    #[default]
    Standard,
    /// Standard backoff plus a client-side rate limiter that reacts to observed
    /// throttling by slowing the whole client down.
    ///
    /// Appropriate where operation counts scale with fragment count rather than
    /// bytes and a large repository can drive a store past its request-rate
    /// ceiling. **Enable it deliberately, and only alongside a generous request
    /// handler timeout.** The rate limiter's delays are not bounded by
    /// [`RetrySettings::max_backoff_seconds`]: it can hold a request for up to
    /// two seconds before the *first* attempt, and up to ten seconds before each
    /// retry, so the defaults below allow a single call to sleep for roughly
    /// forty seconds before failing. The limiter is also process-global per
    /// service, so one caller's throttling delays every other caller sharing
    /// that client.
    Adaptive,
    /// A single attempt, never retried. Intended for tests that assert on the
    /// first failure.
    ///
    /// [`RetrySettings::max_attempts`] and both backoff settings are ignored in
    /// this mode.
    Disabled,
}

/// Retry behavior for every AWS client built by [`AwsClientBuilder`].
///
/// The SDK applies its own retry classification underneath this; these settings
/// only govern how hard and how long it tries.
///
/// Note that setting these at all takes retry configuration out of the SDK's
/// environment-driven path: `AWS_RETRY_MODE`, `AWS_MAX_ATTEMPTS` and the
/// equivalent profile keys no longer apply, because an explicitly supplied
/// `RetryConfig` replaces that provider rather than merging with it.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct RetrySettings {
    #[serde(default)]
    pub mode: RetryMode,
    /// Total attempts, including the initial one. Must be at least 1; a value
    /// of 0 is treated as 1 rather than rejected, so a malformed config cannot
    /// silently disable the request entirely.
    #[serde(default = "default_retry_max_attempts")]
    pub max_attempts: u32,
    #[serde(default = "default_retry_initial_backoff_millis")]
    pub initial_backoff_millis: u64,
    #[serde(default = "default_retry_max_backoff_seconds")]
    pub max_backoff_seconds: u64,
}

impl Default for RetrySettings {
    fn default() -> Self {
        Self {
            mode: RetryMode::default(),
            max_attempts: DEFAULT_RETRY_MAX_ATTEMPTS,
            initial_backoff_millis: DEFAULT_RETRY_INITIAL_BACKOFF_MILLIS,
            max_backoff_seconds: DEFAULT_RETRY_MAX_BACKOFF_SECONDS,
        }
    }
}

impl From<&RetrySettings> for RetryConfig {
    fn from(settings: &RetrySettings) -> Self {
        let config = match settings.mode {
            RetryMode::Adaptive => RetryConfig::adaptive(),
            RetryMode::Standard => RetryConfig::standard(),
            RetryMode::Disabled => return RetryConfig::disabled(),
        };

        let max_attempts = settings.max_attempts.max(1);
        if max_attempts != settings.max_attempts {
            warn!(
                configured = settings.max_attempts,
                using = max_attempts,
                "AWS retry max_attempts must be at least 1; ignoring the configured value"
            );
        }

        config
            .with_max_attempts(max_attempts)
            .with_initial_backoff(Duration::from_millis(settings.initial_backoff_millis))
            .with_max_backoff(Duration::from_secs(settings.max_backoff_seconds))
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct HttpClientSettings {
    #[serde(default = "default_idle_timeout")]
    pub pool_idle_timeout_seconds: u64,
    #[serde(default)]
    pub nodelay: bool,
    #[serde(default)]
    pub retry: RetrySettings,
}

fn default_quota_per_second() -> u32 {
    u32::MAX
}

fn default_concurrency_limit() -> usize {
    Semaphore::MAX_PERMITS
}

fn default_submission_limit() -> usize {
    Semaphore::MAX_PERMITS
}

#[derive(Clone, Debug, Deserialize)]
pub struct TaskQueueSettings {
    #[serde(default = "default_quota_per_second")]
    pub quota_per_second: u32,
    #[serde(default = "default_concurrency_limit")]
    pub concurrency_limit: usize,
    #[serde(default = "default_submission_limit")]
    pub submission_limit: usize,
}

impl Default for TaskQueueSettings {
    fn default() -> Self {
        TaskQueueSettings {
            quota_per_second: default_quota_per_second(),
            concurrency_limit: default_concurrency_limit(),
            submission_limit: default_submission_limit(),
        }
    }
}

pub type TimeoutConfig = aws_config::timeout::TimeoutConfig;

#[derive(Clone, Debug, Deserialize)]
pub struct AwsSettings {
    pub http: Option<HttpClientSettings>,
    pub task_queue: Option<TaskQueueSettings>,
}

impl Default for HttpClientSettings {
    fn default() -> Self {
        Self {
            pool_idle_timeout_seconds: DEFAULT_POOL_IDLE_TIMEOUT_SECONDS,
            nodelay: false,
            retry: RetrySettings::default(),
        }
    }
}

#[derive(Debug, Default)]
pub struct AwsClientBuilder<State>(State);

pub struct WantsHttpConfig(());

impl AwsClientBuilder<WantsHttpConfig> {
    pub fn builder() -> Self {
        Self(WantsHttpConfig(()))
    }

    pub fn with_http_settings(
        self,
        settings: &HttpClientSettings,
    ) -> AwsClientBuilder<WantsAwsConfig> {
        let nodelay = settings.nodelay;
        let http_client = HttpClientBuilder::new()
            .pool_idle_timeout(Duration::from_secs(settings.pool_idle_timeout_seconds))
            .build_with_connector_fn(move |_, _| {
                Connector::builder()
                    .tls_provider(tls::Provider::Rustls(CryptoMode::Ring))
                    .enable_tcp_nodelay(nodelay)
                    .build()
            });

        AwsClientBuilder(WantsAwsConfig {
            config: aws_config::defaults(BehaviorVersion::latest())
                .http_client(NetHttpClient::new(http_client))
                // We default to disabling HTTP connect timeouts for the time being, hopefully once
                // we sort out whatever is causing our mysterious network latency we can remove
                // this. Note: this is override-able in the next phase of the client builder
                // typestate settings.
                .timeout_config(TimeoutConfig::builder().disable_connect_timeout().build())
                .retry_config(RetryConfig::from(&settings.retry)),
        })
    }
}

pub struct WantsAwsConfig {
    config: aws_config::ConfigLoader,
}

impl AwsClientBuilder<WantsAwsConfig> {
    pub fn with_credentials_provider(
        mut self,
        credentials_provider: impl ProvideCredentials + 'static,
    ) -> Self {
        self.0.config = self.0.config.credentials_provider(credentials_provider);

        self
    }

    pub fn region(mut self, region: impl ProvideRegion + 'static) -> Self {
        self.0.config = self.0.config.region(region);

        self
    }

    pub fn maybe_region(mut self, region: Option<String>) -> Self {
        if let Some(region) = region {
            let region = aws_types::region::Region::new(region);
            self.0.config = self.0.config.region(region);
        }

        self
    }

    pub fn endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.0.config = self.0.config.endpoint_url(endpoint.into());

        self
    }

    pub fn maybe_endpoint(mut self, endpoint: Option<String>) -> Self {
        if let Some(endpoint) = endpoint {
            self.0.config = self.0.config.endpoint_url(endpoint);
        }

        self
    }

    pub fn with_timeout_config(mut self, timeout_config: TimeoutConfig) -> Self {
        self.0.config = self.0.config.timeout_config(timeout_config);

        self
    }

    pub async fn build_config(self) -> AwsClientBuilder<WantsService> {
        AwsClientBuilder(WantsService {
            config: self.0.config.load().await,
            slow_operation_threshold: u64::MAX,
            metric_labels: vec![],
        })
    }
}

pub struct WantsService {
    config: aws_config::SdkConfig,
    slow_operation_threshold: u64,
    metric_labels: Vec<KeyValue>,
}

impl AwsClientBuilder<WantsService> {
    pub fn with_slow_operation_threshold(mut self, slow_operation_threshold_millis: u64) -> Self {
        self.0.slow_operation_threshold = slow_operation_threshold_millis;

        self
    }

    pub fn and_append_metric_labels(mut self, mut additional_labels: Vec<KeyValue>) -> Self {
        self.0.metric_labels.append(&mut additional_labels);

        self
    }

    pub fn dynamodb(self) -> AwsClientBuilder<WantsTables> {
        let ddb_config = aws_sdk_dynamodb::config::Builder::from(&self.0.config).build();
        debug!("Using dynamodb config: {ddb_config:?}");

        AwsClientBuilder(WantsTables {
            client: DynamoDb::new(
                aws_sdk_dynamodb::Client::from_conf(ddb_config),
                Duration::from_millis(self.0.slow_operation_threshold),
                self.0.metric_labels,
            ),
            tables: vec![],
        })
    }

    pub fn s3(self) -> AwsClientBuilder<WantsBuckets> {
        self.s3_with_path_style(false)
    }

    pub fn s3_with_path_style(self, force_path_style: bool) -> AwsClientBuilder<WantsBuckets> {
        let s3_config = aws_sdk_s3::config::Builder::from(&self.0.config)
            .force_path_style(force_path_style)
            .build();
        debug!("Using S3 config: {s3_config:?}");

        AwsClientBuilder(WantsBuckets {
            client: S3::new(
                aws_sdk_s3::Client::from_conf(s3_config),
                Duration::from_millis(self.0.slow_operation_threshold),
            ),
            buckets: vec![],
        })
    }
}

pub struct WantsTables {
    client: DynamoDb,
    tables: Vec<String>,
}

impl AwsClientBuilder<WantsTables> {
    pub fn ensure_table(mut self, table_name: impl Into<String>) -> AwsClientBuilder<WantsTables> {
        self.0.tables.push(table_name.into());

        self
    }

    pub async fn build(
        self,
    ) -> Result<DynamoDb, AwsClientError<aws_sdk_dynamodb::error::SdkError<DescribeTableError>>>
    {
        for table_name in self.0.tables {
            debug!("Checking if table exists: {table_name}");

            match self
                .0
                .client
                .table_exists(&Arc::from(table_name.as_str()))
                .await
            {
                Ok(exists) if !exists => {
                    return Err(AwsClientError::DynamoTableNotFound(table_name));
                }
                Ok(_) => {
                    debug!("Dynamo table exists: {table_name}");
                }
                Err(AwsError::AwsSdkError(e)) => return Err(e.into()),
                Err(e) => {
                    warn!("Unknown error while checking if table exists: {e:?}");
                    return Err(AwsClientError::Unknown);
                }
            }
        }

        Ok(self.0.client)
    }
}

pub struct WantsBuckets {
    client: S3,
    buckets: Vec<String>,
}

impl AwsClientBuilder<WantsBuckets> {
    pub fn ensure_bucket(mut self, bucket: impl Into<String>) -> AwsClientBuilder<WantsBuckets> {
        self.0.buckets.push(bucket.into());

        self
    }

    pub async fn build(
        self,
    ) -> Result<S3, AwsClientError<aws_sdk_s3::error::SdkError<HeadBucketError>>> {
        for bucket in self.0.buckets {
            debug!("Checking if bucket exists: {bucket}");

            match self.0.client.bucket_exists(bucket.clone()).await {
                Ok(exists) if exists => {
                    debug!("S3 bucket exists: {bucket}");
                }
                Ok(_) => return Err(AwsClientError::BucketNotFound(bucket)),
                Err(AwsError::AwsSdkError(e)) => return Err(e.into()),
                Err(e) => {
                    warn!("Unknown error while checking if bucket exists: {e:?}");
                    return Err(AwsClientError::Unknown);
                }
            }
        }

        Ok(self.0.client)
    }
}

#[cfg(test)]
mod tests {
    use aws_smithy_types::retry::RetryMode as SmithyRetryMode;
    use tracing_test::traced_test;

    use super::*;

    /// The documented defaults, as a value so tests can lean on the new
    /// `PartialEq` derive instead of asserting field-by-field.
    fn expected_default_retry_settings() -> RetrySettings {
        RetrySettings {
            mode: RetryMode::Standard,
            max_attempts: DEFAULT_RETRY_MAX_ATTEMPTS,
            initial_backoff_millis: DEFAULT_RETRY_INITIAL_BACKOFF_MILLIS,
            max_backoff_seconds: DEFAULT_RETRY_MAX_BACKOFF_SECONDS,
        }
    }

    // --- RetrySettings defaults ------------------------------------------

    #[test]
    fn retry_settings_default_is_standard_with_documented_defaults() {
        // Standard, not adaptive: the rate limiter behind adaptive mode is
        // unbounded by `max_backoff` and process-global, so it must be an
        // opt-in choice, not what every caller gets silently.
        let settings = RetrySettings::default();

        assert_eq!(settings, expected_default_retry_settings());

        let config = RetryConfig::from(&settings);
        assert_eq!(config.mode(), SmithyRetryMode::Standard);
        assert_eq!(config.max_attempts(), DEFAULT_RETRY_MAX_ATTEMPTS);
        assert_eq!(
            config.initial_backoff(),
            Duration::from_millis(DEFAULT_RETRY_INITIAL_BACKOFF_MILLIS)
        );
        assert_eq!(
            config.max_backoff(),
            Duration::from_secs(DEFAULT_RETRY_MAX_BACKOFF_SECONDS)
        );
    }

    #[test]
    fn http_client_settings_default_carries_retry_defaults() {
        // lore-integration-tests and lore-postgres both construct
        // `HttpClientSettings::default()` directly; make sure it still yields
        // the standard retry defaults, not a zeroed-out `RetrySettings`.
        let settings = HttpClientSettings::default();

        assert_eq!(settings.retry, expected_default_retry_settings());
    }

    // --- RetryMode -> RetryConfig mapping ---------------------------------

    #[test]
    fn retry_mode_adaptive_maps_to_adaptive_retry_config() {
        let settings = RetrySettings {
            mode: RetryMode::Adaptive,
            ..RetrySettings::default()
        };

        let config = RetryConfig::from(&settings);

        assert_eq!(config.mode(), SmithyRetryMode::Adaptive);
        assert_eq!(config.max_attempts(), DEFAULT_RETRY_MAX_ATTEMPTS);
    }

    #[test]
    fn retry_mode_standard_maps_to_standard_retry_config() {
        let settings = RetrySettings {
            mode: RetryMode::Standard,
            ..RetrySettings::default()
        };

        let config = RetryConfig::from(&settings);

        assert_eq!(config.mode(), SmithyRetryMode::Standard);
        assert_eq!(config.max_attempts(), DEFAULT_RETRY_MAX_ATTEMPTS);
    }

    #[test]
    fn retry_mode_disabled_maps_to_disabled_retry_config() {
        // `RetryConfig::disabled()` (upstream aws-smithy-types) is
        // `RetryConfig::standard().with_max_attempts(1)` and returns early
        // from `From<&RetrySettings>`, so the configured attempt/backoff
        // overrides deliberately do NOT apply to this mode -- verify that
        // exact (surprising) shape rather than assuming our knobs win.
        let settings = RetrySettings {
            mode: RetryMode::Disabled,
            max_attempts: 9,
            initial_backoff_millis: 500,
            max_backoff_seconds: 60,
        };

        let config = RetryConfig::from(&settings);

        assert!(!config.has_retry());
        assert_eq!(config.max_attempts(), 1);
        assert_eq!(config.mode(), SmithyRetryMode::Standard);
        assert_eq!(config.initial_backoff(), Duration::from_secs(1));
        assert_eq!(config.max_backoff(), Duration::from_secs(20));
    }

    // --- max_attempts clamp -------------------------------------------------

    #[test]
    fn max_attempts_zero_clamps_to_one_not_rejected() {
        let settings = RetrySettings {
            max_attempts: 0,
            ..RetrySettings::default()
        };

        let config = RetryConfig::from(&settings);

        // A literal 0 would mean "never even send the request"; the `.max(1)`
        // guard must turn it into 1, not propagate it or panic.
        assert_eq!(config.max_attempts(), 1);
    }

    #[traced_test]
    #[test]
    fn max_attempts_zero_clamp_is_logged() {
        let settings = RetrySettings {
            max_attempts: 0,
            ..RetrySettings::default()
        };

        let _config = RetryConfig::from(&settings);

        assert!(logs_contain(
            "AWS retry max_attempts must be at least 1; ignoring the configured value"
        ));
    }

    #[traced_test]
    #[test]
    fn max_attempts_above_zero_does_not_log_a_clamp_warning() {
        let settings = RetrySettings {
            max_attempts: 5,
            ..RetrySettings::default()
        };

        let _config = RetryConfig::from(&settings);

        assert!(!logs_contain(
            "AWS retry max_attempts must be at least 1; ignoring the configured value"
        ));
    }

    // --- backoff duration conversion ---------------------------------------

    #[test]
    fn backoff_settings_convert_to_matching_durations() {
        let settings = RetrySettings {
            initial_backoff_millis: 250,
            max_backoff_seconds: 45,
            ..RetrySettings::default()
        };

        let config = RetryConfig::from(&settings);

        assert_eq!(config.initial_backoff(), Duration::from_millis(250));
        assert_eq!(config.max_backoff(), Duration::from_secs(45));
    }

    // --- serde: backward compatibility for existing deployed configs -------

    #[test]
    fn http_client_settings_toml_with_no_retry_key_yields_standard_defaults() {
        // Every existing deployed loreserver TOML config predates the
        // `[retry]` table entirely. It must keep deserializing, and land on
        // the new standard-mode defaults, not fail or silently zero out.
        let toml_str = r#"
            pool_idle_timeout_seconds = 30
            nodelay = true
        "#;

        let settings: HttpClientSettings = toml::from_str(toml_str).unwrap();

        assert_eq!(settings.pool_idle_timeout_seconds, 30);
        assert!(settings.nodelay);
        assert_eq!(settings.retry, expected_default_retry_settings());
    }

    #[test]
    fn http_client_settings_empty_toml_yields_standard_defaults() {
        // The degenerate case of the above: a wholly empty fragment (every
        // field, including `pool_idle_timeout_seconds`/`nodelay`, defaulted).
        let settings: HttpClientSettings = toml::from_str("").unwrap();

        assert_eq!(
            settings.pool_idle_timeout_seconds,
            DEFAULT_POOL_IDLE_TIMEOUT_SECONDS
        );
        assert!(!settings.nodelay);
        assert_eq!(settings.retry, expected_default_retry_settings());
    }

    #[test]
    fn http_client_settings_empty_retry_table_matches_absent_retry_key() {
        // A `[retry]` header with nothing under it must default identically
        // to the key being missing altogether -- not partially defaulted,
        // not an error. Both must equal the same `RetrySettings::default()`.
        let with_empty_table: HttpClientSettings = toml::from_str("[retry]\n").unwrap();
        let without_retry_key: HttpClientSettings = toml::from_str(
            r#"
                pool_idle_timeout_seconds = 30
            "#,
        )
        .unwrap();

        assert_eq!(with_empty_table.retry, expected_default_retry_settings());
        assert_eq!(with_empty_table.retry, without_retry_key.retry);
    }

    #[test]
    fn http_client_settings_json_with_no_retry_key_yields_standard_defaults() {
        let json_str = r#"{ "pool_idle_timeout_seconds": 30 }"#;

        let settings: HttpClientSettings = serde_json::from_str(json_str).unwrap();

        assert_eq!(settings.retry, expected_default_retry_settings());
    }

    #[test]
    fn http_client_settings_partial_retry_table_defaults_the_rest() {
        // Only `mode` set (to a non-default value, so this is distinguishable
        // from the all-defaults tests above); `max_attempts` /
        // `initial_backoff_millis` / `max_backoff_seconds` must still take
        // their individual defaults.
        let toml_str = r#"
            [retry]
            mode = "adaptive"
        "#;

        let settings: HttpClientSettings = toml::from_str(toml_str).unwrap();

        assert_eq!(settings.retry.mode, RetryMode::Adaptive);
        assert_eq!(settings.retry.max_attempts, DEFAULT_RETRY_MAX_ATTEMPTS);
        assert_eq!(
            settings.retry.initial_backoff_millis,
            DEFAULT_RETRY_INITIAL_BACKOFF_MILLIS
        );
        assert_eq!(
            settings.retry.max_backoff_seconds,
            DEFAULT_RETRY_MAX_BACKOFF_SECONDS
        );
    }

    #[test]
    fn retry_mode_lowercase_spellings_deserialize() {
        for (spelling, expected) in [
            ("adaptive", RetryMode::Adaptive),
            ("standard", RetryMode::Standard),
            ("disabled", RetryMode::Disabled),
        ] {
            let toml_str = format!("[retry]\nmode = \"{spelling}\"\n");
            let settings: HttpClientSettings = toml::from_str(&toml_str)
                .unwrap_or_else(|e| panic!("failed to deserialize mode {spelling:?}: {e}"));

            assert_eq!(
                settings.retry.mode, expected,
                "spelling {spelling:?} did not map to {expected:?}"
            );
        }
    }

    #[test]
    fn retry_mode_rejects_unknown_spelling() {
        let toml_str = "[retry]\nmode = \"aggressive\"\n";

        let result: Result<HttpClientSettings, _> = toml::from_str(toml_str);

        assert!(result.is_err());
    }
}

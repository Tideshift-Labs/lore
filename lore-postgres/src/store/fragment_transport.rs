// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! S3 adapter behind `lore-fragment-provider`'s unforgeable request port.

use std::future::Future;
use std::pin::Pin;

use aws_sdk_s3::error::SdkError;
use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::BucketVersioningStatus;
use aws_smithy_types::error::metadata::ProvideErrorMetadata;
use lore_aws::aws_error::is_retryable_sdk_error;
use lore_aws::net_http_client::HttpRequestAttemptCounter;
use lore_fragment_provider::FragmentDirectPutPort;
use lore_fragment_provider::FragmentDirectPutRequest;
use lore_fragment_provider::FragmentGetExchange;
use lore_fragment_provider::FragmentGetPort;
use lore_fragment_provider::FragmentGetRequest;
use lore_fragment_provider::FragmentGetResponse;
use lore_fragment_provider::FragmentTransportExchange;
use lore_fragment_provider::FragmentTransportOperation;
use lore_fragment_provider::FragmentTransportPort;
use lore_fragment_provider::FragmentTransportRequest;
use lore_fragment_provider::FragmentTransportResponse;
use lore_fragment_provider::ProviderAttemptOutcome;

use super::immutable_store::PostgresFragmentTransportConfigError;

/// A retry-disabled S3 client that can be invoked only with a request minted by
/// the fragment-provider seam after admission and charge.
pub(crate) struct PostgresFragmentS3Transport {
    client: aws_sdk_s3::Client,
    bucket: String,
    region: String,
    endpoint_host: String,
}

/// Proof that the exact retry-disabled client observed the exact bucket as
/// never versioned.
///
/// The fields are private and the only constructor is the startup
/// `GetBucketVersioning` probe below. Production transport construction must
/// consume this value, so a caller cannot substitute an unprobed client or a
/// different bucket after attestation.
struct UnversionedBucketAttestation {
    client: aws_sdk_s3::Client,
    bucket: String,
}

impl PostgresFragmentS3Transport {
    pub(crate) async fn new(
        client: aws_sdk_s3::Client,
        bucket: String,
        region: String,
        endpoint_host: String,
        resolved_endpoint_url: &str,
    ) -> Result<Self, PostgresFragmentTransportConfigError> {
        let retry = client
            .config()
            .retry_config()
            .ok_or(PostgresFragmentTransportConfigError::MissingRetryConfiguration)?;
        if retry.has_retry() || retry.max_attempts() != 1 {
            return Err(PostgresFragmentTransportConfigError::RetryEnabled);
        }
        let resolved_region = client
            .config()
            .region()
            .and_then(|value| normalize_region(value.as_ref()))
            .ok_or(PostgresFragmentTransportConfigError::MissingResolvedRegion)?;
        let target_region = normalize_region(&region)
            .ok_or(PostgresFragmentTransportConfigError::InvalidTargetRegion)?;
        if resolved_region != target_region {
            return Err(PostgresFragmentTransportConfigError::RegionMismatch);
        }
        let resolved_endpoint_host = normalize_endpoint_host(resolved_endpoint_url)
            .ok_or(PostgresFragmentTransportConfigError::MissingResolvedEndpoint)?;
        let target_endpoint_host = normalize_dns_name(&endpoint_host)
            .ok_or(PostgresFragmentTransportConfigError::InvalidTargetEndpoint)?;
        if resolved_endpoint_host != target_endpoint_host {
            return Err(PostgresFragmentTransportConfigError::EndpointMismatch);
        }
        let attestation = attest_unversioned_bucket(client, bucket).await?;
        Ok(Self {
            client: attestation.client,
            bucket: attestation.bucket,
            region: target_region,
            endpoint_host: target_endpoint_host,
        })
    }

    fn target_matches(&self, target: lore_fragment_provider::FragmentTransportTarget<'_>) -> bool {
        target.bucket() == self.bucket
            && target.region() == self.region
            && target.endpoint_host() == self.endpoint_host
    }

    fn exchange(
        counter: &HttpRequestAttemptCounter,
        outcome: ProviderAttemptOutcome,
        response: FragmentTransportResponse,
    ) -> FragmentTransportExchange {
        FragmentTransportExchange {
            outcome,
            provider_requests_issued: counter.issued(),
            response,
        }
    }

    async fn issue_request(
        &self,
        request: FragmentTransportRequest<'_>,
    ) -> FragmentTransportExchange {
        if !self.target_matches(request.target()) {
            return FragmentTransportExchange {
                outcome: ProviderAttemptOutcome::Decisive,
                provider_requests_issued: 0,
                response: FragmentTransportResponse::DefiniteFailure,
            };
        }
        match request.operation() {
            FragmentTransportOperation::Head { object_key } => {
                let counter = HttpRequestAttemptCounter::default();
                let result = counter
                    .count_connector_attempts(
                        self.client
                            .head_object()
                            .bucket(&self.bucket)
                            .key(object_key)
                            .send(),
                    )
                    .await;
                match result {
                    Ok(output) => Self::exchange(
                        &counter,
                        ProviderAttemptOutcome::Decisive,
                        FragmentTransportResponse::Head {
                            metadata: output
                                .metadata()
                                .map(|metadata| {
                                    metadata
                                        .iter()
                                        .map(|(key, value)| (key.clone(), value.clone()))
                                        .collect()
                                })
                                .unwrap_or_default(),
                            content_length: output
                                .content_length()
                                .and_then(|size| u64::try_from(size).ok())
                                .unwrap_or_default(),
                        },
                    ),
                    Err(error) => {
                        let response = if error
                            .as_service_error()
                            .is_some_and(|service| service.is_not_found())
                        {
                            FragmentTransportResponse::NotFound
                        } else {
                            FragmentTransportResponse::DefiniteFailure
                        };
                        Self::exchange(&counter, sdk_outcome(&error), response)
                    }
                }
            }
            FragmentTransportOperation::ListVersions { object_key } => {
                let counter = HttpRequestAttemptCounter::default();
                let result = counter
                    .count_connector_attempts(
                        self.client
                            .list_object_versions()
                            .bucket(&self.bucket)
                            .prefix(object_key)
                            .send(),
                    )
                    .await;
                match result {
                    Ok(output) => Self::exchange(
                        &counter,
                        ProviderAttemptOutcome::Decisive,
                        FragmentTransportResponse::Versions(
                            output
                                .versions()
                                .iter()
                                .filter(|version| version.key() == Some(object_key.as_str()))
                                .filter_map(|version| {
                                    Some(lore_fragment_provider::FragmentObjectVersion {
                                        version_id: version.version_id()?.to_string(),
                                        is_latest: version.is_latest().unwrap_or(false),
                                    })
                                })
                                .collect(),
                        ),
                    ),
                    Err(error) => Self::exchange(
                        &counter,
                        sdk_outcome(&error),
                        FragmentTransportResponse::DefiniteFailure,
                    ),
                }
            }
            FragmentTransportOperation::DeleteVersion {
                object_key,
                version_id,
            } => {
                let counter = HttpRequestAttemptCounter::default();
                let result = counter
                    .count_connector_attempts(
                        self.client
                            .delete_object()
                            .bucket(&self.bucket)
                            .key(object_key)
                            .version_id(version_id)
                            .send(),
                    )
                    .await;
                match result {
                    Ok(_) => Self::exchange(
                        &counter,
                        ProviderAttemptOutcome::Decisive,
                        FragmentTransportResponse::Deleted,
                    ),
                    Err(error) => Self::exchange(
                        &counter,
                        sdk_outcome(&error),
                        FragmentTransportResponse::DefiniteFailure,
                    ),
                }
            }
        }
    }

    async fn issue_direct_put_request(
        &self,
        request: FragmentDirectPutRequest<'_>,
    ) -> FragmentTransportExchange {
        if !self.target_matches(request.target()) {
            return FragmentTransportExchange {
                outcome: ProviderAttemptOutcome::Decisive,
                provider_requests_issued: 0,
                response: FragmentTransportResponse::DefiniteFailure,
            };
        }
        let Some(body) = request.body() else {
            return FragmentTransportExchange {
                outcome: ProviderAttemptOutcome::Decisive,
                provider_requests_issued: 0,
                response: FragmentTransportResponse::DefiniteFailure,
            };
        };
        let operation = request.operation();
        let counter = HttpRequestAttemptCounter::default();
        let result = counter
            .count_connector_attempts(
                self.client
                    .put_object()
                    .bucket(&self.bucket)
                    .key(&operation.object_key)
                    .if_none_match("*")
                    .set_metadata(Some(operation.metadata.iter().cloned().collect()))
                    .body(ByteStream::from(body.to_vec()))
                    .send(),
            )
            .await;
        match result {
            Ok(_) => Self::exchange(
                &counter,
                ProviderAttemptOutcome::Decisive,
                FragmentTransportResponse::PutCreated,
            ),
            Err(error) => {
                let precondition = error
                    .as_service_error()
                    .and_then(ProvideErrorMetadata::code)
                    .is_some_and(|code| code == "PreconditionFailed");
                Self::exchange(
                    &counter,
                    conditional_put_outcome(&error),
                    if precondition {
                        FragmentTransportResponse::PutPreconditionFailed
                    } else {
                        FragmentTransportResponse::DefiniteFailure
                    },
                )
            }
        }
    }

    async fn issue_get_request(&self, request: FragmentGetRequest<'_>) -> FragmentGetExchange {
        if !self.target_matches(request.target()) {
            return FragmentGetExchange {
                outcome: ProviderAttemptOutcome::Decisive,
                provider_requests_issued: 0,
                response: FragmentGetResponse::DefiniteFailure,
            };
        }
        let counter = HttpRequestAttemptCounter::default();
        let result = counter
            .count_connector_attempts(
                self.client
                    .get_object()
                    .bucket(&self.bucket)
                    .key(&request.operation().object_key)
                    .send(),
            )
            .await;
        match result {
            Ok(output) => {
                let metadata = output
                    .metadata()
                    .map(|metadata| {
                        metadata
                            .iter()
                            .map(|(key, value)| (key.clone(), value.clone()))
                            .collect()
                    })
                    .unwrap_or_default();
                match output.body.collect().await {
                    Ok(body) => FragmentGetExchange {
                        outcome: ProviderAttemptOutcome::Decisive,
                        provider_requests_issued: counter.issued(),
                        response: FragmentGetResponse::Found {
                            bytes: body.into_bytes().to_vec(),
                            metadata,
                        },
                    },
                    Err(_) => FragmentGetExchange {
                        outcome: ProviderAttemptOutcome::Ambiguous,
                        provider_requests_issued: counter.issued(),
                        response: FragmentGetResponse::AmbiguousFailure,
                    },
                }
            }
            Err(error) => {
                let response = if error
                    .as_service_error()
                    .is_some_and(|service| service.is_no_such_key())
                {
                    FragmentGetResponse::NotFound
                } else if is_retryable_sdk_error(&error) {
                    FragmentGetResponse::Throttled
                } else if sdk_outcome(&error) == ProviderAttemptOutcome::Ambiguous {
                    FragmentGetResponse::AmbiguousFailure
                } else {
                    FragmentGetResponse::DefiniteFailure
                };
                FragmentGetExchange {
                    outcome: sdk_outcome(&error),
                    provider_requests_issued: counter.issued(),
                    response,
                }
            }
        }
    }
}

/// Perform the sole bucket-level provider read used by runtime activation.
///
/// This probe is unmetered and does not enter the dispatch database or charge
/// authority. The retry-disabled client must reach the connector exactly once.
/// Source construction exposes no bucket-versioning mutation operation; an
/// external IAM policy remains responsible for denying that permission.
async fn attest_unversioned_bucket(
    client: aws_sdk_s3::Client,
    bucket: String,
) -> Result<UnversionedBucketAttestation, PostgresFragmentTransportConfigError> {
    let counter = HttpRequestAttemptCounter::default();
    let result = counter
        .count_connector_attempts(client.get_bucket_versioning().bucket(&bucket).send())
        .await;
    if counter.issued() != 1 {
        return Err(PostgresFragmentTransportConfigError::BucketVersioningAttemptCount);
    }
    let output =
        result.map_err(|_| PostgresFragmentTransportConfigError::BucketVersioningProbeFailed)?;
    match output.status() {
        None => Ok(UnversionedBucketAttestation { client, bucket }),
        Some(BucketVersioningStatus::Enabled) => {
            Err(PostgresFragmentTransportConfigError::BucketVersioningEnabled)
        }
        Some(BucketVersioningStatus::Suspended) => {
            Err(PostgresFragmentTransportConfigError::BucketVersioningSuspended)
        }
        Some(_) => Err(PostgresFragmentTransportConfigError::BucketVersioningUnknown),
    }
}

fn normalize_region(value: &str) -> Option<String> {
    let normalized = value.to_ascii_lowercase();
    if normalized.is_empty()
        || !normalized
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        || normalized.starts_with('-')
        || normalized.ends_with('-')
    {
        return None;
    }
    Some(normalized)
}

fn normalize_endpoint_host(endpoint_url: &str) -> Option<String> {
    let (scheme, remainder) = endpoint_url.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return None;
    }
    let authority = remainder
        .split(['/', '?', '#'])
        .next()
        .filter(|value| !value.is_empty())?;
    if authority.contains('@') || authority.starts_with('[') {
        return None;
    }
    let host = match authority.rsplit_once(':') {
        Some((host, port)) => {
            if host.contains(':') || port.parse::<u16>().ok().filter(|port| *port != 0).is_none() {
                return None;
            }
            host
        }
        None => authority,
    };
    normalize_dns_name(host)
}

fn normalize_dns_name(value: &str) -> Option<String> {
    let normalized = value.trim_end_matches('.').to_ascii_lowercase();
    if normalized.is_empty() || normalized.len() > 253 {
        return None;
    }
    for label in normalized.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || label.starts_with('-')
            || label.ends_with('-')
        {
            return None;
        }
    }
    Some(normalized)
}

impl FragmentTransportPort for PostgresFragmentS3Transport {
    fn issue<'a>(
        &'a self,
        request: FragmentTransportRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = FragmentTransportExchange> + Send + 'a>> {
        Box::pin(self.issue_request(request))
    }
}

impl FragmentDirectPutPort for PostgresFragmentS3Transport {
    fn issue_direct_put<'a>(
        &'a self,
        request: FragmentDirectPutRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = FragmentTransportExchange> + Send + 'a>> {
        Box::pin(self.issue_direct_put_request(request))
    }
}

impl FragmentGetPort for PostgresFragmentS3Transport {
    fn issue_get<'a>(
        &'a self,
        request: FragmentGetRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = FragmentGetExchange> + Send + 'a>> {
        Box::pin(self.issue_get_request(request))
    }
}

fn sdk_outcome<E, R>(error: &SdkError<E, R>) -> ProviderAttemptOutcome {
    match error {
        SdkError::ServiceError(_) => ProviderAttemptOutcome::Decisive,
        SdkError::ResponseError(_) => ProviderAttemptOutcome::Ambiguous,
        _ => ProviderAttemptOutcome::Ambiguous,
    }
}

fn conditional_put_outcome<E, R>(error: &SdkError<E, R>) -> ProviderAttemptOutcome {
    match error {
        SdkError::ServiceError(_) => ProviderAttemptOutcome::Decisive,
        SdkError::ResponseError(_) => ProviderAttemptOutcome::Ambiguous,
        _ => ProviderAttemptOutcome::Ambiguous,
    }
}

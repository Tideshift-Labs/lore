// SPDX-FileCopyrightText: 2026 Epic Games, Inc.
// SPDX-FileCopyrightText: 2026 Khurram Virani
// SPDX-License-Identifier: MIT
use std::fmt::Debug;

use aws_smithy_runtime_api::client::orchestrator::HttpResponse;
use aws_smithy_runtime_api::client::result::SdkError;
use aws_smithy_types::error::metadata::ProvideErrorMetadata;
use thiserror::Error;

#[derive(Debug, Error, PartialEq)]
pub enum AwsError<E> {
    #[error("AWS SDK operation failed: {0:?}")]
    AwsSdkError(E),
    #[error("Dynamo BatchGetItem received empty keys")]
    MissingKeys,
    #[error("Failed to build batch request")]
    BatchRequestError,
    #[error("Failed to join task")]
    JoinError,
}

/// HTTP statuses that indicate a transient server-side condition.
///
/// Deliberately an explicit list rather than "any 5xx": the AWS SDK's own
/// `HttpStatusCodeClassifier` retries exactly these, and a permanent 5xx such as
/// `501 Not Implemented` or `505 HTTP Version Not Supported` will never succeed
/// on retry — treating it as retryable only delays the failure by the caller's
/// full backoff schedule. `429` is added for endpoints that signal throttling by
/// status rather than by error code.
const RETRYABLE_STATUS_CODES: &[u16] = &[429, 500, 502, 503, 504];

/// Service error codes that mean "shedding load, back off and retry" rather
/// than "this request is wrong".
///
/// Covers DynamoDB's throttle codes and the S3-style `SlowDown`, so one
/// classifier serves both stores as well as the S3-compatible endpoints a
/// deployment may point at.
const THROTTLE_ERROR_CODES: &[&str] = &[
    "ProvisionedThroughputExceededException",
    "RequestLimitExceeded",
    "RequestThrottled",
    "RequestThrottledException",
    "SlowDown",
    "ThrottledException",
    "Throttling",
    "ThrottlingError",
    "ThrottlingException",
    "ThroughputBelowMinimum",
    "TooManyRequestsException",
];

/// Returns `true` when a service error code names a throttling condition.
///
/// Strips any leading Smithy shape-id namespace (`com.amazonaws.dynamodb#\
/// ThrottlingException`) before matching, since a non-AWS S3-compatible endpoint
/// may report the qualified form where AWS itself reports the bare name.
fn is_throttle_code(code: &str) -> bool {
    let name = code.rsplit('#').next().unwrap_or(code);
    THROTTLE_ERROR_CODES.contains(&name)
}

/// Returns `true` when an SDK failure is a capacity or transport condition the
/// caller should retry with backoff, rather than a definitive rejection of the
/// request.
///
/// Use this wherever a store maps an SDK error onto a domain error: a throttle
/// classified as anything other than [`SlowDown`] loses the one piece of
/// information the caller needs, which is that retrying is worthwhile.
///
/// Deliberately conservative — an unrecognised service error is *not* retryable,
/// so a genuine client-side mistake still fails fast instead of being retried
/// against a service that will keep rejecting it.
///
/// Note for callers on **write** paths: a dispatch failure means the request may
/// or may not have reached the service, so retrying one is only safe for an
/// idempotent operation. A conditional write must decide that for itself rather
/// than treating this predicate as permission to retry.
///
/// [`SlowDown`]: lore_base::error::SlowDown
pub fn is_retryable_sdk_error<E>(error: &SdkError<E, HttpResponse>) -> bool
where
    E: ProvideErrorMetadata,
{
    match error {
        // No answer was received, so the failure says nothing about the
        // resource itself.
        SdkError::TimeoutError(_) => true,
        SdkError::DispatchFailure(failure) => failure.is_io() || failure.is_timeout(),
        // A response arrived but could not be parsed into a modelled error —
        // an intermediary (load balancer, proxy) answering instead of the
        // service, or a truncated body. Retryable regardless of status, matching
        // the SDK's own transient-error classification: a body cut short mid
        // transfer arrives with a perfectly successful status.
        SdkError::ResponseError(_) => true,
        SdkError::ServiceError(service_error) => {
            if RETRYABLE_STATUS_CODES.contains(&service_error.raw().status().as_u16()) {
                return true;
            }

            service_error.err().code().is_some_and(is_throttle_code)
        }
        // `SdkError` is `#[non_exhaustive]`. Treat anything unrecognised as
        // non-retryable so a future variant cannot silently become a retry loop.
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use aws_sdk_dynamodb::operation::get_item::GetItemError;
    use aws_sdk_dynamodb::types::error::ProvisionedThroughputExceededException;
    use aws_sdk_dynamodb::types::error::ResourceNotFoundException;
    use aws_sdk_dynamodb::types::error::ThrottlingException;
    use aws_smithy_runtime_api::client::result::ConnectorError;
    use aws_smithy_runtime_api::client::result::ConstructionFailure;
    use aws_smithy_runtime_api::client::result::DispatchFailure;
    use aws_smithy_runtime_api::client::result::ResponseError;
    use aws_smithy_runtime_api::client::result::ServiceError;
    use aws_smithy_runtime_api::client::result::TimeoutError;
    use aws_smithy_types::body::SdkBody;
    use aws_smithy_types::error::ErrorMetadata;

    use super::*;

    #[derive(Debug, thiserror::Error)]
    #[error("stub")]
    struct StubError;

    fn http_response(status: u16) -> HttpResponse {
        HttpResponse::new(status.try_into().unwrap(), SdkBody::empty())
    }

    fn service_error(error: GetItemError, status: u16) -> SdkError<GetItemError, HttpResponse> {
        SdkError::ServiceError(
            ServiceError::builder()
                .source(error)
                .raw(http_response(status))
                .build(),
        )
    }

    /// Builds a `GetItemError` whose `code()` matches the DynamoDB exception
    /// name, the way a real deserialized service error would.
    fn coded(error_ctor: impl FnOnce(ErrorMetadata) -> GetItemError, code: &str) -> GetItemError {
        error_ctor(ErrorMetadata::builder().code(code).build())
    }

    #[test]
    fn timeout_error_is_retryable() {
        let error: SdkError<GetItemError, HttpResponse> =
            SdkError::TimeoutError(TimeoutError::builder().source(Box::new(StubError)).build());
        assert!(is_retryable_sdk_error(&error));
    }

    #[test]
    fn dispatch_failure_io_is_retryable() {
        let error: SdkError<GetItemError, HttpResponse> = SdkError::DispatchFailure(
            DispatchFailure::builder()
                .source(ConnectorError::io(Box::new(StubError)))
                .build(),
        );
        assert!(is_retryable_sdk_error(&error));
    }

    #[test]
    fn dispatch_failure_timeout_is_retryable() {
        let error: SdkError<GetItemError, HttpResponse> = SdkError::DispatchFailure(
            DispatchFailure::builder()
                .source(ConnectorError::timeout(Box::new(StubError)))
                .build(),
        );
        assert!(is_retryable_sdk_error(&error));
    }

    #[test]
    fn dispatch_failure_user_error_is_not_retryable() {
        let error: SdkError<GetItemError, HttpResponse> = SdkError::DispatchFailure(
            DispatchFailure::builder()
                .source(ConnectorError::user(Box::new(StubError)))
                .build(),
        );
        assert!(!is_retryable_sdk_error(&error));
    }

    #[test]
    fn response_error_is_retryable() {
        let error: SdkError<GetItemError, HttpResponse> = SdkError::ResponseError(
            ResponseError::builder()
                .source(Box::new(StubError))
                .raw(http_response(200))
                .build(),
        );
        assert!(is_retryable_sdk_error(&error));
    }

    #[test]
    fn construction_failure_is_not_retryable() {
        let error: SdkError<GetItemError, HttpResponse> = SdkError::ConstructionFailure(
            ConstructionFailure::builder()
                .source(Box::new(StubError))
                .build(),
        );
        assert!(!is_retryable_sdk_error(&error));
    }

    #[test]
    fn service_error_status_429_is_retryable_regardless_of_code() {
        // No code set at all: the status alone must be sufficient.
        let error = service_error(GetItemError::generic(ErrorMetadata::builder().build()), 429);
        assert!(is_retryable_sdk_error(&error));
    }

    #[test]
    fn service_error_status_5xx_is_retryable() {
        let error = service_error(GetItemError::generic(ErrorMetadata::builder().build()), 503);
        assert!(is_retryable_sdk_error(&error));
    }

    #[test]
    fn service_error_status_501_is_not_retryable() {
        // 501 Not Implemented is a permanent condition, not a capacity
        // problem: retrying it can never succeed. This is the regression
        // `RETRYABLE_STATUS_CODES` (an explicit allow-list, not `is_server_error()`)
        // exists to prevent.
        let error = service_error(GetItemError::generic(ErrorMetadata::builder().build()), 501);
        assert!(!is_retryable_sdk_error(&error));
    }

    #[test]
    fn service_error_namespaced_throttle_code_is_retryable() {
        // A non-AWS S3-compatible endpoint (our deployment target is
        // DigitalOcean Spaces) may report the qualified Smithy shape-id form
        // rather than AWS's bare exception name.
        let error = service_error(
            coded(
                |meta| {
                    GetItemError::ThrottlingException(
                        ThrottlingException::builder().meta(meta).build(),
                    )
                },
                "com.amazonaws.dynamodb#ThrottlingException",
            ),
            400,
        );
        assert!(is_retryable_sdk_error(&error));
    }

    #[test]
    fn service_error_provisioned_throughput_exceeded_code_is_retryable() {
        // Status 400 (DynamoDB's real throttle status), so only the error
        // code drives the classification here.
        let error = service_error(
            coded(
                |meta| {
                    GetItemError::ProvisionedThroughputExceededException(
                        ProvisionedThroughputExceededException::builder()
                            .meta(meta)
                            .build(),
                    )
                },
                "ProvisionedThroughputExceededException",
            ),
            400,
        );
        assert!(is_retryable_sdk_error(&error));
    }

    #[test]
    fn service_error_throttling_exception_code_is_retryable() {
        let error = service_error(
            coded(
                |meta| {
                    GetItemError::ThrottlingException(
                        ThrottlingException::builder().meta(meta).build(),
                    )
                },
                "ThrottlingException",
            ),
            400,
        );
        assert!(is_retryable_sdk_error(&error));
    }

    #[test]
    fn service_error_non_throttle_code_is_not_retryable() {
        // A modelled, non-throttle service error at a non-5xx/429 status:
        // neither classifier should fire.
        let error = service_error(
            coded(
                |meta| {
                    GetItemError::ResourceNotFoundException(
                        ResourceNotFoundException::builder().meta(meta).build(),
                    )
                },
                "ResourceNotFoundException",
            ),
            400,
        );
        assert!(!is_retryable_sdk_error(&error));
    }

    #[test]
    fn service_error_with_no_code_and_non_throttle_status_is_not_retryable() {
        let error = service_error(GetItemError::generic(ErrorMetadata::builder().build()), 400);
        assert!(!is_retryable_sdk_error(&error));
    }
}

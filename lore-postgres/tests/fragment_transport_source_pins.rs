// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Structural pins over the private S3 adapter's opaque authorized inputs.

use std::path::PathBuf;

fn source() -> String {
    std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/store/fragment_transport.rs"),
    )
    .expect("fragment transport source")
}

fn function<'a>(source: &'a str, marker: &str) -> &'a str {
    let start = source.find(marker).expect("function marker");
    let tail = &source[start..];
    let opening = tail.find('{').expect("opening brace");
    let mut depth = 0usize;
    for (offset, byte) in tail.as_bytes()[opening..].iter().copied().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return &tail[..opening + offset + 1];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated function")
}

#[test]
fn direct_put_wire_body_comes_only_from_the_opaque_authorized_request() {
    let source = source();
    let issue = function(&source, "async fn issue_direct_put_request(");
    assert!(issue.contains("let Some(body) = request.body() else"));
    assert!(issue.contains(".body(ByteStream::from(body.to_vec()))"));
    assert!(!issue.contains("operation.body"));
    assert!(!issue.contains("declared_blake3.to_vec()"));
    assert!(!issue.contains("declared_size.to_le_bytes()"));
}

#[test]
fn a_direct_operation_without_authorized_direct_bytes_returns_zero_before_sdk_construction() {
    let source = source();
    let issue = function(&source, "async fn issue_direct_put_request(");
    let absent = issue
        .find("let Some(body) = request.body() else")
        .expect("body gate");
    let zero = issue[absent..]
        .find("provider_requests_issued: 0")
        .map(|offset| absent + offset)
        .expect("zero-request refusal");
    let sdk = issue
        .find(".put_object()")
        .expect("one SDK PUT construction");
    assert!(absent < zero && zero < sdk);
    assert_eq!(issue.matches(".put_object()").count(), 1);
}

#[test]
fn retry_is_resolved_disabled_and_get_throttling_remains_transient() {
    let source = source();
    let constructor = function(&source, "pub(crate) async fn new(");
    assert!(constructor.contains("retry.has_retry() || retry.max_attempts() != 1"));
    assert!(constructor.contains("PostgresFragmentTransportConfigError::RetryEnabled"));

    let get = function(&source, "async fn issue_get_request(");
    assert!(get.contains("is_retryable_sdk_error(&error)"));
    assert!(get.contains("FragmentGetResponse::Throttled"));
    assert!(get.contains("provider_requests_issued: counter.issued()"));
}

#[test]
fn every_sdk_send_is_scoped_by_final_connector_attempt_accounting() {
    let source = source();
    assert_eq!(source.matches(".send()").count(), 7);
    assert_eq!(source.matches(".count_connector_attempts(").count(), 7);
    for (marker, send_marker) in [
        (".get_bucket_versioning()", ".send())"),
        (".head_object()", ".send(),"),
        (".list_object_versions()", ".send(),"),
        (".delete_object()", ".send(),"),
        (".put_object()", ".send(),"),
        (".get_object()", ".send(),"),
    ] {
        let operation = source.find(marker).expect("SDK operation");
        let before = &source[..operation];
        let scope = before
            .rfind(".count_connector_attempts(")
            .expect("attempt scope before SDK operation");
        let send = source[operation..]
            .find(send_marker)
            .map(|offset| operation + offset)
            .expect("SDK send");
        assert!(scope < operation && operation < send);
    }
}

#[test]
fn startup_attests_versioning_off_with_one_unmetered_read_and_no_head_or_list_oracle() {
    let source = source();
    let constructor = function(&source, "pub(crate) async fn new(");
    assert!(constructor.contains("attest_unversioned_bucket(client, bucket).await?"));
    assert!(constructor.contains("client: attestation.client"));
    assert!(constructor.contains("bucket: attestation.bucket"));

    let probe = function(&source, "async fn attest_unversioned_bucket(");
    assert_eq!(probe.matches(".get_bucket_versioning()").count(), 1);
    assert_eq!(probe.matches(".count_connector_attempts(").count(), 1);
    assert!(probe.contains("if counter.issued() != 1"));
    assert!(probe.contains("BucketVersioningAttemptCount"));
    assert!(probe.contains("BucketVersioningProbeFailed"));
    assert!(probe.contains("None => Ok(UnversionedBucketAttestation { client, bucket })"));
    assert!(probe.contains("Some(BucketVersioningStatus::Enabled)"));
    assert!(probe.contains("BucketVersioningEnabled"));
    assert!(probe.contains("Some(BucketVersioningStatus::Suspended)"));
    assert!(probe.contains("BucketVersioningSuspended"));
    assert!(
        probe.contains(
            "Some(_) => Err(PostgresFragmentTransportConfigError::BucketVersioningUnknown)"
        )
    );
    for forbidden in [
        ".head_object()",
        ".list_object_versions()",
        "ProviderAttemptLedger",
        "PostgresProviderChargeAuthority",
        "BudgetPin",
    ] {
        assert!(
            !probe.contains(forbidden),
            "versioning probe widened through {forbidden}"
        );
    }
    assert!(!source.contains(".put_bucket_versioning()"));
}

#[test]
fn direct_put_transport_is_separate_from_standard_and_get_ports() {
    let source = source();
    assert_eq!(source.matches("impl FragmentDirectPutPort").count(), 1);
    assert_eq!(source.matches("impl FragmentTransportPort").count(), 1);
    assert_eq!(source.matches("impl FragmentGetPort").count(), 1);
    assert!(source.contains("Box::pin(self.issue_direct_put_request(request))"));
}

#[test]
fn exact_delete_uses_one_unversioned_delete_without_prefix_head_list_or_version_id() {
    let source = source();
    let issue = function(&source, "async fn issue_request(");
    let start = issue
        .find("FragmentTransportOperation::DeleteExact { object_key }")
        .expect("exact delete arm");
    let arm = &issue[start..];
    assert_eq!(arm.matches(".delete_object()").count(), 1);
    assert_eq!(arm.matches(".count_connector_attempts(").count(), 1);
    assert!(arm.contains(".key(object_key)"));
    assert!(arm.contains("ProviderAttemptOutcome::Decisive"));
    assert!(arm.contains("FragmentTransportResponse::Deleted"));
    for forbidden in [
        ".prefix(",
        ".head_object()",
        ".list_object_versions()",
        ".version_id(",
    ] {
        assert!(
            !arm.contains(forbidden),
            "exact unversioned deletion widened through {forbidden}"
        );
    }
}

#[test]
fn response_errors_are_ambiguous_because_the_put_may_have_reached_the_provider() {
    let source = source();
    let classification = function(&source, "fn conditional_put_outcome<");
    assert!(
        classification.contains("SdkError::ServiceError(_) => ProviderAttemptOutcome::Decisive"),
        "a parsed provider service response is decisive"
    );
    assert!(
        classification.contains("SdkError::ResponseError(_) => ProviderAttemptOutcome::Ambiguous"),
        "an HTTP response parsing failure cannot prove whether conditional PUT committed"
    );
}

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
    let constructor = function(&source, "pub(crate) fn new(");
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
    assert_eq!(source.matches(".send(),").count(), 5);
    assert_eq!(source.matches(".count_connector_attempts(").count(), 5);
    for marker in [
        ".head_object()",
        ".list_object_versions()",
        ".delete_object()",
        ".put_object()",
        ".get_object()",
    ] {
        let operation = source.find(marker).expect("SDK operation");
        let before = &source[..operation];
        let scope = before
            .rfind(".count_connector_attempts(")
            .expect("attempt scope before SDK operation");
        let send = source[operation..]
            .find(".send(),")
            .map(|offset| operation + offset)
            .expect("SDK send");
        assert!(scope < operation && operation < send);
    }
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

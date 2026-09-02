// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Executed and structural controls for final-connector request accounting.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;

use aws_sdk_s3::config::Credentials;
use aws_sdk_s3::config::Region;
use aws_sdk_s3::config::retry::RetryConfig;
use aws_smithy_runtime_api::client::connector_metadata::ConnectorMetadata;
use aws_smithy_runtime_api::client::http::HttpClient;
use aws_smithy_runtime_api::client::http::HttpConnector;
use aws_smithy_runtime_api::client::http::HttpConnectorFuture;
use aws_smithy_runtime_api::client::http::HttpConnectorSettings;
use aws_smithy_runtime_api::client::http::SharedHttpConnector;
use aws_smithy_runtime_api::client::orchestrator::HttpRequest;
use aws_smithy_runtime_api::client::orchestrator::HttpResponse;
use aws_smithy_runtime_api::client::runtime_components::RuntimeComponents;
use aws_smithy_runtime_api::shared::IntoShared;
use aws_smithy_types::body::SdkBody;
use lore_aws::net_http_client::HttpRequestAttemptCounter;
use lore_aws::net_http_client::NetHttpClient;

const CONNECTOR_INCREMENT: &str =
    "HTTP_REQUEST_ATTEMPT_COUNTER.try_with(HttpRequestAttemptCounter::record_issue)";

fn assert_final_connector_accounting(source: &str) {
    let call_start = source
        .find("impl HttpConnector for NetHttpConnector")
        .expect("final connector implementation");
    let call = &source[call_start..];
    assert_eq!(source.matches("record_issue").count(), 2);
    assert!(
        call.contains(CONNECTOR_INCREMENT),
        "the operation counter must increment inside the final connector call"
    );
    for forbidden in ["mutate_request", "request_binder", "insert_header"] {
        assert!(
            !source.contains(forbidden),
            "request preparation hook {forbidden:?} cannot stand in for a physical transmit"
        );
    }
}

#[derive(Clone, Debug)]
struct CountingHttpClient {
    connector_calls: Arc<AtomicU32>,
}

impl HttpConnector for CountingHttpClient {
    fn call(&self, _request: HttpRequest) -> HttpConnectorFuture {
        self.connector_calls.fetch_add(1, Ordering::SeqCst);
        HttpConnectorFuture::ready(Ok(HttpResponse::new(
            200.try_into().expect("valid HTTP status"),
            SdkBody::empty(),
        )))
    }
}

impl HttpClient for CountingHttpClient {
    fn http_connector(
        &self,
        _settings: &HttpConnectorSettings,
        _components: &RuntimeComponents,
    ) -> SharedHttpConnector {
        self.clone().into_shared()
    }

    fn connector_metadata(&self) -> Option<ConnectorMetadata> {
        Some(ConnectorMetadata::new("counting-test-client", None))
    }
}

#[tokio::test]
async fn retry_disabled_operation_still_counts_its_first_final_connector_transmit() {
    let physical_calls = Arc::new(AtomicU32::new(0));
    let client = aws_sdk_s3::Client::from_conf(
        aws_sdk_s3::Config::builder()
            .behavior_version_latest()
            .http_client(NetHttpClient::new(CountingHttpClient {
                connector_calls: physical_calls.clone(),
            }))
            .credentials_provider(Credentials::new("test", "test", None, None, "test"))
            .region(Region::new("us-east-1"))
            .endpoint_url("http://localhost:9000")
            .retry_config(RetryConfig::disabled())
            .force_path_style(true)
            .build(),
    );
    let counter = HttpRequestAttemptCounter::default();

    let result = counter
        .count_connector_attempts(client.head_object().bucket("cell").key("fragment").send())
        .await;

    assert!(result.is_ok(), "fake connector returned a successful HEAD");
    assert_eq!(physical_calls.load(Ordering::SeqCst), 1);
    assert_eq!(counter.issued(), 1);
}

#[test]
fn source_counts_only_at_the_final_connector_call_not_during_request_mutation() {
    let source = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/net_http_client.rs"),
    )
    .expect("net HTTP client source");
    assert_final_connector_accounting(&source);

    let moved_to_request_preparation =
        source.replacen(CONNECTOR_INCREMENT, "", 1) + "\n// request_binder record_issue\n";
    assert!(
        std::panic::catch_unwind(|| assert_final_connector_accounting(
            &moved_to_request_preparation
        ))
        .is_err(),
        "negative control moving the token to request preparation must fail"
    );
}

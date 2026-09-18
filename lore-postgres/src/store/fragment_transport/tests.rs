// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use aws_sdk_s3::config::Credentials;
use aws_smithy_types::retry::RetryConfig;
use aws_smithy_types::timeout::TimeoutConfig;
use lore_aws::clients::AwsClientBuilder;
use lore_aws::clients::HttpClientSettings;
use lore_fragment_provider::BudgetPin;
use lore_fragment_provider::CellProviderBoundary;
use lore_fragment_provider::FragmentAttemptLedger;
use lore_fragment_provider::FragmentDatabaseIdentity;
use lore_fragment_provider::FragmentDirectPutOperation;
use lore_fragment_provider::FragmentDispatchRuntimeConfig;
use lore_fragment_provider::FragmentDispatchTls;
use lore_fragment_provider::FragmentProcessPoolInventory;
use lore_fragment_provider::FragmentProviderAttempt;
use lore_fragment_provider::FragmentProviderEntry;
use lore_fragment_provider::InFlightChargeBound;
use lore_fragment_provider::InFlightPutBound;
use lore_fragment_provider::ProviderAttemptClass;
use lore_fragment_provider::ProviderCapabilities;
use lore_fragment_provider::ProviderTrafficClass;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::time::timeout;
use tokio_util::task::AbortOnDropHandle;

use super::*;

const BOUNDARY: &str = "retry-conformance-boundary";
const BUCKET: &str = "retry-conformance-fragments";
const REGION: &str = "us-east-1";
const HOST: &str = "127.0.0.1";
const BODY: &[u8] = b"real SDK retry conformance payload";
const TIMEOUT: Duration = Duration::from_secs(20);

struct FaultEndpoint {
    url: String,
    received: Arc<AtomicU32>,
    stop: oneshot::Sender<()>,
    task: AbortOnDropHandle<()>,
}

impl FaultEndpoint {
    async fn start() -> Self {
        let listener = TcpListener::bind((HOST, 0))
            .await
            .expect("bind owned endpoint");
        let url = format!("http://{}", listener.local_addr().unwrap());
        let received = Arc::new(AtomicU32::new(0));
        let observed = Arc::clone(&received);
        let (stop, mut stopped) = oneshot::channel();
        let task = AbortOnDropHandle::new(lore_base::lore_spawn!(async move {
            loop {
                let mut stream = tokio::select! {
                    _ = &mut stopped => break,
                    accepted = listener.accept() => accepted.expect("accept SDK request").0,
                };
                timeout(TIMEOUT, async {
                    read_put(&mut stream).await;
                    let ordinal = observed.fetch_add(1, Ordering::SeqCst);
                    let (status, body) = if ordinal == 0 {
                        ("503 Service Unavailable", "<Error><Code>SlowDown</Code><Message>retry fixture</Message></Error>")
                    } else {
                        ("200 OK", "")
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/xml\r\nConnection: close\r\nETag: \"retry-fixture\"\r\n\r\n{body}",
                        body.len(),
                    );
                    stream.write_all(response.as_bytes()).await.expect("write S3 response");
                    stream.shutdown().await.expect("close S3 response");
                }).await.expect("bounded endpoint request");
            }
        }));
        Self {
            url,
            received,
            stop,
            task,
        }
    }

    async fn finish(self) -> u32 {
        let _ = self.stop.send(());
        timeout(TIMEOUT, self.task)
            .await
            .expect("endpoint stopped")
            .expect("endpoint joined");
        self.received.load(Ordering::SeqCst)
    }
}

async fn read_put(stream: &mut TcpStream) {
    let mut bytes = Vec::new();
    let header_end = loop {
        if let Some(index) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
            break index + 4;
        }
        let mut chunk = [0; 4096];
        let count = stream.read(&mut chunk).await.expect("read request headers");
        assert_ne!(count, 0, "request headers ended early");
        bytes.extend_from_slice(&chunk[..count]);
        assert!(bytes.len() < 64 * 1024, "bounded request headers");
    };
    let headers = std::str::from_utf8(&bytes[..header_end]).expect("HTTP headers");
    assert!(
        headers.starts_with("PUT /retry-conformance-fragments/"),
        "{headers}"
    );
    let length: usize = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().unwrap())
        })
        .expect("replayable SDK byte body has Content-Length");
    assert!(length < 64 * 1024, "bounded fixture body");
    if headers
        .lines()
        .any(|line| line.eq_ignore_ascii_case("expect: 100-continue"))
    {
        stream
            .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
            .await
            .unwrap();
    }
    while bytes.len() < header_end + length {
        let mut chunk = [0; 4096];
        let count = stream.read(&mut chunk).await.expect("consume request body");
        assert_ne!(count, 0, "request body ended early");
        bytes.extend_from_slice(&chunk[..count]);
    }
    assert!(
        bytes[header_end..]
            .windows(BODY.len())
            .any(|part| part == BODY),
        "each replay carries the payload"
    );
}

async fn retry_enabled_client(endpoint: &str) -> aws_sdk_s3::Client {
    let builder = AwsClientBuilder::builder()
        .with_http_settings(&HttpClientSettings::default())
        .with_credentials_provider(Credentials::new(
            "retry-fixture",
            "retry-fixture-secret",
            None,
            None,
            "retry-conformance",
        ))
        .maybe_region(Some(REGION.to_owned()))
        .endpoint(endpoint)
        .with_timeout_config(TimeoutConfig::builder().operation_timeout(TIMEOUT).build())
        .build_config();
    let builder = Box::pin(builder).await.s3_with_path_style(true);
    let s3 = Box::pin(builder.build())
        .await
        .expect("build real NetHttpClient-backed SDK client");
    let config = s3
        .sdk_client()
        .config()
        .to_builder()
        .retry_config(
            RetryConfig::standard()
                .with_max_attempts(2)
                .with_initial_backoff(Duration::from_millis(1)),
        )
        .build();
    aws_sdk_s3::Client::from_conf(config)
}

#[tokio::test]
async fn resolved_sdk_retries_are_rejected_before_any_http_request() {
    let endpoint = FaultEndpoint::start().await;
    let client = retry_enabled_client(&endpoint.url).await;
    assert_eq!(client.config().retry_config().unwrap().max_attempts(), 2);
    let result = timeout(
        TIMEOUT,
        PostgresFragmentS3Transport::new(
            client,
            BUCKET.to_owned(),
            REGION.to_owned(),
            HOST.to_owned(),
            &endpoint.url,
        ),
    )
    .await
    .expect("bounded constructor");
    assert!(matches!(
        result,
        Err(PostgresFragmentTransportConfigError::RetryEnabled)
    ));
    assert_eq!(
        endpoint.finish().await,
        0,
        "retry rejection precedes even startup versioning HTTP"
    );
}

// Observe the real adapter's report without replacing its SDK or altering the count.
struct ObservedTransport {
    inner: PostgresFragmentS3Transport,
    reported: Arc<AtomicU32>,
}

impl FragmentTransportPort for ObservedTransport {
    fn issue<'a>(
        &'a self,
        request: FragmentTransportRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = FragmentTransportExchange> + Send + 'a>> {
        self.inner.issue(request)
    }
}

impl FragmentGetPort for ObservedTransport {
    fn issue_get<'a>(
        &'a self,
        request: FragmentGetRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = FragmentGetExchange> + Send + 'a>> {
        self.inner.issue_get(request)
    }
}

impl FragmentDirectPutPort for ObservedTransport {
    fn issue_direct_put<'a>(
        &'a self,
        request: FragmentDirectPutRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = FragmentTransportExchange> + Send + 'a>> {
        Box::pin(async move {
            let report = self.inner.issue_direct_put(request).await;
            self.reported
                .store(report.provider_requests_issued, Ordering::SeqCst);
            report
        })
    }
}

#[tokio::test]
#[ignore = "run with tests/run-fragment-retry-conformance-live.ps1"]
async fn real_sdk_hidden_retry_is_counted_and_closes_the_governed_ledger() {
    timeout(Duration::from_secs(60), hidden_retry_case())
        .await
        .expect("bounded retry conformance");
}

async fn hidden_retry_case() {
    let admin_url = std::env::var("LORE_TEST_RETRY_PG_URL").expect("owned runner admin URL");
    let runtime_url =
        std::env::var("LORE_TEST_RETRY_RUNTIME_URL").expect("owned runner runtime URL");
    let ca = std::fs::read_to_string(
        std::env::var("LORE_TEST_RETRY_CA_PATH").expect("owned runner CA path"),
    )
    .unwrap();
    let (admin, connection) = tokio_postgres::connect(&admin_url, tokio_postgres::NoTls)
        .await
        .expect("connect owned assertion database");
    let connection = AbortOnDropHandle::new(lore_base::lore_spawn!(async move {
        connection.await.expect("assertion connection")
    }));
    let row = admin.query_one("SELECT (SELECT system_identifier::text FROM pg_control_system()), (SELECT oid FROM pg_database WHERE datname=current_database())", &[]).await.unwrap();
    let identity = FragmentDatabaseIdentity::new(&row.get::<_, String>(0), row.get(1)).unwrap();
    let endpoint = FaultEndpoint::start().await;
    let reported = Arc::new(AtomicU32::new(0));
    // Deliberately bypass ONLY construction inside this private test descendant. Every
    // admission, charge, SDK send, connector count, and ledger decision stays production code.
    let transport = ObservedTransport {
        inner: PostgresFragmentS3Transport {
            client: retry_enabled_client(&endpoint.url).await,
            bucket: BUCKET.to_owned(),
            region: REGION.to_owned(),
            endpoint_host: HOST.to_owned(),
        },
        reported: Arc::clone(&reported),
    };
    let entry = FragmentProviderEntry::connect(
        FragmentDispatchRuntimeConfig {
            postgres_url: runtime_url,
            expected_database_identity: identity,
            process_pool_inventory: FragmentProcessPoolInventory {
                immutable_pool_max: 1,
                mutable_pool_max: 1,
                lock_pool_max: 1,
                domain_pool_max: 1,
                dispatch_pool_max: 1,
                relay_pool_max: 0,
            }
            .validate()
            .unwrap(),
            connect_timeout: TIMEOUT,
            acquire_timeout: TIMEOUT,
            statement_timeout: TIMEOUT,
            lock_timeout: Duration::from_secs(2),
            tls: FragmentDispatchTls::PinnedRootCa(ca),
        },
        CellProviderBoundary::new(BOUNDARY, BUCKET, REGION, HOST).unwrap(),
        ProviderCapabilities::none(),
        InFlightPutBound::new(1, TIMEOUT).unwrap(),
        InFlightChargeBound::new(1, TIMEOUT).unwrap(),
        transport,
    )
    .await
    .expect("activate real attested provider entry");
    let logical_uuid = uuid::Uuid::now_v7();
    let logical = logical_uuid.to_string();
    let mut ledger = FragmentAttemptLedger::new(BOUNDARY, &logical).unwrap();
    let deadline = i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
        + 60_000;
    let attempt = |ordinal| FragmentProviderAttempt {
        traffic_class: ProviderTrafficClass::Repair,
        attempt_class: ProviderAttemptClass::PutObject,
        logical_request_id: logical.clone(),
        attempt_id: uuid::Uuid::now_v7().to_string(),
        attempt_ordinal: ordinal,
        deadline_unix_ms: deadline,
        budget_pin: BudgetPin {
            revision: "retry-conformance-r1".to_owned(),
            fence: 1,
        },
        put_body: None,
    };
    let operation = || FragmentDirectPutOperation {
        object_key: "retry-proof".to_owned(),
        metadata: Vec::new(),
        declared_size: BODY.len() as u64,
        declared_blake3: *blake3::hash(BODY).as_bytes(),
    };
    let first = entry
        .admit_put(attempt(1), operation())
        .await
        .unwrap()
        .execute_direct_put(&mut ledger, BODY)
        .await
        .expect_err("hidden retry must fail closed");
    assert_eq!(
        format!("{:?}", ledger.poisoned().expect("ledger poisoned")),
        "TransportIssuedUnauthorizedRequests"
    );
    assert!(format!("{first:?}").contains("TransportIssuedUnauthorizedRequests"));
    assert_eq!(
        endpoint.received.load(Ordering::SeqCst),
        2,
        "independent endpoint sees retry"
    );
    assert_eq!(
        reported.load(Ordering::SeqCst),
        2,
        "below-SDK count sees both sends"
    );
    assert_eq!(ledger.committed_grant_count(), 1);
    assert_eq!(ledger.attempt_count(), 1, "only one attempt was authorized");
    let before = ledger.clone();
    let second = entry
        .admit_put(attempt(2), operation())
        .await
        .unwrap()
        .execute_direct_put(&mut ledger, BODY)
        .await
        .expect_err("closed ledger refuses reuse");
    assert_eq!(second, first, "reuse retains the original poison reason");
    assert_eq!(ledger, before, "reuse changes no ledger counters");
    let grants: i64 = admin.query_one("SELECT count(*) FROM object_store_retention.object_dispatch_provider_charge_grants WHERE logical_request_id=$1", &[&logical_uuid]).await.unwrap().get(0);
    assert_eq!(
        grants, 1,
        "real authority charged once despite SDK retry and refused reuse"
    );
    drop(entry);
    assert_eq!(
        endpoint.finish().await,
        2,
        "closed ledger sends no further HTTP"
    );
    drop(admin);
    timeout(TIMEOUT, connection).await.unwrap().unwrap();
}

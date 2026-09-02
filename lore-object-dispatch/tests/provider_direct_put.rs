// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Public contract for the bounded, synchronous `PutObject` path.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;

use lore_base::types::FRAGMENT_SIZE_THRESHOLD;
use lore_object_dispatch::AuthorizedProviderAttempt;
use lore_object_dispatch::BudgetPin;
use lore_object_dispatch::CellProviderBoundary;
use lore_object_dispatch::GovernedProviderClient;
use lore_object_dispatch::ProviderAttemptClass;
use lore_object_dispatch::ProviderAttemptLedger;
use lore_object_dispatch::ProviderAttemptOutcome;
use lore_object_dispatch::ProviderAttemptReport;
use lore_object_dispatch::ProviderCapabilities;
use lore_object_dispatch::ProviderChargeAuthority;
use lore_object_dispatch::ProviderChargeError;
use lore_object_dispatch::ProviderChargeGrant;
use lore_object_dispatch::ProviderChargeRequest;
use lore_object_dispatch::ProviderClientError;
use lore_object_dispatch::ProviderDirectPutAttemptRequest;
use lore_object_dispatch::ProviderRetryPolicy;
use lore_object_dispatch::ProviderTarget;
use lore_object_dispatch::ProviderTrafficClass;
use lore_object_dispatch::ProviderTransport;
use lore_object_dispatch::ProviderTransportRefusal;

const BOUNDARY_ID: &str = "cell.nyc3.primary";
const LOGICAL_REQUEST_ID: &str = "018f3e12-a456-7abc-8def-000000000001";
const ATTEMPT_ID: &str = "018f3e12-a456-7abc-8def-000000000002";
const GRANT_ID: &str = "018f3e12-a456-7abc-8def-000000000003";
const REQUEST_TIMESTAMP_MS: u64 = 0x018f_3e12_a456;
const DEADLINE_UNIX_MS: i64 = REQUEST_TIMESTAMP_MS as i64 + 60_000;
const RESPONSE: &str = "put-created";
const CLIENT_SOURCE: &str = include_str!("../src/provider_client.rs");

#[derive(Clone, Copy)]
struct DirectPutOperation;

#[derive(Clone, Copy)]
enum ChargeMode {
    Grant,
    Refuse(ProviderChargeError),
    Pending,
}

struct ChargeAuthority {
    mode: ChargeMode,
    calls: Arc<AtomicU32>,
    observed_class: Arc<Mutex<Option<ProviderAttemptClass>>>,
}

impl ProviderChargeAuthority for ChargeAuthority {
    async fn charge(
        &self,
        request: &ProviderChargeRequest,
    ) -> Result<ProviderChargeGrant, ProviderChargeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        *self.observed_class.lock().expect("charge observation lock") =
            Some(request.attempt_class());
        match self.mode {
            ChargeMode::Grant => Ok(binding_grant(request)),
            ChargeMode::Refuse(error) => Err(error),
            ChargeMode::Pending => std::future::pending().await,
        }
    }
}

#[derive(Clone, Copy)]
enum TransportMode {
    Report(u32),
    Refuse,
    Pending,
}

struct Transport {
    mode: TransportMode,
    calls: Arc<AtomicU32>,
    observed_body: Arc<Mutex<Option<Vec<u8>>>>,
}

impl ProviderTransport for Transport {
    type Operation = DirectPutOperation;
    type Response = &'static str;

    fn issue<'a>(
        &'a self,
        attempt: &'a AuthorizedProviderAttempt<'a>,
        _operation: &'a Self::Operation,
    ) -> impl Future<
        Output = Result<ProviderAttemptReport<Self::Response>, ProviderTransportRefusal>,
    > + Send
    + 'a {
        self.calls.fetch_add(1, Ordering::SeqCst);
        assert_eq!(attempt.attempt_class(), ProviderAttemptClass::PutObject);
        assert_eq!(
            attempt.put_body(),
            None,
            "direct PUT is not a durable spool body"
        );
        assert_eq!(
            attempt.put_part(),
            None,
            "bounded direct PUT is never multipart"
        );
        let body = attempt
            .direct_put_body()
            .expect("direct PUT transport must receive validated bytes");
        assert_eq!(attempt.direct_put_size(), Some(body.len() as u64));
        assert_eq!(
            attempt.direct_put_blake3(),
            Some(blake3::hash(body).as_bytes())
        );
        *self.observed_body.lock().expect("body observation lock") = Some(body.to_vec());

        match self.mode {
            TransportMode::Report(provider_requests_issued) => {
                TransportFuture::Ready(Some(Ok(ProviderAttemptReport {
                    outcome: ProviderAttemptOutcome::Decisive,
                    provider_requests_issued,
                    response: RESPONSE,
                })))
            }
            TransportMode::Refuse => {
                TransportFuture::Ready(Some(Err(ProviderTransportRefusal::Unwired)))
            }
            TransportMode::Pending => TransportFuture::Pending,
        }
    }
}

enum TransportFuture {
    Ready(Option<Result<ProviderAttemptReport<&'static str>, ProviderTransportRefusal>>),
    Pending,
}

impl Future for TransportFuture {
    type Output = Result<ProviderAttemptReport<&'static str>, ProviderTransportRefusal>;

    fn poll(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        match &mut *self {
            Self::Ready(result) => Poll::Ready(result.take().expect("ready future polled once")),
            Self::Pending => Poll::Pending,
        }
    }
}

struct Harness {
    client: GovernedProviderClient<ChargeAuthority, Transport>,
    charge_calls: Arc<AtomicU32>,
    transport_calls: Arc<AtomicU32>,
    observed_class: Arc<Mutex<Option<ProviderAttemptClass>>>,
    observed_body: Arc<Mutex<Option<Vec<u8>>>>,
}

impl Harness {
    fn new(charge_mode: ChargeMode, transport_mode: TransportMode) -> Self {
        let charge_calls = Arc::new(AtomicU32::new(0));
        let transport_calls = Arc::new(AtomicU32::new(0));
        let observed_class = Arc::new(Mutex::new(None));
        let observed_body = Arc::new(Mutex::new(None));
        let authority = ChargeAuthority {
            mode: charge_mode,
            calls: Arc::clone(&charge_calls),
            observed_class: Arc::clone(&observed_class),
        };
        let transport = Transport {
            mode: transport_mode,
            calls: Arc::clone(&transport_calls),
            observed_body: Arc::clone(&observed_body),
        };
        Self {
            client: GovernedProviderClient::new(
                boundary(),
                ProviderCapabilities::none(),
                ProviderRetryPolicy::disabled(),
                authority,
                transport,
            ),
            charge_calls,
            transport_calls,
            observed_class,
            observed_body,
        }
    }
}

#[test]
fn direct_put_request_surface_has_only_identity_budget_target_and_declared_binding() {
    let start = CLIENT_SOURCE
        .find("pub struct ProviderDirectPutAttemptRequest {")
        .expect("direct PUT request declaration");
    let tail = &CLIENT_SOURCE[start..];
    let end = tail.find("\n}").expect("direct PUT request closing brace");
    let fields: Vec<_> = tail[..end]
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix("pub "))
        .filter_map(|line| line.split_once(':').map(|(name, _)| name))
        .collect();
    assert_eq!(
        fields,
        [
            "traffic_class",
            "target",
            "logical_request_id",
            "attempt_id",
            "attempt_ordinal",
            "deadline_unix_ms",
            "budget_pin",
            "declared_size",
            "declared_blake3",
        ],
        "direct PUT must not gain durable handles, part ranges, or an arbitrary body source"
    );
    assert!(
        !CLIENT_SOURCE.contains("impl ProviderDirectPutAttemptRequest {"),
        "the public direct request must not gain accessors for a durable handle, part range, or arbitrary body source"
    );
}

#[tokio::test]
async fn direct_put_body_bounds_are_exact_and_checked_before_charge() {
    for (size, expected) in [
        (0, Err(ProviderClientError::DirectPutBodyOutOfBounds)),
        (1, Ok(())),
        (FRAGMENT_SIZE_THRESHOLD, Ok(())),
        (
            FRAGMENT_SIZE_THRESHOLD + 1,
            Err(ProviderClientError::DirectPutBodyOutOfBounds),
        ),
    ] {
        let body = vec![0xa5; size];
        let harness = Harness::new(ChargeMode::Grant, TransportMode::Report(1));
        let mut ledger = ledger();
        let result = harness
            .client
            .execute_direct_put(&mut ledger, &request(&body), &body, &DirectPutOperation)
            .await
            .map(|_| ());
        assert_eq!(result, expected, "body size {size}");
        let expected_calls = u32::from(expected.is_ok());
        assert_eq!(
            harness.charge_calls.load(Ordering::SeqCst),
            expected_calls,
            "body size {size}"
        );
        assert_eq!(
            harness.transport_calls.load(Ordering::SeqCst),
            expected_calls,
            "body size {size}"
        );
    }
}

#[tokio::test]
async fn direct_put_size_and_blake3_mismatches_are_refused_before_charge() {
    let body = b"nontrivial-fragment-body";
    let canonical = request(body);
    let mut wrong_size = canonical.clone();
    wrong_size.declared_size += 1;
    let mut wrong_blake3 = canonical.clone();
    wrong_blake3.declared_blake3[0] ^= 0x80;

    for (label, candidate) in [("size", wrong_size), ("blake3", wrong_blake3)] {
        let harness = Harness::new(ChargeMode::Grant, TransportMode::Report(1));
        let mut ledger = ledger();
        assert_eq!(
            harness
                .client
                .execute_direct_put(&mut ledger, &candidate, body, &DirectPutOperation)
                .await,
            Err(ProviderClientError::DirectPutBodyBindingMismatch),
            "mismatched {label}"
        );
        assert_eq!(harness.charge_calls.load(Ordering::SeqCst), 0, "{label}");
        assert_eq!(harness.transport_calls.load(Ordering::SeqCst), 0, "{label}");
    }
}

#[tokio::test]
async fn direct_put_is_fixed_to_put_object_and_binds_the_actual_bytes() {
    let body = b"actual-bytes-not-a-self-comparison";
    let harness = Harness::new(ChargeMode::Grant, TransportMode::Report(1));
    let mut ledger = ledger();
    let execution = harness
        .client
        .execute_direct_put(&mut ledger, &request(body), body, &DirectPutOperation)
        .await
        .expect("valid direct PUT");

    assert_eq!(execution.response, RESPONSE);
    assert_eq!(
        *harness.observed_class.lock().expect("class lock"),
        Some(ProviderAttemptClass::PutObject)
    );
    assert_eq!(
        harness.observed_body.lock().expect("body lock").as_deref(),
        Some(body.as_slice())
    );
    assert_eq!(harness.charge_calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.transport_calls.load(Ordering::SeqCst), 1);
    assert_eq!(ledger.committed_grant_count(), 1);
    assert_eq!(ledger.attempt_count(), 1);
    assert_eq!(ledger.decisive_terminal_count(), 1);
}

#[tokio::test]
async fn refused_direct_put_charge_reaches_no_transport() {
    let body = b"refused-body";
    let harness = Harness::new(
        ChargeMode::Refuse(ProviderChargeError::BudgetExhausted),
        TransportMode::Report(1),
    );
    let mut ledger = ledger();
    assert_eq!(
        harness
            .client
            .execute_direct_put(&mut ledger, &request(body), body, &DirectPutOperation)
            .await,
        Err(ProviderClientError::ChargeRefused(
            ProviderChargeError::BudgetExhausted
        ))
    );
    assert_eq!(harness.charge_calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.transport_calls.load(Ordering::SeqCst), 0);
    assert_eq!(ledger.committed_grant_count(), 0);
    assert_eq!(ledger.attempt_count(), 0);
}

#[tokio::test]
async fn direct_put_transport_refusal_records_no_wire_attempt() {
    let body = b"transport-refusal";
    let harness = Harness::new(ChargeMode::Grant, TransportMode::Refuse);
    let mut ledger = ledger();
    assert_eq!(
        harness
            .client
            .execute_direct_put(&mut ledger, &request(body), body, &DirectPutOperation)
            .await,
        Err(ProviderClientError::TransportRefused(
            ProviderTransportRefusal::Unwired
        ))
    );
    assert_eq!(harness.charge_calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.transport_calls.load(Ordering::SeqCst), 1);
    assert_eq!(ledger.committed_grant_count(), 1);
    assert_eq!(ledger.attempt_count(), 0);
    assert_eq!(ledger.ambiguous_count(), 0);
}

#[tokio::test]
async fn direct_put_suppresses_responses_unless_exactly_one_request_was_issued() {
    for (reported, expected) in [
        (0, Err(ProviderClientError::TransportReportInconsistent)),
        (1, Ok(RESPONSE)),
        (
            2,
            Err(ProviderClientError::TransportIssuedUnauthorizedRequests),
        ),
    ] {
        let body = b"response-binding";
        let harness = Harness::new(ChargeMode::Grant, TransportMode::Report(reported));
        let mut ledger = ledger();
        let result = harness
            .client
            .execute_direct_put(&mut ledger, &request(body), body, &DirectPutOperation)
            .await
            .map(|execution| execution.response);
        assert_eq!(result, expected, "reported requests {reported}");
        assert_eq!(harness.charge_calls.load(Ordering::SeqCst), 1);
        assert_eq!(harness.transport_calls.load(Ordering::SeqCst), 1);
    }
}

#[tokio::test]
async fn cancelling_direct_put_during_charge_records_one_conservative_grant() {
    let body = b"pending-charge";
    let harness = Harness::new(ChargeMode::Pending, TransportMode::Report(1));
    let request = request(body);
    let mut ledger = ledger();
    let mut execution = Box::pin(harness.client.execute_direct_put(
        &mut ledger,
        &request,
        body,
        &DirectPutOperation,
    ));
    tokio::select! {
        biased;
        result = &mut execution => panic!("pending charge resolved: {result:?}"),
        _ = tokio::time::sleep(std::time::Duration::ZERO) => {}
    }
    drop(execution);

    assert_eq!(harness.charge_calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.transport_calls.load(Ordering::SeqCst), 0);
    assert_eq!(ledger.committed_grant_count(), 1);
    assert_eq!(ledger.attempt_count(), 0);
    assert_eq!(ledger.ambiguous_count(), 0);
}

#[tokio::test]
async fn cancelling_direct_put_during_transport_records_one_ambiguous_attempt() {
    let body = b"pending-transport";
    let harness = Harness::new(ChargeMode::Grant, TransportMode::Pending);
    let request = request(body);
    let mut ledger = ledger();
    let mut execution = Box::pin(harness.client.execute_direct_put(
        &mut ledger,
        &request,
        body,
        &DirectPutOperation,
    ));
    tokio::select! {
        biased;
        result = &mut execution => panic!("pending transport resolved: {result:?}"),
        _ = tokio::time::sleep(std::time::Duration::ZERO) => {}
    }
    drop(execution);

    assert_eq!(harness.charge_calls.load(Ordering::SeqCst), 1);
    assert_eq!(harness.transport_calls.load(Ordering::SeqCst), 1);
    assert_eq!(ledger.committed_grant_count(), 1);
    assert_eq!(ledger.attempt_count(), 1);
    assert_eq!(ledger.ambiguous_count(), 1);
    assert_eq!(ledger.decisive_terminal_count(), 0);
}

fn boundary() -> CellProviderBoundary {
    CellProviderBoundary::new(
        BOUNDARY_ID,
        "commit0-cell-nyc3",
        "nyc3",
        "nyc3.digitaloceanspaces.com",
    )
    .expect("valid provider boundary")
}

fn target() -> ProviderTarget {
    boundary().target().clone()
}

fn request(body: &[u8]) -> ProviderDirectPutAttemptRequest {
    ProviderDirectPutAttemptRequest {
        traffic_class: ProviderTrafficClass::DirectFallback,
        target: target(),
        logical_request_id: LOGICAL_REQUEST_ID.to_string(),
        attempt_id: ATTEMPT_ID.to_string(),
        attempt_ordinal: 1,
        deadline_unix_ms: DEADLINE_UNIX_MS,
        budget_pin: BudgetPin {
            revision: "wp121.envelope.rev.7".to_string(),
            fence: 42,
        },
        declared_size: body.len() as u64,
        declared_blake3: *blake3::hash(body).as_bytes(),
    }
}

fn ledger() -> ProviderAttemptLedger {
    ProviderAttemptLedger::new(BOUNDARY_ID, LOGICAL_REQUEST_ID).expect("valid bound ledger")
}

fn binding_grant(request: &ProviderChargeRequest) -> ProviderChargeGrant {
    ProviderChargeGrant {
        grant_id: GRANT_ID.to_string(),
        traffic_class: request.traffic_class(),
        attempt_class: request.attempt_class(),
        charged_units: request.attempt_units(),
        budget_pin: request.budget_pin().clone(),
        logical_request_id: request.logical_request_id().to_string(),
        attempt_id: request.attempt_id().to_string(),
        attempt_ordinal: request.attempt_ordinal(),
        granted_at_database_unix_ms: REQUEST_TIMESTAMP_MS as i64 + 1,
    }
}

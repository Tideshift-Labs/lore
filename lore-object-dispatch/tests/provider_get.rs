// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Public contract for the one unmetered provider operation, GetObject.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::task::Context;
use std::task::Poll;

use lore_object_dispatch::AuthorizedProviderAttempt;
use lore_object_dispatch::AuthorizedProviderGet;
use lore_object_dispatch::BudgetPin;
use lore_object_dispatch::CellProviderBoundary;
use lore_object_dispatch::GovernedProviderClient;
use lore_object_dispatch::MeteredProviderAttemptRequest;
use lore_object_dispatch::ProviderAttemptClass;
use lore_object_dispatch::ProviderAttemptOutcome;
use lore_object_dispatch::ProviderAttemptReport;
use lore_object_dispatch::ProviderAttemptRequest;
use lore_object_dispatch::ProviderCapabilities;
use lore_object_dispatch::ProviderChargeAuthority;
use lore_object_dispatch::ProviderChargeError;
use lore_object_dispatch::ProviderChargeGrant;
use lore_object_dispatch::ProviderChargeRequest;
use lore_object_dispatch::ProviderClientError;
use lore_object_dispatch::ProviderGetAttemptRequest;
use lore_object_dispatch::ProviderGetTransport;
use lore_object_dispatch::ProviderRetryPolicy;
use lore_object_dispatch::ProviderTarget;
use lore_object_dispatch::ProviderTrafficClass;
use lore_object_dispatch::ProviderTransport;
use lore_object_dispatch::ProviderTransportRefusal;

const LOGICAL_REQUEST_ID: &str = "018f3e12-a456-7abc-8def-000000000001";
const ATTEMPT_ID: &str = "018f3e12-a456-7abc-8def-000000000002";
const CLIENT_SOURCE: &str = include_str!("../src/provider_client.rs");

struct NotAChargeAuthority;

impl ProviderChargeAuthority for NotAChargeAuthority {
    async fn charge(
        &self,
        _request: &ProviderChargeRequest,
    ) -> Result<ProviderChargeGrant, ProviderChargeError> {
        panic!("GetObject must not call the database charge authority")
    }
}

#[derive(Clone, Copy)]
struct GetOperation {
    object_key: &'static str,
}

#[derive(Clone, Copy)]
struct ReportingGetTransport {
    requests: u32,
    outcome: ProviderAttemptOutcome,
    response: &'static str,
}

impl ProviderGetTransport for ReportingGetTransport {
    type Operation = GetOperation;
    type Response = &'static str;

    async fn issue_get<'a>(
        &'a self,
        attempt: &'a AuthorizedProviderGet<'a>,
        operation: &'a Self::Operation,
    ) -> Result<ProviderAttemptReport<Self::Response>, ProviderTransportRefusal> {
        assert_eq!(attempt.target(), &target());
        assert_eq!(attempt.logical_request_id(), LOGICAL_REQUEST_ID);
        assert_eq!(attempt.attempt_id(), ATTEMPT_ID);
        assert_eq!(attempt.attempt_ordinal(), 1);
        assert_eq!(attempt.retry_policy().max_attempts(), 1);
        assert_eq!(operation.object_key, "objects/fragment");
        Ok(ProviderAttemptReport {
            outcome: self.outcome,
            provider_requests_issued: self.requests,
            response: self.response,
        })
    }
}

impl ProviderTransport for ReportingGetTransport {
    type Operation = GetOperation;
    type Response = &'static str;

    async fn issue<'a>(
        &'a self,
        _attempt: &'a AuthorizedProviderAttempt<'a>,
        _operation: &'a Self::Operation,
    ) -> Result<ProviderAttemptReport<Self::Response>, ProviderTransportRefusal> {
        panic!("GetObject must not enter the metered transport path")
    }
}

#[test]
fn the_closed_attempt_inventory_has_one_get_and_ten_metered_classes() {
    assert_eq!(ProviderAttemptClass::ALL.len(), 11);
    let get_count = ProviderAttemptClass::ALL
        .into_iter()
        .filter(|class| *class == ProviderAttemptClass::GetObject)
        .count();
    assert_eq!(get_count, 1);

    let mut metered = 0;
    for class in ProviderAttemptClass::ALL {
        let result = MeteredProviderAttemptRequest::try_from(raw_request(class));
        if class == ProviderAttemptClass::GetObject {
            assert_eq!(
                result,
                Err(ProviderClientError::GetObjectRequiresReadOnlyPath)
            );
        } else {
            assert!(result.is_ok(), "{class:?} must remain metered");
            metered += 1;
        }
    }
    assert_eq!(metered, 10);
}

#[test]
fn get_request_and_entrypoint_cannot_name_a_ledger_pin_deadline_or_other_operation() {
    let request = section(
        CLIENT_SOURCE,
        "pub struct ProviderGetAttemptRequest {",
        "\n}\n\nimpl fmt::Debug for ProviderGetAttemptRequest",
    );
    let fields: Vec<_> = request
        .lines()
        .map(str::trim)
        .filter_map(|line| line.strip_prefix("pub "))
        .filter_map(|line| line.split_once(':').map(|(name, _)| name))
        .collect();
    assert_eq!(
        fields,
        [
            "target",
            "logical_request_id",
            "attempt_id",
            "attempt_ordinal"
        ]
    );

    let get = section(
        CLIENT_SOURCE,
        "pub async fn execute_get(",
        "\n    }\n}\n\nimpl<C, T> fmt::Debug",
    );
    for forbidden in [
        "ProviderAttemptLedger",
        "MeteredProviderAttemptRequest",
        "ProviderChargeAuthority",
        "charge_authority",
        "budget_pin",
        "deadline",
        "attempt_class",
        "traffic_class",
    ] {
        assert!(
            !get.contains(forbidden),
            "execute_get must not name {forbidden:?}"
        );
    }

    let authorized = section(
        CLIENT_SOURCE,
        "pub struct AuthorizedProviderGet<'a> {",
        "\n}\n\nimpl fmt::Debug for AuthorizedProviderGet",
    );
    for forbidden in [
        "attempt_class",
        "traffic_class",
        "grant",
        "put_body",
        "budget_pin",
    ] {
        assert!(
            !authorized.contains(forbidden),
            "the GET-only token must not expose {forbidden:?}"
        );
    }
}

#[tokio::test]
async fn get_executes_without_a_charge_authority_ledger_pin_or_deadline() {
    let client = get_client(ReportingGetTransport {
        requests: 1,
        outcome: ProviderAttemptOutcome::Decisive,
        response: "body-response",
    });

    let execution = client
        .execute_get(
            &get_request(),
            &GetOperation {
                object_key: "objects/fragment",
            },
        )
        .await
        .expect("one GET request must execute without a database authority");

    assert_eq!(execution.outcome, ProviderAttemptOutcome::Decisive);
    assert_eq!(execution.response, "body-response");
}

#[tokio::test]
async fn get_suppresses_responses_unless_exactly_one_request_was_issued() {
    for (requests, expected) in [
        (0, Err(ProviderClientError::TransportReportInconsistent)),
        (1, Ok("visible-only-for-one")),
        (
            2,
            Err(ProviderClientError::TransportIssuedUnauthorizedRequests),
        ),
    ] {
        let client = get_client(ReportingGetTransport {
            requests,
            outcome: ProviderAttemptOutcome::Decisive,
            response: "visible-only-for-one",
        });
        let result = client
            .execute_get(
                &get_request(),
                &GetOperation {
                    object_key: "objects/fragment",
                },
            )
            .await
            .map(|execution| execution.response);
        assert_eq!(result, expected, "reported request count: {requests}");
    }
}

#[tokio::test]
async fn cancelling_a_pending_get_drops_the_transport_future_without_other_accounting() {
    let dropped = Arc::new(AtomicBool::new(false));
    let client = get_client(PendingGetTransport {
        dropped: Arc::clone(&dropped),
    });
    let request = get_request();
    let operation = GetOperation {
        object_key: "objects/fragment",
    };
    let mut execution = Box::pin(client.execute_get(&request, &operation));

    tokio::select! {
        biased;
        result = &mut execution => panic!("pending GET unexpectedly resolved: {result:?}"),
        _ = tokio::time::sleep(std::time::Duration::ZERO) => {}
    }
    drop(execution);

    assert!(dropped.load(Ordering::SeqCst));
}

struct PendingGetTransport {
    dropped: Arc<AtomicBool>,
}

impl ProviderGetTransport for PendingGetTransport {
    type Operation = GetOperation;
    type Response = &'static str;

    fn issue_get<'a>(
        &'a self,
        _attempt: &'a AuthorizedProviderGet<'a>,
        _operation: &'a Self::Operation,
    ) -> impl Future<
        Output = Result<ProviderAttemptReport<Self::Response>, ProviderTransportRefusal>,
    > + Send
    + 'a {
        PendingGetFuture {
            dropped: Arc::clone(&self.dropped),
        }
    }
}

impl ProviderTransport for PendingGetTransport {
    type Operation = GetOperation;
    type Response = &'static str;

    async fn issue<'a>(
        &'a self,
        _attempt: &'a AuthorizedProviderAttempt<'a>,
        _operation: &'a Self::Operation,
    ) -> Result<ProviderAttemptReport<Self::Response>, ProviderTransportRefusal> {
        panic!("GetObject must not enter the metered transport path")
    }
}

struct PendingGetFuture {
    dropped: Arc<AtomicBool>,
}

impl Future for PendingGetFuture {
    type Output = Result<ProviderAttemptReport<&'static str>, ProviderTransportRefusal>;

    fn poll(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}

impl Drop for PendingGetFuture {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

fn get_client<T>(transport: T) -> GovernedProviderClient<NotAChargeAuthority, T>
where
    T: ProviderTransport + ProviderGetTransport,
{
    GovernedProviderClient::new(
        boundary(),
        ProviderCapabilities::none(),
        ProviderRetryPolicy::disabled(),
        NotAChargeAuthority,
        transport,
    )
}

fn boundary() -> CellProviderBoundary {
    CellProviderBoundary::new(
        "cell.nyc3.primary",
        "commit0-cell-nyc3",
        "nyc3",
        "nyc3.digitaloceanspaces.com",
    )
    .expect("valid cell boundary")
}

fn target() -> ProviderTarget {
    boundary().target().clone()
}

fn get_request() -> ProviderGetAttemptRequest {
    ProviderGetAttemptRequest {
        target: target(),
        logical_request_id: LOGICAL_REQUEST_ID.to_string(),
        attempt_id: ATTEMPT_ID.to_string(),
        attempt_ordinal: 1,
    }
}

fn raw_request(attempt_class: ProviderAttemptClass) -> ProviderAttemptRequest {
    ProviderAttemptRequest {
        traffic_class: ProviderTrafficClass::Read,
        attempt_class,
        target: target(),
        logical_request_id: LOGICAL_REQUEST_ID.to_string(),
        attempt_id: ATTEMPT_ID.to_string(),
        attempt_ordinal: 1,
        deadline_unix_ms: 1_715_000_000_000,
        budget_pin: BudgetPin {
            revision: "budget-v1".to_string(),
            fence: 1,
        },
        put_body: None,
        put_part: None,
    }
}

fn section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let from = source
        .find(start)
        .unwrap_or_else(|| panic!("missing source marker {start:?}"));
    let rest = &source[from..];
    let until = rest
        .find(end)
        .unwrap_or_else(|| panic!("missing source end {end:?}"));
    &rest[..until]
}

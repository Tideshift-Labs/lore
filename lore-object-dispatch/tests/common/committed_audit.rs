// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

// This module is `#[path]`-included into several independent test binaries
// (compaction.rs, compact_prune.rs, full_to_compact.rs, retention_fixture.rs), each of which uses
// only a subset of its functions. `dead_code` is evaluated per binary, so every function is
// legitimately unused in at least one consumer; allow it here rather than in each consumer.
#![allow(dead_code)]

//! Shared fixture: a real `BoundProviderAttemptAudit` (WP-114 CD-8), driven through
//! `ProviderAttemptLedger`'s own recording API via one `GovernedProviderClient::execute` call
//! against in-process doubles, rather than fabricated as an `ObjectStoreProviderAttemptAudit`
//! struct literal. The doubles always grant and always report a single decisive commit, so the
//! resulting audit has `attempt_count = 1`, `committed_grant_count = 1`,
//! `decisive_terminal_count = 1`, `no_dispatch_count = 0`, `ambiguous_count = 0` -- the exact
//! shape the compaction fixtures' prior `terminal_audit()`-style literals asserted.

use lore_object_dispatch::AuthorizedProviderAttempt;
use lore_object_dispatch::BoundProviderAttemptAudit;
use lore_object_dispatch::BudgetPin;
use lore_object_dispatch::CanonicalNoDispatchProof;
use lore_object_dispatch::CellProviderBoundary;
use lore_object_dispatch::GovernedProviderClient;
use lore_object_dispatch::MeteredProviderAttemptRequest;
use lore_object_dispatch::ProviderAttemptClass;
use lore_object_dispatch::ProviderAttemptLedger;
use lore_object_dispatch::ProviderAttemptOutcome;
use lore_object_dispatch::ProviderAttemptReport;
use lore_object_dispatch::ProviderAttemptRequest;
use lore_object_dispatch::ProviderCapabilities;
use lore_object_dispatch::ProviderChargeAuthority;
use lore_object_dispatch::ProviderChargeError;
use lore_object_dispatch::ProviderChargeGrant;
use lore_object_dispatch::ProviderChargeRequest;
use lore_object_dispatch::ProviderRetryPolicy;
use lore_object_dispatch::ProviderTrafficClass;
use lore_object_dispatch::ProviderTransport;
use lore_object_dispatch::ProviderTransportRefusal;

const BUCKET: &str = "commit0-cell-fixture";
const REGION: &str = "nyc3";
const ENDPOINT_HOST: &str = "nyc3.digitaloceanspaces.com";
const GRANT_ID: &str = "018f3e12-a457-7abc-8def-0123456789ab";

struct FixedDecisiveTransport;

impl ProviderTransport for FixedDecisiveTransport {
    type Operation = ();
    type Response = ();

    async fn issue<'a>(
        &'a self,
        _attempt: &'a AuthorizedProviderAttempt<'a>,
        _operation: &'a Self::Operation,
    ) -> Result<ProviderAttemptReport<()>, ProviderTransportRefusal> {
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Decisive,
            provider_requests_issued: 1,
            response: (),
        })
    }
}

struct FixedAmbiguousTransport;

impl ProviderTransport for FixedAmbiguousTransport {
    type Operation = ();
    type Response = ();

    async fn issue<'a>(
        &'a self,
        _attempt: &'a AuthorizedProviderAttempt<'a>,
        _operation: &'a Self::Operation,
    ) -> Result<ProviderAttemptReport<()>, ProviderTransportRefusal> {
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Ambiguous,
            provider_requests_issued: 1,
            response: (),
        })
    }
}

struct BindingChargeAuthority;

impl ProviderChargeAuthority for BindingChargeAuthority {
    async fn charge(
        &self,
        request: &ProviderChargeRequest,
    ) -> Result<ProviderChargeGrant, ProviderChargeError> {
        Ok(ProviderChargeGrant {
            grant_id: GRANT_ID.to_string(),
            traffic_class: request.traffic_class(),
            attempt_class: request.attempt_class(),
            charged_units: request.attempt_units(),
            budget_pin: request.budget_pin().clone(),
            logical_request_id: request.logical_request_id().to_string(),
            attempt_id: request.attempt_id().to_string(),
            attempt_ordinal: request.attempt_ordinal(),
            granted_at_database_unix_ms: request.attempt_units() as i64 + 1,
        })
    }
}

/// Drive one real attempt through `transport` and the recording API, on a ledger the caller
/// already owns (so a caller can chain more than one attempt onto one ledger, matching a real
/// retry sequence). `now_unix_ms` only bounds the request's deadline; callers pass their own
/// fixture clock so the attempt's deadline is comfortably in the future of whatever
/// admission/closure timestamps the caller's own fixtures use.
async fn execute_one_attempt<T>(
    ledger: &mut ProviderAttemptLedger,
    transport: T,
    provider_boundary_id: &str,
    logical_request_id: &str,
    attempt_id: &str,
    attempt_ordinal: u32,
    now_unix_ms: i64,
) where
    T: ProviderTransport<Operation = (), Response = ()>,
{
    let boundary = CellProviderBoundary::new(provider_boundary_id, BUCKET, REGION, ENDPOINT_HOST)
        .expect("valid boundary configuration for the committed-audit fixture");
    let client = GovernedProviderClient::new(
        boundary.clone(),
        ProviderCapabilities::none(),
        ProviderRetryPolicy::disabled(),
        BindingChargeAuthority,
        transport,
    );
    let request = ProviderAttemptRequest {
        traffic_class: ProviderTrafficClass::Drain,
        attempt_class: ProviderAttemptClass::Readiness,
        target: boundary.target().clone(),
        logical_request_id: logical_request_id.to_string(),
        attempt_id: attempt_id.to_string(),
        attempt_ordinal,
        deadline_unix_ms: now_unix_ms + 60_000,
        budget_pin: BudgetPin {
            revision: "committed-audit-fixture-rev".to_string(),
            fence: 1,
        },
        put_body: None,
        put_part: None,
    };
    let metered = MeteredProviderAttemptRequest::try_from(request)
        .expect("readiness attempt request must meter for the committed-audit fixture");
    client
        .execute(ledger, &metered, &())
        .await
        .expect("scripted attempt must succeed in the committed-audit fixture");
}

/// Drive one real attempt through `transport` on a fresh ledger and return the resulting bound
/// audit for `logical_request_id`.
async fn run_one_attempt<T>(
    transport: T,
    provider_boundary_id: &str,
    logical_request_id: &str,
    attempt_id: &str,
    now_unix_ms: i64,
) -> BoundProviderAttemptAudit
where
    T: ProviderTransport<Operation = (), Response = ()>,
{
    let mut ledger = ProviderAttemptLedger::new(provider_boundary_id, logical_request_id)
        .expect("valid boundary/request identity for the committed-audit fixture");
    execute_one_attempt(
        &mut ledger,
        transport,
        provider_boundary_id,
        logical_request_id,
        attempt_id,
        1,
        now_unix_ms,
    )
    .await;
    ledger
        .audit_for(logical_request_id)
        .expect("freshly recorded ledger must yield a valid bound audit")
}

/// A real audit with `attempt_count = 1`, `committed_grant_count = 1`, `decisive_terminal_count =
/// 1`, `no_dispatch_count = 0`, `ambiguous_count = 0` -- the exact shape the compaction fixtures'
/// prior `terminal_audit()` literal asserted, now produced by one real decisive commit instead.
pub async fn committed_decisive_audit(
    provider_boundary_id: &str,
    logical_request_id: &str,
    attempt_id: &str,
    now_unix_ms: i64,
) -> BoundProviderAttemptAudit {
    run_one_attempt(
        FixedDecisiveTransport,
        provider_boundary_id,
        logical_request_id,
        attempt_id,
        now_unix_ms,
    )
    .await
}

/// A real audit with `attempt_count = 1`, `committed_grant_count = 1`, `ambiguous_count = 1`,
/// `decisive_terminal_count = 0`, `no_dispatch_count = 0`: the transport reported no definite
/// response, so the charge stands but no decisive terminal was ever counted.
pub async fn committed_ambiguous_audit(
    provider_boundary_id: &str,
    logical_request_id: &str,
    attempt_id: &str,
    now_unix_ms: i64,
) -> BoundProviderAttemptAudit {
    run_one_attempt(
        FixedAmbiguousTransport,
        provider_boundary_id,
        logical_request_id,
        attempt_id,
        now_unix_ms,
    )
    .await
}

/// A real audit with `attempt_count = 2`, `committed_grant_count = 2`, `decisive_terminal_count =
/// 1`, `ambiguous_count = 1`, `no_dispatch_count = 0`: one ambiguous attempt followed by one
/// decisive attempt on the SAME ledger, matching a real retry sequence where an earlier delivery
/// attempt's outcome was never observed and a later one resolved decisively. This is the only real
/// way to reach `decisive_terminal_count >= 1` and `ambiguous_count >= 1` simultaneously -- neither
/// [`committed_decisive_audit`] nor [`committed_ambiguous_audit`] alone can, since one real
/// attempt's outcome is exclusively `Decisive` xor `Ambiguous` (see
/// `lore_object_dispatch::ProviderAttemptOutcome`), and the compaction encoder's
/// `audit_matches_authority` requires exactly this pairing for a terminal state whose
/// `dispatch_attempt.ambiguity_recorded_at_unix_ms` is also set.
pub async fn committed_ambiguous_then_decisive_audit(
    provider_boundary_id: &str,
    logical_request_id: &str,
    first_attempt_id: &str,
    second_attempt_id: &str,
    now_unix_ms: i64,
) -> BoundProviderAttemptAudit {
    let mut ledger = ProviderAttemptLedger::new(provider_boundary_id, logical_request_id)
        .expect("valid boundary/request identity for the committed-audit fixture");
    execute_one_attempt(
        &mut ledger,
        FixedAmbiguousTransport,
        provider_boundary_id,
        logical_request_id,
        first_attempt_id,
        1,
        now_unix_ms,
    )
    .await;
    execute_one_attempt(
        &mut ledger,
        FixedDecisiveTransport,
        provider_boundary_id,
        logical_request_id,
        second_attempt_id,
        2,
        now_unix_ms,
    )
    .await;
    ledger
        .audit_for(logical_request_id)
        .expect("freshly recorded ledger must yield a valid bound audit")
}

/// Synchronous wrapper around [`committed_ambiguous_then_decisive_audit`].
pub fn committed_ambiguous_then_decisive_audit_sync(
    provider_boundary_id: &str,
    logical_request_id: &str,
    first_attempt_id: &str,
    second_attempt_id: &str,
    now_unix_ms: i64,
) -> BoundProviderAttemptAudit {
    block_on_audit(committed_ambiguous_then_decisive_audit(
        provider_boundary_id,
        logical_request_id,
        first_attempt_id,
        second_attempt_id,
        now_unix_ms,
    ))
}

/// Synchronous wrapper for the plain (non-`#[tokio::test]`) fixtures in `compaction.rs`,
/// `compact_prune.rs`, and `full_to_compact.rs`. Spins up its own current-thread runtime, so it
/// must not be called from inside an already-running one -- async callers
/// (`retention_client_live.rs`) call [`committed_decisive_audit`]/[`committed_ambiguous_audit`]
/// directly instead.
fn block_on_audit<F>(future: F) -> BoundProviderAttemptAudit
where
    F: std::future::Future<Output = BoundProviderAttemptAudit>,
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("current-thread runtime for the committed-audit fixture")
        .block_on(future)
}

/// Synchronous wrapper around [`committed_decisive_audit`].
pub fn committed_decisive_audit_sync(
    provider_boundary_id: &str,
    logical_request_id: &str,
    attempt_id: &str,
    now_unix_ms: i64,
) -> BoundProviderAttemptAudit {
    block_on_audit(committed_decisive_audit(
        provider_boundary_id,
        logical_request_id,
        attempt_id,
        now_unix_ms,
    ))
}

/// Synchronous wrapper around [`committed_ambiguous_audit`].
pub fn committed_ambiguous_audit_sync(
    provider_boundary_id: &str,
    logical_request_id: &str,
    attempt_id: &str,
    now_unix_ms: i64,
) -> BoundProviderAttemptAudit {
    block_on_audit(committed_ambiguous_audit(
        provider_boundary_id,
        logical_request_id,
        attempt_id,
        now_unix_ms,
    ))
}

/// A real, freshly opened ledger's audit: `attempt_count = 0`, `committed_grant_count = 0`,
/// `no_dispatch_count = 0`, `decisive_terminal_count = 0`, `ambiguous_count = 0`. No transport or
/// charge authority is involved, so this has no async variant.
pub fn fresh_bound_audit(
    provider_boundary_id: &str,
    logical_request_id: &str,
) -> BoundProviderAttemptAudit {
    ProviderAttemptLedger::new(provider_boundary_id, logical_request_id)
        .expect("valid boundary/request identity for the fresh-audit fixture")
        .audit_for(logical_request_id)
        .expect("a fresh ledger must yield a valid bound audit")
}

/// A bound audit reflecting one recorded no-dispatch resolution, via
/// [`ProviderAttemptLedger::record_no_dispatch`] rather than a fabricated counter literal.
/// Synchronous: `record_no_dispatch` and `audit_for` are both non-async.
pub fn no_dispatch_bound_audit(
    provider_boundary_id: &str,
    logical_request_id: &str,
    proof: &CanonicalNoDispatchProof,
) -> BoundProviderAttemptAudit {
    let mut ledger = ProviderAttemptLedger::new(provider_boundary_id, logical_request_id)
        .expect("valid boundary/request identity for the no-dispatch audit fixture");
    ledger
        .record_no_dispatch(proof)
        .expect("no-dispatch proof must record on a fresh ledger");
    ledger
        .audit_for(logical_request_id)
        .expect("freshly recorded ledger must yield a valid bound audit")
}

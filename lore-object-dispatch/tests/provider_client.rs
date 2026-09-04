// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! WP-114 CD-5's governed provider client: cell boundary binding, the put execution plan, and the
//! charge-before-send kernel. Drives the public API in `lore_object_dispatch::provider_client`
//! (re-exported from the crate root) with in-process test doubles for the two unwired seams
//! (`ProviderChargeAuthority`, `ProviderTransport`); no provider SDK, no database, no filesystem.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;
use std::time::Duration;

use lore_object_dispatch::AuthorizedProviderAttempt;
use lore_object_dispatch::BudgetPin;
use lore_object_dispatch::CanonicalNoDispatchProof;
use lore_object_dispatch::CellProviderBoundary;
use lore_object_dispatch::DurableProviderPutBody;
use lore_object_dispatch::GovernedProviderClient;
use lore_object_dispatch::LedgerSpoolView;
use lore_object_dispatch::MeteredProviderAttemptRequest;
use lore_object_dispatch::NoDispatchProofFields;
use lore_object_dispatch::NoDispatchReason;
use lore_object_dispatch::ObjectStoreCompactReceiptLimits;
use lore_object_dispatch::PROVIDER_MAX_MULTIPART_PARTS;
use lore_object_dispatch::PROVIDER_MAX_PART_SIZE_BYTES;
use lore_object_dispatch::PROVIDER_MAX_SINGLE_PUT_BYTES;
use lore_object_dispatch::PROVIDER_MIN_PART_SIZE_BYTES;
use lore_object_dispatch::ProviderAttemptClass;
use lore_object_dispatch::ProviderAttemptExecution;
use lore_object_dispatch::ProviderAttemptLedger;
use lore_object_dispatch::ProviderAttemptOutcome;
use lore_object_dispatch::ProviderAttemptReport;
use lore_object_dispatch::ProviderAttemptRequest;
use lore_object_dispatch::ProviderCapClass;
use lore_object_dispatch::ProviderCapabilities;
use lore_object_dispatch::ProviderChargeAuthority;
use lore_object_dispatch::ProviderChargeError;
use lore_object_dispatch::ProviderChargeGrant;
use lore_object_dispatch::ProviderChargeRequest;
use lore_object_dispatch::ProviderClientError;
use lore_object_dispatch::ProviderPutLimits;
use lore_object_dispatch::ProviderPutPart;
use lore_object_dispatch::ProviderRetryPolicy;
use lore_object_dispatch::ProviderTarget;
use lore_object_dispatch::ProviderTrafficClass;
use lore_object_dispatch::ProviderTransport;
use lore_object_dispatch::ProviderTransportRefusal;
use lore_object_dispatch::PutObjectPlan;
use lore_object_dispatch::SpoolLayout;
use lore_object_dispatch::SpoolObjectKey;
use lore_object_dispatch::SpoolObjectKind;
use lore_object_dispatch::UnwiredChargeAuthority;
use lore_object_dispatch::UnwiredProviderTransport;
use lore_object_dispatch::bind_durable_put_body;
use lore_object_dispatch::build_no_dispatch_proof;
use lore_object_dispatch::plan_put_object;
use lore_object_dispatch::validate_and_encode_object_store_provider_attempt_audit;

const BOUNDARY_ID: &str = "cell.nyc3.primary";
const BUCKET: &str = "commit0-cell-nyc3";
const REGION: &str = "nyc3";
const ENDPOINT_HOST: &str = "nyc3.digitaloceanspaces.com";
const REQUEST_TIMESTAMP_MS: u64 = 0x018f_3e12_a456;
const VALID_DEADLINE_MS: i64 = REQUEST_TIMESTAMP_MS as i64 + 60_000;
const DURABLE_BODY_SIZE: u64 = 4096;
const DURABLE_BODY_BLAKE3: [u8; 32] = [7u8; 32];

// ---------------------------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------------------------

fn uuid_v7(timestamp_unix_ms: u64, tail: &str) -> String {
    let timestamp = format!("{timestamp_unix_ms:012x}");
    format!("{}-{}-7abc-8def-{tail}", &timestamp[..8], &timestamp[8..])
}

fn logical_request_id() -> String {
    uuid_v7(REQUEST_TIMESTAMP_MS, "000000000001")
}

fn attempt_id() -> String {
    uuid_v7(REQUEST_TIMESTAMP_MS, "000000000002")
}

fn other_logical_request_id() -> String {
    uuid_v7(REQUEST_TIMESTAMP_MS, "0000000000aa")
}

fn other_attempt_id() -> String {
    uuid_v7(REQUEST_TIMESTAMP_MS, "0000000000bb")
}

fn grant_id() -> String {
    uuid_v7(REQUEST_TIMESTAMP_MS, "000000000003")
}

fn boundary() -> CellProviderBoundary {
    CellProviderBoundary::new(BOUNDARY_ID, BUCKET, REGION, ENDPOINT_HOST)
        .expect("realistic boundary configuration must validate")
}

fn target_value() -> ProviderTarget {
    boundary().target().clone()
}

fn budget_pin() -> BudgetPin {
    BudgetPin {
        revision: "wp121.envelope.rev.7".to_string(),
        fence: 42,
    }
}

fn spool_root() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\object-dispatch-spool-provider-client-fixture")
    } else {
        PathBuf::from("/var/lib/object-dispatch-spool-provider-client-fixture")
    }
}

fn spool_layout() -> SpoolLayout {
    SpoolLayout::new(spool_root()).expect("absolute normalized test root must be valid")
}

fn put_spool_key(logical_request_id: &str, attempt_id: &str) -> SpoolObjectKey {
    SpoolObjectKey {
        provider_boundary_id: BOUNDARY_ID.to_string(),
        logical_request_id: logical_request_id.to_string(),
        attempt_id: attempt_id.to_string(),
        kind: SpoolObjectKind::Put,
    }
}

fn ready_ledger_view_for(key: &SpoolObjectKey) -> LedgerSpoolView {
    let paths = spool_layout()
        .derive_paths(key)
        .expect("derive paths for a valid key");
    LedgerSpoolView::Ready {
        opaque_handle: paths.opaque_handle().to_string(),
        size: DURABLE_BODY_SIZE,
        blake3: DURABLE_BODY_BLAKE3,
    }
}

fn durable_put_body() -> DurableProviderPutBody {
    let key = put_spool_key(&logical_request_id(), &attempt_id());
    let ledger = ready_ledger_view_for(&key);
    bind_durable_put_body(&spool_layout(), &key, &ledger).expect("durable put body must bind")
}

/// A durable put body bound to the default logical/attempt/boundary identity, but with `size` set
/// to whatever the caller needs -- used where a test needs a body large enough to host a
/// multi-megabyte non-final part, unlike the crate-wide `DURABLE_BODY_SIZE` fixture.
fn durable_put_body_of_size(size: u64) -> DurableProviderPutBody {
    let key = put_spool_key(&logical_request_id(), &attempt_id());
    let opaque_handle = spool_layout()
        .derive_paths(&key)
        .expect("derive paths for a valid key")
        .opaque_handle()
        .to_string();
    let ledger = LedgerSpoolView::Ready {
        opaque_handle,
        size,
        blake3: DURABLE_BODY_BLAKE3,
    };
    bind_durable_put_body(&spool_layout(), &key, &ledger).expect("durable put body must bind")
}

fn base_request(attempt_class: ProviderAttemptClass) -> ProviderAttemptRequest {
    ProviderAttemptRequest {
        traffic_class: ProviderTrafficClass::Drain,
        attempt_class,
        target: target_value(),
        logical_request_id: logical_request_id(),
        attempt_id: attempt_id(),
        attempt_ordinal: 1,
        deadline_unix_ms: VALID_DEADLINE_MS,
        budget_pin: budget_pin(),
        put_body: None,
        put_part: None,
    }
}

fn request_for_attempt_number(attempt_number: u32) -> ProviderAttemptRequest {
    assert!(attempt_number > 0, "attempt numbers are one-based");
    let mut request = base_request(ProviderAttemptClass::Readiness);
    request.attempt_id = uuid_v7(REQUEST_TIMESTAMP_MS, &format!("f{attempt_number:011x}"));
    request.attempt_ordinal = attempt_number;
    request
}

fn put_object_request() -> ProviderAttemptRequest {
    let mut request = base_request(ProviderAttemptClass::PutObject);
    request.put_body = Some(durable_put_body());
    request
}

fn upload_part_request() -> ProviderAttemptRequest {
    let mut request = base_request(ProviderAttemptClass::UploadPart);
    request.put_body = Some(durable_put_body());
    request.put_part = Some(ProviderPutPart {
        part_number: 1,
        offset: 0,
        length: DURABLE_BODY_SIZE,
    });
    request
}

/// A fully valid request for `attempt_class`, with a durable body/part attached where the class
/// requires one. The single source every test drives class-parameterized coverage from.
fn attempt_request_for(attempt_class: ProviderAttemptClass) -> ProviderAttemptRequest {
    match attempt_class {
        ProviderAttemptClass::PutObject => put_object_request(),
        ProviderAttemptClass::UploadPart => upload_part_request(),
        _ => base_request(attempt_class),
    }
}

fn client_with<C, T>(
    capabilities: ProviderCapabilities,
    charge_authority: C,
    transport: T,
) -> UnitOperationClient<C, T>
where
    C: ProviderChargeAuthority,
    T: ProviderTransport<Operation = ()>,
{
    UnitOperationClient(GovernedProviderClient::new(
        boundary(),
        capabilities,
        ProviderRetryPolicy::disabled(),
        charge_authority,
        transport,
    ))
}

struct UnitOperationClient<C, T>(GovernedProviderClient<C, T>);

impl<C, T> UnitOperationClient<C, T>
where
    C: ProviderChargeAuthority,
    T: ProviderTransport<Operation = ()>,
{
    async fn execute(
        &self,
        ledger: &mut ProviderAttemptLedger,
        request: &ProviderAttemptRequest,
    ) -> Result<ProviderAttemptOutcome, ProviderClientError> {
        let request = MeteredProviderAttemptRequest::try_from(request.clone())?;
        self.0
            .execute(ledger, &request, &())
            .await
            .map(|execution| execution.outcome)
    }

    async fn execute_with_response(
        &self,
        ledger: &mut ProviderAttemptLedger,
        request: &ProviderAttemptRequest,
    ) -> Result<ProviderAttemptExecution<T::Response>, ProviderClientError> {
        let request = MeteredProviderAttemptRequest::try_from(request.clone())?;
        self.0.execute(ledger, &request, &()).await
    }

    fn validate_attempt(
        &self,
        request: &ProviderAttemptRequest,
    ) -> Result<(), ProviderClientError> {
        let request = MeteredProviderAttemptRequest::try_from(request.clone())?;
        self.0.validate_attempt(&request)
    }
}

impl<C, T> std::ops::Deref for UnitOperationClient<C, T> {
    type Target = GovernedProviderClient<C, T>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A ledger bound to the default boundary and logical request identity every fixture in this file
/// uses (`base_request`/`put_object_request`/`upload_part_request`/`attempt_request_for` all leave
/// `logical_request_id` at its default). Tests that deliberately bind a ledger to a *different*
/// identity to exercise WP-114 CD-5's ledger/request binding construct
/// `ProviderAttemptLedger::new` directly instead of using this helper.
fn new_ledger() -> ProviderAttemptLedger {
    ProviderAttemptLedger::new(BOUNDARY_ID, &logical_request_id())
        .expect("default boundary and request identity must construct a valid ledger")
}

/// A grant that binds `request` exactly: every echoed field matches, the grant ID is canonical
/// UUIDv7, and the database clock is nonnegative.
fn binding_grant(request: &ProviderChargeRequest) -> ProviderChargeGrant {
    ProviderChargeGrant {
        grant_id: grant_id(),
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

fn compact_receipt_limits() -> ObjectStoreCompactReceiptLimits {
    ObjectStoreCompactReceiptLimits {
        max_identity_bytes: 256,
        max_canonical_row_bytes: 16_384,
        max_compact_row_bytes: 16_384,
        max_dependency_floors: 16,
        full_record_retention_ms: 30,
        anti_replay_admission_past_ms: 100,
        anti_replay_admission_future_ms: 20,
        anti_replay_compact_safety_ms: 10,
    }
}

fn no_dispatch_proof() -> CanonicalNoDispatchProof {
    build_no_dispatch_proof(
        NoDispatchProofFields {
            reason: NoDispatchReason::PreparedTtlExpired,
            proof_id: uuid_v7(1_000, "0000000000cc"),
            proof_fence: 1,
            committed_at_unix_ms: 1_000,
            authority_epoch: 1,
        },
        1024,
    )
    .expect("canonical no-dispatch proof must validate")
}

/// A `ProviderChargeAuthority` test double scripted by a closure, with a shared call counter the
/// caller keeps a handle to after the double itself is moved into a client.
struct ScriptedChargeAuthority<F> {
    respond: F,
    calls: Arc<TestCounter>,
}

struct TestCounter(AtomicU32);

impl TestCounter {
    fn get(&self) -> u32 {
        self.0.load(Ordering::SeqCst)
    }

    fn increment(&self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

impl<F> ScriptedChargeAuthority<F>
where
    F: Fn(&ProviderChargeRequest) -> Result<ProviderChargeGrant, ProviderChargeError>,
{
    fn new(respond: F) -> (Self, Arc<TestCounter>) {
        let calls = Arc::new(TestCounter(AtomicU32::new(0)));
        (
            Self {
                respond,
                calls: calls.clone(),
            },
            calls,
        )
    }
}

impl<F> ProviderChargeAuthority for ScriptedChargeAuthority<F>
where
    F: Fn(&ProviderChargeRequest) -> Result<ProviderChargeGrant, ProviderChargeError> + Sync,
{
    async fn charge(
        &self,
        request: &ProviderChargeRequest,
    ) -> Result<ProviderChargeGrant, ProviderChargeError> {
        self.calls.increment();
        (self.respond)(request)
    }
}

struct PendingChargeAuthority;

impl ProviderChargeAuthority for PendingChargeAuthority {
    async fn charge(
        &self,
        _request: &ProviderChargeRequest,
    ) -> Result<ProviderChargeGrant, ProviderChargeError> {
        std::future::pending().await
    }
}

struct PendingThenSuccessChargeAuthority {
    pending_calls: u32,
    calls: AtomicU32,
}

impl PendingThenSuccessChargeAuthority {
    fn new(pending_calls: u32) -> Self {
        Self {
            pending_calls,
            calls: AtomicU32::new(0),
        }
    }
}

impl ProviderChargeAuthority for PendingThenSuccessChargeAuthority {
    async fn charge(
        &self,
        request: &ProviderChargeRequest,
    ) -> Result<ProviderChargeGrant, ProviderChargeError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        if call < self.pending_calls {
            std::future::pending().await
        } else {
            Ok(binding_grant(request))
        }
    }
}

/// A `ProviderTransport` test double scripted by a closure, with the same call-counter shape as
/// [`ScriptedChargeAuthority`].
struct ScriptedTransport<F> {
    respond: F,
    calls: Arc<TestCounter>,
}

impl<F> ScriptedTransport<F>
where
    F: Fn(
        &AuthorizedProviderAttempt<'_>,
    ) -> Result<ProviderAttemptReport<()>, ProviderTransportRefusal>,
{
    fn new(respond: F) -> (Self, Arc<TestCounter>) {
        let calls = Arc::new(TestCounter(AtomicU32::new(0)));
        (
            Self {
                respond,
                calls: calls.clone(),
            },
            calls,
        )
    }
}

impl<F> ProviderTransport for ScriptedTransport<F>
where
    F: Fn(
            &AuthorizedProviderAttempt<'_>,
        ) -> Result<ProviderAttemptReport<()>, ProviderTransportRefusal>
        + Send
        + Sync,
{
    type Operation = ();
    type Response = ();

    async fn issue<'a>(
        &'a self,
        attempt: &'a AuthorizedProviderAttempt<'a>,
        _operation: &'a Self::Operation,
    ) -> Result<ProviderAttemptReport<()>, ProviderTransportRefusal> {
        self.calls.increment();
        (self.respond)(attempt)
    }
}

#[derive(Clone, Copy)]
struct TypedResponseTransport {
    outcome: ProviderAttemptOutcome,
    provider_requests_issued: u32,
    response: &'static str,
}

impl ProviderTransport for TypedResponseTransport {
    type Operation = ();
    type Response = &'static str;

    async fn issue<'a>(
        &'a self,
        _attempt: &'a AuthorizedProviderAttempt<'a>,
        _operation: &'a Self::Operation,
    ) -> Result<ProviderAttemptReport<Self::Response>, ProviderTransportRefusal> {
        Ok(ProviderAttemptReport {
            outcome: self.outcome,
            provider_requests_issued: self.provider_requests_issued,
            response: self.response,
        })
    }
}

struct PendingProviderTransport;

impl ProviderTransport for PendingProviderTransport {
    type Operation = ();
    type Response = &'static str;

    async fn issue<'a>(
        &'a self,
        _attempt: &'a AuthorizedProviderAttempt<'a>,
        _operation: &'a Self::Operation,
    ) -> Result<ProviderAttemptReport<Self::Response>, ProviderTransportRefusal> {
        std::future::pending().await
    }
}

// ---------------------------------------------------------------------------------------------
// 1. CellProviderBoundary::new
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn cell_provider_boundary_accepts_a_realistic_do_spaces_configuration() {
    let boundary = boundary();

    assert_eq!(boundary.provider_boundary_id(), BOUNDARY_ID);
    assert_eq!(boundary.target().bucket, BUCKET);
    assert_eq!(boundary.target().region, REGION);
    assert_eq!(boundary.target().endpoint_host, ENDPOINT_HOST);
}

#[tokio::test]
async fn cell_provider_boundary_rejects_every_invalid_bucket_shape() {
    let too_long = "a".repeat(64);
    let cases: [(&str, &str); 13] = [
        ("ab", "shorter than 3 bytes"),
        (too_long.as_str(), "longer than 63 bytes"),
        ("Commit0-cell", "uppercase"),
        ("commit0_cell", "underscore"),
        ("-commit0-cell", "leading dash"),
        ("commit0-cell-", "trailing dash"),
        (".commit0-cell", "leading dot"),
        ("commit0-cell.", "trailing dot"),
        ("commit0..cell", "double dot"),
        ("commit0.-cell", "dot-dash"),
        ("commit0-.cell", "dash-dot"),
        ("192.168.0.1", "ipv4-shaped"),
        ("xn--commit0-cell", "xn-- punycode prefix"),
    ];

    for (bucket, label) in cases {
        assert_eq!(
            CellProviderBoundary::new(BOUNDARY_ID, bucket, REGION, ENDPOINT_HOST),
            Err(ProviderClientError::InvalidBucketName),
            "case: {label}"
        );
    }
}

#[tokio::test]
async fn cell_provider_boundary_rejects_every_invalid_region_shape() {
    let too_long = "a".repeat(64);
    let cases: [(&str, &str); 5] = [
        ("", "empty"),
        (too_long.as_str(), "longer than 63 bytes"),
        ("NYC3", "uppercase"),
        ("-nyc3", "leading dash"),
        ("nyc3-", "trailing dash"),
    ];

    for (region, label) in cases {
        assert_eq!(
            CellProviderBoundary::new(BOUNDARY_ID, BUCKET, region, ENDPOINT_HOST),
            Err(ProviderClientError::InvalidRegion),
            "case: {label}"
        );
    }
}

#[tokio::test]
async fn cell_provider_boundary_rejects_every_invalid_endpoint_host_shape() {
    let long_label_host = format!("{}.example.com", "a".repeat(64));
    let over_253_host = vec!["aa"; 85].join(".");
    assert!(over_253_host.len() > 253, "fixture must exceed 253 bytes");

    // A single-label host is no longer in this rejects list: the dot requirement is gone, and a
    // single-label host is covered positively by
    // `cell_provider_boundary_accepts_a_single_label_endpoint_host`.
    let cases: [(&str, &str); 6] = [
        ("nyc3..example.com", "empty label"),
        (long_label_host.as_str(), "over-long label"),
        ("-nyc3.example.com", "leading-dash label"),
        ("nyc3-.example.com", "trailing-dash label"),
        ("NYC3.example.com", "uppercase"),
        (over_253_host.as_str(), "over 253 bytes"),
    ];

    for (host, label) in cases {
        assert_eq!(
            CellProviderBoundary::new(BOUNDARY_ID, BUCKET, REGION, host),
            Err(ProviderClientError::InvalidEndpointHost),
            "case: {label}"
        );
    }
}

#[tokio::test]
async fn cell_provider_boundary_accepts_a_single_label_endpoint_host() {
    let boundary = CellProviderBoundary::new(BOUNDARY_ID, BUCKET, REGION, "minio")
        .expect("single-label host must validate");
    assert_eq!(boundary.target().endpoint_host, "minio");

    // A single-label host must still be exact-matched by validate_target: the configured host
    // matches, and a different single-label host does not.
    let matching = boundary.target().clone();
    assert!(boundary.validate_target(&matching).is_ok());

    let mut mismatched = boundary.target().clone();
    mismatched.endpoint_host = "other".to_string();
    assert_eq!(
        boundary.validate_target(&mismatched),
        Err(ProviderClientError::EndpointOutsideCellRegion)
    );
}

#[tokio::test]
async fn cell_provider_boundary_rejects_non_canonical_boundary_ids() {
    let cases: [(&str, &str); 3] = [
        ("", "empty"),
        ("-cell.nyc3", "leading non-alphanumeric"),
        ("cell nyc3", "contains a space"),
    ];

    for (id, label) in cases {
        assert_eq!(
            CellProviderBoundary::new(id, BUCKET, REGION, ENDPOINT_HOST),
            Err(ProviderClientError::InvalidProviderBoundaryId),
            "case: {label}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// 2. CellProviderBoundary::validate_target
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn validate_target_accepts_an_exact_match_and_rejects_by_precedence() {
    let boundary = boundary();
    assert!(boundary.validate_target(&target_value()).is_ok());

    let mut wrong_bucket = target_value();
    wrong_bucket.bucket = "other-bucket".to_string();
    assert_eq!(
        boundary.validate_target(&wrong_bucket),
        Err(ProviderClientError::BucketOutsideCellBoundary)
    );

    let mut wrong_region = target_value();
    wrong_region.region = "nyc1".to_string();
    assert_eq!(
        boundary.validate_target(&wrong_region),
        Err(ProviderClientError::RegionOutsideCell)
    );

    let mut wrong_host = target_value();
    wrong_host.endpoint_host = "other.example.com".to_string();
    assert_eq!(
        boundary.validate_target(&wrong_host),
        Err(ProviderClientError::EndpointOutsideCellRegion)
    );

    // All three differ: bucket must win.
    let mut all_wrong = target_value();
    all_wrong.bucket = "other-bucket".to_string();
    all_wrong.region = "nyc1".to_string();
    all_wrong.endpoint_host = "other.example.com".to_string();
    assert_eq!(
        boundary.validate_target(&all_wrong),
        Err(ProviderClientError::BucketOutsideCellBoundary)
    );
}

// ---------------------------------------------------------------------------------------------
// 3. plan_put_object / PutObjectPlan
// ---------------------------------------------------------------------------------------------

fn put_limits() -> ProviderPutLimits {
    ProviderPutLimits {
        multipart_threshold_bytes: PROVIDER_MIN_PART_SIZE_BYTES,
        part_size_bytes: PROVIDER_MIN_PART_SIZE_BYTES,
        max_parts: 10,
    }
}

/// Walks every part in `plan` and asserts the ranges tile the body with no gap or overlap.
fn assert_ranges_tile(plan: PutObjectPlan, body_size: u64) {
    let part_count = match plan {
        PutObjectPlan::Multipart { part_count, .. } => part_count,
        PutObjectPlan::SingleShot { .. } => panic!("expected a multipart plan"),
    };

    let mut expected_offset = 0u64;
    for part_number in 1..=part_count {
        let (offset, length) = plan
            .part_range(part_number)
            .unwrap_or_else(|| panic!("part {part_number} must be in range"));
        assert_eq!(offset, expected_offset, "part {part_number} offset");
        expected_offset += length;
    }
    assert_eq!(
        expected_offset, body_size,
        "part ranges must tile the body with no gap or overlap"
    );
}

#[tokio::test]
async fn plan_put_object_is_single_shot_at_and_below_the_threshold() {
    let limits = put_limits();

    assert_eq!(
        plan_put_object(0, &limits),
        Ok(PutObjectPlan::SingleShot { body_size: 0 })
    );
    assert_eq!(
        plan_put_object(limits.multipart_threshold_bytes, &limits),
        Ok(PutObjectPlan::SingleShot {
            body_size: limits.multipart_threshold_bytes
        })
    );
}

#[tokio::test]
async fn plan_put_object_becomes_multipart_one_byte_past_the_threshold() {
    let limits = put_limits();
    let plan = plan_put_object(limits.multipart_threshold_bytes + 1, &limits)
        .expect("must plan a multipart body");
    assert!(matches!(plan, PutObjectPlan::Multipart { .. }));
}

#[tokio::test]
async fn plan_put_object_computes_exact_multiple_part_arithmetic_and_tiles_the_body() {
    let limits = put_limits();
    let body_size = limits.part_size_bytes * 4;

    let plan = plan_put_object(body_size, &limits).expect("must plan");
    assert_eq!(
        plan,
        PutObjectPlan::Multipart {
            body_size,
            part_size_bytes: limits.part_size_bytes,
            part_count: 4,
            final_part_size_bytes: limits.part_size_bytes,
        }
    );
    assert_ranges_tile(plan, body_size);
}

#[tokio::test]
async fn plan_put_object_computes_remainder_part_arithmetic_and_tiles_the_body() {
    let limits = put_limits();
    let remainder = 1024 * 1024;
    let body_size = limits.part_size_bytes * 3 + remainder;

    let plan = plan_put_object(body_size, &limits).expect("must plan");
    assert_eq!(
        plan,
        PutObjectPlan::Multipart {
            body_size,
            part_size_bytes: limits.part_size_bytes,
            part_count: 4,
            final_part_size_bytes: remainder,
        }
    );
    assert_ranges_tile(plan, body_size);
}

#[tokio::test]
async fn planned_attempt_count_matches_single_shot_and_multipart_expansion() {
    let limits = put_limits();

    let single = plan_put_object(0, &limits).expect("must plan");
    assert_eq!(single.planned_attempt_count(), 1);

    let body_size = limits.part_size_bytes * 4;
    let multipart = plan_put_object(body_size, &limits).expect("must plan");
    assert_eq!(multipart.planned_attempt_count(), 4 + 2);
}

#[tokio::test]
async fn attempt_class_at_walks_create_parts_complete_and_never_names_abort() {
    let limits = put_limits();
    let body_size = limits.part_size_bytes * 4;
    let plan = plan_put_object(body_size, &limits).expect("must plan");
    let part_count = 4u64;

    assert_eq!(
        plan.attempt_class_at(0),
        Some(ProviderAttemptClass::CreateMultipartUpload)
    );
    for index in 1..=part_count {
        assert_eq!(
            plan.attempt_class_at(index),
            Some(ProviderAttemptClass::UploadPart),
            "index {index}"
        );
    }
    assert_eq!(
        plan.attempt_class_at(part_count + 1),
        Some(ProviderAttemptClass::CompleteMultipartUpload)
    );
    assert_eq!(plan.attempt_class_at(part_count + 2), None);

    // AbortMultipartUpload is contingent on failure and is charged only when it is actually
    // issued, so it must never appear in the planned sequence.
    for index in 0..=(part_count + 5) {
        assert_ne!(
            plan.attempt_class_at(index),
            Some(ProviderAttemptClass::AbortMultipartUpload),
            "index {index}"
        );
    }

    let single = plan_put_object(0, &limits).expect("must plan");
    assert_eq!(
        single.attempt_class_at(0),
        Some(ProviderAttemptClass::PutObject)
    );
    assert_eq!(single.attempt_class_at(1), None);
}

#[tokio::test]
async fn part_range_is_none_outside_the_plan_and_always_none_for_single_shot() {
    let limits = put_limits();
    let body_size = limits.part_size_bytes * 4;
    let plan = plan_put_object(body_size, &limits).expect("must plan");

    assert_eq!(plan.part_range(0), None);
    assert_eq!(plan.part_range(5), None);

    let single = plan_put_object(0, &limits).expect("must plan");
    assert_eq!(single.part_range(0), None);
    assert_eq!(single.part_range(1), None);
}

#[tokio::test]
async fn plan_put_object_rejects_bodies_needing_more_parts_than_max_parts() {
    let limits = ProviderPutLimits {
        multipart_threshold_bytes: PROVIDER_MIN_PART_SIZE_BYTES,
        part_size_bytes: PROVIDER_MIN_PART_SIZE_BYTES,
        max_parts: 2,
    };
    let body_size = limits.part_size_bytes * 3 + 1;

    assert_eq!(
        plan_put_object(body_size, &limits),
        Err(ProviderClientError::MultipartPartCountExceeded)
    );
}

#[tokio::test]
async fn plan_put_object_rejects_limits_outside_the_supported_range() {
    let base = put_limits();

    let mut too_small_part = base;
    too_small_part.part_size_bytes = PROVIDER_MIN_PART_SIZE_BYTES - 1;
    assert_eq!(
        plan_put_object(0, &too_small_part),
        Err(ProviderClientError::InvalidPutLimits)
    );

    let mut too_large_part = base;
    too_large_part.part_size_bytes = PROVIDER_MAX_PART_SIZE_BYTES + 1;
    assert_eq!(
        plan_put_object(0, &too_large_part),
        Err(ProviderClientError::InvalidPutLimits)
    );

    let mut zero_max_parts = base;
    zero_max_parts.max_parts = 0;
    assert_eq!(
        plan_put_object(0, &zero_max_parts),
        Err(ProviderClientError::InvalidPutLimits)
    );

    let mut too_many_max_parts = base;
    too_many_max_parts.max_parts = PROVIDER_MAX_MULTIPART_PARTS + 1;
    assert_eq!(
        plan_put_object(0, &too_many_max_parts),
        Err(ProviderClientError::InvalidPutLimits)
    );

    let mut threshold_below_part = base;
    threshold_below_part.multipart_threshold_bytes = base.part_size_bytes - 1;
    assert_eq!(
        plan_put_object(0, &threshold_below_part),
        Err(ProviderClientError::InvalidPutLimits)
    );

    let mut threshold_too_large = base;
    threshold_too_large.multipart_threshold_bytes = PROVIDER_MAX_SINGLE_PUT_BYTES + 1;
    assert_eq!(
        plan_put_object(0, &threshold_too_large),
        Err(ProviderClientError::InvalidPutLimits)
    );
}

/// `part_range`'s variants are public, so a caller can hand it a `Multipart` plan `plan_put_object`
/// would never mint. Its own arithmetic must be checked rather than trusted, and answer `None`
/// for a plan whose own numbers do not fit -- not panic or silently wrap.
#[tokio::test]
async fn part_range_returns_none_when_a_hand_built_plans_offset_multiplication_overflows() {
    let plan = PutObjectPlan::Multipart {
        body_size: u64::MAX,
        part_size_bytes: u64::MAX,
        part_count: 3,
        final_part_size_bytes: 1,
    };

    // part_number=3: offset = (3 - 1).checked_mul(u64::MAX) overflows outright.
    assert_eq!(plan.part_range(3), None);
}

#[tokio::test]
async fn part_range_returns_none_when_offset_plus_length_overflows() {
    let plan = PutObjectPlan::Multipart {
        body_size: u64::MAX,
        part_size_bytes: u64::MAX / 2,
        part_count: 2,
        final_part_size_bytes: u64::MAX,
    };

    // part_number=2 is the final part: offset = (2 - 1) * (u64::MAX / 2) fits, but
    // offset.checked_add(final_part_size_bytes) then overflows.
    assert_eq!(plan.part_range(2), None);
}

#[tokio::test]
async fn part_range_well_formed_plans_from_plan_put_object_are_unaffected_by_the_checked_arithmetic()
 {
    let limits = put_limits();
    let body_size = limits.part_size_bytes * 4;
    let plan = plan_put_object(body_size, &limits).expect("must plan");
    assert_ranges_tile(plan, body_size);
}

// ---------------------------------------------------------------------------------------------
// 4. bind_durable_put_body
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn bind_durable_put_body_succeeds_for_a_ready_put_key_and_echoes_every_field() {
    let key = put_spool_key(&logical_request_id(), &attempt_id());
    let ledger = ready_ledger_view_for(&key);
    let body = bind_durable_put_body(&spool_layout(), &key, &ledger).expect("must bind");
    let paths = spool_layout().derive_paths(&key).expect("derive paths");

    assert_eq!(body.opaque_handle(), paths.opaque_handle());
    assert_eq!(body.size(), DURABLE_BODY_SIZE);
    assert_eq!(body.blake3(), &DURABLE_BODY_BLAKE3);
    assert_eq!(body.logical_request_id(), key.logical_request_id);
    assert_eq!(body.spool_attempt_id(), key.attempt_id);
    assert_eq!(body.provider_boundary_id(), key.provider_boundary_id);
}

#[tokio::test]
async fn bind_durable_put_body_requires_a_ready_ledger_row() {
    let key = put_spool_key(&logical_request_id(), &attempt_id());

    for ledger in [
        LedgerSpoolView::Absent,
        LedgerSpoolView::Reserved {
            expected_size: 10,
            expected_blake3: [1u8; 32],
            accounted_prefix_bytes: 0,
        },
        LedgerSpoolView::Released {
            release_receipt_blake3: [2u8; 32],
        },
    ] {
        assert_eq!(
            bind_durable_put_body(&spool_layout(), &key, &ledger),
            Err(ProviderClientError::PutBodyNotDurable)
        );
    }
}

#[tokio::test]
async fn bind_durable_put_body_rejects_a_ready_row_with_the_wrong_handle() {
    let key = put_spool_key(&logical_request_id(), &attempt_id());
    let ledger = LedgerSpoolView::Ready {
        opaque_handle: "wrong-handle".to_string(),
        size: DURABLE_BODY_SIZE,
        blake3: DURABLE_BODY_BLAKE3,
    };

    assert_eq!(
        bind_durable_put_body(&spool_layout(), &key, &ledger),
        Err(ProviderClientError::PutBodyHandleMismatch)
    );
}

#[tokio::test]
async fn bind_durable_put_body_rejects_a_result_kind_key_before_deriving_paths() {
    // An empty boundary ID would also fail path derivation (InvalidSpoolKey). Using it here
    // proves the kind check runs first: if derivation ran first, this would report
    // InvalidSpoolKey instead of InvalidSpoolKind.
    let key = SpoolObjectKey {
        provider_boundary_id: String::new(),
        logical_request_id: logical_request_id(),
        attempt_id: attempt_id(),
        kind: SpoolObjectKind::Result,
    };
    let ledger = LedgerSpoolView::Absent;

    assert_eq!(
        bind_durable_put_body(&spool_layout(), &key, &ledger),
        Err(ProviderClientError::InvalidSpoolKind)
    );
}

#[tokio::test]
async fn bind_durable_put_body_rejects_non_canonical_spool_keys() {
    let ledger = LedgerSpoolView::Absent;

    let mut bad_logical = put_spool_key(&logical_request_id(), &attempt_id());
    bad_logical.logical_request_id = "not-a-uuid-v7".to_string();
    assert_eq!(
        bind_durable_put_body(&spool_layout(), &bad_logical, &ledger),
        Err(ProviderClientError::InvalidSpoolKey)
    );

    let mut bad_attempt = put_spool_key(&logical_request_id(), &attempt_id());
    bad_attempt.attempt_id = "not-a-uuid-v7".to_string();
    assert_eq!(
        bind_durable_put_body(&spool_layout(), &bad_attempt, &ledger),
        Err(ProviderClientError::InvalidSpoolKey)
    );

    let mut bad_boundary = put_spool_key(&logical_request_id(), &attempt_id());
    bad_boundary.provider_boundary_id = String::new();
    assert_eq!(
        bind_durable_put_body(&spool_layout(), &bad_boundary, &ledger),
        Err(ProviderClientError::InvalidSpoolKey)
    );
}

// ---------------------------------------------------------------------------------------------
// 5. GovernedProviderClient::authorize
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn authorize_gates_listing_classes_on_the_capability_and_leaves_others_unaffected() {
    let without_listing = client_with(
        ProviderCapabilities::none(),
        UnwiredChargeAuthority,
        UnwiredProviderTransport,
    );
    let with_listing = client_with(
        ProviderCapabilities::none().with_listing(),
        UnwiredChargeAuthority,
        UnwiredProviderTransport,
    );

    for class in ProviderAttemptClass::ALL {
        let request = attempt_request_for(class);
        let result_without = without_listing.validate_attempt(&request);
        let result_with = with_listing.validate_attempt(&request);

        if class == ProviderAttemptClass::GetObject {
            assert_eq!(
                result_without,
                Err(ProviderClientError::GetObjectRequiresReadOnlyPath)
            );
            assert_eq!(
                result_with,
                Err(ProviderClientError::GetObjectRequiresReadOnlyPath)
            );
        } else if class.is_listing() {
            assert_eq!(
                result_without,
                Err(ProviderClientError::ListCapabilityNotGranted),
                "{class:?}"
            );
            assert!(result_with.is_ok(), "{class:?}: {result_with:?}");
        } else {
            assert!(result_without.is_ok(), "{class:?}: {result_without:?}");
            assert!(result_with.is_ok(), "{class:?}: {result_with:?}");
        }
    }
}

#[tokio::test]
async fn authorize_requires_canonical_uuid_v7_identities_and_a_positive_ordinal() {
    let client = client_with(
        ProviderCapabilities::none(),
        UnwiredChargeAuthority,
        UnwiredProviderTransport,
    );

    let mut bad_logical = attempt_request_for(ProviderAttemptClass::Readiness);
    bad_logical.logical_request_id = "not-a-uuid".to_string();
    assert_eq!(
        client.validate_attempt(&bad_logical),
        Err(ProviderClientError::InvalidRequestIdentity)
    );

    let mut bad_attempt = attempt_request_for(ProviderAttemptClass::Readiness);
    bad_attempt.attempt_id = "not-a-uuid".to_string();
    assert_eq!(
        client.validate_attempt(&bad_attempt),
        Err(ProviderClientError::InvalidRequestIdentity)
    );

    let mut bad_ordinal = attempt_request_for(ProviderAttemptClass::Readiness);
    bad_ordinal.attempt_ordinal = 0;
    assert_eq!(
        client.validate_attempt(&bad_ordinal),
        Err(ProviderClientError::InvalidAttemptOrdinal)
    );
}

#[tokio::test]
async fn authorize_requires_a_canonical_nonzero_budget_pin() {
    let client = client_with(
        ProviderCapabilities::none(),
        UnwiredChargeAuthority,
        UnwiredProviderTransport,
    );

    let mut non_canonical = attempt_request_for(ProviderAttemptClass::Readiness);
    non_canonical.budget_pin.revision = "not canonical!".to_string();
    assert_eq!(
        client.validate_attempt(&non_canonical),
        Err(ProviderClientError::InvalidBudgetPin)
    );

    let mut empty_revision = attempt_request_for(ProviderAttemptClass::Readiness);
    empty_revision.budget_pin.revision = String::new();
    assert_eq!(
        client.validate_attempt(&empty_revision),
        Err(ProviderClientError::InvalidBudgetPin)
    );

    let mut zero_fence = attempt_request_for(ProviderAttemptClass::Readiness);
    zero_fence.budget_pin.fence = 0;
    assert_eq!(
        client.validate_attempt(&zero_fence),
        Err(ProviderClientError::InvalidBudgetPin)
    );
}

/// Budget-pin revisions go through a narrower validator than the crate's general canonical
/// identifier: `/` and `:` are excluded, the cap is 128 bytes (not 256), and the first byte must
/// be ASCII alphanumeric.
#[tokio::test]
async fn authorize_rejects_budget_pin_revisions_outside_the_narrow_charset() {
    let client = client_with(
        ProviderCapabilities::none(),
        UnwiredChargeAuthority,
        UnwiredProviderTransport,
    );

    let mut with_slash = attempt_request_for(ProviderAttemptClass::Readiness);
    with_slash.budget_pin.revision = "wp121/rev.7".to_string();
    assert_eq!(
        client.validate_attempt(&with_slash),
        Err(ProviderClientError::InvalidBudgetPin)
    );

    let mut with_colon = attempt_request_for(ProviderAttemptClass::Readiness);
    with_colon.budget_pin.revision = "wp121:rev.7".to_string();
    assert_eq!(
        client.validate_attempt(&with_colon),
        Err(ProviderClientError::InvalidBudgetPin)
    );

    let mut over_length = attempt_request_for(ProviderAttemptClass::Readiness);
    over_length.budget_pin.revision = "a".repeat(129);
    assert_eq!(
        client.validate_attempt(&over_length),
        Err(ProviderClientError::InvalidBudgetPin)
    );

    let mut leading_dash = attempt_request_for(ProviderAttemptClass::Readiness);
    leading_dash.budget_pin.revision = "-wp121".to_string();
    assert_eq!(
        client.validate_attempt(&leading_dash),
        Err(ProviderClientError::InvalidBudgetPin)
    );

    let mut leading_dot = attempt_request_for(ProviderAttemptClass::Readiness);
    leading_dot.budget_pin.revision = ".wp121".to_string();
    assert_eq!(
        client.validate_attempt(&leading_dot),
        Err(ProviderClientError::InvalidBudgetPin)
    );

    // Exactly 128 bytes is accepted; the cap is inclusive.
    let mut at_the_128_byte_boundary = attempt_request_for(ProviderAttemptClass::Readiness);
    at_the_128_byte_boundary.budget_pin.revision = "a".repeat(128);
    assert!(client.validate_attempt(&at_the_128_byte_boundary).is_ok());
}

#[tokio::test]
async fn budget_revision_frozen_grammar_accepts_exact_byte_boundaries_and_later_punctuation() {
    let client = client_with(
        ProviderCapabilities::none(),
        UnwiredChargeAuthority,
        UnwiredProviderTransport,
    );

    for revision in ["A", "a", "0", "A._-z", &"x".repeat(128)] {
        let mut request = attempt_request_for(ProviderAttemptClass::Readiness);
        request.budget_pin.revision = revision.to_string();
        assert!(
            client.validate_attempt(&request).is_ok(),
            "frozen grammar must accept {revision:?}"
        );
    }
}

#[tokio::test]
async fn budget_revision_frozen_grammar_rejects_every_leading_punctuation_and_unicode_bytes() {
    let client = client_with(
        ProviderCapabilities::none(),
        UnwiredChargeAuthority,
        UnwiredProviderTransport,
    );

    for revision in [".a", "_a", "-a", "é", "e\u{301}"] {
        let mut request = attempt_request_for(ProviderAttemptClass::Readiness);
        request.budget_pin.revision = revision.to_string();
        assert_eq!(
            client.validate_attempt(&request),
            Err(ProviderClientError::InvalidBudgetPin),
            "frozen grammar must reject {revision:?} without Unicode normalization"
        );
    }
}

#[test]
fn attempt_deadline_is_bounded_to_five_minutes_from_the_attempt_identity_clock() {
    let client = client_with(
        ProviderCapabilities::none(),
        UnwiredChargeAuthority,
        UnwiredProviderTransport,
    );
    let mut at_bound = base_request(ProviderAttemptClass::Readiness);
    at_bound.deadline_unix_ms = REQUEST_TIMESTAMP_MS as i64 + 300_000;
    let mut beyond_bound = base_request(ProviderAttemptClass::Readiness);
    beyond_bound.deadline_unix_ms = REQUEST_TIMESTAMP_MS as i64 + 300_001;

    assert_eq!(client.validate_attempt(&at_bound), Ok(()));
    assert_eq!(
        client.validate_attempt(&beyond_bound),
        Err(ProviderClientError::InvalidAttemptDeadline)
    );
}

#[tokio::test]
async fn authorize_enforces_body_presence_across_every_attempt_class() {
    let client = client_with(
        ProviderCapabilities::none().with_listing(),
        UnwiredChargeAuthority,
        UnwiredProviderTransport,
    );

    for class in ProviderAttemptClass::ALL {
        if class == ProviderAttemptClass::GetObject {
            assert_eq!(
                client.validate_attempt(&attempt_request_for(class)),
                Err(ProviderClientError::GetObjectRequiresReadOnlyPath)
            );
            continue;
        }
        if class.carries_object_body() {
            let mut missing = attempt_request_for(class);
            missing.put_body = None;
            assert_eq!(
                client.validate_attempt(&missing),
                Err(ProviderClientError::PutBodyRequired),
                "{class:?}"
            );
        } else {
            let mut extra = attempt_request_for(class);
            extra.put_body = Some(durable_put_body());
            assert_eq!(
                client.validate_attempt(&extra),
                Err(ProviderClientError::PutBodyNotPermitted),
                "{class:?}"
            );
        }
    }
}

#[tokio::test]
async fn authorize_requires_a_part_range_only_for_upload_part() {
    let client = client_with(
        ProviderCapabilities::none().with_listing(),
        UnwiredChargeAuthority,
        UnwiredProviderTransport,
    );

    let mut missing_part = attempt_request_for(ProviderAttemptClass::UploadPart);
    missing_part.put_part = None;
    assert_eq!(
        client.validate_attempt(&missing_part),
        Err(ProviderClientError::PutPartRequired)
    );

    for class in ProviderAttemptClass::ALL {
        if class == ProviderAttemptClass::UploadPart {
            continue;
        }
        let mut request = attempt_request_for(class);
        request.put_part = Some(ProviderPutPart {
            part_number: 1,
            offset: 0,
            length: 1,
        });
        let expected = if class == ProviderAttemptClass::GetObject {
            ProviderClientError::GetObjectRequiresReadOnlyPath
        } else {
            ProviderClientError::PutPartNotPermitted
        };
        assert_eq!(
            client.validate_attempt(&request),
            Err(expected),
            "{class:?}"
        );
    }
}

#[tokio::test]
async fn authorize_validates_the_upload_part_range_against_its_body() {
    let client = client_with(
        ProviderCapabilities::none(),
        UnwiredChargeAuthority,
        UnwiredProviderTransport,
    );
    let body_size = durable_put_body().size();

    let mut zero_part_number = upload_part_request();
    zero_part_number.put_part = Some(ProviderPutPart {
        part_number: 0,
        offset: 0,
        length: 1,
    });
    assert_eq!(
        client.validate_attempt(&zero_part_number),
        Err(ProviderClientError::InvalidPutPart)
    );

    let mut over_max_part_number = upload_part_request();
    over_max_part_number.put_part = Some(ProviderPutPart {
        part_number: PROVIDER_MAX_MULTIPART_PARTS + 1,
        offset: 0,
        length: 1,
    });
    assert_eq!(
        client.validate_attempt(&over_max_part_number),
        Err(ProviderClientError::InvalidPutPart)
    );

    let mut zero_length = upload_part_request();
    zero_length.put_part = Some(ProviderPutPart {
        part_number: 1,
        offset: 0,
        length: 0,
    });
    assert_eq!(
        client.validate_attempt(&zero_length),
        Err(ProviderClientError::InvalidPutPart)
    );

    let mut over_max_length = upload_part_request();
    over_max_length.put_part = Some(ProviderPutPart {
        part_number: 1,
        offset: 0,
        length: PROVIDER_MAX_PART_SIZE_BYTES + 1,
    });
    assert_eq!(
        client.validate_attempt(&over_max_length),
        Err(ProviderClientError::InvalidPutPart)
    );

    let mut overflowing = upload_part_request();
    overflowing.put_part = Some(ProviderPutPart {
        part_number: 1,
        offset: u64::MAX,
        length: 1,
    });
    assert_eq!(
        client.validate_attempt(&overflowing),
        Err(ProviderClientError::InvalidPutPart)
    );

    let mut past_body = upload_part_request();
    past_body.put_part = Some(ProviderPutPart {
        part_number: 1,
        offset: 0,
        length: body_size + 1,
    });
    assert_eq!(
        client.validate_attempt(&past_body),
        Err(ProviderClientError::InvalidPutPart)
    );

    let mut exact_end = upload_part_request();
    exact_end.put_part = Some(ProviderPutPart {
        part_number: 1,
        offset: 0,
        length: body_size,
    });
    assert!(client.validate_attempt(&exact_end).is_ok());
}

/// A part is non-final exactly when `offset + length < body.size`. Only a non-final part is held
/// to the provider's minimum part size; the final part (ending exactly at `body.size`) may be any
/// positive length.
#[tokio::test]
async fn authorize_requires_the_provider_minimum_for_a_non_final_upload_part_but_not_the_final_one()
{
    let client = client_with(
        ProviderCapabilities::none(),
        UnwiredChargeAuthority,
        UnwiredProviderTransport,
    );
    // Large enough to host a non-final part right up to (and one byte short of) the provider
    // minimum, with room left for a genuinely final byte after it.
    let body_size = PROVIDER_MIN_PART_SIZE_BYTES * 2;
    let body = durable_put_body_of_size(body_size);

    let mut base = base_request(ProviderAttemptClass::UploadPart);
    base.put_body = Some(body);

    let mut one_byte_non_final = base.clone();
    one_byte_non_final.put_part = Some(ProviderPutPart {
        part_number: 1,
        offset: 0,
        length: 1,
    });
    assert_eq!(
        client.validate_attempt(&one_byte_non_final),
        Err(ProviderClientError::InvalidPutPart)
    );

    let mut just_under_min_non_final = base.clone();
    just_under_min_non_final.put_part = Some(ProviderPutPart {
        part_number: 1,
        offset: 0,
        length: PROVIDER_MIN_PART_SIZE_BYTES - 1,
    });
    assert_eq!(
        client.validate_attempt(&just_under_min_non_final),
        Err(ProviderClientError::InvalidPutPart)
    );

    let mut exactly_min_non_final = base.clone();
    exactly_min_non_final.put_part = Some(ProviderPutPart {
        part_number: 1,
        offset: 0,
        length: PROVIDER_MIN_PART_SIZE_BYTES,
    });
    assert!(client.validate_attempt(&exactly_min_non_final).is_ok());

    let mut one_byte_final = base;
    one_byte_final.put_part = Some(ProviderPutPart {
        part_number: 2,
        offset: body_size - 1,
        length: 1,
    });
    assert!(client.validate_attempt(&one_byte_final).is_ok());
}

#[tokio::test]
async fn authorize_rejects_a_put_body_bound_to_a_different_request_or_boundary() {
    let client = client_with(
        ProviderCapabilities::none(),
        UnwiredChargeAuthority,
        UnwiredProviderTransport,
    );

    let other_request_key = put_spool_key(&other_logical_request_id(), &attempt_id());
    let other_request_ledger = ready_ledger_view_for(&other_request_key);
    let other_request_body =
        bind_durable_put_body(&spool_layout(), &other_request_key, &other_request_ledger)
            .expect("bind");
    let mut mismatched_request = put_object_request();
    mismatched_request.put_body = Some(other_request_body);
    assert_eq!(
        client.validate_attempt(&mismatched_request),
        Err(ProviderClientError::PutBodyRequestMismatch)
    );

    let other_boundary_key = SpoolObjectKey {
        provider_boundary_id: "cell.other.primary".to_string(),
        ..put_spool_key(&logical_request_id(), &attempt_id())
    };
    let other_boundary_ledger = ready_ledger_view_for(&other_boundary_key);
    let other_boundary_body =
        bind_durable_put_body(&spool_layout(), &other_boundary_key, &other_boundary_ledger)
            .expect("bind");
    let mut mismatched_boundary = put_object_request();
    mismatched_boundary.put_body = Some(other_boundary_body);
    assert_eq!(
        client.validate_attempt(&mismatched_boundary),
        Err(ProviderClientError::PutBodyBoundaryMismatch)
    );
}

/// The fields of a `ProviderChargeRequest` a `ProviderChargeAuthority` double can assert on,
/// copied out of the real (borrowed) value at the moment the authority receives it.
///
/// `ProviderChargeRequest` is deliberately not `Clone` (WP-114 CD-5 round 4 / INV-EJ P2): an
/// authority implementation that could retain a copy past the `charge()` call could charge again
/// later, outside any ledger, producing a committed grant the audit reports as zero in a shape the
/// frozen encoder accepts. A capture double must therefore read what it needs out of the borrow it
/// is handed and copy only those fields into a plain struct of our own -- never retain the value
/// itself. `debug_output` is the one exception a plain field-copy cannot substitute for: it is
/// captured with `format!("{request:?}")` while the real value is still alive, so a redaction test
/// can still inspect `ProviderChargeRequest`'s own `Debug` impl through this same capture path.
#[derive(Debug, Clone, PartialEq, Eq)]
struct CapturedChargeRequest {
    provider_boundary_id: String,
    traffic_class: ProviderTrafficClass,
    attempt_class: ProviderAttemptClass,
    attempt_units: u64,
    budget_pin_revision: String,
    budget_pin_fence: u64,
    logical_request_id: String,
    attempt_id: String,
    attempt_ordinal: u32,
    cap_classes: Vec<ProviderCapClass>,
    debug_output: String,
}

impl CapturedChargeRequest {
    fn from_request(request: &ProviderChargeRequest) -> Self {
        Self {
            provider_boundary_id: request.provider_boundary_id().to_string(),
            traffic_class: request.traffic_class(),
            attempt_class: request.attempt_class(),
            attempt_units: request.attempt_units(),
            budget_pin_revision: request.budget_pin().revision.clone(),
            budget_pin_fence: request.budget_pin().fence,
            logical_request_id: request.logical_request_id().to_string(),
            attempt_id: request.attempt_id().to_string(),
            attempt_ordinal: request.attempt_ordinal(),
            cap_classes: request.cap_classes(),
            debug_output: format!("{request:?}"),
        }
    }
}

/// Captures the fields of the `&ProviderChargeRequest` a `ProviderChargeAuthority` double receives
/// during a real `execute` call, copying them into a [`CapturedChargeRequest`] the caller retains.
/// The double always refuses with `Unwired` after capturing, so no grant is ever committed and no
/// ledger state needs cleanup between iterations -- only the request that reached the authority
/// matters here.
///
/// `authorize`/its `ProviderChargeRequest` return value are no longer public (WP-114 CD-5's ledger
/// binding fix made the constructor crate-private, because handing the charge request to a caller
/// let it charge outside any ledger). Asserting what the authority actually receives through a real
/// `execute` call is better coverage than asserting a helper's return value: it proves the request
/// reaches the authority, not merely that some function computed it.
async fn capture_charge_request_with_boundary(
    boundary: CellProviderBoundary,
    capabilities: ProviderCapabilities,
    request: &ProviderAttemptRequest,
    label: &str,
) -> CapturedChargeRequest {
    let captured: Arc<Mutex<Option<CapturedChargeRequest>>> = Arc::new(Mutex::new(None));
    let captured_for_closure = captured.clone();
    let (charge_authority, _calls) = ScriptedChargeAuthority::new(move |charge_request| {
        *captured_for_closure.lock().expect("capture lock") =
            Some(CapturedChargeRequest::from_request(charge_request));
        Err(ProviderChargeError::Unwired)
    });
    let provider_boundary_id = boundary.provider_boundary_id().to_string();
    let client = GovernedProviderClient::new(
        boundary,
        capabilities,
        ProviderRetryPolicy::disabled(),
        charge_authority,
        UnwiredProviderTransport,
    );
    let mut ledger = ProviderAttemptLedger::new(&provider_boundary_id, &request.logical_request_id)
        .expect("request's own logical_request_id must be a valid ledger identity");

    let metered = MeteredProviderAttemptRequest::try_from(request.clone())
        .unwrap_or_else(|error| panic!("{label}: request must be metered: {error}"));
    match client.execute(&mut ledger, &metered, &()).await {
        Err(ProviderClientError::ChargeRefused(ProviderChargeError::Unwired)) => {}
        other => panic!("{label}: expected the scripted Unwired refusal, got {other:?}"),
    }

    captured
        .lock()
        .expect("capture lock")
        .take()
        .unwrap_or_else(|| panic!("{label}: charge authority must have been called"))
}

async fn capture_charge_request(
    request: &ProviderAttemptRequest,
    label: &str,
) -> CapturedChargeRequest {
    capture_charge_request_with_boundary(
        boundary(),
        ProviderCapabilities::none().with_listing(),
        request,
        label,
    )
    .await
}

#[tokio::test]
async fn cd5_conformance_grant_binds_exactly_one_provider_attempt() {
    let metered_classes: Vec<_> = ProviderAttemptClass::ALL
        .into_iter()
        .filter(|class| *class != ProviderAttemptClass::GetObject)
        .collect();
    assert_eq!(metered_classes.len(), 10);
    for class in metered_classes {
        let request = attempt_request_for(class);
        let charge = capture_charge_request(&request, &format!("{class:?}")).await;

        assert_eq!(charge.attempt_units, 1, "{class:?}");
        assert_eq!(charge.provider_boundary_id, BOUNDARY_ID, "{class:?}");
        assert_eq!(charge.traffic_class, request.traffic_class, "{class:?}");
        assert_eq!(charge.attempt_class, request.attempt_class, "{class:?}");
        assert_eq!(
            charge.logical_request_id, request.logical_request_id,
            "{class:?}"
        );
        assert_eq!(charge.attempt_id, request.attempt_id, "{class:?}");
        assert_eq!(charge.attempt_ordinal, request.attempt_ordinal, "{class:?}");
        assert_eq!(
            charge.budget_pin_revision, request.budget_pin.revision,
            "{class:?}"
        );
        assert_eq!(
            charge.budget_pin_fence, request.budget_pin.fence,
            "{class:?}"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// 6. ProviderChargeRequest::cap_classes
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn cap_classes_always_start_with_the_shared_budget_and_include_exactly_the_matching_caps() {
    let metered_classes: Vec<_> = ProviderAttemptClass::ALL
        .into_iter()
        .filter(|class| *class != ProviderAttemptClass::GetObject)
        .collect();
    assert_eq!(metered_classes.len(), 10);
    for traffic_class in ProviderTrafficClass::ALL {
        for attempt_class in metered_classes.iter().copied() {
            let mut request = attempt_request_for(attempt_class);
            request.traffic_class = traffic_class;
            let charge = capture_charge_request(&request, &format!("{attempt_class:?}")).await;
            let caps = &charge.cap_classes;

            assert_eq!(caps.first(), Some(&ProviderCapClass::SharedPhysicalBudget));
            assert!(caps.contains(&traffic_class.cap_class()));

            let listing_count = caps
                .iter()
                .filter(|cap| **cap == ProviderCapClass::List)
                .count();
            if attempt_class.is_listing() {
                assert_eq!(listing_count, 1, "{attempt_class:?}");
                assert_eq!(caps.len(), 3, "{attempt_class:?}");
            } else {
                assert_eq!(listing_count, 0, "{attempt_class:?}");
                assert_eq!(caps.len(), 2, "{attempt_class:?}");
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// 7. execute: the charge-before-send kernel and the ledger
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn cd5_conformance_refused_charge_sends_nothing() {
    let cases = [
        ProviderChargeError::Unwired,
        ProviderChargeError::BudgetPinRejected,
        ProviderChargeError::BudgetExhausted,
        ProviderChargeError::ClassCapExhausted,
        ProviderChargeError::ConfigurationUnresolved,
        ProviderChargeError::AuthorityUnavailable,
        ProviderChargeError::DeadlineExceeded,
        ProviderChargeError::AttemptAlreadyCharged,
    ];

    for error in cases {
        let (charge_authority, charge_calls) =
            ScriptedChargeAuthority::new(move |_request| Err(error));
        let (transport, transport_calls) =
            ScriptedTransport::new(|_attempt| unreachable!("transport must not be reached"));
        let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
        let mut ledger = new_ledger();

        let outcome = client
            .execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness))
            .await;

        assert_eq!(
            outcome,
            Err(ProviderClientError::ChargeRefused(error)),
            "case: {error:?}"
        );
        assert_eq!(ledger.attempt_count(), 0, "case: {error:?}");
        assert_eq!(ledger.committed_grant_count(), 0, "case: {error:?}");
        assert_eq!(ledger.no_dispatch_count(), 0, "case: {error:?}");
        assert_eq!(ledger.decisive_terminal_count(), 0, "case: {error:?}");
        assert_eq!(ledger.ambiguous_count(), 0, "case: {error:?}");
        assert_eq!(ledger.poisoned(), None, "case: {error:?}");
        assert_eq!(charge_calls.get(), 1, "case: {error:?}");
        assert_eq!(transport_calls.get(), 0, "case: {error:?}");
    }
}

#[tokio::test]
async fn every_one_of_the_ten_metered_classes_calls_authority_exactly_once() {
    let metered_classes: Vec<_> = ProviderAttemptClass::ALL
        .into_iter()
        .filter(|class| *class != ProviderAttemptClass::GetObject)
        .collect();
    assert_eq!(metered_classes.len(), 10);

    for class in metered_classes {
        let (charge_authority, charge_calls) =
            ScriptedChargeAuthority::new(|_request| Err(ProviderChargeError::Unwired));
        let (transport, transport_calls) =
            ScriptedTransport::new(|_attempt| unreachable!("refused charge must not send"));
        let client = client_with(
            ProviderCapabilities::none().with_listing(),
            charge_authority,
            transport,
        );
        let request = attempt_request_for(class);
        let mut ledger = new_ledger();

        assert_eq!(
            client.execute(&mut ledger, &request).await,
            Err(ProviderClientError::ChargeRefused(
                ProviderChargeError::Unwired
            )),
            "{class:?}"
        );
        assert_eq!(charge_calls.get(), 1, "{class:?}");
        assert_eq!(transport_calls.get(), 0, "{class:?}");
        assert_eq!(ledger.committed_grant_count(), 0, "{class:?}");
        assert_eq!(ledger.attempt_count(), 0, "{class:?}");
    }
}

#[tokio::test]
async fn get_is_rejected_before_the_metered_authority_can_be_called() {
    let (charge_authority, charge_calls) =
        ScriptedChargeAuthority::new(|_request| panic!("GetObject reached the metered authority"));
    let (transport, transport_calls) =
        ScriptedTransport::new(|_attempt| unreachable!("GetObject must use execute_get"));
    let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
    let mut ledger = new_ledger();

    assert_eq!(
        client
            .execute(
                &mut ledger,
                &attempt_request_for(ProviderAttemptClass::GetObject),
            )
            .await,
        Err(ProviderClientError::GetObjectRequiresReadOnlyPath)
    );
    assert_eq!(charge_calls.get(), 0);
    assert_eq!(transport_calls.get(), 0);
}

#[tokio::test]
async fn unwired_charge_authority_and_transport_are_the_shipped_fail_closed_guards() {
    let client = client_with(
        ProviderCapabilities::none(),
        UnwiredChargeAuthority,
        UnwiredProviderTransport,
    );
    let mut ledger = new_ledger();

    let outcome = client
        .execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness))
        .await;

    assert_eq!(
        outcome,
        Err(ProviderClientError::ChargeRefused(
            ProviderChargeError::Unwired
        ))
    );
    assert_eq!(ledger.attempt_count(), 0);
    assert_eq!(ledger.committed_grant_count(), 0);
    assert_eq!(ledger.poisoned(), None);
}

#[tokio::test]
async fn cd5_conformance_ambiguous_commit_stays_charged_and_sends_nothing() {
    let (charge_authority, charge_calls) =
        ScriptedChargeAuthority::new(|_request| Err(ProviderChargeError::AmbiguousCommit));
    let (transport, transport_calls) =
        ScriptedTransport::new(|_attempt| unreachable!("transport must not be reached"));
    let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
    let mut ledger = new_ledger();

    let outcome = client
        .execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness))
        .await;

    assert_eq!(outcome, Err(ProviderClientError::ChargeAmbiguous));
    assert_eq!(ledger.committed_grant_count(), 1);
    assert_eq!(ledger.attempt_count(), 0);
    assert_eq!(ledger.ambiguous_count(), 0);
    assert_eq!(ledger.poisoned(), None);
    assert_eq!(charge_calls.get(), 1);
    assert_eq!(transport_calls.get(), 0);
}

#[tokio::test]
async fn same_ledger_already_charged_replay_does_not_increment_the_proven_single_charge() {
    let calls = Arc::new(AtomicU32::new(0));
    let response_calls = calls.clone();
    let (charge_authority, _charge_calls) = ScriptedChargeAuthority::new(move |request| {
        if response_calls.fetch_add(1, Ordering::SeqCst) == 0 {
            Ok(binding_grant(request))
        } else {
            Err(ProviderChargeError::AttemptAlreadyCharged)
        }
    });
    let (transport, transport_calls) = ScriptedTransport::new(|_attempt| {
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Decisive,
            provider_requests_issued: 1,
            response: (),
        })
    });
    let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
    let request = base_request(ProviderAttemptClass::Readiness);
    let mut ledger = new_ledger();

    assert_eq!(
        client.execute(&mut ledger, &request).await,
        Ok(ProviderAttemptOutcome::Decisive)
    );
    assert_eq!(
        client.execute(&mut ledger, &request).await,
        Err(ProviderClientError::ChargeRefused(
            ProviderChargeError::AttemptAlreadyCharged
        ))
    );
    assert_eq!(ledger.committed_grant_count(), 1);
    assert_eq!(ledger.attempt_count(), 1);
    assert_eq!(transport_calls.get(), 1);
}

#[tokio::test]
async fn fresh_ledger_recovery_counts_one_distinct_committed_charge_and_sends_nothing() {
    let (charge_authority, charge_calls) =
        ScriptedChargeAuthority::new(|_request| Err(ProviderChargeError::RecoveredCommittedCharge));
    let (transport, transport_calls) =
        ScriptedTransport::new(|_attempt| unreachable!("transport must not be reached"));
    let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
    let mut ledger = new_ledger();

    let outcome = client
        .execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness))
        .await;

    assert_eq!(outcome, Err(ProviderClientError::ChargeRecovered));
    assert_eq!(ledger.committed_grant_count(), 1);
    assert_eq!(ledger.attempt_count(), 0);
    assert_eq!(ledger.poisoned(), None);
    assert_eq!(charge_calls.get(), 1);
    assert_eq!(transport_calls.get(), 0);
}

#[tokio::test]
async fn dropping_execute_while_charge_is_pending_cannot_under_report_the_charge() {
    let client = client_with(
        ProviderCapabilities::none(),
        PendingChargeAuthority,
        UnwiredProviderTransport,
    );
    let request = base_request(ProviderAttemptClass::Readiness);
    let mut ledger = new_ledger();
    let mut execution = Box::pin(client.execute(&mut ledger, &request));

    tokio::select! {
        biased;
        outcome = &mut execution => panic!("pending authority unexpectedly resolved: {outcome:?}"),
        _ = tokio::time::sleep(Duration::ZERO) => {}
    }
    drop(execution);

    assert_eq!(ledger.committed_grant_count(), 1);
    assert_eq!(ledger.attempt_count(), 0);
}

#[tokio::test]
async fn success_after_one_cancel_reconciles_the_provisional_charge_to_exactly_one_grant() {
    let (transport, transport_calls) = ScriptedTransport::new(|_attempt| {
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Decisive,
            provider_requests_issued: 1,
            response: (),
        })
    });
    let client = client_with(
        ProviderCapabilities::none(),
        PendingThenSuccessChargeAuthority::new(1),
        transport,
    );
    let request = base_request(ProviderAttemptClass::Readiness);
    let mut ledger = new_ledger();
    let mut cancelled = Box::pin(client.execute(&mut ledger, &request));
    tokio::select! {
        biased;
        outcome = &mut cancelled => panic!("pending authority unexpectedly resolved: {outcome:?}"),
        _ = tokio::time::sleep(Duration::ZERO) => {}
    }
    drop(cancelled);

    let outcome = client.execute(&mut ledger, &request).await;

    assert_eq!(outcome, Ok(ProviderAttemptOutcome::Decisive));
    assert_eq!(ledger.committed_grant_count(), 1);
    assert_eq!(ledger.attempt_count(), 1);
    assert_eq!(transport_calls.get(), 1);
}

#[tokio::test]
async fn success_after_repeated_cancels_still_reconciles_to_exactly_one_grant() {
    let (transport, transport_calls) = ScriptedTransport::new(|_attempt| {
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Decisive,
            provider_requests_issued: 1,
            response: (),
        })
    });
    let client = client_with(
        ProviderCapabilities::none(),
        PendingThenSuccessChargeAuthority::new(2),
        transport,
    );
    let request = base_request(ProviderAttemptClass::Readiness);
    let mut ledger = new_ledger();

    for _ in 0..2 {
        let mut cancelled = Box::pin(client.execute(&mut ledger, &request));
        tokio::select! {
            biased;
            outcome = &mut cancelled => {
                panic!("pending authority unexpectedly resolved: {outcome:?}")
            },
            _ = tokio::time::sleep(Duration::ZERO) => {}
        }
        drop(cancelled);
    }

    let outcome = client.execute(&mut ledger, &request).await;

    assert_eq!(outcome, Ok(ProviderAttemptOutcome::Decisive));
    assert_eq!(ledger.committed_grant_count(), 1);
    assert_eq!(ledger.attempt_count(), 1);
    assert_eq!(transport_calls.get(), 1);
}

#[tokio::test]
async fn same_attempt_id_with_distinct_ordinals_counts_two_grants_and_two_attempts() {
    let (charge_authority, _charge_calls) =
        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
    let (transport, transport_calls) = ScriptedTransport::new(|_attempt| {
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Decisive,
            provider_requests_issued: 1,
            response: (),
        })
    });
    let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
    let first = base_request(ProviderAttemptClass::Readiness);
    let mut second = base_request(ProviderAttemptClass::Readiness);
    second.attempt_ordinal = 2;
    let mut ledger = new_ledger();

    assert_eq!(
        client.execute(&mut ledger, &first).await,
        Ok(ProviderAttemptOutcome::Decisive)
    );
    assert_eq!(
        client.execute(&mut ledger, &second).await,
        Ok(ProviderAttemptOutcome::Decisive)
    );
    assert_eq!(ledger.committed_grant_count(), 2);
    assert_eq!(ledger.attempt_count(), 2);
    assert_eq!(transport_calls.get(), 2);
}

#[tokio::test]
async fn distinct_attempt_ids_with_same_ordinal_count_two_grants_and_two_attempts() {
    let (charge_authority, _charge_calls) =
        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
    let (transport, transport_calls) = ScriptedTransport::new(|_attempt| {
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Decisive,
            provider_requests_issued: 1,
            response: (),
        })
    });
    let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
    let first = base_request(ProviderAttemptClass::Readiness);
    let mut second = base_request(ProviderAttemptClass::Readiness);
    second.attempt_id = other_attempt_id();
    let mut ledger = new_ledger();

    assert_eq!(
        client.execute(&mut ledger, &first).await,
        Ok(ProviderAttemptOutcome::Decisive)
    );
    assert_eq!(
        client.execute(&mut ledger, &second).await,
        Ok(ProviderAttemptOutcome::Decisive)
    );
    assert_eq!(ledger.committed_grant_count(), 2);
    assert_eq!(ledger.attempt_count(), 2);
    assert_eq!(transport_calls.get(), 2);
}

#[tokio::test]
async fn execute_poisons_the_ledger_when_the_grant_does_not_bind_the_attempt() {
    type Mutator = Box<dyn Fn(ProviderChargeGrant) -> ProviderChargeGrant + Sync>;
    let mutators: Vec<(&str, Mutator)> = vec![
        (
            "traffic_class",
            Box::new(|mut grant: ProviderChargeGrant| {
                grant.traffic_class = ProviderTrafficClass::Read;
                grant
            }),
        ),
        (
            "attempt_class",
            Box::new(|mut grant: ProviderChargeGrant| {
                grant.attempt_class = ProviderAttemptClass::HeadObject;
                grant
            }),
        ),
        (
            "charged_units",
            Box::new(|mut grant: ProviderChargeGrant| {
                grant.charged_units = 2;
                grant
            }),
        ),
        (
            "budget_pin.revision",
            Box::new(|mut grant: ProviderChargeGrant| {
                grant.budget_pin.revision = "other.revision".to_string();
                grant
            }),
        ),
        (
            "budget_pin.fence",
            Box::new(|mut grant: ProviderChargeGrant| {
                grant.budget_pin.fence += 1;
                grant
            }),
        ),
        (
            "logical_request_id",
            Box::new(|mut grant: ProviderChargeGrant| {
                grant.logical_request_id = other_logical_request_id();
                grant
            }),
        ),
        (
            "attempt_id",
            Box::new(|mut grant: ProviderChargeGrant| {
                grant.attempt_id = other_attempt_id();
                grant
            }),
        ),
        (
            "attempt_ordinal",
            Box::new(|mut grant: ProviderChargeGrant| {
                grant.attempt_ordinal += 1;
                grant
            }),
        ),
        (
            "granted_at_database_unix_ms",
            Box::new(|mut grant: ProviderChargeGrant| {
                grant.granted_at_database_unix_ms = -1;
                grant
            }),
        ),
        (
            "granted_at_database_unix_ms_at_deadline",
            Box::new(|mut grant: ProviderChargeGrant| {
                grant.granted_at_database_unix_ms = VALID_DEADLINE_MS;
                grant
            }),
        ),
        (
            "grant_id",
            Box::new(|mut grant: ProviderChargeGrant| {
                grant.grant_id = "not-a-uuid-v7".to_string();
                grant
            }),
        ),
    ];

    for (label, mutate) in mutators {
        let (charge_authority, charge_calls) =
            ScriptedChargeAuthority::new(move |request| Ok(mutate(binding_grant(request))));
        let (transport, transport_calls) =
            ScriptedTransport::new(|_attempt| unreachable!("transport must not be reached"));
        let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
        let mut ledger = new_ledger();

        let outcome = client
            .execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness))
            .await;

        assert_eq!(
            outcome,
            Err(ProviderClientError::GrantDoesNotBindAttempt),
            "case: {label}"
        );
        assert_eq!(ledger.committed_grant_count(), 1, "case: {label}");
        assert_eq!(ledger.attempt_count(), 0, "case: {label}");
        assert_eq!(
            ledger.poisoned(),
            Some(ProviderClientError::GrantDoesNotBindAttempt),
            "case: {label}"
        );
        assert_eq!(charge_calls.get(), 1, "case: {label}");
        assert_eq!(transport_calls.get(), 0, "case: {label}");
    }
}

#[tokio::test]
async fn execute_reports_transport_refusal_while_keeping_the_grant_charged() {
    let (charge_authority, _charge_calls) =
        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
    let client = client_with(
        ProviderCapabilities::none(),
        charge_authority,
        UnwiredProviderTransport,
    );
    let mut ledger = new_ledger();

    let outcome = client
        .execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness))
        .await;

    assert_eq!(
        outcome,
        Err(ProviderClientError::TransportRefused(
            ProviderTransportRefusal::Unwired
        ))
    );
    assert_eq!(ledger.committed_grant_count(), 1);
    assert_eq!(ledger.attempt_count(), 0);
    assert_eq!(ledger.poisoned(), None);

    let audit = ledger
        .audit_for(&logical_request_id())
        .expect("non-poisoned ledger must audit its own bound request");
    assert_eq!(audit.audit().committed_grant_count, 1);
    assert_eq!(audit.audit().attempt_count, 0);
}

#[tokio::test]
async fn exactly_one_report_returns_the_response_bound_to_that_attempt() {
    let (charge_authority, _charge_calls) =
        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
    let client = client_with(
        ProviderCapabilities::none(),
        charge_authority,
        TypedResponseTransport {
            outcome: ProviderAttemptOutcome::Decisive,
            provider_requests_issued: 1,
            response: "response-for-this-attempt",
        },
    );
    let mut ledger = new_ledger();

    let execution = client
        .execute_with_response(&mut ledger, &base_request(ProviderAttemptClass::Readiness))
        .await
        .expect("one authorized request must return its bound response");

    assert_eq!(execution.outcome, ProviderAttemptOutcome::Decisive);
    assert_eq!(execution.response, "response-for-this-attempt");
    assert_eq!(ledger.attempt_count(), 1);
    assert_eq!(ledger.ambiguous_count(), 0);
}

#[tokio::test]
async fn zero_and_multiple_request_reports_expose_no_transport_response() {
    for (issued, expected) in [
        (0, ProviderClientError::TransportReportInconsistent),
        (2, ProviderClientError::TransportIssuedUnauthorizedRequests),
    ] {
        let (charge_authority, _charge_calls) =
            ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
        let client = client_with(
            ProviderCapabilities::none(),
            charge_authority,
            TypedResponseTransport {
                outcome: ProviderAttemptOutcome::Decisive,
                provider_requests_issued: issued,
                response: "must-not-escape",
            },
        );
        let mut ledger = new_ledger();

        let result = client
            .execute_with_response(&mut ledger, &base_request(ProviderAttemptClass::Readiness))
            .await;

        assert_eq!(result, Err(expected), "issued request count: {issued}");
    }
}

#[tokio::test]
async fn dropping_a_pending_transport_after_grant_records_one_ambiguous_attempt() {
    let (charge_authority, _charge_calls) =
        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
    let client = client_with(
        ProviderCapabilities::none(),
        charge_authority,
        PendingProviderTransport,
    );
    let request = base_request(ProviderAttemptClass::Readiness);
    let mut ledger = new_ledger();
    let mut execution = Box::pin(client.execute_with_response(&mut ledger, &request));

    tokio::select! {
        biased;
        result = &mut execution => panic!("pending transport unexpectedly resolved: {result:?}"),
        _ = tokio::time::sleep(Duration::ZERO) => {}
    }
    drop(execution);

    assert_eq!(ledger.committed_grant_count(), 1);
    assert_eq!(ledger.attempt_count(), 1);
    assert_eq!(ledger.ambiguous_count(), 1);
    assert_eq!(ledger.decisive_terminal_count(), 0);
    assert_eq!(ledger.poisoned(), None);
}

#[tokio::test]
async fn execute_poisons_when_transport_reports_success_with_zero_requests_issued() {
    let (charge_authority, _charge_calls) =
        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
    let (transport, transport_calls) = ScriptedTransport::new(|_attempt| {
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Decisive,
            provider_requests_issued: 0,
            response: (),
        })
    });
    let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
    let mut ledger = new_ledger();

    let outcome = client
        .execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness))
        .await;

    assert_eq!(
        outcome,
        Err(ProviderClientError::TransportReportInconsistent)
    );
    assert_eq!(
        ledger.poisoned(),
        Some(ProviderClientError::TransportReportInconsistent)
    );
    assert_eq!(ledger.attempt_count(), 0);
    assert_eq!(ledger.committed_grant_count(), 1);
    assert_eq!(transport_calls.get(), 1);
}

#[tokio::test]
async fn execute_poisons_when_transport_issues_more_requests_than_authorized() {
    let (charge_authority, _charge_calls) =
        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
    let (transport, _transport_calls) = ScriptedTransport::new(|_attempt| {
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Decisive,
            provider_requests_issued: 2,
            response: (),
        })
    });
    let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
    let mut ledger = new_ledger();

    let outcome = client
        .execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness))
        .await;

    assert_eq!(
        outcome,
        Err(ProviderClientError::TransportIssuedUnauthorizedRequests)
    );
    assert_eq!(ledger.attempt_count(), 1);
    assert_eq!(ledger.committed_grant_count(), 1);
    assert_eq!(
        ledger.poisoned(),
        Some(ProviderClientError::TransportIssuedUnauthorizedRequests)
    );
}

#[tokio::test]
async fn execute_records_one_decisive_attempt() {
    let (charge_authority, _charge_calls) =
        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
    let (transport, transport_calls) = ScriptedTransport::new(|_attempt| {
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Decisive,
            provider_requests_issued: 1,
            response: (),
        })
    });
    let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
    let mut ledger = new_ledger();

    let outcome = client
        .execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness))
        .await;

    assert_eq!(outcome, Ok(ProviderAttemptOutcome::Decisive));
    assert_eq!(ledger.attempt_count(), 1);
    assert_eq!(ledger.committed_grant_count(), 1);
    assert_eq!(ledger.no_dispatch_count(), 0);
    assert_eq!(ledger.decisive_terminal_count(), 1);
    assert_eq!(ledger.ambiguous_count(), 0);
    assert_eq!(ledger.poisoned(), None);
    assert_eq!(transport_calls.get(), 1);
}

#[tokio::test]
async fn execute_records_one_ambiguous_attempt() {
    let (charge_authority, _charge_calls) =
        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
    let (transport, transport_calls) = ScriptedTransport::new(|_attempt| {
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Ambiguous,
            provider_requests_issued: 1,
            response: (),
        })
    });
    let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
    let mut ledger = new_ledger();

    let outcome = client
        .execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness))
        .await;

    assert_eq!(outcome, Ok(ProviderAttemptOutcome::Ambiguous));
    assert_eq!(ledger.attempt_count(), 1);
    assert_eq!(ledger.committed_grant_count(), 1);
    assert_eq!(ledger.no_dispatch_count(), 0);
    assert_eq!(ledger.decisive_terminal_count(), 0);
    assert_eq!(ledger.ambiguous_count(), 1);
    assert_eq!(ledger.poisoned(), None);
    assert_eq!(transport_calls.get(), 1);
}

#[tokio::test]
async fn execute_accumulates_counters_across_several_successful_attempts() {
    let mut ledger = new_ledger();
    for (index, outcome) in [
        ProviderAttemptOutcome::Decisive,
        ProviderAttemptOutcome::Decisive,
        ProviderAttemptOutcome::Decisive,
        ProviderAttemptOutcome::Ambiguous,
    ]
    .into_iter()
    .enumerate()
    {
        let (charge_authority, _charge_calls) =
            ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
        let (transport, _transport_calls) = ScriptedTransport::new(move |_attempt| {
            Ok(ProviderAttemptReport {
                outcome,
                provider_requests_issued: 1,
                response: (),
            })
        });
        let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
        client
            .execute(
                &mut ledger,
                &request_for_attempt_number(u32::try_from(index + 1).expect("small fixture index")),
            )
            .await
            .expect("attempt must succeed");
    }

    assert_eq!(ledger.attempt_count(), 4);
    assert_eq!(ledger.committed_grant_count(), 4);
    assert_eq!(ledger.no_dispatch_count(), 0);
    assert_eq!(ledger.decisive_terminal_count(), 3);
    assert_eq!(ledger.ambiguous_count(), 1);
    assert_eq!(ledger.poisoned(), None);
}

#[tokio::test]
async fn execute_returns_the_same_poison_and_calls_neither_seam_again() {
    let (charge_authority, charge_calls) =
        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
    let (transport, transport_calls) = ScriptedTransport::new(|_attempt| {
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Decisive,
            provider_requests_issued: 0,
            response: (),
        })
    });
    let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
    let mut ledger = new_ledger();

    let first = client
        .execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness))
        .await;
    assert_eq!(first, Err(ProviderClientError::TransportReportInconsistent));
    assert_eq!(charge_calls.get(), 1);
    assert_eq!(transport_calls.get(), 1);

    let second = client
        .execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness))
        .await;
    assert_eq!(
        second,
        Err(ProviderClientError::TransportReportInconsistent)
    );
    assert_eq!(
        charge_calls.get(),
        1,
        "charge authority must not be called again"
    );
    assert_eq!(
        transport_calls.get(),
        1,
        "transport must not be called again"
    );
}

#[tokio::test]
async fn execute_hands_the_transport_the_exact_authorized_permit() {
    let request = upload_part_request();
    let expected_target = target_value();
    let expected_opaque_handle = durable_put_body().opaque_handle().to_string();
    let expected_grant_id = grant_id();

    let (charge_authority, _charge_calls) =
        ScriptedChargeAuthority::new(|charge_request| Ok(binding_grant(charge_request)));
    let (transport, transport_calls) = ScriptedTransport::new(move |attempt| {
        assert_eq!(attempt.attempt_class(), ProviderAttemptClass::UploadPart);
        assert_eq!(attempt.traffic_class(), ProviderTrafficClass::Drain);
        assert_eq!(attempt.target(), &expected_target);
        assert_eq!(attempt.logical_request_id(), logical_request_id());
        assert_eq!(attempt.attempt_id(), attempt_id());
        assert_eq!(attempt.attempt_ordinal(), 1);
        assert_eq!(
            attempt
                .put_body()
                .map(DurableProviderPutBody::opaque_handle),
            Some(expected_opaque_handle.as_str())
        );
        assert_eq!(
            attempt.put_part(),
            Some(ProviderPutPart {
                part_number: 1,
                offset: 0,
                length: DURABLE_BODY_SIZE,
            })
        );
        assert_eq!(attempt.grant().grant_id, expected_grant_id);
        assert_eq!(attempt.retry_policy().max_attempts(), 1);
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Decisive,
            provider_requests_issued: 1,
            response: (),
        })
    });
    let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
    let mut ledger = new_ledger();

    let outcome = client.execute(&mut ledger, &request).await;

    assert_eq!(outcome, Ok(ProviderAttemptOutcome::Decisive));
    assert_eq!(transport_calls.get(), 1);
}

// ---------------------------------------------------------------------------------------------
// 7b. ProviderAttemptLedger::new and execute's ledger/request binding (INV-EJ P1)
// ---------------------------------------------------------------------------------------------
//
// Before this fix, `ProviderAttemptLedger` carried five counters and no identity, and `execute`
// never compared the request it was given to anything: one ledger could accumulate two different
// logical requests' attempts and then be attached to one request's compact receipt, and the frozen
// encoder would accept that shape because it validates counters without knowing whose they are.
// `ProviderAttemptLedger::new` now takes and validates the boundary/request identity, and `execute`
// refuses any attempt naming a different logical request or boundary than the ledger is bound to,
// checked before the poison and no-dispatch guards and before `authorize`, the charge, and the
// transport -- whether this is even the caller's ledger precedes every other question, including
// what state that ledger is in. Like `DispatchAfterNoDispatch`, the refusal never poisons the
// ledger. See `execute_on_a_poisoned_ledger_reports_mismatch_for_a_different_request_but_still_the_poison_for_its_own`
// below for the case this order actually distinguishes from poison-first.

#[tokio::test]
async fn ledger_new_validates_boundary_and_request_identity_and_exposes_them() {
    let ledger = ProviderAttemptLedger::new(BOUNDARY_ID, &logical_request_id())
        .expect("valid boundary and request identity must construct");
    assert_eq!(ledger.provider_boundary_id(), BOUNDARY_ID);
    assert_eq!(ledger.logical_request_id(), logical_request_id());

    assert_eq!(
        ProviderAttemptLedger::new("", &logical_request_id()),
        Err(ProviderClientError::InvalidProviderBoundaryId)
    );
    assert_eq!(
        ProviderAttemptLedger::new(BOUNDARY_ID, "not-a-uuid"),
        Err(ProviderClientError::InvalidRequestIdentity)
    );
}

/// The reviewer's exact finding: drive one ledger through a successful attempt for request A, then
/// attempt request B on the same ledger. Request B must be refused, and the ledger's counters must
/// still describe only request A -- the two-request accumulation the finding reported is no longer
/// possible.
#[tokio::test]
async fn a_ledger_that_completed_one_request_refuses_to_accumulate_a_second_requests_attempts() {
    let request_a = base_request(ProviderAttemptClass::Readiness);
    let mut ledger = ProviderAttemptLedger::new(BOUNDARY_ID, &request_a.logical_request_id)
        .expect("valid ledger identity for request A");

    let (charge_authority_a, _calls) =
        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
    let (transport_a, _calls2) = ScriptedTransport::new(|_attempt| {
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Decisive,
            provider_requests_issued: 1,
            response: (),
        })
    });
    let client_a = client_with(
        ProviderCapabilities::none(),
        charge_authority_a,
        transport_a,
    );
    client_a
        .execute(&mut ledger, &request_a)
        .await
        .expect("request A's attempt must succeed");

    assert_eq!(ledger.attempt_count(), 1);
    assert_eq!(ledger.committed_grant_count(), 1);
    assert_eq!(ledger.decisive_terminal_count(), 1);

    let mut request_b = base_request(ProviderAttemptClass::Readiness);
    request_b.logical_request_id = other_logical_request_id();
    request_b.attempt_id = other_attempt_id();

    let (charge_authority_b, charge_calls_b) =
        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
    let (transport_b, transport_calls_b) = ScriptedTransport::new(|_attempt| {
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Decisive,
            provider_requests_issued: 1,
            response: (),
        })
    });
    let client_b = client_with(
        ProviderCapabilities::none(),
        charge_authority_b,
        transport_b,
    );

    let outcome = client_b.execute(&mut ledger, &request_b).await;

    assert_eq!(outcome, Err(ProviderClientError::LedgerRequestMismatch));
    assert_eq!(
        charge_calls_b.get(),
        0,
        "request B must never reach the charge authority"
    );
    assert_eq!(
        transport_calls_b.get(),
        0,
        "request B must never reach the transport"
    );

    assert_eq!(ledger.attempt_count(), 1);
    assert_eq!(ledger.committed_grant_count(), 1);
    assert_eq!(ledger.decisive_terminal_count(), 1);
    assert_eq!(ledger.ambiguous_count(), 0);
    assert_eq!(ledger.no_dispatch_count(), 0);
    assert_eq!(ledger.poisoned(), None);
    assert_eq!(ledger.logical_request_id(), request_a.logical_request_id);

    let audit = ledger
        .audit_for(&request_a.logical_request_id)
        .expect("ledger must still audit request A only");
    assert_eq!(audit.audit().attempt_count, 1);
    assert_eq!(audit.audit().decisive_terminal_count, 1);
    validate_and_encode_object_store_provider_attempt_audit(
        audit.audit(),
        &compact_receipt_limits(),
    )
    .expect("request A's audit must still be accepted by the frozen encoder");

    // The audit binding (not only execute's) refuses request B's id too: naming B never gets a
    // receipt attached to A's counters.
    assert_eq!(
        ledger.audit_for(&request_b.logical_request_id),
        Err(ProviderClientError::LedgerRequestMismatch)
    );
}

#[tokio::test]
async fn execute_refuses_an_attempt_naming_a_different_logical_request_than_the_ledger_is_bound_to()
{
    let mut ledger = ProviderAttemptLedger::new(BOUNDARY_ID, &logical_request_id())
        .expect("valid ledger identity");

    let mut request = base_request(ProviderAttemptClass::Readiness);
    request.logical_request_id = other_logical_request_id();

    let (charge_authority, charge_calls) =
        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
    let (transport, transport_calls) = ScriptedTransport::new(|_attempt| {
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Decisive,
            provider_requests_issued: 1,
            response: (),
        })
    });
    let client = client_with(ProviderCapabilities::none(), charge_authority, transport);

    let outcome = client.execute(&mut ledger, &request).await;

    assert_eq!(outcome, Err(ProviderClientError::LedgerRequestMismatch));
    assert_eq!(ledger.poisoned(), None);
    assert_eq!(ledger.attempt_count(), 0);
    assert_eq!(ledger.committed_grant_count(), 0);
    assert_eq!(ledger.no_dispatch_count(), 0);
    assert_eq!(ledger.decisive_terminal_count(), 0);
    assert_eq!(ledger.ambiguous_count(), 0);
    assert_eq!(charge_calls.get(), 0, "charge authority must not be called");
    assert_eq!(transport_calls.get(), 0, "transport must not be called");

    let audit = ledger
        .audit_for(&logical_request_id())
        .expect("unpoisoned ledger must still audit its own bound request");
    validate_and_encode_object_store_provider_attempt_audit(
        audit.audit(),
        &compact_receipt_limits(),
    )
    .expect("audit must be accepted by the frozen encoder");
}

#[tokio::test]
async fn execute_refuses_an_attempt_when_the_ledger_is_bound_to_a_different_boundary_than_the_client()
 {
    let mut ledger = ProviderAttemptLedger::new("cell.other.primary", &logical_request_id())
        .expect("valid ledger identity for a different boundary");

    // Otherwise entirely valid, and its logical_request_id matches the ledger's -- only the
    // boundary differs, isolating that half of the binding check.
    let request = base_request(ProviderAttemptClass::Readiness);

    let (charge_authority, charge_calls) =
        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
    let (transport, transport_calls) = ScriptedTransport::new(|_attempt| {
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Decisive,
            provider_requests_issued: 1,
            response: (),
        })
    });
    let client = client_with(ProviderCapabilities::none(), charge_authority, transport);

    let outcome = client.execute(&mut ledger, &request).await;

    assert_eq!(outcome, Err(ProviderClientError::LedgerRequestMismatch));
    assert_eq!(ledger.poisoned(), None);
    assert_eq!(ledger.attempt_count(), 0);
    assert_eq!(ledger.committed_grant_count(), 0);
    assert_eq!(charge_calls.get(), 0, "charge authority must not be called");
    assert_eq!(transport_calls.get(), 0, "transport must not be called");

    let audit = ledger
        .audit_for(&logical_request_id())
        .expect("unpoisoned ledger must still audit its own bound request");
    validate_and_encode_object_store_provider_attempt_audit(
        audit.audit(),
        &compact_receipt_limits(),
    )
    .expect("audit must be accepted by the frozen encoder");
}

/// Regression guard that the binding check is not over-tight: a ledger bound to exactly the
/// attempt's request and boundary still works end to end.
#[tokio::test]
async fn execute_succeeds_when_the_ledger_is_bound_to_exactly_the_attempts_request_and_boundary() {
    let request = base_request(ProviderAttemptClass::Readiness);
    let mut ledger = ProviderAttemptLedger::new(BOUNDARY_ID, &request.logical_request_id)
        .expect("valid ledger identity matching the request");

    let (charge_authority, _calls) =
        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
    let (transport, _calls2) = ScriptedTransport::new(|_attempt| {
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Decisive,
            provider_requests_issued: 1,
            response: (),
        })
    });
    let client = client_with(ProviderCapabilities::none(), charge_authority, transport);

    let outcome = client.execute(&mut ledger, &request).await;

    assert_eq!(outcome, Ok(ProviderAttemptOutcome::Decisive));
    assert_eq!(ledger.attempt_count(), 1);
    assert_eq!(ledger.committed_grant_count(), 1);
    assert_eq!(ledger.decisive_terminal_count(), 1);
    assert_eq!(ledger.poisoned(), None);
}

/// A listing class with no listing capability granted would independently fail `authorize`'s
/// capability gate. Binding the ledger to a different logical request than the attempt proves the
/// ledger/request binding wins: it is checked before `authorize`, not merely whichever error a
/// combined check happens to sort first.
#[tokio::test]
async fn execute_refuses_the_ledger_mismatch_before_authorize_even_when_the_request_would_also_fail_validation()
 {
    let mut ledger = ProviderAttemptLedger::new(BOUNDARY_ID, &other_logical_request_id())
        .expect("valid ledger identity for a different request");

    // Default logical_request_id (mismatched with the ledger above); a listing class with no
    // listing capability granted on the client below.
    let request = base_request(ProviderAttemptClass::ListObjectsV2);

    let (charge_authority, charge_calls) =
        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
    let (transport, transport_calls) =
        ScriptedTransport::new(|_attempt| unreachable!("transport must not be reached"));
    let client = client_with(ProviderCapabilities::none(), charge_authority, transport);

    let outcome = client.execute(&mut ledger, &request).await;

    assert_eq!(outcome, Err(ProviderClientError::LedgerRequestMismatch));
    assert_eq!(charge_calls.get(), 0);
    assert_eq!(transport_calls.get(), 0);
    assert_eq!(ledger.poisoned(), None);
}

/// Guard order (INV-EJ round 5): the ledger/request identity check now precedes the
/// `DispatchAfterNoDispatch` check, so an attempt naming a *different* logical request than a
/// no-dispatch-recorded ledger reports the mismatch it actually has, not a sequencing fault it
/// does not have. Paired with `execute_refuses_after_a_recorded_no_dispatch_without_poisoning_the_ledger`
/// (Section 9), which pins the other direction on the same kind of ledger: an attempt naming the
/// ledger's *own* request after the same no-dispatch still reports `DispatchAfterNoDispatch`.
#[tokio::test]
async fn execute_reports_the_ledger_mismatch_before_dispatch_after_no_dispatch_on_a_no_dispatch_ledger()
 {
    let mut ledger = new_ledger();
    ledger
        .record_no_dispatch(&no_dispatch_proof())
        .expect("record no dispatch on a fresh ledger");

    let mut request = base_request(ProviderAttemptClass::Readiness);
    request.logical_request_id = other_logical_request_id();

    let (charge_authority, charge_calls) =
        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
    let (transport, transport_calls) =
        ScriptedTransport::new(|_attempt| unreachable!("transport must not be reached"));
    let client = client_with(ProviderCapabilities::none(), charge_authority, transport);

    let outcome = client.execute(&mut ledger, &request).await;

    assert_eq!(outcome, Err(ProviderClientError::LedgerRequestMismatch));
    assert_eq!(ledger.poisoned(), None);
    assert_eq!(ledger.no_dispatch_count(), 1);
    assert_eq!(ledger.attempt_count(), 0);
    assert_eq!(ledger.committed_grant_count(), 0);
    assert_eq!(charge_calls.get(), 0, "charge authority must not be called");
    assert_eq!(transport_calls.get(), 0, "transport must not be called");
}

/// The case that distinguishes `execute`'s current identity-then-poison order from the poison-first
/// order it used to have: on a poisoned ledger, an attempt naming a *different* logical request must
/// report `LedgerRequestMismatch`, not leak this ledger's poison to a caller asking about a request
/// it never handled, while an attempt naming the ledger's own bound request must still surface the
/// poison. Mirrors `audit_for_returns_the_poison_for_the_bound_request_id_on_a_poisoned_ledger` /
/// `audit_for_returns_a_ledger_request_mismatch_for_a_different_id_on_a_poisoned_ledger` (Section 9),
/// which already pinned this shape for `audit_for`; `execute` had no equivalent pair, which is
/// exactly how the two functions' orders were able to disagree unnoticed. Neither call reaches the
/// charge authority or the transport, and the ledger's poison/counters are unchanged by either --
/// a rejected call never mutates.
#[tokio::test]
async fn execute_on_a_poisoned_ledger_reports_mismatch_for_a_different_request_but_still_the_poison_for_its_own()
 {
    let (charge_authority, charge_calls) =
        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
    let (transport, transport_calls) = ScriptedTransport::new(|_attempt| {
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Decisive,
            provider_requests_issued: 0,
            response: (),
        })
    });
    let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
    let mut ledger = new_ledger();

    // Poison the ledger.
    let poisoning = client
        .execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness))
        .await;
    assert_eq!(
        poisoning,
        Err(ProviderClientError::TransportReportInconsistent)
    );
    assert_eq!(
        ledger.poisoned(),
        Some(ProviderClientError::TransportReportInconsistent)
    );
    let attempt_count_after_poisoning = ledger.attempt_count();
    let committed_grant_count_after_poisoning = ledger.committed_grant_count();
    assert_eq!(charge_calls.get(), 1);
    assert_eq!(transport_calls.get(), 1);

    // A different logical request: the identity check runs first, so the caller is told this
    // isn't its ledger rather than handed a poison belonging to someone else's request.
    let mut different_request = base_request(ProviderAttemptClass::Readiness);
    different_request.logical_request_id = other_logical_request_id();
    different_request.attempt_id = other_attempt_id();

    let mismatch_outcome = client.execute(&mut ledger, &different_request).await;
    assert_eq!(
        mismatch_outcome,
        Err(ProviderClientError::LedgerRequestMismatch)
    );
    assert_eq!(
        ledger.poisoned(),
        Some(ProviderClientError::TransportReportInconsistent),
        "poison must be unchanged by the rejected mismatched-identity call"
    );
    assert_eq!(ledger.attempt_count(), attempt_count_after_poisoning);
    assert_eq!(
        ledger.committed_grant_count(),
        committed_grant_count_after_poisoning
    );
    assert_eq!(
        charge_calls.get(),
        1,
        "a mismatched-identity attempt must not reach the charge authority"
    );
    assert_eq!(
        transport_calls.get(),
        1,
        "a mismatched-identity attempt must not reach the transport"
    );

    // The ledger's own bound request: identity matches, so the poison still surfaces, unchanged.
    let own_request_outcome = client
        .execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness))
        .await;
    assert_eq!(
        own_request_outcome,
        Err(ProviderClientError::TransportReportInconsistent)
    );
    assert_eq!(
        ledger.poisoned(),
        Some(ProviderClientError::TransportReportInconsistent),
        "poison must be unchanged by the rejected own-request replay"
    );
    assert_eq!(ledger.attempt_count(), attempt_count_after_poisoning);
    assert_eq!(
        ledger.committed_grant_count(),
        committed_grant_count_after_poisoning
    );
    assert_eq!(
        charge_calls.get(),
        1,
        "an own-request replay on a poisoned ledger must not reach the charge authority again"
    );
    assert_eq!(
        transport_calls.get(),
        1,
        "an own-request replay on a poisoned ledger must not reach the transport again"
    );
}

// ---------------------------------------------------------------------------------------------
// 8. ProviderRetryPolicy
// ---------------------------------------------------------------------------------------------

// `ProviderRetryPolicy` has exactly one inhabitant -- the private-tuple-constructed
// `ProviderRetryPolicy(())`, reachable only through `disabled()`, whose `max_attempts()` always
// returns the const `1`. There is nothing behavioral to assert about a single-inhabitant type
// beyond restating its own body, so no test asserts `max_attempts() == 1` here.
//
// The actual enforcement this type documents is narrower than "SDK retry is off": a transport
// whose `provider_requests_issued` is anything but exactly `1` closes the ledger, regardless of
// whether the extra requests came from an SDK-internal retry or the transport simply misreporting.
// See the module header's corrected wording, and Section 7's
// `execute_poisons_when_transport_issues_more_requests_than_authorized` and
// `execute_poisons_when_transport_reports_success_with_zero_requests_issued` for the tests that
// actually exercise this contract.

// ---------------------------------------------------------------------------------------------
// 9. ProviderAttemptLedger::record_no_dispatch and audit
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn record_no_dispatch_succeeds_once_then_refuses_a_second_call() {
    let mut ledger = new_ledger();

    assert!(ledger.record_no_dispatch(&no_dispatch_proof()).is_ok());
    assert_eq!(ledger.no_dispatch_count(), 1);

    assert_eq!(
        ledger.record_no_dispatch(&no_dispatch_proof()),
        Err(ProviderClientError::NoDispatchNotPermitted)
    );
    assert_eq!(ledger.no_dispatch_count(), 1);
}

/// The exact fail-open the reviewer found: a no-dispatch proof asserts nothing reached the
/// provider, so ANY issued attempt forbids it -- including one whose outcome was merely
/// `Ambiguous` rather than a decisive terminal. Recording a no-dispatch after an ambiguous attempt
/// would let the audit claim a dispatched request never dispatched.
#[tokio::test]
async fn record_no_dispatch_refuses_after_any_issued_attempt_decisive_or_ambiguous() {
    for outcome in [
        ProviderAttemptOutcome::Decisive,
        ProviderAttemptOutcome::Ambiguous,
    ] {
        let (charge_authority, _charge_calls) =
            ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
        let (transport, _transport_calls) = ScriptedTransport::new(move |_attempt| {
            Ok(ProviderAttemptReport {
                outcome,
                provider_requests_issued: 1,
                response: (),
            })
        });
        let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
        let mut ledger = new_ledger();
        client
            .execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness))
            .await
            .unwrap_or_else(|error| panic!("{outcome:?} attempt must succeed: {error}"));

        assert_eq!(
            ledger.record_no_dispatch(&no_dispatch_proof()),
            Err(ProviderClientError::NoDispatchNotPermitted),
            "case: {outcome:?}"
        );
        assert_eq!(ledger.no_dispatch_count(), 0, "case: {outcome:?}");
    }
}

/// A committed grant that never reached the wire is exactly the case a no-dispatch proof records
/// -- unlike an issued attempt, it must not forbid recording one.
#[tokio::test]
async fn record_no_dispatch_is_still_allowed_after_a_committed_grant_that_never_reached_the_wire() {
    let (charge_authority, _charge_calls) =
        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
    let client = client_with(
        ProviderCapabilities::none(),
        charge_authority,
        UnwiredProviderTransport,
    );
    let mut ledger = new_ledger();

    let outcome = client
        .execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness))
        .await;
    assert_eq!(
        outcome,
        Err(ProviderClientError::TransportRefused(
            ProviderTransportRefusal::Unwired
        ))
    );
    assert_eq!(ledger.committed_grant_count(), 1);
    assert_eq!(ledger.attempt_count(), 0);
    assert_eq!(ledger.poisoned(), None);

    ledger
        .record_no_dispatch(&no_dispatch_proof())
        .expect("no-dispatch must be permitted after a grant with no attempt");
    assert_eq!(ledger.no_dispatch_count(), 1);

    let audit = ledger
        .audit_for(&logical_request_id())
        .expect("non-poisoned ledger must audit its own bound request");
    validate_and_encode_object_store_provider_attempt_audit(
        audit.audit(),
        &compact_receipt_limits(),
    )
    .expect("audit must be accepted by the frozen encoder");
}

/// A recorded no-dispatch asserts the request resolved without reaching the provider. The refusal
/// happens before anything is charged or sent, so it is the mirror image of the sequencing fault
/// `record_no_dispatch` itself refuses (an issued attempt after a no-dispatch): `execute` refuses
/// the call, but the ledger stays open and unpoisoned, keeping the truthful
/// `{no_dispatch: 1, attempt: 0}` audit finalizable rather than destroying it.
#[tokio::test]
async fn execute_refuses_after_a_recorded_no_dispatch_without_poisoning_the_ledger() {
    let mut ledger = new_ledger();
    ledger
        .record_no_dispatch(&no_dispatch_proof())
        .expect("record no dispatch on a fresh ledger");

    let (charge_authority, charge_calls) =
        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
    let (transport, transport_calls) = ScriptedTransport::new(|_attempt| {
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Decisive,
            provider_requests_issued: 1,
            response: (),
        })
    });
    let client = client_with(ProviderCapabilities::none(), charge_authority, transport);

    let outcome = client
        .execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness))
        .await;

    assert_eq!(outcome, Err(ProviderClientError::DispatchAfterNoDispatch));
    assert_eq!(
        ledger.poisoned(),
        None,
        "the refusal happens before any charge or send, so it must not destroy a truthful \
         no-dispatch audit"
    );
    assert_eq!(ledger.no_dispatch_count(), 1);
    assert_eq!(ledger.attempt_count(), 0);
    assert_eq!(ledger.committed_grant_count(), 0);
    assert_eq!(ledger.decisive_terminal_count(), 0);
    assert_eq!(ledger.ambiguous_count(), 0);
    assert_eq!(
        charge_calls.get(),
        0,
        "charge authority must not be called after a recorded no-dispatch"
    );
    assert_eq!(
        transport_calls.get(),
        0,
        "transport must not be called after a recorded no-dispatch"
    );

    let audit = ledger.audit_for(&logical_request_id()).expect(
        "the refused-but-unpoisoned ledger must still produce an audit for its own bound request",
    );
    assert_eq!(audit.audit().no_dispatch_count, 1);
    assert_eq!(audit.audit().attempt_count, 0);
    validate_and_encode_object_store_provider_attempt_audit(
        audit.audit(),
        &compact_receipt_limits(),
    )
    .expect("the truthful no-dispatch audit must still be accepted by the frozen encoder");
}

#[tokio::test]
async fn record_no_dispatch_returns_the_poison_on_a_poisoned_ledger() {
    let (charge_authority, _charge_calls) =
        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
    let (transport, _transport_calls) = ScriptedTransport::new(|_attempt| {
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Decisive,
            provider_requests_issued: 0,
            response: (),
        })
    });
    let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
    let mut ledger = new_ledger();
    let _ = client
        .execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness))
        .await;
    assert_eq!(
        ledger.poisoned(),
        Some(ProviderClientError::TransportReportInconsistent)
    );

    // `record_no_dispatch` takes no request id, so there is no identity to check against poison
    // here -- it always reports the poison. This is unaffected by `audit_for`'s
    // identity-before-poison ordering below; the two guards have nothing in common to reorder.
    assert_eq!(
        ledger.record_no_dispatch(&no_dispatch_proof()),
        Err(ProviderClientError::TransportReportInconsistent)
    );
}

// `ProviderAttemptLedger::audit_for` checks the request identity before the poison (see its own
// doc comment on the ordering rationale: whether this is the caller's ledger at all precedes any
// question about the state that ledger is in). Do not "fix" this back to poison-first: on a
// poisoned ledger, only the ledger's own bound request id may surface the poison; a different
// (but validly formed) id names a request this ledger never handled at all, so it must surface
// `LedgerRequestMismatch` instead -- never leaking this ledger's poison to a caller asking about
// someone else's request. Keep both cases below if this ordering is ever touched again.

#[tokio::test]
async fn audit_for_returns_the_poison_for_the_bound_request_id_on_a_poisoned_ledger() {
    let (charge_authority, _charge_calls) =
        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
    let (transport, _transport_calls) = ScriptedTransport::new(|_attempt| {
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Decisive,
            provider_requests_issued: 0,
            response: (),
        })
    });
    let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
    let mut ledger = new_ledger();
    let _ = client
        .execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness))
        .await;
    assert_eq!(
        ledger.poisoned(),
        Some(ProviderClientError::TransportReportInconsistent)
    );

    assert_eq!(
        ledger.audit_for(&logical_request_id()),
        Err(ProviderClientError::TransportReportInconsistent)
    );
}

#[tokio::test]
async fn audit_for_returns_a_ledger_request_mismatch_for_a_different_id_on_a_poisoned_ledger() {
    let (charge_authority, _charge_calls) =
        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
    let (transport, _transport_calls) = ScriptedTransport::new(|_attempt| {
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Decisive,
            provider_requests_issued: 0,
            response: (),
        })
    });
    let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
    let mut ledger = new_ledger();
    let _ = client
        .execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness))
        .await;
    assert_eq!(
        ledger.poisoned(),
        Some(ProviderClientError::TransportReportInconsistent)
    );

    assert_eq!(
        ledger.audit_for(&other_logical_request_id()),
        Err(ProviderClientError::LedgerRequestMismatch)
    );
}

// ---------------------------------------------------------------------------------------------
// 9b. ProviderAttemptLedger::audit_for identity binding (INV-EJ round 5)
// ---------------------------------------------------------------------------------------------
//
// Binding `execute`'s input (Section 7b) was only half of INV-EJ B1: the audit itself carried
// bare counters, so a correctly accumulated audit could still be attached to another request's
// compact receipt, and the frozen encoder would accept that shape because it validates counters
// without knowing whose they are. `audit_for` closes that half by requiring the caller to name the
// request, and refusing unless it is exactly the ledger's own bound request.

#[tokio::test]
async fn audit_for_the_bound_request_id_returns_ok_with_the_expected_counters() {
    let (charge_authority, _calls) =
        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
    let (transport, _calls2) = ScriptedTransport::new(|_attempt| {
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Decisive,
            provider_requests_issued: 1,
            response: (),
        })
    });
    let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
    let mut ledger = new_ledger();
    client
        .execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness))
        .await
        .expect("attempt must succeed");

    let audit = ledger
        .audit_for(&logical_request_id())
        .expect("the ledger's own bound request id must audit");
    assert_eq!(audit.audit().attempt_count, 1);
    assert_eq!(audit.audit().committed_grant_count, 1);
    assert_eq!(audit.audit().decisive_terminal_count, 1);
    assert_eq!(audit.audit().ambiguous_count, 0);
    assert_eq!(audit.audit().no_dispatch_count, 0);
}

#[tokio::test]
async fn audit_for_a_different_valid_uuidv7_request_id_is_a_ledger_request_mismatch() {
    let ledger = new_ledger();

    assert_eq!(
        ledger.audit_for(&other_logical_request_id()),
        Err(ProviderClientError::LedgerRequestMismatch)
    );
}

#[tokio::test]
async fn audit_for_a_malformed_request_id_is_a_ledger_request_mismatch_not_a_validation_error() {
    let ledger = new_ledger();

    // audit_for compares the caller-supplied id against the ledger's own bound id by equality; it
    // does not re-validate the caller's string as canonical UUIDv7. A malformed id is therefore
    // still a mismatch -- the same error a well-formed-but-different id gets -- never
    // `InvalidRequestIdentity`.
    assert_eq!(
        ledger.audit_for("not-a-uuid"),
        Err(ProviderClientError::LedgerRequestMismatch)
    );
    assert_eq!(
        ledger.audit_for(""),
        Err(ProviderClientError::LedgerRequestMismatch)
    );
}

// `ProviderClientError::LedgerAlgebraViolation` restates the frozen encoder's own algebra at the
// ledger, so a transition this crate later gets wrong fails at the ledger instead of downstream.
// Every increment path the public API can reach (`record_committed_grant`,
// `record_issued_attempt`, `record_decisive_terminal`, `record_ambiguous`, and
// `record_no_dispatch`'s own preconditions) keeps `attempt_count <= committed_grant_count`,
// `decisive_terminal_count + ambiguous_count <= attempt_count`, `no_dispatch_count <= 1`, and
// `no_dispatch_count == 1` only while `decisive_terminal_count == 0`. As far as this suite can
// determine, no sequence of public `execute`/`record_no_dispatch` calls can violate that algebra,
// so `LedgerAlgebraViolation` is not reachable through the public API today -- this is stated
// honestly rather than fabricated by poking private fields. What the matrix below proves instead
// is the *mirroring* property the variant exists to guard: for every ledger state reachable
// through the real API, `audit_for` the ledger's own bound request returns `Ok`, and the frozen
// encoder accepts that value.

/// Every terminal error path `execute` can take, applied to `ledger`'s current state through the
/// real public API. `"none"` performs no action. Used only by the systematic matrix below.
async fn apply_terminal_action(
    label: &str,
    ledger: &mut ProviderAttemptLedger,
    attempt_number: u32,
) {
    let request = request_for_attempt_number(attempt_number);
    match label {
        "none" => {}
        "charge_ambiguous_commit" => {
            let (charge_authority, _calls) =
                ScriptedChargeAuthority::new(|_request| Err(ProviderChargeError::AmbiguousCommit));
            let (transport, _calls2) =
                ScriptedTransport::new(|_attempt| unreachable!("transport must not be reached"));
            let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
            let _ = client.execute(ledger, &request).await;
        }
        "grant_mismatch" => {
            let (charge_authority, _calls) = ScriptedChargeAuthority::new(|request| {
                let mut grant = binding_grant(request);
                grant.attempt_ordinal += 1;
                Ok(grant)
            });
            let (transport, _calls2) =
                ScriptedTransport::new(|_attempt| unreachable!("transport must not be reached"));
            let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
            let _ = client.execute(ledger, &request).await;
        }
        "transport_refused" => {
            let (charge_authority, _calls) =
                ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
            let client = client_with(
                ProviderCapabilities::none(),
                charge_authority,
                UnwiredProviderTransport,
            );
            let _ = client.execute(ledger, &request).await;
        }
        "transport_report_inconsistent" => {
            let (charge_authority, _calls) =
                ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
            let (transport, _calls2) = ScriptedTransport::new(|_attempt| {
                Ok(ProviderAttemptReport {
                    outcome: ProviderAttemptOutcome::Decisive,
                    provider_requests_issued: 0,
                    response: (),
                })
            });
            let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
            let _ = client.execute(ledger, &request).await;
        }
        "transport_issued_unauthorized" => {
            let (charge_authority, _calls) =
                ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
            let (transport, _calls2) = ScriptedTransport::new(|_attempt| {
                Ok(ProviderAttemptReport {
                    outcome: ProviderAttemptOutcome::Decisive,
                    provider_requests_issued: 2,
                    response: (),
                })
            });
            let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
            let _ = client.execute(ledger, &request).await;
        }
        other => panic!("unknown terminal action: {other}"),
    }
}

const TERMINAL_ACTIONS: [&str; 6] = [
    "none",
    "charge_ambiguous_commit",
    "grant_mismatch",
    "transport_refused",
    "transport_report_inconsistent",
    "transport_issued_unauthorized",
];

/// Every sequence of 0..=3 successful attempts, with every combination of `Decisive`/`Ambiguous`
/// outcomes at each position (1 + 2 + 4 + 8 = 15 sequences).
fn outcome_sequences() -> Vec<Vec<ProviderAttemptOutcome>> {
    let mut sequences = Vec::new();
    for length in 0..=3usize {
        for mask in 0..(1usize << length) {
            let sequence = (0..length)
                .map(|bit| {
                    if (mask >> bit) & 1 == 0 {
                        ProviderAttemptOutcome::Decisive
                    } else {
                        ProviderAttemptOutcome::Ambiguous
                    }
                })
                .collect();
            sequences.push(sequence);
        }
    }
    sequences
}

/// A compact fingerprint of a ledger's publicly observable state: its five counters plus a label
/// for its poison (empty when unpoisoned). Two ledgers reached through different call sequences
/// but landing on the same fingerprint are the same audited state as far as any caller, including
/// the frozen encoder, can ever observe.
fn ledger_state_fingerprint(ledger: &ProviderAttemptLedger) -> (u64, u64, u64, u64, u64, String) {
    (
        ledger.attempt_count(),
        ledger.committed_grant_count(),
        ledger.no_dispatch_count(),
        ledger.decisive_terminal_count(),
        ledger.ambiguous_count(),
        ledger
            .poisoned()
            .map(|error| format!("{error:?}"))
            .unwrap_or_default(),
    )
}

/// Asserts the mirroring property `LedgerAlgebraViolation` exists to guard: a poisoned ledger's
/// `audit_for` (called with the ledger's own bound request id, so only the poison/non-poison arm
/// is under test here, never the identity check) returns exactly that poison, and a non-poisoned
/// ledger's `audit_for` is `Ok` and accepted by the frozen encoder.
fn assert_mirrors_audit_algebra(ledger: &ProviderAttemptLedger, label: &str) {
    let bound_request_id = ledger.logical_request_id().to_string();
    match ledger.poisoned() {
        Some(poison) => {
            assert_eq!(
                ledger.audit_for(&bound_request_id),
                Err(poison),
                "case: {label}"
            );
        }
        None => {
            let audit = ledger.audit_for(&bound_request_id).unwrap_or_else(|error| {
                panic!("case {label}: non-poisoned ledger must audit: {error}")
            });
            // ProviderAttemptLedger has no refund method at all, so this must always be false.
            assert!(!audit.audit().provider_authority_refunded, "case: {label}");
            validate_and_encode_object_store_provider_attempt_audit(
                audit.audit(),
                &compact_receipt_limits(),
            )
            .unwrap_or_else(|error| {
                panic!(
                    "case {label}: audit must be accepted by the frozen encoder: {error:?}: \
                         {audit:?}"
                )
            });
        }
    }
}

/// The exact set of ledger-state fingerprints ([`ledger_state_fingerprint`]) the matrix below
/// reaches through the public API. Most of the matrix's raw combinations collapse into a handful
/// of poisoned states, and the loop bounds alone say nothing about how many distinct audited
/// states that actually produces, so the matrix does not assert a restated case count. Pinning
/// this set instead means a change that silently shrinks the reachable state space -- collapsing
/// two states the algebra should keep distinct -- fails visibly here rather than passing a vacuous
/// count check.
///
/// `DispatchAfterNoDispatch` never appears here: `execute` refuses before touching either seam
/// once a no-dispatch is recorded, so every sequence-loop or terminal-action `execute` call after
/// `preceding_no_dispatch` leaves the ledger's fingerprint exactly as it was; the states this test
/// actually reaches for that path are `(0, 0, 1, 0, 0, "")` and, with `preceding_grant`,
/// `(0, 1, 1, 0, 0, "")`, never a poisoned variant.
///
/// Generated, not hand-derived: produced by sorting and printing `reachable_states` from a
/// temporary run of the test below. Regenerate the same way after any deliberate change to
/// `provider_client.rs`'s `execute`/`record_no_dispatch`, `TERMINAL_ACTIONS`, or
/// `outcome_sequences` that should move this set.
fn expected_reachable_states() -> HashSet<(u64, u64, u64, u64, u64, String)> {
    [
        (0, 0, 0, 0, 0, String::new()),
        (0, 0, 1, 0, 0, String::new()),
        (0, 1, 0, 0, 0, String::new()),
        (0, 1, 0, 0, 0, "GrantDoesNotBindAttempt".to_string()),
        (0, 1, 0, 0, 0, "TransportReportInconsistent".to_string()),
        (0, 1, 1, 0, 0, String::new()),
        (0, 2, 0, 0, 0, String::new()),
        (0, 2, 0, 0, 0, "GrantDoesNotBindAttempt".to_string()),
        (0, 2, 0, 0, 0, "TransportReportInconsistent".to_string()),
        (
            1,
            1,
            0,
            0,
            0,
            "TransportIssuedUnauthorizedRequests".to_string(),
        ),
        (1, 1, 0, 0, 1, String::new()),
        (1, 1, 0, 1, 0, String::new()),
        (
            1,
            2,
            0,
            0,
            0,
            "TransportIssuedUnauthorizedRequests".to_string(),
        ),
        (1, 2, 0, 0, 1, String::new()),
        (1, 2, 0, 0, 1, "GrantDoesNotBindAttempt".to_string()),
        (1, 2, 0, 0, 1, "TransportReportInconsistent".to_string()),
        (1, 2, 0, 1, 0, String::new()),
        (1, 2, 0, 1, 0, "GrantDoesNotBindAttempt".to_string()),
        (1, 2, 0, 1, 0, "TransportReportInconsistent".to_string()),
        (1, 3, 0, 0, 1, String::new()),
        (1, 3, 0, 0, 1, "GrantDoesNotBindAttempt".to_string()),
        (1, 3, 0, 0, 1, "TransportReportInconsistent".to_string()),
        (1, 3, 0, 1, 0, String::new()),
        (1, 3, 0, 1, 0, "GrantDoesNotBindAttempt".to_string()),
        (1, 3, 0, 1, 0, "TransportReportInconsistent".to_string()),
        (
            2,
            2,
            0,
            0,
            1,
            "TransportIssuedUnauthorizedRequests".to_string(),
        ),
        (2, 2, 0, 0, 2, String::new()),
        (
            2,
            2,
            0,
            1,
            0,
            "TransportIssuedUnauthorizedRequests".to_string(),
        ),
        (2, 2, 0, 1, 1, String::new()),
        (2, 2, 0, 2, 0, String::new()),
        (
            2,
            3,
            0,
            0,
            1,
            "TransportIssuedUnauthorizedRequests".to_string(),
        ),
        (2, 3, 0, 0, 2, String::new()),
        (2, 3, 0, 0, 2, "GrantDoesNotBindAttempt".to_string()),
        (2, 3, 0, 0, 2, "TransportReportInconsistent".to_string()),
        (
            2,
            3,
            0,
            1,
            0,
            "TransportIssuedUnauthorizedRequests".to_string(),
        ),
        (2, 3, 0, 1, 1, String::new()),
        (2, 3, 0, 1, 1, "GrantDoesNotBindAttempt".to_string()),
        (2, 3, 0, 1, 1, "TransportReportInconsistent".to_string()),
        (2, 3, 0, 2, 0, String::new()),
        (2, 3, 0, 2, 0, "GrantDoesNotBindAttempt".to_string()),
        (2, 3, 0, 2, 0, "TransportReportInconsistent".to_string()),
        (2, 4, 0, 0, 2, String::new()),
        (2, 4, 0, 0, 2, "GrantDoesNotBindAttempt".to_string()),
        (2, 4, 0, 0, 2, "TransportReportInconsistent".to_string()),
        (2, 4, 0, 1, 1, String::new()),
        (2, 4, 0, 1, 1, "GrantDoesNotBindAttempt".to_string()),
        (2, 4, 0, 1, 1, "TransportReportInconsistent".to_string()),
        (2, 4, 0, 2, 0, String::new()),
        (2, 4, 0, 2, 0, "GrantDoesNotBindAttempt".to_string()),
        (2, 4, 0, 2, 0, "TransportReportInconsistent".to_string()),
        (
            3,
            3,
            0,
            0,
            2,
            "TransportIssuedUnauthorizedRequests".to_string(),
        ),
        (3, 3, 0, 0, 3, String::new()),
        (
            3,
            3,
            0,
            1,
            1,
            "TransportIssuedUnauthorizedRequests".to_string(),
        ),
        (3, 3, 0, 1, 2, String::new()),
        (
            3,
            3,
            0,
            2,
            0,
            "TransportIssuedUnauthorizedRequests".to_string(),
        ),
        (3, 3, 0, 2, 1, String::new()),
        (3, 3, 0, 3, 0, String::new()),
        (
            3,
            4,
            0,
            0,
            2,
            "TransportIssuedUnauthorizedRequests".to_string(),
        ),
        (3, 4, 0, 0, 3, String::new()),
        (3, 4, 0, 0, 3, "GrantDoesNotBindAttempt".to_string()),
        (3, 4, 0, 0, 3, "TransportReportInconsistent".to_string()),
        (
            3,
            4,
            0,
            1,
            1,
            "TransportIssuedUnauthorizedRequests".to_string(),
        ),
        (3, 4, 0, 1, 2, String::new()),
        (3, 4, 0, 1, 2, "GrantDoesNotBindAttempt".to_string()),
        (3, 4, 0, 1, 2, "TransportReportInconsistent".to_string()),
        (
            3,
            4,
            0,
            2,
            0,
            "TransportIssuedUnauthorizedRequests".to_string(),
        ),
        (3, 4, 0, 2, 1, String::new()),
        (3, 4, 0, 2, 1, "GrantDoesNotBindAttempt".to_string()),
        (3, 4, 0, 2, 1, "TransportReportInconsistent".to_string()),
        (3, 4, 0, 3, 0, String::new()),
        (3, 4, 0, 3, 0, "GrantDoesNotBindAttempt".to_string()),
        (3, 4, 0, 3, 0, "TransportReportInconsistent".to_string()),
        (3, 5, 0, 0, 3, String::new()),
        (3, 5, 0, 0, 3, "GrantDoesNotBindAttempt".to_string()),
        (3, 5, 0, 0, 3, "TransportReportInconsistent".to_string()),
        (3, 5, 0, 1, 2, String::new()),
        (3, 5, 0, 1, 2, "GrantDoesNotBindAttempt".to_string()),
        (3, 5, 0, 1, 2, "TransportReportInconsistent".to_string()),
        (3, 5, 0, 2, 1, String::new()),
        (3, 5, 0, 2, 1, "GrantDoesNotBindAttempt".to_string()),
        (3, 5, 0, 2, 1, "TransportReportInconsistent".to_string()),
        (3, 5, 0, 3, 0, String::new()),
        (3, 5, 0, 3, 0, "GrantDoesNotBindAttempt".to_string()),
        (3, 5, 0, 3, 0, "TransportReportInconsistent".to_string()),
        (
            4,
            4,
            0,
            0,
            3,
            "TransportIssuedUnauthorizedRequests".to_string(),
        ),
        (
            4,
            4,
            0,
            1,
            2,
            "TransportIssuedUnauthorizedRequests".to_string(),
        ),
        (
            4,
            4,
            0,
            2,
            1,
            "TransportIssuedUnauthorizedRequests".to_string(),
        ),
        (
            4,
            4,
            0,
            3,
            0,
            "TransportIssuedUnauthorizedRequests".to_string(),
        ),
        (
            4,
            5,
            0,
            0,
            3,
            "TransportIssuedUnauthorizedRequests".to_string(),
        ),
        (
            4,
            5,
            0,
            1,
            2,
            "TransportIssuedUnauthorizedRequests".to_string(),
        ),
        (
            4,
            5,
            0,
            2,
            1,
            "TransportIssuedUnauthorizedRequests".to_string(),
        ),
        (
            4,
            5,
            0,
            3,
            0,
            "TransportIssuedUnauthorizedRequests".to_string(),
        ),
    ]
    .into_iter()
    .collect()
}

/// Rebuilds `every_non_poisoned_ledger_audit_is_accepted_by_the_frozen_compact_encoder` (removed):
/// that test asserted the mirroring property over a hand-listed set of 6 states and missed the one
/// that failed (no-dispatch recorded after an ambiguous, not just a decisive, attempt). This
/// version generates every ledger state from a systematic matrix driven entirely through the real
/// public API -- every 0-3-attempt outcome sequence, every terminal error path, with and without a
/// preceding no-dispatch, with and without a preceding grant-without-attempt, and a **trailing**
/// no-dispatch attempted immediately after the outcome sequence (closing the gap a prior version of
/// this comment claimed was covered but was not: `record_no_dispatch` was previously only ever
/// called *before* the sequence in this matrix) -- and asserts the mirroring property on every
/// resulting state: `audit_for` the ledger's own bound request is `Ok` on a non-poisoned ledger
/// and the frozen encoder accepts it, or the ledger is poisoned and `audit_for` returns that same
/// poison. Every ledger in this matrix is `new_ledger()`, so it is always called with the id it is
/// actually bound to -- this matrix exercises the poison/counter algebra `audit_for` restates from
/// `LedgerAlgebraViolation`, not its identity check, which Section 9b pins on its own.
///
/// Most of the matrix's raw combinations collapse into the poison branch, and the loop bounds alone
/// say nothing about how many distinct audited states that actually reaches, so this test does not
/// assert a restated case count. It fingerprints every reachable state instead ([`
/// ledger_state_fingerprint`]) and pins the exact resulting set against [`expected_reachable_states`].
#[tokio::test]
async fn every_ledger_state_reachable_through_the_public_api_matches_the_frozen_audit_algebra() {
    let mut reachable_states = HashSet::new();

    for preceding_grant in [false, true] {
        for preceding_no_dispatch in [false, true] {
            for sequence in outcome_sequences() {
                let mut base_ledger = new_ledger();
                let base_label = format!(
                    "preceding_grant={preceding_grant} preceding_no_dispatch=\
                     {preceding_no_dispatch} sequence={sequence:?}"
                );

                if preceding_grant {
                    let (charge_authority, _calls) =
                        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
                    let client = client_with(
                        ProviderCapabilities::none(),
                        charge_authority,
                        UnwiredProviderTransport,
                    );
                    let _ = client
                        .execute(&mut base_ledger, &request_for_attempt_number(1))
                        .await;
                }

                if preceding_no_dispatch {
                    let _ = base_ledger.record_no_dispatch(&no_dispatch_proof());
                }

                for (index, outcome) in sequence.iter().enumerate() {
                    let outcome = *outcome;
                    let (charge_authority, _calls) =
                        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
                    let (transport, _calls2) = ScriptedTransport::new(move |_attempt| {
                        Ok(ProviderAttemptReport {
                            outcome,
                            provider_requests_issued: 1,
                            response: (),
                        })
                    });
                    let client =
                        client_with(ProviderCapabilities::none(), charge_authority, transport);
                    let attempt_number = u32::try_from(index + 1).expect("small fixture index")
                        + u32::from(preceding_grant);
                    let _ = client
                        .execute(
                            &mut base_ledger,
                            &request_for_attempt_number(attempt_number),
                        )
                        .await;
                }

                // Trailing axis: attempt a no-dispatch immediately after the sequence, on a clone
                // so it does not disturb the terminal-action states built below. Ok exactly when
                // no attempt was ever issued and no no-dispatch was already recorded; otherwise
                // NoDispatchNotPermitted, or the ledger's existing poison if it was already
                // poisoned.
                {
                    let mut trailing_ledger = base_ledger.clone();
                    let expected = match trailing_ledger.poisoned() {
                        Some(poison) => Err(poison),
                        None if trailing_ledger.attempt_count() != 0
                            || trailing_ledger.no_dispatch_count() != 0 =>
                        {
                            Err(ProviderClientError::NoDispatchNotPermitted)
                        }
                        None => Ok(()),
                    };
                    let label = format!("{base_label} trailing_no_dispatch");
                    assert_eq!(
                        trailing_ledger.record_no_dispatch(&no_dispatch_proof()),
                        expected,
                        "case: {label}"
                    );
                    assert_mirrors_audit_algebra(&trailing_ledger, &label);
                    reachable_states.insert(ledger_state_fingerprint(&trailing_ledger));
                }

                for terminal in TERMINAL_ACTIONS {
                    let mut ledger = base_ledger.clone();
                    let label = format!("{base_label} terminal={terminal}");
                    let terminal_attempt_number = u32::try_from(sequence.len() + 1)
                        .expect("small fixture sequence")
                        + u32::from(preceding_grant);

                    apply_terminal_action(terminal, &mut ledger, terminal_attempt_number).await;

                    assert_mirrors_audit_algebra(&ledger, &label);
                    reachable_states.insert(ledger_state_fingerprint(&ledger));
                }
            }
        }
    }

    assert_eq!(
        reachable_states,
        expected_reachable_states(),
        "the matrix's reachable-state set changed -- update expected_reachable_states() \
         deliberately if this is an intended change to the algebra's reachable states"
    );
}

// `ProviderClientError::LedgerOverflow` is not reachable through the public API either: every
// counter is `u64`, so closing the ledger on overflow needs 2^64 successful `execute` calls (or
// committed grants) against one ledger -- not something a test can drive. Noted rather than
// fabricated by any means other than the public API.

// ---------------------------------------------------------------------------------------------
// 10. Redaction
// ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn debug_output_never_leaks_sensitive_fields() {
    let sentinel_boundary_id = "cell.sentinel.redact.7e2";
    let sentinel_bucket = "sentinel-redact-bucket-9f3";
    let sentinel_region = "sentinel-redact-region-2b7";
    let sentinel_host = "sentinel-redact-host-4c1.example.com";
    let sentinel_revision = "sentinel-redact-revision-1a2";
    let sentinel_logical_request_id = uuid_v7(9_999, "aaaaaaaaaaaa");
    let sentinel_attempt_id = uuid_v7(9_999, "bbbbbbbbbbbb");
    let sentinel_grant_id = uuid_v7(9_999, "cccccccccccc");

    let boundary = CellProviderBoundary::new(
        sentinel_boundary_id,
        sentinel_bucket,
        sentinel_region,
        sentinel_host,
    )
    .expect("sentinel boundary must validate");
    let target = boundary.target().clone();
    let budget_pin = BudgetPin {
        revision: sentinel_revision.to_string(),
        fence: 77,
    };

    let layout = spool_layout();
    let key = SpoolObjectKey {
        provider_boundary_id: sentinel_boundary_id.to_string(),
        logical_request_id: sentinel_logical_request_id.clone(),
        attempt_id: sentinel_attempt_id.clone(),
        kind: SpoolObjectKind::Put,
    };
    let paths = layout.derive_paths(&key).expect("derive paths");
    let sentinel_opaque_handle = paths.opaque_handle().to_string();
    let ledger_view = LedgerSpoolView::Ready {
        opaque_handle: sentinel_opaque_handle.clone(),
        size: DURABLE_BODY_SIZE,
        blake3: [9u8; 32],
    };
    let put_body = bind_durable_put_body(&layout, &key, &ledger_view).expect("bind sentinel body");

    let request = ProviderAttemptRequest {
        traffic_class: ProviderTrafficClass::Drain,
        attempt_class: ProviderAttemptClass::PutObject,
        target: target.clone(),
        logical_request_id: sentinel_logical_request_id.clone(),
        attempt_id: sentinel_attempt_id.clone(),
        attempt_ordinal: 1,
        deadline_unix_ms: 9_999 + 60_000,
        budget_pin: budget_pin.clone(),
        put_body: Some(put_body.clone()),
        put_part: None,
    };

    let sentinel_client = GovernedProviderClient::new(
        boundary.clone(),
        ProviderCapabilities::none(),
        ProviderRetryPolicy::disabled(),
        UnwiredChargeAuthority,
        UnwiredProviderTransport,
    );
    // authorize()'s ProviderChargeRequest is crate-private now (WP-114 CD-5) and not `Clone`
    // (INV-EJ P2 round 4), so it is captured through a real execute() call the same way Section
    // 5's charge-request tests do, rather than called or retained directly. The captured struct's
    // `debug_output` is `ProviderChargeRequest`'s own `Debug` output, taken while the value was
    // still alive, which is what lets this fixture still exercise its real redaction below.
    let charge_request = capture_charge_request_with_boundary(
        boundary.clone(),
        ProviderCapabilities::none(),
        &request,
        "sentinel redaction fixture",
    )
    .await;
    let grant = ProviderChargeGrant {
        grant_id: sentinel_grant_id.clone(),
        traffic_class: charge_request.traffic_class,
        attempt_class: charge_request.attempt_class,
        charged_units: charge_request.attempt_units,
        budget_pin: BudgetPin {
            revision: charge_request.budget_pin_revision.clone(),
            fence: charge_request.budget_pin_fence,
        },
        logical_request_id: charge_request.logical_request_id.clone(),
        attempt_id: charge_request.attempt_id.clone(),
        attempt_ordinal: charge_request.attempt_ordinal,
        granted_at_database_unix_ms: 1_000,
    };

    let sentinels = [
        sentinel_bucket,
        sentinel_region,
        sentinel_host,
        sentinel_logical_request_id.as_str(),
        sentinel_attempt_id.as_str(),
        sentinel_revision,
        sentinel_opaque_handle.as_str(),
        sentinel_grant_id.as_str(),
    ];

    let debug_outputs = [
        format!("{target:?}"),
        format!("{boundary:?}"),
        format!("{put_body:?}"),
        format!("{budget_pin:?}"),
        format!("{request:?}"),
        charge_request.debug_output.clone(),
        format!("{grant:?}"),
        format!("{sentinel_client:?}"),
    ];

    for output in &debug_outputs {
        for sentinel in sentinels {
            assert!(!output.contains(sentinel), "leaked {sentinel} in {output}");
        }
    }
}

/// Regression guard for a defect the INV-EJ fix round introduced and the same round fixed.
///
/// Binding the ledger to an identity gave `ProviderAttemptLedger` a `provider_boundary_id` and a
/// `logical_request_id` while it still carried a derived `Debug`, so `{ledger:?}` printed both in
/// clear text -- the one identity-bearing type in this module without the hand-written redacting
/// `Debug` its siblings (`ProviderTarget`, `CellProviderBoundary`, `DurableProviderPutBody`,
/// `ProviderAttemptRequest`, `ProviderChargeRequest`, `ProviderChargeGrant`, `BudgetPin`) all have.
/// This test was written red and turned green by that impl. Adding a field to the ledger without
/// extending the impl reopens it, which is what this guards.
#[tokio::test]
async fn ledger_debug_output_must_not_leak_the_boundary_or_request_identity() {
    let sentinel_boundary_id = "cell.sentinel.ledger-redact.7e2";
    let sentinel_logical_request_id = uuid_v7(9_999, "dddddddddddd");
    let ledger = ProviderAttemptLedger::new(sentinel_boundary_id, &sentinel_logical_request_id)
        .expect("sentinel identity must validate");

    let rendered = format!("{ledger:?}");

    assert!(
        !rendered.contains(sentinel_boundary_id),
        "leaked boundary id in {rendered}"
    );
    assert!(
        !rendered.contains(sentinel_logical_request_id.as_str()),
        "leaked logical request id in {rendered}"
    );
}

#[tokio::test]
async fn provider_client_error_display_never_contains_sensitive_values() {
    let errors = [
        ProviderClientError::InvalidProviderBoundaryId,
        ProviderClientError::InvalidBucketName,
        ProviderClientError::InvalidRegion,
        ProviderClientError::InvalidEndpointHost,
        ProviderClientError::BucketOutsideCellBoundary,
        ProviderClientError::RegionOutsideCell,
        ProviderClientError::EndpointOutsideCellRegion,
        ProviderClientError::ListCapabilityNotGranted,
        ProviderClientError::InvalidRequestIdentity,
        ProviderClientError::InvalidAttemptOrdinal,
        ProviderClientError::InvalidAttemptDeadline,
        ProviderClientError::InvalidBudgetPin,
        ProviderClientError::InvalidPutLimits,
        ProviderClientError::MultipartPartCountExceeded,
        ProviderClientError::InvalidSpoolKind,
        ProviderClientError::InvalidSpoolKey,
        ProviderClientError::PutBodyNotDurable,
        ProviderClientError::PutBodyHandleMismatch,
        ProviderClientError::PutBodyBoundaryMismatch,
        ProviderClientError::PutBodyRequestMismatch,
        ProviderClientError::PutBodyRequired,
        ProviderClientError::PutBodyNotPermitted,
        ProviderClientError::SinglePutBodyTooLarge,
        ProviderClientError::PutPartRequired,
        ProviderClientError::PutPartNotPermitted,
        ProviderClientError::InvalidPutPart,
        ProviderClientError::DirectPutBodyOutOfBounds,
        ProviderClientError::DirectPutBodyBindingMismatch,
        ProviderClientError::GetObjectRequiresReadOnlyPath,
        ProviderClientError::ChargeRefused(ProviderChargeError::Unwired),
        ProviderClientError::ChargeAmbiguous,
        ProviderClientError::ChargeRecovered,
        ProviderClientError::GrantDoesNotBindAttempt,
        ProviderClientError::TransportRefused(ProviderTransportRefusal::Unwired),
        ProviderClientError::TransportReportInconsistent,
        ProviderClientError::TransportIssuedUnauthorizedRequests,
        ProviderClientError::NoDispatchNotPermitted,
        ProviderClientError::DispatchAfterNoDispatch,
        ProviderClientError::LedgerRequestMismatch,
        ProviderClientError::LedgerAlgebraViolation,
        ProviderClientError::LedgerOverflow,
    ];
    // The match below forces a new *arm*, which a `_ => {}` would satisfy without adding the
    // variant to the array these tests actually sweep. Pinning the length is what makes adding a
    // variant fail here rather than pass unswept -- the same shape as
    // `cell_schema_install.rs`'s `every_error_variant`. This is a change-detector, not proof the
    // array is complete on its own: it only catches the *next* new variant, which is exactly the
    // failure mode INV-EJ round 5 found (`LedgerRequestMismatch`, `DispatchAfterNoDispatch`, and
    // `LedgerAlgebraViolation` were all missing from this sweep).
    assert_eq!(
        errors.len(),
        41,
        "a new ProviderClientError variant must be added to this array, not only to the match \
         below"
    );
    for error in &errors {
        // No wildcard: this is the compile-time exhaustiveness check.
        match error {
            ProviderClientError::InvalidProviderBoundaryId
            | ProviderClientError::InvalidBucketName
            | ProviderClientError::InvalidRegion
            | ProviderClientError::InvalidEndpointHost
            | ProviderClientError::BucketOutsideCellBoundary
            | ProviderClientError::RegionOutsideCell
            | ProviderClientError::EndpointOutsideCellRegion
            | ProviderClientError::ListCapabilityNotGranted
            | ProviderClientError::InvalidRequestIdentity
            | ProviderClientError::InvalidAttemptOrdinal
            | ProviderClientError::InvalidAttemptDeadline
            | ProviderClientError::InvalidBudgetPin
            | ProviderClientError::InvalidPutLimits
            | ProviderClientError::MultipartPartCountExceeded
            | ProviderClientError::InvalidSpoolKind
            | ProviderClientError::InvalidSpoolKey
            | ProviderClientError::PutBodyNotDurable
            | ProviderClientError::PutBodyHandleMismatch
            | ProviderClientError::PutBodyBoundaryMismatch
            | ProviderClientError::PutBodyRequestMismatch
            | ProviderClientError::PutBodyRequired
            | ProviderClientError::PutBodyNotPermitted
            | ProviderClientError::SinglePutBodyTooLarge
            | ProviderClientError::PutPartRequired
            | ProviderClientError::PutPartNotPermitted
            | ProviderClientError::InvalidPutPart
            | ProviderClientError::DirectPutBodyOutOfBounds
            | ProviderClientError::DirectPutBodyBindingMismatch
            | ProviderClientError::GetObjectRequiresReadOnlyPath
            | ProviderClientError::ChargeRefused(_)
            | ProviderClientError::ChargeAmbiguous
            | ProviderClientError::ChargeRecovered
            | ProviderClientError::GrantDoesNotBindAttempt
            | ProviderClientError::TransportRefused(_)
            | ProviderClientError::TransportReportInconsistent
            | ProviderClientError::TransportIssuedUnauthorizedRequests
            | ProviderClientError::NoDispatchNotPermitted
            | ProviderClientError::DispatchAfterNoDispatch
            | ProviderClientError::LedgerRequestMismatch
            | ProviderClientError::LedgerAlgebraViolation
            | ProviderClientError::LedgerOverflow => {}
        }
    }

    let sentinels = [
        "sentinel-redact-bucket-9f3",
        "sentinel-redact-region-2b7",
        "sentinel-redact-host-4c1.example.com",
        "sentinel-redact-revision-1a2",
    ];

    for error in errors {
        let rendered = format!("{error}");
        for sentinel in sentinels {
            assert!(
                !rendered.contains(sentinel),
                "leaked {sentinel} in {rendered}"
            );
        }
    }
}

// ---------------------------------------------------------------------------------------------
// 11. Closed-enum hygiene
// ---------------------------------------------------------------------------------------------

fn assert_distinct_labels(labels: &[&str]) {
    let mut sorted = labels.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), labels.len(), "labels: {labels:?}");
}

#[tokio::test]
async fn attempt_class_all_has_eleven_entries_with_distinct_metric_labels() {
    assert_eq!(ProviderAttemptClass::ALL.len(), 11);
    let labels: Vec<&str> = ProviderAttemptClass::ALL
        .iter()
        .map(|class| class.metric_label())
        .collect();
    assert_distinct_labels(&labels);
}

#[tokio::test]
async fn traffic_class_all_has_five_entries_with_distinct_metric_labels() {
    assert_eq!(ProviderTrafficClass::ALL.len(), 5);
    let labels: Vec<&str> = ProviderTrafficClass::ALL
        .iter()
        .map(|class| class.metric_label())
        .collect();
    assert_distinct_labels(&labels);
}

#[tokio::test]
async fn is_listing_is_true_for_exactly_the_two_listing_classes() {
    for class in ProviderAttemptClass::ALL {
        let expected = matches!(
            class,
            ProviderAttemptClass::ListObjectsV2 | ProviderAttemptClass::ListObjectVersions
        );
        assert_eq!(class.is_listing(), expected, "{class:?}");
    }
}

#[tokio::test]
async fn carries_object_body_is_true_for_exactly_put_object_and_upload_part() {
    for class in ProviderAttemptClass::ALL {
        let expected = matches!(
            class,
            ProviderAttemptClass::PutObject | ProviderAttemptClass::UploadPart
        );
        assert_eq!(class.carries_object_body(), expected, "{class:?}");
    }
}

#[tokio::test]
async fn every_provider_cap_class_metric_label_is_distinct() {
    let caps = [
        ProviderCapClass::SharedPhysicalBudget,
        ProviderCapClass::TrafficDrain,
        ProviderCapClass::TrafficDirectFallback,
        ProviderCapClass::TrafficRead,
        ProviderCapClass::TrafficRepair,
        ProviderCapClass::TrafficOperator,
        ProviderCapClass::List,
    ];
    let labels: Vec<&str> = caps.iter().map(|cap| cap.metric_label()).collect();
    assert_distinct_labels(&labels);
}

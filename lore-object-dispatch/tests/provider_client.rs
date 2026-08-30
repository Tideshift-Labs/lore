// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! WP-114 CD-5's governed provider client: cell boundary binding, the put execution plan, and the
//! charge-before-send kernel. Drives the public API in `lore_object_dispatch::provider_client`
//! (re-exported from the crate root) with in-process test doubles for the two unwired seams
//! (`ProviderChargeAuthority`, `ProviderTransport`); no provider SDK, no database, no filesystem.

use std::cell::Cell;
use std::path::PathBuf;
use std::rc::Rc;

use lore_object_dispatch::AuthorizedProviderAttempt;
use lore_object_dispatch::BudgetPin;
use lore_object_dispatch::CanonicalNoDispatchProof;
use lore_object_dispatch::CellProviderBoundary;
use lore_object_dispatch::DurableProviderPutBody;
use lore_object_dispatch::GovernedProviderClient;
use lore_object_dispatch::LedgerSpoolView;
use lore_object_dispatch::NoDispatchProofFields;
use lore_object_dispatch::NoDispatchReason;
use lore_object_dispatch::ObjectStoreCompactReceiptLimits;
use lore_object_dispatch::PROVIDER_MAX_MULTIPART_PARTS;
use lore_object_dispatch::PROVIDER_MAX_PART_SIZE_BYTES;
use lore_object_dispatch::PROVIDER_MAX_SINGLE_PUT_BYTES;
use lore_object_dispatch::PROVIDER_MIN_PART_SIZE_BYTES;
use lore_object_dispatch::ProviderAttemptClass;
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
        budget_pin: budget_pin(),
        put_body: None,
        put_part: None,
    }
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
) -> GovernedProviderClient<C, T>
where
    C: ProviderChargeAuthority,
    T: ProviderTransport,
{
    GovernedProviderClient::new(
        boundary(),
        capabilities,
        ProviderRetryPolicy::disabled(),
        charge_authority,
        transport,
    )
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
        granted_at_database_unix_ms: 1_000,
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
    calls: Rc<Cell<u32>>,
}

impl<F> ScriptedChargeAuthority<F>
where
    F: Fn(&ProviderChargeRequest) -> Result<ProviderChargeGrant, ProviderChargeError>,
{
    fn new(respond: F) -> (Self, Rc<Cell<u32>>) {
        let calls = Rc::new(Cell::new(0));
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
    F: Fn(&ProviderChargeRequest) -> Result<ProviderChargeGrant, ProviderChargeError>,
{
    fn charge(
        &self,
        request: &ProviderChargeRequest,
    ) -> Result<ProviderChargeGrant, ProviderChargeError> {
        self.calls.set(self.calls.get() + 1);
        (self.respond)(request)
    }
}

/// A `ProviderTransport` test double scripted by a closure, with the same call-counter shape as
/// [`ScriptedChargeAuthority`].
struct ScriptedTransport<F> {
    respond: F,
    calls: Rc<Cell<u32>>,
}

impl<F> ScriptedTransport<F>
where
    F: Fn(
        &AuthorizedProviderAttempt<'_>,
    ) -> Result<ProviderAttemptReport, ProviderTransportRefusal>,
{
    fn new(respond: F) -> (Self, Rc<Cell<u32>>) {
        let calls = Rc::new(Cell::new(0));
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
    ) -> Result<ProviderAttemptReport, ProviderTransportRefusal>,
{
    fn issue(
        &self,
        attempt: &AuthorizedProviderAttempt<'_>,
    ) -> Result<ProviderAttemptReport, ProviderTransportRefusal> {
        self.calls.set(self.calls.get() + 1);
        (self.respond)(attempt)
    }
}

// ---------------------------------------------------------------------------------------------
// 1. CellProviderBoundary::new
// ---------------------------------------------------------------------------------------------

#[test]
fn cell_provider_boundary_accepts_a_realistic_do_spaces_configuration() {
    let boundary = boundary();

    assert_eq!(boundary.provider_boundary_id(), BOUNDARY_ID);
    assert_eq!(boundary.target().bucket, BUCKET);
    assert_eq!(boundary.target().region, REGION);
    assert_eq!(boundary.target().endpoint_host, ENDPOINT_HOST);
}

#[test]
fn cell_provider_boundary_rejects_every_invalid_bucket_shape() {
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

#[test]
fn cell_provider_boundary_rejects_every_invalid_region_shape() {
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

#[test]
fn cell_provider_boundary_rejects_every_invalid_endpoint_host_shape() {
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

#[test]
fn cell_provider_boundary_accepts_a_single_label_endpoint_host() {
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

#[test]
fn cell_provider_boundary_rejects_non_canonical_boundary_ids() {
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

#[test]
fn validate_target_accepts_an_exact_match_and_rejects_by_precedence() {
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

#[test]
fn plan_put_object_is_single_shot_at_and_below_the_threshold() {
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

#[test]
fn plan_put_object_becomes_multipart_one_byte_past_the_threshold() {
    let limits = put_limits();
    let plan = plan_put_object(limits.multipart_threshold_bytes + 1, &limits)
        .expect("must plan a multipart body");
    assert!(matches!(plan, PutObjectPlan::Multipart { .. }));
}

#[test]
fn plan_put_object_computes_exact_multiple_part_arithmetic_and_tiles_the_body() {
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

#[test]
fn plan_put_object_computes_remainder_part_arithmetic_and_tiles_the_body() {
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

#[test]
fn planned_attempt_count_matches_single_shot_and_multipart_expansion() {
    let limits = put_limits();

    let single = plan_put_object(0, &limits).expect("must plan");
    assert_eq!(single.planned_attempt_count(), 1);

    let body_size = limits.part_size_bytes * 4;
    let multipart = plan_put_object(body_size, &limits).expect("must plan");
    assert_eq!(multipart.planned_attempt_count(), 4 + 2);
}

#[test]
fn attempt_class_at_walks_create_parts_complete_and_never_names_abort() {
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

#[test]
fn part_range_is_none_outside_the_plan_and_always_none_for_single_shot() {
    let limits = put_limits();
    let body_size = limits.part_size_bytes * 4;
    let plan = plan_put_object(body_size, &limits).expect("must plan");

    assert_eq!(plan.part_range(0), None);
    assert_eq!(plan.part_range(5), None);

    let single = plan_put_object(0, &limits).expect("must plan");
    assert_eq!(single.part_range(0), None);
    assert_eq!(single.part_range(1), None);
}

#[test]
fn plan_put_object_rejects_bodies_needing_more_parts_than_max_parts() {
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

#[test]
fn plan_put_object_rejects_limits_outside_the_supported_range() {
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
#[test]
fn part_range_returns_none_when_a_hand_built_plans_offset_multiplication_overflows() {
    let plan = PutObjectPlan::Multipart {
        body_size: u64::MAX,
        part_size_bytes: u64::MAX,
        part_count: 3,
        final_part_size_bytes: 1,
    };

    // part_number=3: offset = (3 - 1).checked_mul(u64::MAX) overflows outright.
    assert_eq!(plan.part_range(3), None);
}

#[test]
fn part_range_returns_none_when_offset_plus_length_overflows() {
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

#[test]
fn part_range_well_formed_plans_from_plan_put_object_are_unaffected_by_the_checked_arithmetic() {
    let limits = put_limits();
    let body_size = limits.part_size_bytes * 4;
    let plan = plan_put_object(body_size, &limits).expect("must plan");
    assert_ranges_tile(plan, body_size);
}

// ---------------------------------------------------------------------------------------------
// 4. bind_durable_put_body
// ---------------------------------------------------------------------------------------------

#[test]
fn bind_durable_put_body_succeeds_for_a_ready_put_key_and_echoes_every_field() {
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

#[test]
fn bind_durable_put_body_requires_a_ready_ledger_row() {
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

#[test]
fn bind_durable_put_body_rejects_a_ready_row_with_the_wrong_handle() {
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

#[test]
fn bind_durable_put_body_rejects_a_result_kind_key_before_deriving_paths() {
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

#[test]
fn bind_durable_put_body_rejects_non_canonical_spool_keys() {
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

#[test]
fn authorize_gates_listing_classes_on_the_capability_and_leaves_others_unaffected() {
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
        let result_without = without_listing.authorize(&request);
        let result_with = with_listing.authorize(&request);

        if class.is_listing() {
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

#[test]
fn authorize_requires_canonical_uuid_v7_identities_and_a_positive_ordinal() {
    let client = client_with(
        ProviderCapabilities::none(),
        UnwiredChargeAuthority,
        UnwiredProviderTransport,
    );

    let mut bad_logical = attempt_request_for(ProviderAttemptClass::Readiness);
    bad_logical.logical_request_id = "not-a-uuid".to_string();
    assert_eq!(
        client.authorize(&bad_logical),
        Err(ProviderClientError::InvalidRequestIdentity)
    );

    let mut bad_attempt = attempt_request_for(ProviderAttemptClass::Readiness);
    bad_attempt.attempt_id = "not-a-uuid".to_string();
    assert_eq!(
        client.authorize(&bad_attempt),
        Err(ProviderClientError::InvalidRequestIdentity)
    );

    let mut bad_ordinal = attempt_request_for(ProviderAttemptClass::Readiness);
    bad_ordinal.attempt_ordinal = 0;
    assert_eq!(
        client.authorize(&bad_ordinal),
        Err(ProviderClientError::InvalidAttemptOrdinal)
    );
}

#[test]
fn authorize_requires_a_canonical_nonzero_budget_pin() {
    let client = client_with(
        ProviderCapabilities::none(),
        UnwiredChargeAuthority,
        UnwiredProviderTransport,
    );

    let mut non_canonical = attempt_request_for(ProviderAttemptClass::Readiness);
    non_canonical.budget_pin.revision = "not canonical!".to_string();
    assert_eq!(
        client.authorize(&non_canonical),
        Err(ProviderClientError::InvalidBudgetPin)
    );

    let mut empty_revision = attempt_request_for(ProviderAttemptClass::Readiness);
    empty_revision.budget_pin.revision = String::new();
    assert_eq!(
        client.authorize(&empty_revision),
        Err(ProviderClientError::InvalidBudgetPin)
    );

    let mut zero_fence = attempt_request_for(ProviderAttemptClass::Readiness);
    zero_fence.budget_pin.fence = 0;
    assert_eq!(
        client.authorize(&zero_fence),
        Err(ProviderClientError::InvalidBudgetPin)
    );
}

/// Budget-pin revisions go through a narrower validator than the crate's general canonical
/// identifier: `/` and `:` are excluded, the cap is 128 bytes (not 256), and the first byte must
/// be ASCII alphanumeric.
#[test]
fn authorize_rejects_budget_pin_revisions_outside_the_narrow_charset() {
    let client = client_with(
        ProviderCapabilities::none(),
        UnwiredChargeAuthority,
        UnwiredProviderTransport,
    );

    let mut with_slash = attempt_request_for(ProviderAttemptClass::Readiness);
    with_slash.budget_pin.revision = "wp121/rev.7".to_string();
    assert_eq!(
        client.authorize(&with_slash),
        Err(ProviderClientError::InvalidBudgetPin)
    );

    let mut with_colon = attempt_request_for(ProviderAttemptClass::Readiness);
    with_colon.budget_pin.revision = "wp121:rev.7".to_string();
    assert_eq!(
        client.authorize(&with_colon),
        Err(ProviderClientError::InvalidBudgetPin)
    );

    let mut over_length = attempt_request_for(ProviderAttemptClass::Readiness);
    over_length.budget_pin.revision = "a".repeat(129);
    assert_eq!(
        client.authorize(&over_length),
        Err(ProviderClientError::InvalidBudgetPin)
    );

    let mut leading_dash = attempt_request_for(ProviderAttemptClass::Readiness);
    leading_dash.budget_pin.revision = "-wp121".to_string();
    assert_eq!(
        client.authorize(&leading_dash),
        Err(ProviderClientError::InvalidBudgetPin)
    );

    let mut leading_dot = attempt_request_for(ProviderAttemptClass::Readiness);
    leading_dot.budget_pin.revision = ".wp121".to_string();
    assert_eq!(
        client.authorize(&leading_dot),
        Err(ProviderClientError::InvalidBudgetPin)
    );

    // Exactly 128 bytes is accepted; the cap is inclusive.
    let mut at_the_128_byte_boundary = attempt_request_for(ProviderAttemptClass::Readiness);
    at_the_128_byte_boundary.budget_pin.revision = "a".repeat(128);
    assert!(client.authorize(&at_the_128_byte_boundary).is_ok());
}

#[test]
fn authorize_enforces_body_presence_across_every_attempt_class() {
    let client = client_with(
        ProviderCapabilities::none().with_listing(),
        UnwiredChargeAuthority,
        UnwiredProviderTransport,
    );

    for class in ProviderAttemptClass::ALL {
        if class.carries_object_body() {
            let mut missing = attempt_request_for(class);
            missing.put_body = None;
            assert_eq!(
                client.authorize(&missing),
                Err(ProviderClientError::PutBodyRequired),
                "{class:?}"
            );
        } else {
            let mut extra = attempt_request_for(class);
            extra.put_body = Some(durable_put_body());
            assert_eq!(
                client.authorize(&extra),
                Err(ProviderClientError::PutBodyNotPermitted),
                "{class:?}"
            );
        }
    }
}

#[test]
fn authorize_requires_a_part_range_only_for_upload_part() {
    let client = client_with(
        ProviderCapabilities::none().with_listing(),
        UnwiredChargeAuthority,
        UnwiredProviderTransport,
    );

    let mut missing_part = attempt_request_for(ProviderAttemptClass::UploadPart);
    missing_part.put_part = None;
    assert_eq!(
        client.authorize(&missing_part),
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
        assert_eq!(
            client.authorize(&request),
            Err(ProviderClientError::PutPartNotPermitted),
            "{class:?}"
        );
    }
}

#[test]
fn authorize_validates_the_upload_part_range_against_its_body() {
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
        client.authorize(&zero_part_number),
        Err(ProviderClientError::InvalidPutPart)
    );

    let mut over_max_part_number = upload_part_request();
    over_max_part_number.put_part = Some(ProviderPutPart {
        part_number: PROVIDER_MAX_MULTIPART_PARTS + 1,
        offset: 0,
        length: 1,
    });
    assert_eq!(
        client.authorize(&over_max_part_number),
        Err(ProviderClientError::InvalidPutPart)
    );

    let mut zero_length = upload_part_request();
    zero_length.put_part = Some(ProviderPutPart {
        part_number: 1,
        offset: 0,
        length: 0,
    });
    assert_eq!(
        client.authorize(&zero_length),
        Err(ProviderClientError::InvalidPutPart)
    );

    let mut over_max_length = upload_part_request();
    over_max_length.put_part = Some(ProviderPutPart {
        part_number: 1,
        offset: 0,
        length: PROVIDER_MAX_PART_SIZE_BYTES + 1,
    });
    assert_eq!(
        client.authorize(&over_max_length),
        Err(ProviderClientError::InvalidPutPart)
    );

    let mut overflowing = upload_part_request();
    overflowing.put_part = Some(ProviderPutPart {
        part_number: 1,
        offset: u64::MAX,
        length: 1,
    });
    assert_eq!(
        client.authorize(&overflowing),
        Err(ProviderClientError::InvalidPutPart)
    );

    let mut past_body = upload_part_request();
    past_body.put_part = Some(ProviderPutPart {
        part_number: 1,
        offset: 0,
        length: body_size + 1,
    });
    assert_eq!(
        client.authorize(&past_body),
        Err(ProviderClientError::InvalidPutPart)
    );

    let mut exact_end = upload_part_request();
    exact_end.put_part = Some(ProviderPutPart {
        part_number: 1,
        offset: 0,
        length: body_size,
    });
    assert!(client.authorize(&exact_end).is_ok());
}

/// A part is non-final exactly when `offset + length < body.size`. Only a non-final part is held
/// to the provider's minimum part size; the final part (ending exactly at `body.size`) may be any
/// positive length.
#[test]
fn authorize_requires_the_provider_minimum_for_a_non_final_upload_part_but_not_the_final_one() {
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
        client.authorize(&one_byte_non_final),
        Err(ProviderClientError::InvalidPutPart)
    );

    let mut just_under_min_non_final = base.clone();
    just_under_min_non_final.put_part = Some(ProviderPutPart {
        part_number: 1,
        offset: 0,
        length: PROVIDER_MIN_PART_SIZE_BYTES - 1,
    });
    assert_eq!(
        client.authorize(&just_under_min_non_final),
        Err(ProviderClientError::InvalidPutPart)
    );

    let mut exactly_min_non_final = base.clone();
    exactly_min_non_final.put_part = Some(ProviderPutPart {
        part_number: 1,
        offset: 0,
        length: PROVIDER_MIN_PART_SIZE_BYTES,
    });
    assert!(client.authorize(&exactly_min_non_final).is_ok());

    let mut one_byte_final = base;
    one_byte_final.put_part = Some(ProviderPutPart {
        part_number: 2,
        offset: body_size - 1,
        length: 1,
    });
    assert!(client.authorize(&one_byte_final).is_ok());
}

#[test]
fn authorize_rejects_a_put_body_bound_to_a_different_request_or_boundary() {
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
        client.authorize(&mismatched_request),
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
        client.authorize(&mismatched_boundary),
        Err(ProviderClientError::PutBodyBoundaryMismatch)
    );
}

#[test]
fn authorize_returns_a_charge_request_that_echoes_the_attempt_and_charges_one_unit() {
    let client = client_with(
        ProviderCapabilities::none().with_listing(),
        UnwiredChargeAuthority,
        UnwiredProviderTransport,
    );

    for class in ProviderAttemptClass::ALL {
        let request = attempt_request_for(class);
        let charge = client
            .authorize(&request)
            .unwrap_or_else(|error| panic!("{class:?} must authorize: {error:?}"));

        assert_eq!(charge.attempt_units(), 1, "{class:?}");
        assert_eq!(charge.provider_boundary_id(), BOUNDARY_ID, "{class:?}");
        assert_eq!(charge.traffic_class(), request.traffic_class, "{class:?}");
        assert_eq!(charge.attempt_class(), request.attempt_class, "{class:?}");
        assert_eq!(
            charge.logical_request_id(),
            request.logical_request_id,
            "{class:?}"
        );
        assert_eq!(charge.attempt_id(), request.attempt_id, "{class:?}");
        assert_eq!(
            charge.attempt_ordinal(),
            request.attempt_ordinal,
            "{class:?}"
        );
        assert_eq!(charge.budget_pin(), &request.budget_pin, "{class:?}");
    }
}

// ---------------------------------------------------------------------------------------------
// 6. ProviderChargeRequest::cap_classes
// ---------------------------------------------------------------------------------------------

#[test]
fn cap_classes_always_start_with_the_shared_budget_and_include_exactly_the_matching_caps() {
    let client = client_with(
        ProviderCapabilities::none().with_listing(),
        UnwiredChargeAuthority,
        UnwiredProviderTransport,
    );

    for traffic_class in ProviderTrafficClass::ALL {
        for attempt_class in ProviderAttemptClass::ALL {
            let mut request = attempt_request_for(attempt_class);
            request.traffic_class = traffic_class;
            let charge = client
                .authorize(&request)
                .unwrap_or_else(|error| panic!("{attempt_class:?} must authorize: {error:?}"));
            let caps = charge.cap_classes();

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

#[test]
fn execute_refuses_every_charge_error_before_touching_the_ledger_or_transport() {
    let cases = [
        ProviderChargeError::Unwired,
        ProviderChargeError::BudgetPinRejected,
        ProviderChargeError::BudgetExhausted,
        ProviderChargeError::ClassCapExhausted,
        ProviderChargeError::ConfigurationUnresolved,
        ProviderChargeError::AuthorityUnavailable,
    ];

    for error in cases {
        let (charge_authority, charge_calls) =
            ScriptedChargeAuthority::new(move |_request| Err(error));
        let (transport, transport_calls) =
            ScriptedTransport::new(|_attempt| unreachable!("transport must not be reached"));
        let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
        let mut ledger = ProviderAttemptLedger::new();

        let outcome = client.execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness));

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

#[test]
fn unwired_charge_authority_and_transport_are_the_shipped_fail_closed_guards() {
    let client = client_with(
        ProviderCapabilities::none(),
        UnwiredChargeAuthority,
        UnwiredProviderTransport,
    );
    let mut ledger = ProviderAttemptLedger::new();

    let outcome = client.execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness));

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

#[test]
fn execute_counts_an_ambiguous_commit_as_a_charged_grant_without_an_attempt() {
    let (charge_authority, charge_calls) =
        ScriptedChargeAuthority::new(|_request| Err(ProviderChargeError::AmbiguousCommit));
    let (transport, transport_calls) =
        ScriptedTransport::new(|_attempt| unreachable!("transport must not be reached"));
    let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
    let mut ledger = ProviderAttemptLedger::new();

    let outcome = client.execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness));

    assert_eq!(outcome, Err(ProviderClientError::ChargeAmbiguous));
    assert_eq!(ledger.committed_grant_count(), 1);
    assert_eq!(ledger.attempt_count(), 0);
    assert_eq!(ledger.poisoned(), None);
    assert_eq!(charge_calls.get(), 1);
    assert_eq!(transport_calls.get(), 0);
}

#[test]
fn execute_poisons_the_ledger_when_the_grant_does_not_bind_the_attempt() {
    type Mutator = Box<dyn Fn(ProviderChargeGrant) -> ProviderChargeGrant>;
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
        let mut ledger = ProviderAttemptLedger::new();

        let outcome = client.execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness));

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

#[test]
fn execute_reports_transport_refusal_while_keeping_the_grant_charged() {
    let (charge_authority, _charge_calls) =
        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
    let client = client_with(
        ProviderCapabilities::none(),
        charge_authority,
        UnwiredProviderTransport,
    );
    let mut ledger = ProviderAttemptLedger::new();

    let outcome = client.execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness));

    assert_eq!(
        outcome,
        Err(ProviderClientError::TransportRefused(
            ProviderTransportRefusal::Unwired
        ))
    );
    assert_eq!(ledger.committed_grant_count(), 1);
    assert_eq!(ledger.attempt_count(), 0);
    assert_eq!(ledger.poisoned(), None);

    let audit = ledger.audit().expect("non-poisoned ledger must audit");
    assert_eq!(audit.committed_grant_count, 1);
    assert_eq!(audit.attempt_count, 0);
}

#[test]
fn execute_poisons_when_transport_reports_success_with_zero_requests_issued() {
    let (charge_authority, _charge_calls) =
        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
    let (transport, transport_calls) = ScriptedTransport::new(|_attempt| {
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Decisive,
            provider_requests_issued: 0,
        })
    });
    let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
    let mut ledger = ProviderAttemptLedger::new();

    let outcome = client.execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness));

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

#[test]
fn execute_poisons_when_transport_issues_more_requests_than_authorized() {
    let (charge_authority, _charge_calls) =
        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
    let (transport, _transport_calls) = ScriptedTransport::new(|_attempt| {
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Decisive,
            provider_requests_issued: 2,
        })
    });
    let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
    let mut ledger = ProviderAttemptLedger::new();

    let outcome = client.execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness));

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

#[test]
fn execute_records_one_decisive_attempt() {
    let (charge_authority, _charge_calls) =
        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
    let (transport, transport_calls) = ScriptedTransport::new(|_attempt| {
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Decisive,
            provider_requests_issued: 1,
        })
    });
    let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
    let mut ledger = ProviderAttemptLedger::new();

    let outcome = client.execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness));

    assert_eq!(outcome, Ok(ProviderAttemptOutcome::Decisive));
    assert_eq!(ledger.attempt_count(), 1);
    assert_eq!(ledger.committed_grant_count(), 1);
    assert_eq!(ledger.no_dispatch_count(), 0);
    assert_eq!(ledger.decisive_terminal_count(), 1);
    assert_eq!(ledger.ambiguous_count(), 0);
    assert_eq!(ledger.poisoned(), None);
    assert_eq!(transport_calls.get(), 1);
}

#[test]
fn execute_records_one_ambiguous_attempt() {
    let (charge_authority, _charge_calls) =
        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
    let (transport, transport_calls) = ScriptedTransport::new(|_attempt| {
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Ambiguous,
            provider_requests_issued: 1,
        })
    });
    let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
    let mut ledger = ProviderAttemptLedger::new();

    let outcome = client.execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness));

    assert_eq!(outcome, Ok(ProviderAttemptOutcome::Ambiguous));
    assert_eq!(ledger.attempt_count(), 1);
    assert_eq!(ledger.committed_grant_count(), 1);
    assert_eq!(ledger.no_dispatch_count(), 0);
    assert_eq!(ledger.decisive_terminal_count(), 0);
    assert_eq!(ledger.ambiguous_count(), 1);
    assert_eq!(ledger.poisoned(), None);
    assert_eq!(transport_calls.get(), 1);
}

#[test]
fn execute_accumulates_counters_across_several_successful_attempts() {
    let mut ledger = ProviderAttemptLedger::new();
    for outcome in [
        ProviderAttemptOutcome::Decisive,
        ProviderAttemptOutcome::Decisive,
        ProviderAttemptOutcome::Decisive,
        ProviderAttemptOutcome::Ambiguous,
    ] {
        let (charge_authority, _charge_calls) =
            ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
        let (transport, _transport_calls) = ScriptedTransport::new(move |_attempt| {
            Ok(ProviderAttemptReport {
                outcome,
                provider_requests_issued: 1,
            })
        });
        let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
        client
            .execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness))
            .expect("attempt must succeed");
    }

    assert_eq!(ledger.attempt_count(), 4);
    assert_eq!(ledger.committed_grant_count(), 4);
    assert_eq!(ledger.no_dispatch_count(), 0);
    assert_eq!(ledger.decisive_terminal_count(), 3);
    assert_eq!(ledger.ambiguous_count(), 1);
    assert_eq!(ledger.poisoned(), None);
}

#[test]
fn execute_returns_the_same_poison_and_calls_neither_seam_again() {
    let (charge_authority, charge_calls) =
        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
    let (transport, transport_calls) = ScriptedTransport::new(|_attempt| {
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Decisive,
            provider_requests_issued: 0,
        })
    });
    let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
    let mut ledger = ProviderAttemptLedger::new();

    let first = client.execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness));
    assert_eq!(first, Err(ProviderClientError::TransportReportInconsistent));
    assert_eq!(charge_calls.get(), 1);
    assert_eq!(transport_calls.get(), 1);

    let second = client.execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness));
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

#[test]
fn execute_hands_the_transport_the_exact_authorized_permit() {
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
        })
    });
    let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
    let mut ledger = ProviderAttemptLedger::new();

    let outcome = client.execute(&mut ledger, &request);

    assert_eq!(outcome, Ok(ProviderAttemptOutcome::Decisive));
    assert_eq!(transport_calls.get(), 1);
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

#[test]
fn record_no_dispatch_succeeds_once_then_refuses_a_second_call() {
    let mut ledger = ProviderAttemptLedger::new();

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
#[test]
fn record_no_dispatch_refuses_after_any_issued_attempt_decisive_or_ambiguous() {
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
            })
        });
        let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
        let mut ledger = ProviderAttemptLedger::new();
        client
            .execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness))
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
#[test]
fn record_no_dispatch_is_still_allowed_after_a_committed_grant_that_never_reached_the_wire() {
    let (charge_authority, _charge_calls) =
        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
    let client = client_with(
        ProviderCapabilities::none(),
        charge_authority,
        UnwiredProviderTransport,
    );
    let mut ledger = ProviderAttemptLedger::new();

    let outcome = client.execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness));
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

    let audit = ledger.audit().expect("non-poisoned ledger must audit");
    validate_and_encode_object_store_provider_attempt_audit(&audit, &compact_receipt_limits())
        .expect("audit must be accepted by the frozen encoder");
}

/// A recorded no-dispatch asserts the request resolved without reaching the provider. Dispatching
/// afterwards would contradict that durable claim, so `execute` must refuse before charging or
/// sending, and poison the ledger rather than leave it open to a later successful dispatch.
#[test]
fn execute_refuses_after_a_recorded_no_dispatch_and_poisons_the_ledger() {
    let mut ledger = ProviderAttemptLedger::new();
    ledger
        .record_no_dispatch(&no_dispatch_proof())
        .expect("record no dispatch on a fresh ledger");

    let (charge_authority, charge_calls) =
        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
    let (transport, transport_calls) = ScriptedTransport::new(|_attempt| {
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Decisive,
            provider_requests_issued: 1,
        })
    });
    let client = client_with(ProviderCapabilities::none(), charge_authority, transport);

    let outcome = client.execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness));

    assert_eq!(outcome, Err(ProviderClientError::DispatchAfterNoDispatch));
    assert_eq!(
        ledger.poisoned(),
        Some(ProviderClientError::DispatchAfterNoDispatch)
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
}

#[test]
fn record_no_dispatch_and_audit_return_the_poison_on_a_poisoned_ledger() {
    let (charge_authority, _charge_calls) =
        ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
    let (transport, _transport_calls) = ScriptedTransport::new(|_attempt| {
        Ok(ProviderAttemptReport {
            outcome: ProviderAttemptOutcome::Decisive,
            provider_requests_issued: 0,
        })
    });
    let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
    let mut ledger = ProviderAttemptLedger::new();
    let _ = client.execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness));
    assert_eq!(
        ledger.poisoned(),
        Some(ProviderClientError::TransportReportInconsistent)
    );

    assert_eq!(
        ledger.record_no_dispatch(&no_dispatch_proof()),
        Err(ProviderClientError::TransportReportInconsistent)
    );
    assert_eq!(
        ledger.audit(),
        Err(ProviderClientError::TransportReportInconsistent)
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
// through the real API, `audit()` returns `Ok`, and the frozen encoder accepts that value.

/// Every terminal error path `execute` can take, applied to `ledger`'s current state through the
/// real public API. `"none"` performs no action. Used only by the systematic matrix below.
fn apply_terminal_action(label: &str, ledger: &mut ProviderAttemptLedger) {
    match label {
        "none" => {}
        "charge_ambiguous_commit" => {
            let (charge_authority, _calls) =
                ScriptedChargeAuthority::new(|_request| Err(ProviderChargeError::AmbiguousCommit));
            let (transport, _calls2) =
                ScriptedTransport::new(|_attempt| unreachable!("transport must not be reached"));
            let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
            let _ = client.execute(ledger, &base_request(ProviderAttemptClass::Readiness));
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
            let _ = client.execute(ledger, &base_request(ProviderAttemptClass::Readiness));
        }
        "transport_refused" => {
            let (charge_authority, _calls) =
                ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
            let client = client_with(
                ProviderCapabilities::none(),
                charge_authority,
                UnwiredProviderTransport,
            );
            let _ = client.execute(ledger, &base_request(ProviderAttemptClass::Readiness));
        }
        "transport_report_inconsistent" => {
            let (charge_authority, _calls) =
                ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
            let (transport, _calls2) = ScriptedTransport::new(|_attempt| {
                Ok(ProviderAttemptReport {
                    outcome: ProviderAttemptOutcome::Decisive,
                    provider_requests_issued: 0,
                })
            });
            let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
            let _ = client.execute(ledger, &base_request(ProviderAttemptClass::Readiness));
        }
        "transport_issued_unauthorized" => {
            let (charge_authority, _calls) =
                ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
            let (transport, _calls2) = ScriptedTransport::new(|_attempt| {
                Ok(ProviderAttemptReport {
                    outcome: ProviderAttemptOutcome::Decisive,
                    provider_requests_issued: 2,
                })
            });
            let client = client_with(ProviderCapabilities::none(), charge_authority, transport);
            let _ = client.execute(ledger, &base_request(ProviderAttemptClass::Readiness));
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

/// Rebuilds `every_non_poisoned_ledger_audit_is_accepted_by_the_frozen_compact_encoder` (removed):
/// that test asserted the mirroring property over a hand-listed set of 6 states and missed the one
/// that failed (no-dispatch recorded after an ambiguous, not just a decisive, attempt). This
/// version generates every ledger state from a systematic matrix driven entirely through the real
/// public API -- every 0-3-attempt outcome sequence, every terminal error path, with and without a
/// preceding no-dispatch, with and without a preceding grant-without-attempt -- and asserts the
/// mirroring property on each: a non-poisoned ledger's `audit()` is `Ok` and the frozen encoder
/// accepts it, or the ledger is poisoned and `audit()` returns that same poison.
#[test]
fn every_ledger_state_reachable_through_the_public_api_matches_the_frozen_audit_algebra() {
    let mut case_count = 0usize;

    for preceding_grant in [false, true] {
        for preceding_no_dispatch in [false, true] {
            for sequence in outcome_sequences() {
                for terminal in TERMINAL_ACTIONS {
                    let mut ledger = ProviderAttemptLedger::new();
                    let label = format!(
                        "preceding_grant={preceding_grant} preceding_no_dispatch=\
                         {preceding_no_dispatch} sequence={sequence:?} terminal={terminal}"
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
                            .execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness));
                    }

                    if preceding_no_dispatch {
                        let _ = ledger.record_no_dispatch(&no_dispatch_proof());
                    }

                    for outcome in &sequence {
                        let outcome = *outcome;
                        let (charge_authority, _calls) =
                            ScriptedChargeAuthority::new(|request| Ok(binding_grant(request)));
                        let (transport, _calls2) = ScriptedTransport::new(move |_attempt| {
                            Ok(ProviderAttemptReport {
                                outcome,
                                provider_requests_issued: 1,
                            })
                        });
                        let client =
                            client_with(ProviderCapabilities::none(), charge_authority, transport);
                        let _ = client
                            .execute(&mut ledger, &base_request(ProviderAttemptClass::Readiness));
                    }

                    apply_terminal_action(terminal, &mut ledger);

                    match ledger.poisoned() {
                        Some(poison) => {
                            assert_eq!(ledger.audit(), Err(poison), "case: {label}");
                        }
                        None => {
                            let audit = ledger.audit().unwrap_or_else(|error| {
                                panic!("case {label}: non-poisoned ledger must audit: {error}")
                            });
                            // ProviderAttemptLedger has no refund method at all, so this must
                            // always be false.
                            assert!(!audit.provider_authority_refunded, "case: {label}");
                            validate_and_encode_object_store_provider_attempt_audit(
                                &audit,
                                &compact_receipt_limits(),
                            )
                            .unwrap_or_else(|error| {
                                panic!(
                                    "case {label}: audit must be accepted by the frozen encoder: \
                                     {error:?}: {audit:?}"
                                )
                            });
                        }
                    }
                    case_count += 1;
                }
            }
        }
    }

    assert_eq!(
        case_count,
        2 * 2 * outcome_sequences().len() * TERMINAL_ACTIONS.len(),
        "matrix must enumerate every combination"
    );
}

// `ProviderClientError::LedgerOverflow` is not reachable through the public API either: every
// counter is `u64`, so closing the ledger on overflow needs 2^64 successful `execute` calls (or
// committed grants) against one ledger -- not something a test can drive. Noted rather than
// fabricated by any means other than the public API.

// ---------------------------------------------------------------------------------------------
// 10. Redaction
// ---------------------------------------------------------------------------------------------

#[test]
fn debug_output_never_leaks_sensitive_fields() {
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
    let charge_request = sentinel_client
        .authorize(&request)
        .expect("sentinel request must authorize");
    let grant = ProviderChargeGrant {
        grant_id: sentinel_grant_id.clone(),
        traffic_class: charge_request.traffic_class(),
        attempt_class: charge_request.attempt_class(),
        charged_units: charge_request.attempt_units(),
        budget_pin: charge_request.budget_pin().clone(),
        logical_request_id: charge_request.logical_request_id().to_string(),
        attempt_id: charge_request.attempt_id().to_string(),
        attempt_ordinal: charge_request.attempt_ordinal(),
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
        format!("{charge_request:?}"),
        format!("{grant:?}"),
        format!("{sentinel_client:?}"),
    ];

    for output in &debug_outputs {
        for sentinel in sentinels {
            assert!(!output.contains(sentinel), "leaked {sentinel} in {output}");
        }
    }
}

#[test]
fn provider_client_error_display_never_contains_sensitive_values() {
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
        ProviderClientError::ChargeRefused(ProviderChargeError::Unwired),
        ProviderClientError::ChargeAmbiguous,
        ProviderClientError::GrantDoesNotBindAttempt,
        ProviderClientError::TransportRefused(ProviderTransportRefusal::Unwired),
        ProviderClientError::TransportReportInconsistent,
        ProviderClientError::TransportIssuedUnauthorizedRequests,
        ProviderClientError::NoDispatchNotPermitted,
        ProviderClientError::LedgerOverflow,
    ];
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

#[test]
fn attempt_class_all_has_eleven_entries_with_distinct_metric_labels() {
    assert_eq!(ProviderAttemptClass::ALL.len(), 11);
    let labels: Vec<&str> = ProviderAttemptClass::ALL
        .iter()
        .map(|class| class.metric_label())
        .collect();
    assert_distinct_labels(&labels);
}

#[test]
fn traffic_class_all_has_five_entries_with_distinct_metric_labels() {
    assert_eq!(ProviderTrafficClass::ALL.len(), 5);
    let labels: Vec<&str> = ProviderTrafficClass::ALL
        .iter()
        .map(|class| class.metric_label())
        .collect();
    assert_distinct_labels(&labels);
}

#[test]
fn is_listing_is_true_for_exactly_the_two_listing_classes() {
    for class in ProviderAttemptClass::ALL {
        let expected = matches!(
            class,
            ProviderAttemptClass::ListObjectsV2 | ProviderAttemptClass::ListObjectVersions
        );
        assert_eq!(class.is_listing(), expected, "{class:?}");
    }
}

#[test]
fn carries_object_body_is_true_for_exactly_put_object_and_upload_part() {
    for class in ProviderAttemptClass::ALL {
        let expected = matches!(
            class,
            ProviderAttemptClass::PutObject | ProviderAttemptClass::UploadPart
        );
        assert_eq!(class.carries_object_body(), expected, "{class:?}");
    }
}

#[test]
fn every_provider_cap_class_metric_label_is_distinct() {
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

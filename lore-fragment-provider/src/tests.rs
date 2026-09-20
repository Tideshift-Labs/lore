// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
#![cfg(test)]

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicI64;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::Ordering;

use lore_object_dispatch::AuthorizedProviderAttempt;
use lore_object_dispatch::PROVIDER_MAX_MULTIPART_PARTS;
use lore_object_dispatch::ProviderAttemptReport;
use lore_object_dispatch::ProviderChargeError;
use lore_object_dispatch::ProviderChargeGrant;
use lore_object_dispatch::ProviderChargeRequest;
use lore_object_dispatch::ProviderPutLimits;
use lore_object_dispatch::ProviderTarget;
use lore_object_dispatch::ProviderTransportRefusal;
use lore_object_dispatch::PutObjectPlan;
use lore_object_dispatch::cell_schema_install::CellSchemaLayer;
use lore_object_dispatch::plan_put_object;

use super::*;

// -----------------------------------------------------------------------
// Fixtures
// -----------------------------------------------------------------------

/// Canonical UUIDv7s whose 48-bit timestamp is 1_700_000_000_000 ms.
const REQUEST_ID: &str = "018bcfe5-6800-7abc-8def-000000000001";
const ATTEMPT_ID: &str = "018bcfe5-6800-7abc-8def-000000000002";
const GRANT_ID: &str = "018bcfe5-6800-7abc-8def-000000000003";
const ATTEMPT_TIMESTAMP_MS: i64 = 1_700_000_000_000;
const DEADLINE_MS: i64 = ATTEMPT_TIMESTAMP_MS + 60_000;
const BOUNDARY_ID: &str = "cell-alpha-boundary";

fn boundary() -> CellProviderBoundary {
    match CellProviderBoundary::new(
        BOUNDARY_ID,
        "cell-alpha-fragments",
        "us-east-1",
        "obj.example.invalid",
    ) {
        Ok(boundary) => boundary,
        Err(error) => panic!("fixture boundary must be valid: {error}"),
    }
}

fn other_boundary() -> CellProviderBoundary {
    match CellProviderBoundary::new(
        "cell-beta-boundary",
        "cell-beta-fragments",
        "eu-west-1",
        "obj-eu.example.invalid",
    ) {
        Ok(boundary) => boundary,
        Err(error) => panic!("fixture boundary must be valid: {error}"),
    }
}

fn bound() -> InFlightPutBound {
    match InFlightPutBound::new(2, Duration::from_millis(50)) {
        Ok(bound) => bound,
        Err(error) => panic!("fixture bound must be valid: {error}"),
    }
}

/// Wide enough that no existing test queues on it, so adding the charge bound
/// changes no assertion that was not about the charge bound. A test that wants
/// to observe the queue builds its own narrow bound instead.
fn test_charge_bound() -> InFlightChargeBound {
    match InFlightChargeBound::new(64, Duration::from_millis(50)) {
        Ok(bound) => bound,
        Err(error) => panic!("fixture charge bound must be valid: {error}"),
    }
}

fn pin() -> BudgetPin {
    BudgetPin {
        revision: "cell-alpha-budget-r1".to_string(),
        fence: 1,
    }
}

fn attempt(class: ProviderAttemptClass) -> FragmentProviderAttempt {
    FragmentProviderAttempt {
        traffic_class: ProviderTrafficClass::Repair,
        attempt_class: class,
        logical_request_id: REQUEST_ID.to_string(),
        attempt_id: ATTEMPT_ID.to_string(),
        attempt_ordinal: 1,
        deadline_unix_ms: DEADLINE_MS,
        budget_pin: pin(),
        put_body: None,
    }
}

fn put_operation(body: &[u8]) -> FragmentDirectPutOperation {
    FragmentDirectPutOperation {
        object_key: "objects/fragment.bin".to_string(),
        metadata: vec![("codec".to_string(), "raw".to_string())],
        declared_size: body.len() as u64,
        declared_blake3: *blake3::hash(body).as_bytes(),
    }
}

fn ledger() -> FragmentAttemptLedger {
    match FragmentAttemptLedger::new(BOUNDARY_ID, REQUEST_ID) {
        Ok(ledger) => ledger,
        Err(error) => panic!("fixture ledger must open: {error}"),
    }
}

// -----------------------------------------------------------------------
// Doubles
// -----------------------------------------------------------------------

/// What a scripted authority does with one charge.
#[derive(Clone, Copy)]
enum ChargeScript {
    /// Mint a grant that exactly binds the request.
    Grant,
    /// Deliberately block the current-thread test runtime before granting.
    #[cfg(target_os = "linux")]
    GrantAfterBlocking(Duration),
    /// Mint a grant naming a different ordinal, so it does not bind.
    GrantForAnotherAttempt,
    /// Refuse with this error.
    Refuse(ProviderChargeError),
    /// Never resolve, so the caller keeps its admission permit.
    Hang,
}

struct ScriptedChargeAuthority {
    script: ChargeScript,
    calls: AtomicU32,
    /// The most recent `deadline_unix_ms` this authority observed in a
    /// charge request. There is no public accessor on an admitted
    /// attempt, so this is the closest honest way to see whether
    /// `admit_operation` shifted the deadline it built its request from.
    last_seen_deadline_unix_ms: AtomicI64,
    /// The most recent `traffic_class` this authority observed. Added for
    /// the WP-114 CD-6 drain tests, which need to prove — not merely read
    /// from source — that a drain send is charged under
    /// [`ProviderTrafficClass::Drain`] and that a caller cannot influence
    /// it. `Mutex` rather than an atomic: the class is a small `Copy` enum
    /// with no natural integer encoding worth inventing one for.
    last_seen_traffic_class: Mutex<Option<ProviderTrafficClass>>,
}

impl ScriptedChargeAuthority {
    fn new(script: ChargeScript) -> Self {
        Self {
            script,
            calls: AtomicU32::new(0),
            last_seen_deadline_unix_ms: AtomicI64::new(0),
            last_seen_traffic_class: Mutex::new(None),
        }
    }

    #[cfg(target_os = "linux")]
    fn last_seen_traffic_class(&self) -> Option<ProviderTrafficClass> {
        *self
            .last_seen_traffic_class
            .lock()
            .expect("traffic class lock")
    }
}

impl ProviderChargeAuthority for ScriptedChargeAuthority {
    async fn charge(
        &self,
        request: &ProviderChargeRequest,
    ) -> Result<ProviderChargeGrant, ProviderChargeError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.last_seen_deadline_unix_ms
            .store(request.deadline_unix_ms(), Ordering::SeqCst);
        *self
            .last_seen_traffic_class
            .lock()
            .expect("traffic class lock") = Some(request.traffic_class());
        let grant = |ordinal: u32| ProviderChargeGrant {
            grant_id: GRANT_ID.to_string(),
            traffic_class: request.traffic_class(),
            attempt_class: request.attempt_class(),
            charged_units: request.attempt_units(),
            budget_pin: request.budget_pin().clone(),
            logical_request_id: request.logical_request_id().to_string(),
            attempt_id: request.attempt_id().to_string(),
            attempt_ordinal: ordinal,
            granted_at_database_unix_ms: ATTEMPT_TIMESTAMP_MS,
        };
        match self.script {
            ChargeScript::Grant => Ok(grant(request.attempt_ordinal())),
            #[cfg(target_os = "linux")]
            ChargeScript::GrantAfterBlocking(delay) => {
                std::thread::sleep(delay);
                Ok(grant(request.attempt_ordinal()))
            }
            ChargeScript::GrantForAnotherAttempt => {
                Ok(grant(request.attempt_ordinal().saturating_add(1)))
            }
            ChargeScript::Refuse(error) => Err(error),
            ChargeScript::Hang => {
                std::future::pending::<()>().await;
                Err(ProviderChargeError::Unwired)
            }
        }
    }
}

/// Counts what actually reached the wire. That count is the only observable
/// that can contradict a charge-before-send claim.
struct CountingTransport {
    issued: AtomicUsize,
    requests_per_call: u32,
    outcome: ProviderAttemptOutcome,
}

impl CountingTransport {
    fn new(requests_per_call: u32, outcome: ProviderAttemptOutcome) -> Self {
        Self {
            issued: AtomicUsize::new(0),
            requests_per_call,
            outcome,
        }
    }
}

impl ProviderTransport for CountingTransport {
    type Operation = ();
    type Response = ();

    async fn issue(
        &self,
        _attempt: &AuthorizedProviderAttempt<'_>,
        _operation: &Self::Operation,
    ) -> Result<ProviderAttemptReport<Self::Response>, ProviderTransportRefusal> {
        self.issued.fetch_add(1, Ordering::SeqCst);
        Ok(ProviderAttemptReport {
            outcome: self.outcome,
            provider_requests_issued: self.requests_per_call,
            response: (),
        })
    }
}

/// A gateway plus the two counters its doubles keep, so a test can assert on
/// what was charged and what was sent without reaching through the gateway's
/// private client.
struct Harness {
    gateway: FragmentProviderGateway,
    authority: Arc<ScriptedChargeAuthority>,
    transport: Arc<CountingTransport>,
}

impl Harness {
    fn new(script: ChargeScript, requests_per_call: u32, bound: InFlightPutBound) -> Self {
        Self::with_boundary(script, requests_per_call, bound, boundary())
    }

    fn with_boundary(
        script: ChargeScript,
        requests_per_call: u32,
        bound: InFlightPutBound,
        boundary: CellProviderBoundary,
    ) -> Self {
        Self::with_outcome(
            script,
            requests_per_call,
            bound,
            boundary,
            ProviderAttemptOutcome::Decisive,
        )
    }

    fn with_outcome(
        script: ChargeScript,
        requests_per_call: u32,
        bound: InFlightPutBound,
        boundary: CellProviderBoundary,
        outcome: ProviderAttemptOutcome,
    ) -> Self {
        let authority = Arc::new(ScriptedChargeAuthority::new(script));
        let transport = Arc::new(CountingTransport::new(requests_per_call, outcome));
        Self {
            gateway: FragmentProviderGateway::new(
                CellSchemaAttestation::for_tests(boundary),
                ProviderCapabilities::none().with_listing(),
                bound,
                test_charge_bound(),
                SharedAuthority(Arc::clone(&authority)),
                SharedTransport(Arc::clone(&transport)),
            ),
            authority,
            transport,
        }
    }

    fn charge_calls(&self) -> u32 {
        self.authority.calls.load(Ordering::SeqCst)
    }

    fn issued(&self) -> usize {
        self.transport.issued.load(Ordering::SeqCst)
    }
}

/// Local newtypes so the test can hold a counter the gateway also owns.
/// `Arc<T>` is foreign for these two foreign traits, so a wrapper is the
/// only way to share the doubles with the assertions.
struct SharedAuthority(Arc<ScriptedChargeAuthority>);

struct SharedTransport(Arc<CountingTransport>);

struct CountingGetPort {
    get_calls: AtomicUsize,
    metered_calls: AtomicUsize,
    requests_per_call: u32,
    outcome: ProviderAttemptOutcome,
    direct_body: Mutex<Option<Vec<u8>>>,
    metered_operations: Mutex<Vec<FragmentTransportOperation>>,
}

struct SharedGetPort(Arc<CountingGetPort>);

impl ProviderChargeAuthority for SharedAuthority {
    fn charge(
        &self,
        request: &ProviderChargeRequest,
    ) -> impl std::future::Future<Output = Result<ProviderChargeGrant, ProviderChargeError>> + Send
    {
        ScriptedChargeAuthority::charge(self.0.as_ref(), request)
    }
}

impl ProviderTransport for SharedTransport {
    type Operation = ();
    type Response = ();

    async fn issue(
        &self,
        attempt: &AuthorizedProviderAttempt<'_>,
        operation: &Self::Operation,
    ) -> Result<ProviderAttemptReport<Self::Response>, ProviderTransportRefusal> {
        CountingTransport::issue(self.0.as_ref(), attempt, operation).await
    }
}

impl FragmentTransportPort for SharedGetPort {
    fn issue<'a>(
        &'a self,
        request: FragmentTransportRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = FragmentTransportExchange> + Send + 'a>> {
        self.0.metered_calls.fetch_add(1, Ordering::SeqCst);
        self.0
            .metered_operations
            .lock()
            .expect("metered operation lock")
            .push(request.operation().clone());
        let requests_per_call = self.0.requests_per_call;
        let response = match request.operation() {
            FragmentTransportOperation::Head { .. } => FragmentTransportResponse::Head {
                metadata: Vec::new(),
                content_length: 1,
            },
            FragmentTransportOperation::ListVersions { .. } => {
                FragmentTransportResponse::Versions(Vec::new())
            }
            FragmentTransportOperation::DeleteVersion { .. } => FragmentTransportResponse::Deleted,
            FragmentTransportOperation::DeleteExact { .. } => FragmentTransportResponse::Deleted,
        };
        Box::pin(async move {
            FragmentTransportExchange {
                outcome: self.0.outcome,
                provider_requests_issued: requests_per_call,
                response,
            }
        })
    }
}

impl FragmentDirectPutPort for SharedGetPort {
    fn issue_direct_put<'a>(
        &'a self,
        request: FragmentDirectPutRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = FragmentTransportExchange> + Send + 'a>> {
        self.0.metered_calls.fetch_add(1, Ordering::SeqCst);
        let requests_per_call = self.0.requests_per_call;
        let body = request.body().expect("direct PUT request carries bytes");
        assert_eq!(request.size(), Some(body.len() as u64));
        assert_eq!(request.blake3(), Some(blake3::hash(body).as_bytes()));
        *self.0.direct_body.lock().expect("direct body lock") = Some(body.to_vec());
        Box::pin(async move {
            FragmentTransportExchange {
                outcome: self.0.outcome,
                provider_requests_issued: requests_per_call,
                response: FragmentTransportResponse::PutCreated,
            }
        })
    }
}

impl FragmentGetPort for SharedGetPort {
    fn issue_get<'a>(
        &'a self,
        request: FragmentGetRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = FragmentGetExchange> + Send + 'a>> {
        self.0.get_calls.fetch_add(1, Ordering::SeqCst);
        let requests_per_call = self.0.requests_per_call;
        Box::pin(async move {
            assert_eq!(request.target().bucket(), "cell-alpha-fragments");
            assert_eq!(request.operation().object_key, "objects/fragment.bin");
            FragmentGetExchange {
                outcome: ProviderAttemptOutcome::Decisive,
                provider_requests_issued: requests_per_call,
                response: FragmentGetResponse::Found {
                    bytes: vec![1, 2, 3],
                    metadata: vec![("codec".to_string(), "raw".to_string())],
                },
            }
        })
    }
}

fn get_attempt() -> FragmentGetAttempt {
    FragmentGetAttempt {
        logical_request_id: REQUEST_ID.to_string(),
        attempt_id: ATTEMPT_ID.to_string(),
        attempt_ordinal: 1,
    }
}

fn get_operation() -> FragmentGetOperation {
    FragmentGetOperation {
        object_key: "objects/fragment.bin".to_string(),
    }
}

fn get_harness(
    requests_per_call: u32,
) -> (
    FragmentProviderGateway,
    Arc<ScriptedChargeAuthority>,
    Arc<CountingGetPort>,
) {
    port_harness(ChargeScript::Grant, requests_per_call, bound())
}

fn port_harness(
    script: ChargeScript,
    requests_per_call: u32,
    put_bound: InFlightPutBound,
) -> (
    FragmentProviderGateway,
    Arc<ScriptedChargeAuthority>,
    Arc<CountingGetPort>,
) {
    port_harness_with_bounds(script, requests_per_call, put_bound, test_charge_bound())
}

/// Same as [`port_harness`], with the charge bound also caller-supplied, so
/// a test that wants to observe the charge queue does not have to widen the
/// put bound to get there.
fn port_harness_with_bounds(
    script: ChargeScript,
    requests_per_call: u32,
    put_bound: InFlightPutBound,
    charge_bound: InFlightChargeBound,
) -> (
    FragmentProviderGateway,
    Arc<ScriptedChargeAuthority>,
    Arc<CountingGetPort>,
) {
    let authority = Arc::new(ScriptedChargeAuthority::new(script));
    let port = Arc::new(CountingGetPort {
        get_calls: AtomicUsize::new(0),
        metered_calls: AtomicUsize::new(0),
        requests_per_call,
        outcome: ProviderAttemptOutcome::Decisive,
        direct_body: Mutex::new(None),
        metered_operations: Mutex::new(Vec::new()),
    });
    let gateway = FragmentProviderGateway::with_transport_port(
        CellSchemaAttestation::for_tests(boundary()),
        ProviderCapabilities::none().with_listing(),
        put_bound,
        charge_bound,
        SharedAuthority(Arc::clone(&authority)),
        SharedGetPort(Arc::clone(&port)),
    );
    (gateway, authority, port)
}

fn harness(script: ChargeScript) -> Harness {
    Harness::new(script, 1, bound())
}

/// Waits until every in-flight put slot is taken, then returns.
///
/// Bounded rather than an open spin: if admission ever stops taking a permit
/// for a put, the condition becomes unreachable, and an unbounded loop would
/// hang the suite instead of reporting the regression. A hang is not a test
/// result.
async fn wait_until_puts_are_saturated(gateway: &FragmentProviderGateway) {
    for _ in 0..100_000 {
        if gateway.available_put_permits() == 0 {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("an in-flight put never took its admission permit");
}

/// Waits until the scripted authority has observed `n` charge calls.
///
/// Mirrors [`wait_until_puts_are_saturated`]'s bounded-spin shape for the
/// same reason: an open loop would hang the suite, not fail it, if
/// admission ever stopped reaching the limiter. Reaching the limiter
/// proves the admission permit was already taken, since
/// `admit_operation`/`admit_put` acquire it before `execute` can ever call
/// the charge authority.
async fn wait_until_charge_calls_reach(authority: &ScriptedChargeAuthority, n: u32) {
    for _ in 0..100_000 {
        if authority.calls.load(Ordering::SeqCst) >= n {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("the charge authority never observed {n} call(s)");
}

/// A one-permit charge bound, so a second concurrent charge-carrying
/// attempt has nowhere to go and must queue or fail closed.
fn narrow_charge_bound() -> InFlightChargeBound {
    match InFlightChargeBound::new(1, Duration::from_millis(40)) {
        Ok(bound) => bound,
        Err(error) => panic!("fixture charge bound must be valid: {error}"),
    }
}

// -----------------------------------------------------------------------
// Property 1: installed cell schema and the typed authority client
// -----------------------------------------------------------------------

fn expected_layer(id: CellSchemaLayerId) -> &'static CellSchemaLayer {
    match CELL_SCHEMA_LAYERS.iter().find(|layer| layer.id == id) {
        Some(layer) => layer,
        None => panic!("every attested layer must exist in CELL_SCHEMA_LAYERS"),
    }
}

fn installed(id: CellSchemaLayerId) -> InstalledLayerIdentity {
    let layer = expected_layer(id);
    let decoded = match hex::decode(layer.migration_blake3_hex) {
        Ok(decoded) => decoded,
        Err(error) => panic!("frozen layer digest must be hex: {error}"),
    };
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&decoded);
    InstalledLayerIdentity {
        schema_revision: layer.schema_revision.to_string(),
        migration_blake3: digest,
        install_revision: 1,
        installed_at_unix_ms: ATTEMPT_TIMESTAMP_MS,
    }
}

fn installed_state() -> DispatcherIdentityState {
    DispatcherIdentityState {
        retention: installed(CellSchemaLayerId::Retention),
        local_authority: installed(CellSchemaLayerId::Authority),
        put_reservation: installed(CellSchemaLayerId::PutReservation),
        dispatcher_identity: installed(CellSchemaLayerId::DispatcherIdentity),
    }
}

fn layer_slot(state: &mut DispatcherIdentityState, index: usize) -> &mut InstalledLayerIdentity {
    match index {
        0 => &mut state.retention,
        1 => &mut state.local_authority,
        2 => &mut state.put_reservation,
        3 => &mut state.dispatcher_identity,
        _ => panic!("ATTESTED_LAYERS has exactly four slots"),
    }
}

/// The recorded install revisions must come from the readback, not from a
/// local constant. A distinctive revision per layer is what makes that
/// falsifiable: comparing against `ATTESTED_LAYERS` alone would restate the
/// module's own definition and could not fail.
#[test]
fn an_attestation_records_the_readbacks_own_install_revisions() {
    let mut state = installed_state();
    state.retention.install_revision = 11;
    state.local_authority.install_revision = 22;
    state.put_reservation.install_revision = 33;
    state.dispatcher_identity.install_revision = 44;

    let attestation = match verify_installed_layers(&state, boundary()) {
        Ok(attestation) => attestation,
        Err(error) => panic!("a fully installed cell must attest: {error}"),
    };
    assert_eq!(
        attestation.attested_layers(),
        [
            (CellSchemaLayerId::Retention.label(), 11),
            (CellSchemaLayerId::Authority.label(), 22),
            (CellSchemaLayerId::PutReservation.label(), 33),
            (CellSchemaLayerId::DispatcherIdentity.label(), 44),
        ],
    );
    assert_eq!(attestation.boundary(), &boundary());
    assert_ne!(
        attestation,
        CellSchemaAttestation::for_tests(boundary()),
        "a fabricated attestation must not compare equal to an attested one",
    );
}

/// The gateway addresses the cell its attestation was minted for, and there
/// is no second boundary that could disagree.
#[test]
fn a_gateway_addresses_the_boundary_its_attestation_carries() {
    let here = harness(ChargeScript::Grant);
    let elsewhere = Harness::with_boundary(ChargeScript::Grant, 1, bound(), other_boundary());
    assert_eq!(here.gateway.boundary(), &boundary());
    assert_eq!(elsewhere.gateway.boundary(), &other_boundary());
    assert_eq!(
        here.gateway.attestation().boundary(),
        here.gateway.boundary(),
    );
    assert_eq!(
        elsewhere.gateway.attestation().boundary(),
        elsewhere.gateway.boundary(),
    );
}

/// Drives every attested layer against every field the attestation reads,
/// rather than a hand-picked pair.
///
/// The loop ranges over the local `ATTESTED_LAYERS`, so it cannot by itself
/// notice a fifth layer appearing in the readback — an earlier version of
/// this comment claimed it could. What notices that is
/// [`the_attestation_does_not_cover_the_budget_limiter_layer`], which ranges
/// over `CELL_SCHEMA_LAYERS` instead and names the one deliberate
/// exclusion.
#[test]
fn each_attested_layer_and_each_read_field_independently_refuses() {
    assert_eq!(ATTESTED_LAYERS.len(), 4);
    for (index, id) in ATTESTED_LAYERS.iter().enumerate() {
        for mutation in 0..3 {
            let mut state = installed_state();
            {
                let slot = layer_slot(&mut state, index);
                match mutation {
                    0 => slot.schema_revision.push('x'),
                    1 => slot.migration_blake3[0] ^= 0xff,
                    _ => slot.install_revision = 0,
                }
            }
            assert_eq!(
                verify_installed_layers(&state, boundary()),
                Err(FragmentSchemaAttestationError::Mismatch { layer: *id }),
                "layer {} mutation {mutation} must refuse and name its own layer",
                id.label(),
            );
        }
    }
}

/// Pins the honest scope of the attestation. 0019's readback covers four of
/// the six installed layers, and the two it leaves out are left out for
/// different reasons rather than by oversight.
///
/// CD-4's budget-limiter layer — the one the charge itself executes against
/// — has no readback at all here. CD-8's cell-retention layer has one, but
/// it is 0024's own `read_state`, called by `lore-server` when it schedules
/// the retention pass, not by this connect-time attestation. A cell may run
/// the governed provider route with the retention layer absent; that is a
/// refusal at the scheduler, not at provider activation.
#[test]
fn the_attestation_covers_every_layer_with_a_readback_here() {
    const UNATTESTED: [CellSchemaLayerId; 2] = [
        CellSchemaLayerId::BudgetLimiter,
        CellSchemaLayerId::CellRetention,
    ];
    assert_eq!(CELL_SCHEMA_LAYERS.len(), 6);
    for excluded in UNATTESTED {
        assert!(
            !ATTESTED_LAYERS.contains(&excluded),
            "layer {} is documented as unattested here but appears in ATTESTED_LAYERS",
            excluded.label(),
        );
    }
    for layer in CELL_SCHEMA_LAYERS {
        if !UNATTESTED.contains(&layer.id) {
            assert!(
                ATTESTED_LAYERS.contains(&layer.id),
                "layer {} must be attested or explicitly excluded",
                layer.id.label(),
            );
        }
    }
}

// -----------------------------------------------------------------------
// Property 2: through the shared limiter and the governed client
// -----------------------------------------------------------------------

#[tokio::test]
async fn a_refused_charge_reaches_no_transport_and_counts_no_grant() {
    let harness = harness(ChargeScript::Refuse(ProviderChargeError::BudgetExhausted));
    let mut ledger = ledger();
    let outcome = harness
        .gateway
        .execute(&mut ledger, &attempt(ProviderAttemptClass::HeadObject))
        .await;
    assert_eq!(
        outcome,
        Err(FragmentProviderError::Provider(
            ProviderClientError::ChargeRefused(ProviderChargeError::BudgetExhausted)
        ))
    );
    assert_eq!(harness.charge_calls(), 1);
    assert_eq!(harness.issued(), 0);
    assert_eq!(ledger.committed_grant_count(), 0);
    assert_eq!(ledger.attempt_count(), 0);
}

#[tokio::test]
async fn a_granted_charge_binds_exactly_one_issued_attempt() {
    let harness = harness(ChargeScript::Grant);
    let mut ledger = ledger();
    let outcome = harness
        .gateway
        .execute(&mut ledger, &attempt(ProviderAttemptClass::HeadObject))
        .await;
    assert_eq!(outcome, Ok(ProviderAttemptOutcome::Decisive));
    assert_eq!(harness.charge_calls(), 1);
    assert_eq!(harness.issued(), 1);
    assert_eq!(ledger.committed_grant_count(), 1);
    assert_eq!(ledger.attempt_count(), 1);
    assert_eq!(ledger.decisive_terminal_count(), 1);
}

#[tokio::test]
async fn get_returns_the_typed_response_with_zero_database_authority_calls() {
    let (gateway, authority, port) = get_harness(1);

    let execution = gateway.get(&get_attempt(), &get_operation()).await;

    assert_eq!(
        execution,
        Ok(FragmentGetExecution {
            outcome: ProviderAttemptOutcome::Decisive,
            response: FragmentGetResponse::Found {
                bytes: vec![1, 2, 3],
                metadata: vec![("codec".to_string(), "raw".to_string())],
            },
        })
    );
    assert_eq!(authority.calls.load(Ordering::SeqCst), 0);
    assert_eq!(port.get_calls.load(Ordering::SeqCst), 1);
    assert_eq!(port.metered_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn get_exposes_a_response_only_for_exactly_one_wire_request() {
    for (reported, expected) in [
        (
            0,
            Err(FragmentProviderError::Provider(
                ProviderClientError::TransportReportInconsistent,
            )),
        ),
        (
            2,
            Err(FragmentProviderError::Provider(
                ProviderClientError::TransportIssuedUnauthorizedRequests,
            )),
        ),
    ] {
        let (gateway, authority, port) = get_harness(reported);

        assert_eq!(
            gateway.get(&get_attempt(), &get_operation()).await,
            expected
        );
        assert_eq!(
            authority.calls.load(Ordering::SeqCst),
            0,
            "reported={reported}"
        );
        assert_eq!(
            port.get_calls.load(Ordering::SeqCst),
            1,
            "reported={reported}"
        );
        assert_eq!(
            port.metered_calls.load(Ordering::SeqCst),
            0,
            "reported={reported}"
        );
    }
}

#[tokio::test]
async fn head_list_and_delete_each_charge_and_send_once_while_get_stays_unmetered() {
    let cases = [
        (
            ProviderAttemptClass::HeadObject,
            FragmentTransportOperation::Head {
                object_key: "objects/fragment.bin".to_string(),
            },
        ),
        (
            ProviderAttemptClass::ListObjectVersions,
            FragmentTransportOperation::ListVersions {
                object_key: "objects/fragment.bin".to_string(),
            },
        ),
        (
            ProviderAttemptClass::DeleteObject,
            FragmentTransportOperation::DeleteVersion {
                object_key: "objects/fragment.bin".to_string(),
                version_id: "version-1".to_string(),
            },
        ),
        (
            ProviderAttemptClass::DeleteObject,
            FragmentTransportOperation::DeleteExact {
                object_key: "objects/exact-fragment.bin".to_string(),
            },
        ),
    ];
    for (class, operation) in cases {
        let (gateway, authority, port) = port_harness(ChargeScript::Grant, 1, bound());
        let admitted = gateway
            .admit_operation(attempt(class), operation.clone())
            .await
            .expect("metered non-GET admission");
        admitted
            .execute(&mut ledger())
            .await
            .expect("metered non-GET execution");
        assert_eq!(authority.calls.load(Ordering::SeqCst), 1, "{class:?}");
        assert_eq!(port.metered_calls.load(Ordering::SeqCst), 1, "{class:?}");
        assert_eq!(port.get_calls.load(Ordering::SeqCst), 0, "{class:?}");
        assert_eq!(
            port.metered_operations
                .lock()
                .expect("metered operation lock")
                .as_slice(),
            std::slice::from_ref(&operation),
            "the gateway must preserve the exact operation and key"
        );
    }

    let (gateway, authority, port) = get_harness(1);
    gateway
        .get(&get_attempt(), &get_operation())
        .await
        .expect("unmetered GET");
    assert_eq!(authority.calls.load(Ordering::SeqCst), 0);
    assert_eq!(port.get_calls.load(Ordering::SeqCst), 1);
    assert_eq!(port.metered_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn an_ambiguous_commit_stays_charged_and_sends_nothing() {
    let harness = harness(ChargeScript::Refuse(ProviderChargeError::AmbiguousCommit));
    let mut ledger = ledger();
    let outcome = harness
        .gateway
        .execute(&mut ledger, &attempt(ProviderAttemptClass::HeadObject))
        .await;
    assert_eq!(
        outcome,
        Err(FragmentProviderError::Provider(
            ProviderClientError::ChargeAmbiguous
        ))
    );
    assert_eq!(harness.issued(), 0);
    assert_eq!(ledger.committed_grant_count(), 1);
    assert_eq!(ledger.attempt_count(), 0);
}

/// A provider that gave no definite answer is reported as `Ok`, and the
/// seam must hand that back rather than flattening it into success or into
/// an error. The ledger counts one charged, one issued, one ambiguous, and
/// no decisive terminal, which is what a caller has to distinguish on.
#[tokio::test]
async fn a_transport_reported_ambiguous_outcome_is_returned_as_itself() {
    let harness = Harness::with_outcome(
        ChargeScript::Grant,
        1,
        bound(),
        boundary(),
        ProviderAttemptOutcome::Ambiguous,
    );
    let mut ledger = ledger();
    let outcome = harness
        .gateway
        .execute(&mut ledger, &attempt(ProviderAttemptClass::HeadObject))
        .await;
    assert_eq!(
        outcome,
        Ok(ProviderAttemptOutcome::Ambiguous),
        "an unknown provider effect must not arrive as Decisive",
    );
    assert_eq!(harness.issued(), 1);
    assert_eq!(ledger.committed_grant_count(), 1);
    assert_eq!(ledger.attempt_count(), 1);
    assert_eq!(ledger.ambiguous_count(), 1);
    assert_eq!(
        ledger.decisive_terminal_count(),
        0,
        "an ambiguous outcome is not a terminal one",
    );
}

#[tokio::test]
async fn a_grant_that_does_not_bind_the_attempt_sends_nothing_and_closes_the_ledger() {
    let harness = harness(ChargeScript::GrantForAnotherAttempt);
    let mut ledger = ledger();
    let outcome = harness
        .gateway
        .execute(&mut ledger, &attempt(ProviderAttemptClass::DeleteObject))
        .await;
    assert_eq!(
        outcome,
        Err(FragmentProviderError::Provider(
            ProviderClientError::GrantDoesNotBindAttempt
        ))
    );
    assert_eq!(harness.issued(), 0);
    assert_eq!(ledger.committed_grant_count(), 1);
    assert!(ledger.poisoned().is_some());
}

#[tokio::test]
async fn the_shipped_gateway_charges_nothing_and_sends_nothing() {
    let gateway = FragmentProviderGateway::unwired(
        CellSchemaAttestation::for_tests(boundary()),
        ProviderCapabilities::none(),
        bound(),
        test_charge_bound(),
    );
    let mut ledger = ledger();
    let outcome = gateway
        .execute(&mut ledger, &attempt(ProviderAttemptClass::HeadObject))
        .await;
    assert_eq!(
        outcome,
        Err(FragmentProviderError::Provider(
            ProviderClientError::ChargeRefused(ProviderChargeError::Unwired)
        ))
    );
    assert_eq!(ledger.committed_grant_count(), 0);
    assert_eq!(ledger.attempt_count(), 0);
}

// -----------------------------------------------------------------------
// Property 3: no SDK automatic retries
// -----------------------------------------------------------------------

/// The observable half of the no-auto-retry rule. A declaration proves
/// nothing about an SDK's internals; the count a transport reports does, and
/// more than the one charged request closes the ledger.
#[tokio::test]
async fn a_transport_that_issued_more_than_the_charged_request_poisons_the_ledger() {
    let harness = Harness::new(ChargeScript::Grant, 3, bound());
    let mut ledger = ledger();
    let outcome = harness
        .gateway
        .execute(&mut ledger, &attempt(ProviderAttemptClass::HeadObject))
        .await;
    assert_eq!(
        outcome,
        Err(FragmentProviderError::Provider(
            ProviderClientError::TransportIssuedUnauthorizedRequests
        ))
    );
    assert!(ledger.poisoned().is_some());
    assert_eq!(ledger.committed_grant_count(), 1);
}

/// A shape assertion, not an independent pin: `ProviderRetryPolicy` has one
/// constructible value, so this cannot fail on its own. It is here to state
/// what the constructor chose. The falsifiable enforcement is the test above
/// and the constructor-signature pin in
/// `tests/seam_source_pins.rs`.
#[test]
fn the_gateway_states_retries_disabled() {
    let harness = harness(ChargeScript::Grant);
    assert_eq!(
        harness.gateway.retry_policy(),
        ProviderRetryPolicy::disabled()
    );
    assert_eq!(harness.gateway.retry_policy().max_attempts(), 1);
}

// -----------------------------------------------------------------------
// Property 4: the ingress cap, the class allowlist, and in-flight puts
// -----------------------------------------------------------------------

#[test]
fn the_ingress_cap_is_lore_bases_existing_fragment_threshold() {
    // Comparing the constant to `FRAGMENT_SIZE_THRESHOLD` would restate its
    // own definition and could not fail. What the literals catch is a
    // *value* change on either side: `lore-base` raising the fragment
    // threshold, or this seam's cap drifting away from it. They do not catch
    // a re-spelling of the cap as its own `256 * 1024` literal — that keeps
    // the value and only loses the coupling, and the guard against it is the
    // constant's own definition, which is one line and reviewable.
    assert_eq!(FRAGMENT_PROVIDER_INGRESS_CAP_BYTES, 256 * 1024);
    assert_eq!(FRAGMENT_SIZE_THRESHOLD, 256 * 1024);
}

#[tokio::test]
async fn direct_put_bounds_are_zero_one_cap_and_cap_plus_one_before_charge() {
    for (size, expected) in [
        (
            0,
            Err(FragmentProviderError::Provider(
                ProviderClientError::DirectPutBodyOutOfBounds,
            )),
        ),
        (1, Ok(())),
        (FRAGMENT_PROVIDER_INGRESS_CAP_BYTES as usize, Ok(())),
        (
            FRAGMENT_PROVIDER_INGRESS_CAP_BYTES as usize + 1,
            Err(FragmentProviderError::IngressCapExceeded),
        ),
    ] {
        let body = vec![0x5a; size];
        let (gateway, authority, port) = port_harness(ChargeScript::Grant, 1, bound());
        let admitted = gateway
            .admit_put(
                attempt(ProviderAttemptClass::PutObject),
                put_operation(&body),
            )
            .await;
        let result = match admitted {
            Ok(admitted) => admitted
                .execute_direct_put(&mut ledger(), &body)
                .await
                .map(|_| ()),
            Err(error) => Err(error),
        };
        assert_eq!(result, expected, "body size {size}");
        let expected_calls = u32::from(expected.is_ok());
        assert_eq!(authority.calls.load(Ordering::SeqCst), expected_calls);
        assert_eq!(
            port.metered_calls.load(Ordering::SeqCst),
            expected_calls as usize
        );
    }
}

#[tokio::test]
async fn direct_put_admission_is_body_free_and_precedes_charge_and_send() {
    let body = b"body-arrives-only-after-admission";
    let (gateway, authority, port) = port_harness(ChargeScript::Grant, 1, bound());
    let admitted = gateway
        .admit_put(
            attempt(ProviderAttemptClass::PutObject),
            put_operation(body),
        )
        .await
        .expect("body-free PUT admission");
    assert_eq!(authority.calls.load(Ordering::SeqCst), 0);
    assert_eq!(port.metered_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        gateway.available_put_permits(),
        gateway.in_flight_put_bound().permits() - 1
    );

    let execution = admitted
        .execute_direct_put(&mut ledger(), body)
        .await
        .expect("admitted direct PUT");
    assert_eq!(execution.response, FragmentTransportResponse::PutCreated);
    assert_eq!(authority.calls.load(Ordering::SeqCst), 1);
    assert_eq!(port.metered_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        port.direct_body
            .lock()
            .expect("direct body lock")
            .as_deref(),
        Some(body.as_slice())
    );
}

#[tokio::test]
async fn direct_put_declared_size_and_hash_mismatch_before_charge() {
    let body = b"bound-body";
    for mutation in [0, 1] {
        let (gateway, authority, port) = port_harness(ChargeScript::Grant, 1, bound());
        let mut operation = put_operation(body);
        let FragmentDirectPutOperation {
            declared_size,
            declared_blake3,
            ..
        } = &mut operation;
        if mutation == 0 {
            *declared_size += 1;
        } else {
            declared_blake3[0] ^= 0x80;
        }
        let admitted = gateway
            .admit_put(attempt(ProviderAttemptClass::PutObject), operation)
            .await
            .expect("declaration shape admits without body");
        assert_eq!(
            admitted.execute_direct_put(&mut ledger(), body).await,
            Err(FragmentProviderError::Provider(
                ProviderClientError::DirectPutBodyBindingMismatch
            )),
            "mutation {mutation}"
        );
        assert_eq!(authority.calls.load(Ordering::SeqCst), 0);
        assert_eq!(port.metered_calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn refused_direct_put_charge_sends_zero_wire_requests() {
    let body = b"refused-direct-put";
    let (gateway, authority, port) = port_harness(
        ChargeScript::Refuse(ProviderChargeError::BudgetExhausted),
        1,
        bound(),
    );
    let admitted = gateway
        .admit_put(
            attempt(ProviderAttemptClass::PutObject),
            put_operation(body),
        )
        .await
        .expect("body-free PUT admission");
    let mut ledger = ledger();
    assert_eq!(
        admitted.execute_direct_put(&mut ledger, body).await,
        Err(FragmentProviderError::Provider(
            ProviderClientError::ChargeRefused(ProviderChargeError::BudgetExhausted)
        ))
    );
    assert_eq!(authority.calls.load(Ordering::SeqCst), 1);
    assert_eq!(port.metered_calls.load(Ordering::SeqCst), 0);
    assert_eq!(ledger.committed_grant_count(), 0);
    assert_eq!(ledger.attempt_count(), 0);
}

/// Iterates the closed `ProviderAttemptClass::ALL`, so a variant added
/// upstream must be classified here rather than defaulting into either set.
#[test]
fn every_attempt_class_is_either_permitted_or_refused_by_name() {
    let mut refused = Vec::new();
    for class in ProviderAttemptClass::ALL {
        let verdict = FragmentProviderGateway::check_attempt_class(class);
        if FRAGMENT_PROVIDER_ATTEMPT_CLASSES.contains(&class) {
            assert_eq!(
                verdict,
                Ok(()),
                "{} must be permitted",
                class.metric_label()
            );
        } else {
            assert_eq!(
                verdict,
                Err(FragmentProviderError::AttemptClassNotPermitted {
                    class: class.metric_label()
                }),
                "{} must be refused by its own name",
                class.metric_label(),
            );
            refused.push(class);
        }
    }
    assert_eq!(
        refused,
        vec![
            ProviderAttemptClass::GetObject,
            ProviderAttemptClass::CreateMultipartUpload,
            ProviderAttemptClass::UploadPart,
            ProviderAttemptClass::CompleteMultipartUpload,
            ProviderAttemptClass::AbortMultipartUpload,
        ],
        "the refused set is GET, which has its own path, plus unreachable multipart",
    );
}

/// The arithmetic reason multipart is refused rather than merely unused: a
/// capped body cannot plan as multipart under any limits the provider itself
/// accepts, because the smallest legal part is 5 MiB.
#[test]
fn a_capped_body_can_never_plan_as_multipart() {
    let limits = ProviderPutLimits {
        multipart_threshold_bytes: PROVIDER_MIN_PART_SIZE_BYTES,
        part_size_bytes: PROVIDER_MIN_PART_SIZE_BYTES,
        max_parts: PROVIDER_MAX_MULTIPART_PARTS,
    };
    let plan = match plan_put_object(FRAGMENT_PROVIDER_INGRESS_CAP_BYTES, &limits) {
        Ok(plan) => plan,
        Err(error) => panic!("the smallest legal limits must plan a capped body: {error}"),
    };
    assert!(matches!(plan, PutObjectPlan::SingleShot { .. }));
}

#[test]
fn the_in_flight_put_bound_refuses_every_out_of_domain_configuration() {
    assert_eq!(
        InFlightPutBound::new(0, Duration::from_millis(1)),
        Err(FragmentProviderError::InvalidInFlightPutBound)
    );
    assert_eq!(
        InFlightPutBound::new(MAX_IN_FLIGHT_PUTS + 1, Duration::from_millis(1)),
        Err(FragmentProviderError::InvalidInFlightPutBound)
    );
    assert_eq!(
        InFlightPutBound::new(1, Duration::ZERO),
        Err(FragmentProviderError::InvalidInFlightPutBound)
    );
    assert!(InFlightPutBound::new(DEFAULT_IN_FLIGHT_PUTS, Duration::from_secs(1)).is_ok());
    assert!(InFlightPutBound::new(MAX_IN_FLIGHT_PUTS, Duration::from_secs(1)).is_ok());
}

/// Drives the bound to exhaustion with a real in-flight put and proves the
/// next put fails closed rather than joining an unbounded queue.
#[tokio::test]
async fn a_put_beyond_the_configured_bound_fails_closed_while_a_slot_is_held() {
    let single = match InFlightPutBound::new(1, Duration::from_millis(40)) {
        Ok(bound) => bound,
        Err(error) => panic!("fixture bound must be valid: {error}"),
    };
    let (gateway, authority, _port) = port_harness(ChargeScript::Hang, 1, single);
    let gateway = Arc::new(gateway);

    let holder = Arc::clone(&gateway);
    let held = lore_base::lore_spawn!(async move {
        let body = vec![0x5a; 1_024];
        let mut ledger = ledger();
        let admitted = holder
            .admit_put(
                attempt(ProviderAttemptClass::PutObject),
                put_operation(&body),
            )
            .await;
        if let Ok(admitted) = admitted {
            let _ = admitted.execute_direct_put(&mut ledger, &body).await;
        }
    });
    // Wait for the first put to actually own the only slot. No sleep: the
    // permit count is the condition, so this cannot pass early.
    wait_until_puts_are_saturated(&gateway).await;

    let body = vec![0x5a; 1_024];
    let outcome = gateway
        .admit_put(
            attempt(ProviderAttemptClass::PutObject),
            put_operation(&body),
        )
        .await;
    assert!(matches!(
        outcome,
        Err(FragmentProviderError::PutAdmissionTimedOut)
    ));
    assert_eq!(
        authority.calls.load(Ordering::SeqCst),
        1,
        "only the admitted put may reach the limiter",
    );
    held.abort();
}

/// The bound is a *put* bound. A HEAD carries no body, so it must proceed
/// while every put slot is taken.
#[tokio::test]
async fn a_non_body_class_takes_no_in_flight_put_slot() {
    let single = match InFlightPutBound::new(1, Duration::from_millis(40)) {
        Ok(bound) => bound,
        Err(error) => panic!("fixture bound must be valid: {error}"),
    };
    let (gateway, authority, _port) = port_harness(ChargeScript::Hang, 1, single);
    let gateway = Arc::new(gateway);

    let holder = Arc::clone(&gateway);
    let held = lore_base::lore_spawn!(async move {
        let body = vec![0x5a; 1_024];
        let mut ledger = ledger();
        let admitted = holder
            .admit_put(
                attempt(ProviderAttemptClass::PutObject),
                put_operation(&body),
            )
            .await;
        if let Ok(admitted) = admitted {
            let _ = admitted.execute_direct_put(&mut ledger, &body).await;
        }
    });
    wait_until_puts_are_saturated(&gateway).await;

    // The scripted authority hangs, so a HEAD that took a put slot would time
    // out on admission first. Racing it against a bounded timeout separates
    // "queued behind the put bound" from "reached the limiter and is waiting
    // there", which are the two outcomes this test has to tell apart.
    let mut ledger = ledger();
    let raced = tokio::time::timeout(Duration::from_millis(200), async {
        gateway
            .admit_operation(
                attempt(ProviderAttemptClass::HeadObject),
                FragmentTransportOperation::Head {
                    object_key: "objects/fragment.bin".to_string(),
                },
            )
            .await?
            .execute(&mut ledger)
            .await
    })
    .await;
    match raced {
        Err(_elapsed) => {
            assert_eq!(
                authority.calls.load(Ordering::SeqCst),
                2,
                "the bodyless attempt must have reached the limiter, not the put queue",
            );
        }
        Ok(outcome) => {
            panic!("a bodyless attempt must not resolve while the limiter hangs, got {outcome:?}")
        }
    }
    held.abort();
}

// -----------------------------------------------------------------------
// The charge-admission bound (CR-033 charge authority pool exhaustion)
// -----------------------------------------------------------------------

/// CR-033's cell charge authority pool is at most 4-5 leases, and every
/// charge takes one of them. With no bound on the attempts themselves, a
/// 1550-fragment push issued HeadObject/ListObjectVersions/DeleteObject
/// charges as fast as its fan-out allowed and the pool refused 50 of them
/// with `PoolExhausted`. This drives the narrow charge bound to exhaustion
/// with a real held admission for every accepted non-body class and proves
/// a concurrent second attempt of that class fails closed rather than
/// joining an unbounded queue, then proves the slot is usable again once
/// released — the same shape as
/// `a_put_beyond_the_configured_bound_fails_closed_while_a_slot_is_held`
/// for the put bound.
#[tokio::test]
async fn a_charge_carrying_attempt_beyond_the_configured_bound_fails_closed_then_releases() {
    let (gateway, _authority, _port) =
        port_harness_with_bounds(ChargeScript::Grant, 1, bound(), narrow_charge_bound());
    let gateway = Arc::new(gateway);

    for (class, operation) in [
        (
            ProviderAttemptClass::HeadObject,
            FragmentTransportOperation::Head {
                object_key: "objects/fragment.bin".to_string(),
            },
        ),
        (
            ProviderAttemptClass::ListObjectVersions,
            FragmentTransportOperation::ListVersions {
                object_key: "objects/fragment.bin".to_string(),
            },
        ),
        (
            ProviderAttemptClass::DeleteObject,
            FragmentTransportOperation::DeleteVersion {
                object_key: "objects/fragment.bin".to_string(),
                version_id: "v1".to_string(),
            },
        ),
    ] {
        let admitted_signal = Arc::new(tokio::sync::Notify::new());
        let release_signal = Arc::new(tokio::sync::Notify::new());
        let holder = Arc::clone(&gateway);
        let holder_operation = operation.clone();
        let admitted_signal_task = Arc::clone(&admitted_signal);
        let release_signal_task = Arc::clone(&release_signal);
        let held = lore_base::lore_spawn!(async move {
            let admitted = holder
                .admit_operation(attempt(class), holder_operation)
                .await
                .expect("the first attempt must take the only charge slot");
            admitted_signal_task.notify_one();
            release_signal_task.notified().await;
            drop(admitted);
        });
        admitted_signal.notified().await;

        // A second attempt of the same class queues behind the held slot
        // and times out rather than joining an unbounded queue.
        let refused = gateway
            .admit_operation(attempt(class), operation.clone())
            .await
            .err();
        assert_eq!(
            refused,
            Some(FragmentProviderError::ChargeAdmissionTimedOut),
            "{} must fail closed while the only charge slot is held",
            class.metric_label(),
        );

        release_signal.notify_one();
        held.await.expect("holder task must complete");

        // Once released, a fresh attempt of the same class admits again
        // rather than hanging behind a permit that was never returned.
        let admitted = tokio::time::timeout(
            Duration::from_millis(200),
            gateway.admit_operation(attempt(class), operation),
        )
        .await
        .unwrap_or_else(|_| {
            panic!(
                "{} admission must not hang once the charge slot is released",
                class.metric_label(),
            )
        })
        .unwrap_or_else(|error| {
            panic!(
                "{} must admit once the charge slot is released: {error}",
                class.metric_label(),
            )
        });
        drop(admitted);
    }
}

/// The charge bound governs non-body attempts only. A put must proceed
/// while the charge bound is fully saturated, or CR-031's put bound would
/// stop meaning what it says — the two numbers must stay independent in
/// both directions, and `a_non_body_class_takes_no_in_flight_put_slot`
/// above already pins the other direction (a saturated put bound does not
/// block a non-body attempt).
#[tokio::test]
async fn charge_admission_saturation_does_not_block_a_put() {
    let (gateway, authority, _port) =
        port_harness_with_bounds(ChargeScript::Hang, 1, bound(), narrow_charge_bound());
    let gateway = Arc::new(gateway);

    let holder = Arc::clone(&gateway);
    let held = lore_base::lore_spawn!(async move {
        let mut ledger = ledger();
        let admitted = holder
            .admit_operation(
                attempt(ProviderAttemptClass::HeadObject),
                FragmentTransportOperation::Head {
                    object_key: "objects/fragment.bin".to_string(),
                },
            )
            .await;
        if let Ok(admitted) = admitted {
            let _ = admitted.execute(&mut ledger).await;
        }
    });
    // Wait for the HEAD to actually own the only charge slot and reach the
    // (hanging) limiter. No sleep: the call count is the condition, so this
    // cannot pass early.
    wait_until_charge_calls_reach(&authority, 1).await;

    // The scripted authority hangs, so a put that queued behind the charge
    // bound would time out on admission first. Racing it against a bounded
    // timeout separates "queued behind the charge bound" from "reached the
    // limiter and is waiting there", the two outcomes this test has to
    // tell apart — the mirror of `a_non_body_class_takes_no_in_flight_put_slot`.
    let body = vec![0x5a; 1_024];
    let mut ledger = ledger();
    let raced = tokio::time::timeout(Duration::from_millis(200), async {
        gateway
            .admit_put(
                attempt(ProviderAttemptClass::PutObject),
                put_operation(&body),
            )
            .await?
            .execute_direct_put(&mut ledger, &body)
            .await
    })
    .await;
    match raced {
        Err(_elapsed) => {
            assert_eq!(
                authority.calls.load(Ordering::SeqCst),
                2,
                "the put must have reached the limiter, not queued behind the charge bound",
            );
        }
        Ok(outcome) => {
            panic!("a put must not resolve while the limiter hangs, got {outcome:?}")
        }
    }
    held.abort();
}

/// **The deadline must survive the charge queue.** Callers mint
/// `deadline_unix_ms` while building the attempt, before any admission
/// wait. Without `admit_operation` shifting it by the time actually
/// spent queueing, a deep charge queue would burn the caller's whole
/// `io_timeout` waiting and then fail as `charge_deadline_exceeded` — the
/// same push failure wearing a different name.
///
/// There is no public accessor on an admitted attempt or on
/// `AdmittedFragmentAttempt`, so this observes the shift the closest
/// honest way available: the exact `deadline_unix_ms` the scripted charge
/// authority receives in the request `execute` builds from the (shifted)
/// attempt. **Missing observability, not filled in here** — flagged as
/// requested rather than adding a public accessor.
///
/// This deliberately stays on the real, unpaused clock rather than
/// `#[tokio::test(start_paused = true)]`. The holder task below is
/// dispatched with `lore_base::lore_spawn!`, which puts it on
/// `lore_base::runtime::runtime()` — a separate, lazily-built, real
/// multi-thread Tokio runtime shared process-wide (see
/// `lore-base/src/runtime.rs`), not on this test's own `#[tokio::test]`
/// runtime. Pausing time is scoped to the calling runtime's time driver;
/// it would not slow or synchronize the holder's `tokio::time::sleep`,
/// which runs for real regardless. Worse, `admit_operation`'s own
/// `queued_at.elapsed()` is read from *this* task's (paused) clock, so
/// pausing here would make the production shift arithmetic observe ~0ms
/// waited despite the holder genuinely sleeping for real — an unsound
/// combination, the same shape as the `IoDriver` case in
/// `docs/testing-gotchas.md`'s "Deterministic async tests" section.
///
/// So instead of a tight real-clock margin, this widens both sides: the
/// hold is long enough (400ms) that ordinary scheduling jitter under a
/// loaded machine (this rig also runs Docker and cargo builds) cannot
/// plausibly eat the whole interval, and the assertion only requires a
/// third of that (100ms) rather than requiring most of it — proving a
/// real, substantial forward shift occurred without demanding a value
/// close to the nominal hold.
#[tokio::test]
async fn a_charge_carrying_attempts_deadline_survives_the_admission_queue() {
    const HOLD: Duration = Duration::from_millis(400);
    const MIN_OBSERVED_SHIFT_MS: i64 = 100;

    let generous = match InFlightChargeBound::new(1, Duration::from_secs(5)) {
        Ok(bound) => bound,
        Err(error) => panic!("fixture charge bound must be valid: {error}"),
    };
    let (gateway, authority, _port) =
        port_harness_with_bounds(ChargeScript::Grant, 1, bound(), generous);
    let gateway = Arc::new(gateway);

    let admitted_signal = Arc::new(tokio::sync::Notify::new());
    let holder = Arc::clone(&gateway);
    let admitted_signal_task = Arc::clone(&admitted_signal);
    let held = lore_base::lore_spawn!(async move {
        let admitted = holder
            .admit_operation(
                attempt(ProviderAttemptClass::HeadObject),
                FragmentTransportOperation::Head {
                    object_key: "objects/fragment.bin".to_string(),
                },
            )
            .await
            .expect("the first attempt must take the only charge slot");
        admitted_signal_task.notify_one();
        // Hold the slot for a measurable interval so the second attempt
        // has a real, known-minimum wait to observe.
        tokio::time::sleep(HOLD).await;
        drop(admitted);
    });
    admitted_signal.notified().await;

    let mut ledger = ledger();
    let admitted = gateway
        .admit_operation(
            attempt(ProviderAttemptClass::HeadObject),
            FragmentTransportOperation::Head {
                object_key: "objects/fragment.bin".to_string(),
            },
        )
        .await
        .expect("the second attempt must admit once the slot frees");
    admitted
        .execute(&mut ledger)
        .await
        .expect("a granted charge must execute");
    held.await.expect("holder task must complete");

    let observed = authority.last_seen_deadline_unix_ms.load(Ordering::SeqCst);
    assert!(
        observed >= DEADLINE_MS + MIN_OBSERVED_SHIFT_MS,
        "the deadline the charge authority observed ({observed}) must be shifted forward \
             by a substantial fraction of the {HOLD:?} the second attempt waited for the charge \
             slot, starting from {DEADLINE_MS}",
    );
}

/// The companion negative control: an admission that never queues must
/// not shift the deadline. Without this, the test above alone could pass
/// against an implementation that inflates every deadline unconditionally
/// rather than by the actual wait.
///
/// Unlike the queueing test above, this one calls `admit_operation`
/// directly with no `lore_spawn!` holder and no real wait at all, so it
/// is safe to run on a fully paused virtual clock: `queued_at` and the
/// `Instant::now()` it is measured against both come from this same
/// test's own runtime, and nothing here ever calls `tokio::time::advance`,
/// so the clock cannot move. That makes the old ~50ms real-clock
/// tolerance unnecessary — the wait is exactly zero, deterministically,
/// not just usually.
#[tokio::test(start_paused = true)]
async fn a_charge_carrying_attempts_deadline_is_unchanged_on_the_fast_path() {
    let (gateway, authority, _port) = port_harness(ChargeScript::Grant, 1, bound());

    let mut ledger = ledger();
    let admitted = gateway
        .admit_operation(
            attempt(ProviderAttemptClass::HeadObject),
            FragmentTransportOperation::Head {
                object_key: "objects/fragment.bin".to_string(),
            },
        )
        .await
        .expect("an unsaturated charge bound must admit immediately");
    admitted
        .execute(&mut ledger)
        .await
        .expect("a granted charge must execute");

    let observed = authority.last_seen_deadline_unix_ms.load(Ordering::SeqCst);
    assert_eq!(
        observed, DEADLINE_MS,
        "an immediate admission on a paused clock that never advances must not shift the \
             deadline at all",
    );
}

#[test]
fn the_in_flight_charge_bound_refuses_every_out_of_domain_configuration() {
    assert_eq!(
        InFlightChargeBound::new(0, Duration::from_millis(1)),
        Err(FragmentProviderError::InvalidInFlightChargeBound)
    );
    assert_eq!(
        InFlightChargeBound::new(MAX_IN_FLIGHT_CHARGES + 1, Duration::from_millis(1)),
        Err(FragmentProviderError::InvalidInFlightChargeBound)
    );
    assert_eq!(
        InFlightChargeBound::new(1, Duration::ZERO),
        Err(FragmentProviderError::InvalidInFlightChargeBound)
    );
    let valid = match InFlightChargeBound::new(DEFAULT_IN_FLIGHT_CHARGES, Duration::from_secs(1)) {
        Ok(bound) => bound,
        Err(error) => panic!("a valid charge bound must construct: {error}"),
    };
    assert_eq!(valid.permits(), DEFAULT_IN_FLIGHT_CHARGES as usize);
    assert_eq!(valid.acquire_timeout(), Duration::from_secs(1));
    assert!(InFlightChargeBound::new(MAX_IN_FLIGHT_CHARGES, Duration::from_secs(1)).is_ok());
}

/// Without these two arms, `transient_diagnostic`'s `_ => None` catch-all
/// would swallow both — exactly the blindness the charge bound exists to
/// fix, since a refusal that cannot be counted is invisible.
#[test]
fn charge_admission_refusals_carry_their_own_transient_diagnostic() {
    assert_eq!(
        FragmentProviderError::ChargeAdmissionTimedOut.transient_diagnostic(),
        Some("charge_admission_timeout"),
    );
    assert_eq!(
        FragmentProviderError::ChargeAdmissionClosed.transient_diagnostic(),
        Some("charge_admission_closed"),
    );
}

// -----------------------------------------------------------------------
// Property 5: the cell's own region and nothing else
// -----------------------------------------------------------------------

#[test]
fn every_built_request_addresses_exactly_this_cells_boundary() {
    let harness = harness(ChargeScript::Grant);
    let expected: &ProviderTarget = harness.gateway.boundary().target();
    for class in FRAGMENT_PROVIDER_ATTEMPT_CLASSES {
        let request = harness.gateway.build_request(&attempt(class));
        assert_eq!(
            &request.target,
            expected,
            "{} must address the cell's own bucket, region, and endpoint",
            class.metric_label(),
        );
        assert_eq!(request.put_part, None);
    }
}

#[test]
fn a_gateway_never_addresses_another_cells_boundary() {
    let here = harness(ChargeScript::Grant);
    let elsewhere = Harness::with_boundary(ChargeScript::Grant, 1, bound(), other_boundary());
    let here_target = here
        .gateway
        .build_request(&attempt(ProviderAttemptClass::GetObject))
        .target;
    let elsewhere_target = elsewhere
        .gateway
        .build_request(&attempt(ProviderAttemptClass::GetObject))
        .target;
    assert_ne!(here_target.bucket, elsewhere_target.bucket);
    assert_ne!(here_target.region, elsewhere_target.region);
    assert_ne!(here_target.endpoint_host, elsewhere_target.endpoint_host);
    assert_eq!(&here_target, here.gateway.boundary().target());
    assert_eq!(&elsewhere_target, elsewhere.gateway.boundary().target());
}

// -----------------------------------------------------------------------
// Disposition — the dispatch-free classification consumers match on
// -----------------------------------------------------------------------

/// Every charge refusal, named, with the disposition it carries. The list is
/// exhaustive over `ProviderChargeError`; `disposition`'s charge arm is too,
/// with no wildcard, so a variant added upstream breaks the build there and
/// this list here rather than landing in a catch-all.
///
/// The four that used to fall through untested are `BudgetPinRejected`,
/// `ConfigurationUnresolved`, `DeadlineExceeded` and `AttemptAlreadyCharged`.
#[test]
fn every_charge_refusal_carries_a_named_disposition() {
    let expected: [(ProviderChargeError, FragmentProviderDisposition); 10] = [
        (
            ProviderChargeError::Unwired,
            FragmentProviderDisposition::Transient,
        ),
        (
            ProviderChargeError::BudgetExhausted,
            FragmentProviderDisposition::Transient,
        ),
        (
            ProviderChargeError::ClassCapExhausted,
            FragmentProviderDisposition::Transient,
        ),
        (
            ProviderChargeError::AuthorityUnavailable,
            FragmentProviderDisposition::Transient,
        ),
        (
            ProviderChargeError::DeadlineExceeded,
            FragmentProviderDisposition::Transient,
        ),
        (
            ProviderChargeError::BudgetPinRejected,
            FragmentProviderDisposition::NotReady,
        ),
        (
            ProviderChargeError::ConfigurationUnresolved,
            FragmentProviderDisposition::NotReady,
        ),
        (
            ProviderChargeError::AttemptAlreadyCharged,
            FragmentProviderDisposition::OutcomeUnknown,
        ),
        (
            ProviderChargeError::AmbiguousCommit,
            FragmentProviderDisposition::OutcomeUnknown,
        ),
        (
            ProviderChargeError::RecoveredCommittedCharge,
            FragmentProviderDisposition::OutcomeUnknown,
        ),
    ];

    for (refusal, disposition) in expected {
        let observed = FragmentProviderError::Provider(ProviderClientError::ChargeRefused(refusal))
            .disposition();
        assert_eq!(
            observed, disposition,
            "{refusal} must carry {disposition:?}"
        );
        assert_ne!(
            observed,
            FragmentProviderDisposition::Internal,
            "{refusal} must not reach the catch-all",
        );
    }
}

/// An unresolved outcome must never be classified as retryable capacity.
#[test]
fn an_unresolved_charge_outcome_is_never_transient() {
    for error in [
        FragmentProviderError::Provider(ProviderClientError::ChargeAmbiguous),
        FragmentProviderError::Provider(ProviderClientError::ChargeRecovered),
        FragmentProviderError::Provider(ProviderClientError::ChargeRefused(
            ProviderChargeError::AmbiguousCommit,
        )),
    ] {
        assert_eq!(
            error.disposition(),
            FragmentProviderDisposition::OutcomeUnknown,
            "{error} must be OutcomeUnknown",
        );
    }
}

/// The seam's own refusals classify without touching the provider at all.
#[test]
fn every_local_refusal_carries_a_named_disposition() {
    for (error, disposition) in [
        (
            FragmentProviderError::IngressCapExceeded,
            FragmentProviderDisposition::InvalidInput,
        ),
        (
            FragmentProviderError::InvalidInFlightPutBound,
            FragmentProviderDisposition::InvalidInput,
        ),
        (
            FragmentProviderError::AttemptClassNotPermitted {
                class: "UploadPart",
            },
            FragmentProviderDisposition::InvalidInput,
        ),
        (
            FragmentProviderError::PutAdmissionTimedOut,
            FragmentProviderDisposition::Transient,
        ),
        (
            FragmentProviderError::PutAdmissionClosed,
            FragmentProviderDisposition::Transient,
        ),
        (
            FragmentProviderError::InvalidInFlightChargeBound,
            FragmentProviderDisposition::InvalidInput,
        ),
        (
            FragmentProviderError::ChargeAdmissionTimedOut,
            FragmentProviderDisposition::Transient,
        ),
        (
            FragmentProviderError::ChargeAdmissionClosed,
            FragmentProviderDisposition::Transient,
        ),
        (
            FragmentProviderError::Provider(ProviderClientError::ChargeRefused(
                ProviderChargeError::BudgetPinRejected,
            )),
            FragmentProviderDisposition::NotReady,
        ),
        // WP-114 CD-6's drain refusals. All four are decisive caller
        // faults the seam catches before any charge or send, so all four
        // classify the same way the direct-PUT path's own local refusals
        // above do.
        (
            FragmentProviderError::SpoolBindingRejected(ProviderClientError::PutBodyNotDurable),
            FragmentProviderDisposition::InvalidInput,
        ),
        (
            FragmentProviderError::SpoolBindingRequestMismatch,
            FragmentProviderDisposition::InvalidInput,
        ),
        (
            FragmentProviderError::ClaimBindingMismatch,
            FragmentProviderDisposition::InvalidInput,
        ),
        (
            FragmentProviderError::DrainBodyMismatch,
            FragmentProviderDisposition::InvalidInput,
        ),
    ] {
        assert_eq!(
            error.disposition(),
            disposition,
            "{error} must carry {disposition:?}",
        );
    }
}

// -----------------------------------------------------------------------
// WP-114 CD-6: FragmentDrainCapability
// -----------------------------------------------------------------------
//
// Narrowness by construction (no pool/dispatch/gateway/entry accessor, no
// caller-nameable traffic class or declared size/digest, the three-token
// confinement to this capability's own impl block) is proved structurally
// in `tests/seam_source_pins.rs` and demonstrated in
// `tests/drain_capability_compile_fail.rs`. What belongs here instead is
// behavior: the independent-anchor fail-open case, the refusal ordering,
// the shared limiter, and the disposition each refusal carries.

use lore_object_dispatch::SpoolLayout;
use lore_object_dispatch::SpoolObjectKey;
use lore_object_dispatch::SpoolObjectKind;

/// A one-permit put bound with a short timeout, so a drain that must
/// queue behind an already-held permit fails fast instead of hanging the
/// suite.
fn narrow_put_bound() -> InFlightPutBound {
    match InFlightPutBound::new(1, Duration::from_millis(50)) {
        Ok(bound) => bound,
        Err(error) => panic!("fixture put bound must be valid: {error}"),
    }
}

/// A syntactically absolute path that is never opened. `SpoolLayout::new`
/// only validates that a root is absolute and carries no `.`/`..`
/// component, and `bind_durable_put_body_from_ready` performs no
/// filesystem access at all — exactly the property these tests exercise
/// without a real spool directory.
///
/// The `cfg!(windows)` fork is load-bearing, not cosmetic: a `C:\` root is
/// not `is_absolute()` on Linux, so a Windows-only literal makes
/// `SpoolLayout::new` return `InvalidSharedSpoolRoot` and every case in
/// this module panic in its fixture — on the platform production runs on.
fn drain_spool_root() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\lore-fragment-provider-test-spool")
    } else {
        PathBuf::from("/var/lib/lore-fragment-provider-test-spool")
    }
}

/// The opaque handle a real spool write would have produced for this
/// logical request and attempt, computed the same way the seam derives
/// and checks it. Building this once per fixture, rather than guessing a
/// string, is what lets a fixture legitimately bind instead of failing
/// for the wrong reason.
fn drain_durable_handle(logical_request_id: &str, attempt_id: &str) -> String {
    let key = SpoolObjectKey {
        provider_boundary_id: BOUNDARY_ID.to_string(),
        logical_request_id: logical_request_id.to_string(),
        attempt_id: attempt_id.to_string(),
        kind: SpoolObjectKind::Put,
    };
    let layout = match SpoolLayout::new(drain_spool_root()) {
        Ok(layout) => layout,
        Err(error) => panic!("fixture spool layout must be valid: {error}"),
    };
    match layout.derive_paths(&key) {
        Ok(paths) => paths.opaque_handle().to_string(),
        Err(error) => panic!("fixture spool paths must derive: {error}"),
    }
}

/// A ready outcome that binds cleanly to `drain_durable_handle`'s own
/// handle for the given size and digest. Every field the binder does not
/// read is a fixed, arbitrary value.
fn drain_ready_outcome(
    logical_request_id: &str,
    attempt_id: &str,
    committed_size: u64,
    committed_blake3: [u8; 32],
) -> PutSpoolReadyOutcome {
    let parse = |value: &str| match Uuid::parse_str(value) {
        Ok(id) => id,
        Err(error) => panic!("fixture uuid {value} must parse: {error}"),
    };
    PutSpoolReadyOutcome {
        spool_object_id: parse(attempt_id),
        logical_request_id: parse(logical_request_id),
        attempt_id: parse(attempt_id),
        upload_id: parse(attempt_id),
        upload_fence: 1,
        durable_handle: drain_durable_handle(logical_request_id, attempt_id),
        committed_size,
        committed_blake3,
        ready_at_unix_ms: ATTEMPT_TIMESTAMP_MS,
        reserve_put_ack_canonical_bytes: Vec::new(),
        reserve_put_ack_blake3: [0u8; 32],
        spool_revision: 1,
        record_blake3: [0u8; 32],
    }
}

/// A drain attempt naming `claim_body_blake3`/`claim_body_size` exactly
/// as given — callers building the fail-open case pass a claim digest
/// that disagrees with the spool on purpose.
fn drain_attempt_fixture(
    logical_request_id: &str,
    attempt_id: &str,
    claim_body_blake3: [u8; 32],
    claim_body_size: u64,
) -> FragmentDrainAttempt {
    FragmentDrainAttempt {
        logical_request_id: logical_request_id.to_string(),
        attempt_id: attempt_id.to_string(),
        attempt_ordinal: 1,
        deadline_unix_ms: DEADLINE_MS,
        budget_pin: pin(),
        object_key: "objects/fragment.bin".to_string(),
        metadata: vec![("codec".to_string(), "raw".to_string())],
        claim_body_blake3,
        claim_body_size,
    }
}

/// A syntactically valid, never-connecting dispatch pool configuration.
/// `DispatchRuntimePool::new`'s own doc says configuration is validated
/// and an empty pool is built; no connection is opened. And
/// `DispatchRuntimeClient::new` only checks the pool's configured role.
/// So every case below that returns before `admit_put`'s doubles run
/// never touches Postgres. `cell.invalid` is the same deliberately
/// non-resolving host `lore-object-dispatch`'s own `dispatch_pool.rs`
/// tests use, for the same reason.
fn offline_dispatch_pool() -> Arc<DispatchRuntimePool> {
    let budget = match DispatchConnectionBudget::new(1, 1, 1, 1, 1, 0) {
        Ok(budget) => budget,
        Err(error) => panic!("fixture dispatch budget must be valid: {error}"),
    };
    let config = DispatchPoolConfig {
        postgres_url: format!(
            "postgres://{}:secret@cell.invalid:5432/lorecell?sslmode=disable",
            lore_object_dispatch::DISPATCH_RUNTIME_ROLE,
        ),
        role: DispatchPoolRole::Runtime,
        expected_database_identity: match DispatchDatabaseIdentity::new(1, 1) {
            Ok(identity) => identity,
            Err(error) => panic!("fixture database identity must be valid: {error}"),
        },
        pool_max: 1,
        connect_timeout: Duration::from_millis(50),
        acquire_timeout: Duration::from_millis(50),
        statement_timeout: Duration::from_millis(50),
        lock_timeout: Duration::from_millis(50),
        tls: DispatchTlsMode::Disabled,
        budget,
    };
    match DispatchRuntimePool::new(config) {
        Ok(pool) => Arc::new(pool),
        Err(error) => panic!("fixture dispatch pool config must be valid: {error}"),
    }
}

/// A wired `FragmentProviderEntry` (`port_wired` true, via
/// `with_transport_port`) built on the same `SharedAuthority`/
/// `SharedGetPort` doubles the rest of this module uses, plus an offline
/// dispatch pool. Private-field construction is legitimate here: this
/// helper lives inside the crate, the same access `FragmentProviderEntry::connect`
/// itself has, and it is the only way to reach a drain capability without
/// a live database.
fn drain_entry(
    script: ChargeScript,
    put_bound: InFlightPutBound,
) -> (
    Arc<FragmentProviderEntry>,
    Arc<ScriptedChargeAuthority>,
    Arc<CountingGetPort>,
) {
    let authority = Arc::new(ScriptedChargeAuthority::new(script));
    let port = Arc::new(CountingGetPort {
        get_calls: AtomicUsize::new(0),
        metered_calls: AtomicUsize::new(0),
        requests_per_call: 1,
        outcome: ProviderAttemptOutcome::Decisive,
        direct_body: Mutex::new(None),
        metered_operations: Mutex::new(Vec::new()),
    });
    let gateway = FragmentProviderGateway::with_transport_port(
        CellSchemaAttestation::for_tests(boundary()),
        ProviderCapabilities::none().with_listing(),
        put_bound,
        test_charge_bound(),
        SharedAuthority(Arc::clone(&authority)),
        SharedGetPort(Arc::clone(&port)),
    );
    let pool = offline_dispatch_pool();
    let dispatch = match DispatchRuntimeClient::new(pool.clone()) {
        Ok(dispatch) => dispatch,
        Err(error) => panic!("fixture dispatch client must construct: {error}"),
    };
    let entry = Arc::new(FragmentProviderEntry {
        gateway,
        _dispatch: dispatch,
        pool,
    });
    (entry, authority, port)
}

fn mint_drain_capability(entry: &Arc<FragmentProviderEntry>) -> FragmentDrainCapability {
    match entry.drain_capability(drain_spool_root()) {
        Ok(capability) => capability,
        Err(error) => panic!("fixture drain capability must construct: {error}"),
    }
}

/// The fail-open case this tranche exists to close. The spool digest
/// agrees with itself — the sent bytes match the bound spool body
/// exactly — but the independent claim anchor does not. Before this
/// check existed, a caller that spooled the wrong file would have its
/// bytes agree with its own spool-ready declaration and the send would
/// proceed; comparing only against a digest the same caller had already
/// spooled lets a wrong file pass with both sides agreeing. Refused
/// before any charge, any send, or even the put permit.
#[tokio::test]
async fn attempt_drain_refuses_when_the_claim_digest_disagrees_even_though_the_spool_matches_itself()
 {
    let body = b"drain payload matches the spool exactly".to_vec();
    let spool_blake3 = *blake3::hash(&body).as_bytes();
    let (entry, authority, port) = drain_entry(ChargeScript::Grant, narrow_put_bound());
    let capability = mint_drain_capability(&entry);
    let ready = FragmentDrainReady(drain_ready_outcome(
        REQUEST_ID,
        ATTEMPT_ID,
        body.len() as u64,
        spool_blake3,
    ));
    // A different digest than the spool's own — the independent anchor a
    // caller cannot forge by spooling consistently with itself.
    let wrong_claim_blake3 = *blake3::hash(b"a different file entirely").as_bytes();
    let request = drain_attempt_fixture(
        REQUEST_ID,
        ATTEMPT_ID,
        wrong_claim_blake3,
        body.len() as u64,
    );

    let mut ledger = ledger();
    let outcome = capability
        .attempt_drain(&mut ledger, request, &ready, &body)
        .await;

    assert_eq!(outcome, Err(FragmentProviderError::ClaimBindingMismatch));
    assert_eq!(
        authority.calls.load(Ordering::SeqCst),
        0,
        "a claim mismatch must be refused before any charge",
    );
    assert_eq!(
        port.metered_calls.load(Ordering::SeqCst),
        0,
        "a claim mismatch must be refused before any send",
    );
    assert_eq!(
        entry.gateway.available_put_permits(),
        1,
        "a claim mismatch must be refused before the put permit is taken",
    );
}

/// The ready receipt was minted for a different logical request than the
/// attempt claims. Caught by the seam's own cross-check, before the claim
/// anchor is read at all.
#[tokio::test]
async fn attempt_drain_refuses_when_the_ready_receipt_names_a_different_logical_request() {
    const OTHER_REQUEST_ID: &str = "018bcfe5-6800-7abc-8def-000000000099";
    let body = b"drain payload".to_vec();
    let spool_blake3 = *blake3::hash(&body).as_bytes();
    let (entry, authority, port) = drain_entry(ChargeScript::Grant, narrow_put_bound());
    let capability = mint_drain_capability(&entry);
    // Minted for OTHER_REQUEST_ID, so it binds cleanly to its OWN
    // identity — the mismatch is entirely in the cross-check against the
    // attempt below, not in the spool binding itself.
    let ready = FragmentDrainReady(drain_ready_outcome(
        OTHER_REQUEST_ID,
        ATTEMPT_ID,
        body.len() as u64,
        spool_blake3,
    ));
    let request = drain_attempt_fixture(REQUEST_ID, ATTEMPT_ID, spool_blake3, body.len() as u64);

    let mut ledger = ledger();
    let outcome = capability
        .attempt_drain(&mut ledger, request, &ready, &body)
        .await;

    assert_eq!(
        outcome,
        Err(FragmentProviderError::SpoolBindingRequestMismatch),
        "the binding itself succeeded — the receipt is canonically derived \
             for its own identity — so this must be the seam's cross-check, not \
             a dispatch binding refusal",
    );
    assert_eq!(authority.calls.load(Ordering::SeqCst), 0);
    assert_eq!(port.metered_calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn attempt_drain_refuses_ready_from_another_physical_attempt_of_the_same_request() {
    const OTHER_ATTEMPT_ID: &str = "018bcfe5-6800-7abc-8def-000000000098";
    let body = b"same logical request, different physical send".to_vec();
    let digest = *blake3::hash(&body).as_bytes();
    let (entry, authority, port) = drain_entry(ChargeScript::Grant, narrow_put_bound());
    let capability = mint_drain_capability(&entry);
    let ready = FragmentDrainReady(drain_ready_outcome(
        REQUEST_ID,
        OTHER_ATTEMPT_ID,
        body.len() as u64,
        digest,
    ));
    let request = drain_attempt_fixture(REQUEST_ID, ATTEMPT_ID, digest, body.len() as u64);
    let outcome = capability
        .attempt_drain(&mut ledger(), request, &ready, &body)
        .await;
    assert_eq!(
        outcome,
        Err(FragmentProviderError::SpoolBindingRequestMismatch)
    );
    assert_eq!(authority.calls.load(Ordering::SeqCst), 0);
    assert_eq!(port.metered_calls.load(Ordering::SeqCst), 0);
}

/// The bound body is above the existing 256 KiB ingress cap. Refused
/// before the put permit is taken — the same "cheapest check first"
/// ordering the direct-PUT path already proves for itself.
#[tokio::test]
async fn attempt_drain_refuses_an_oversized_bound_body_before_taking_a_permit() {
    let arbitrary_blake3 = [0xAB; 32];
    let oversized = FRAGMENT_PROVIDER_INGRESS_CAP_BYTES + 1;
    let (entry, authority, port) = drain_entry(ChargeScript::Grant, narrow_put_bound());
    let capability = mint_drain_capability(&entry);
    let ready = FragmentDrainReady(drain_ready_outcome(
        REQUEST_ID,
        ATTEMPT_ID,
        oversized,
        arbitrary_blake3,
    ));
    let request = drain_attempt_fixture(REQUEST_ID, ATTEMPT_ID, arbitrary_blake3, oversized);

    let mut ledger = ledger();
    let outcome = capability
        .attempt_drain(
            &mut ledger,
            request,
            &ready,
            b"irrelevant, refused before read",
        )
        .await;

    assert_eq!(outcome, Err(FragmentProviderError::IngressCapExceeded));
    assert_eq!(authority.calls.load(Ordering::SeqCst), 0);
    assert_eq!(port.metered_calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        entry.gateway.available_put_permits(),
        1,
        "an oversized bound body must be refused before the put permit is taken",
    );
}

/// The claim agrees with the spool; only the bytes actually handed to
/// `attempt_drain` disagree with both.
#[tokio::test]
async fn attempt_drain_refuses_when_the_supplied_bytes_do_not_match_the_bound_body() {
    let spooled = b"the body the drain worker actually spooled".to_vec();
    let spool_blake3 = *blake3::hash(&spooled).as_bytes();
    let (entry, authority, port) = drain_entry(ChargeScript::Grant, narrow_put_bound());
    let capability = mint_drain_capability(&entry);
    let ready = FragmentDrainReady(drain_ready_outcome(
        REQUEST_ID,
        ATTEMPT_ID,
        spooled.len() as u64,
        spool_blake3,
    ));
    let request = drain_attempt_fixture(REQUEST_ID, ATTEMPT_ID, spool_blake3, spooled.len() as u64);
    let wrong_bytes = b"a completely different body".to_vec();

    let mut ledger = ledger();
    let outcome = capability
        .attempt_drain(&mut ledger, request, &ready, &wrong_bytes)
        .await;

    assert_eq!(outcome, Err(FragmentProviderError::DrainBodyMismatch));
    assert_eq!(authority.calls.load(Ordering::SeqCst), 0);
    assert_eq!(port.metered_calls.load(Ordering::SeqCst), 0);
}

/// An empty bound body passes every one of the seam's own pre-checks
/// (zero equals zero, and the empty hash agrees with itself), so the
/// refusal originates downstream in CD-5's own body-bounds check
/// (`DirectPutBodyOutOfBounds`) and must land on `Internal` via the
/// catch-all, not on `InvalidInput`: this is a request the seam should
/// never have let through, not a caller-supplied value it caught itself.
#[tokio::test]
async fn attempt_drain_maps_an_empty_bound_body_to_internal_not_invalid_input() {
    let empty: Vec<u8> = Vec::new();
    let empty_blake3 = *blake3::hash(&empty).as_bytes();
    let (entry, _authority, _port) = drain_entry(ChargeScript::Grant, narrow_put_bound());
    let capability = mint_drain_capability(&entry);
    let ready = FragmentDrainReady(drain_ready_outcome(REQUEST_ID, ATTEMPT_ID, 0, empty_blake3));
    let request = drain_attempt_fixture(REQUEST_ID, ATTEMPT_ID, empty_blake3, 0);

    let mut ledger = ledger();
    let outcome = capability
        .attempt_drain(&mut ledger, request, &ready, &empty)
        .await;

    let error = outcome.expect_err("an empty body must be refused, not sent");
    assert_eq!(
        error.disposition(),
        FragmentProviderDisposition::Internal,
        "got {error}",
    );
    assert_ne!(
        error.disposition(),
        FragmentProviderDisposition::InvalidInput
    );
}

/// A fully agreeing drain succeeds, and the charge authority observes
/// exactly the forced `Drain` traffic class — never a caller-supplied
/// one, since `FragmentDrainAttempt` has no such field — while the
/// transport receives exactly the bound spool body's own bytes.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "requires a fresh disposable PostgreSQL 16 database and Linux spool root"]
async fn attempt_drain_forces_the_drain_traffic_class_and_sends_the_bound_bodys_own_bytes() {
    use lore_object_dispatch::cell_budget_configure::LOCAL_BUDGET_REVISION;
    use lore_object_dispatch::cell_budget_configure::LocalBudgetConfiguration;
    mod local_budget_fixture {
        // Copyright 2026 Tideshift Labs
        // SPDX-License-Identifier: MIT
        // Fixture publisher for a disposable local database. It uses the real guarded
        // maintenance procedure. Production configure_budget retains its TLS requirement.
        use lore_object_dispatch::cell_budget_configure::LocalBudgetConfiguration;

        pub async fn publish(
            client: &tokio_postgres::Client,
            config: &LocalBudgetConfiguration,
        ) -> Result<(), Box<dyn std::error::Error>> {
            config.validate()?;
            assert!(
                config.predecessor.is_none(),
                "fixture supports first publication only"
            );
            assert_eq!(config.allocation_fence, 1);
            fn digest(label: &str, bytes: &[u8]) -> blake3::Hash {
                let mut hasher = blake3::Hasher::new_derive_key(label);
                hasher.update(bytes);
                hasher.finalize()
            }
            let core = digest(
                "Commit0 local development budget core v1",
                &serde_json::to_vec(config)?,
            );
            let disposition = digest(
                "Commit0 local development no-cache disposition v1",
                core.as_bytes(),
            );
            let envelope = digest(
                "Commit0 local development budget envelope v1",
                disposition.as_bytes(),
            );
            let disposition_id = uuid::Uuid::from_slice(&disposition.as_bytes()[..16])?;
            let dimensions = serde_json::json!([{"dimensionId":"local-policy-requests", "effectiveBound":config.shared_units,
                    "measuredLoad":0, "targetDemand":0, "failureReserve":0, "preCacheHeadroom":config.shared_units, "finalBudget":config.shared_units}]).to_string();
            let vector = digest(
                "Commit0 local development budget vector v1",
                dimensions.as_bytes(),
            );
            let caps = serde_json::to_string(&(1..=7).map(|class| {
                    let units = match class { 1 => config.shared_units, 7 => config.list_units, _ => config.class_units };
                    serde_json::json!({"capClass":class,"capacityUnits":units,"refillUnits":units,"refillIntervalMs":config.refill_interval_ms})
                }).collect::<Vec<_>>())?;
            client.batch_execute("SET SESSION AUTHORIZATION object_dispatch_retention_maintenance; BEGIN ISOLATION LEVEL SERIALIZABLE").await?;
            let row = client
                .query_one(
                    PUBLISH_SQL,
                    &[
                        &config.provider_boundary_id,
                        &config.allocation_revision,
                        &"1",
                        &config.hard_expires_at_unix_ms,
                        &config.cell_id,
                        &core.as_bytes().as_slice(),
                        &disposition_id,
                        &disposition.as_bytes().as_slice(),
                        &Option::<uuid::Uuid>::None,
                        &Option::<Vec<u8>>::None,
                        &"0",
                        &Option::<Vec<u8>>::None,
                        &envelope.as_bytes().as_slice(),
                        &vector.as_bytes().as_slice(),
                        &dimensions,
                        &caps,
                    ],
                )
                .await?;
            let code: String = row.get("result_code");
            assert_eq!(code, "PUBLISHED", "fresh fixture must publish once");
            client
                .batch_execute("COMMIT; RESET SESSION AUTHORIZATION")
                .await?;
            Ok(())
        }

        const PUBLISH_SQL: &str = "SELECT r.result_code FROM
            object_store_retention.object_store_dispatch_publish_budget_configuration_v1(
            'object-store-dispatch-budget-limiter-v1', $1, $2, $3::text::object_store_retention.uint64, $4,
            'object-store-frozen-capacity-budget-core-v1', 'object-store-exact-target-cache-disposition-v1',
            'object-store-budget-frozen-envelope-v1', 1::smallint, $5, $3::text::object_store_retention.uint64,
            1::smallint, $5, $3::text::object_store_retention.uint64,
            1::smallint, $5, $3::text::object_store_retention.uint64, $5, $5, $1, $1,
            $3::text::object_store_retention.uint64, $3::text::object_store_retention.uint64,
            $3::text::object_store_retention.uint64, $3::text::object_store_retention.uint64,
            $3::text::object_store_retention.uint64, $3::text::object_store_retention.uint64,
            $6, $7, $8, $6, $3::text::object_store_retention.uint64,
            $9, $10, $11::text::object_store_retention.uint64, $12,
            $13, $6, $8, $14, $3::text::object_store_retention.uint64, 1::smallint,
            NULL::text, NULL::text, NULL::bytea, NULL::bytea, $14, $15::text::jsonb, $16::text::jsonb) AS r";
    }
    use lore_object_dispatch::drain_policy::DrainClient;
    use lore_object_dispatch::drain_policy::DrainDescriptor;
    use lore_object_dispatch::drain_policy::DrainPolicy;
    use lore_object_dispatch::drain_policy::DrainStagePolicy;
    use tokio_postgres::Client;
    use tokio_util::task::AbortOnDropHandle;

    // PostgreSQL 16 has no built-in BLAKE3. As in dispatch_client_live, the
    // test supplies exact genuine digests, never a permissive fallback.
    // A bounded rollback-only primer discovers each canonical preimage;
    // real reserve/ready calls then execute against that immutable lookup.
    async fn prime(admin: &Client, role: &str, sql: &str) {
        for _ in 0..24 {
            let call = format!(
                "SET SESSION AUTHORIZATION {role}; BEGIN ISOLATION LEVEL SERIALIZABLE; {sql}; ROLLBACK; RESET SESSION AUTHORIZATION;"
            );
            match admin.batch_execute(&call).await {
                Ok(()) => return,
                Err(error) => {
                    admin
                        .batch_execute("ROLLBACK; RESET SESSION AUTHORIZATION;")
                        .await
                        .unwrap();
                    let message = error.as_db_error().expect("prime SQL error").message();
                    let payload = message.strip_prefix("FIXTURE_BLAKE3:").unwrap_or_else(|| {
                        panic!("unexpected authority refusal while priming: {error:?}")
                    });
                    let bytes = hex::decode(payload).unwrap();
                    let digest = blake3::hash(&bytes);
                    admin.execute("INSERT INTO public.test_drain_hashes(payload,digest) VALUES($1,$2) ON CONFLICT DO NOTHING", &[&bytes,&&digest.as_bytes()[..]]).await.unwrap();
                }
            }
        }
        panic!("canonical hash primer exceeded its finite bound");
    }
    fn quoted(text: &str) -> String {
        format!("'{}'", text.replace('\'', "''"))
    }

    let url =
        std::env::var("LORE_TEST_PG_URL").expect("owned disposable PostgreSQL URL is required");
    assert!(
        url.starts_with("postgresql://postgres@"),
        "runner must supply its fresh superuser fixture"
    );
    let (admin, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
        .await
        .unwrap();
    let _connection = AbortOnDropHandle::new(lore_base::lore_spawn!("drain-live-pg", async move {
        let _ = connection.await;
    }));
    admin.batch_execute("DO $$ BEGIN
          IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='object_dispatch_retention_owner') THEN CREATE ROLE object_dispatch_retention_owner NOLOGIN; END IF;
          IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='object_dispatch_retention_runtime') THEN CREATE ROLE object_dispatch_retention_runtime LOGIN; END IF;
          IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='object_dispatch_retention_maintenance') THEN CREATE ROLE object_dispatch_retention_maintenance LOGIN; END IF;
          IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='object_dispatch_retention_migrator') THEN CREATE ROLE object_dispatch_retention_migrator LOGIN; END IF;
          END $$;
          ALTER ROLE object_dispatch_retention_runtime LOGIN;
          ALTER ROLE object_dispatch_retention_maintenance LOGIN;
          GRANT object_dispatch_retention_owner TO object_dispatch_retention_migrator WITH INHERIT FALSE, SET TRUE;").await.unwrap();
    let database: String = admin
        .query_one("SELECT current_database()", &[])
        .await
        .unwrap()
        .get(0);
    admin.batch_execute(&format!("GRANT CREATE ON DATABASE \"{}\" TO object_dispatch_retention_owner; SET SESSION AUTHORIZATION object_dispatch_retention_migrator;",database.replace('"',"\"\""))).await.unwrap();
    lore_object_dispatch::cell_schema_install::install_cell_schema(&admin)
        .await
        .expect("supported full-chain install and attestation");
    admin.batch_execute("RESET SESSION AUTHORIZATION;
          CREATE TABLE public.test_drain_hashes(payload bytea PRIMARY KEY,digest bytea NOT NULL);
          CREATE FUNCTION public.blake3(payload bytea) RETURNS bytea LANGUAGE plpgsql STABLE STRICT SECURITY DEFINER SET search_path=pg_catalog AS $$
          DECLARE value bytea; BEGIN SELECT h.digest INTO value FROM public.test_drain_hashes h WHERE h.payload=blake3.payload;
          IF value IS NULL THEN RAISE EXCEPTION 'FIXTURE_BLAKE3:%',encode(payload,'hex'); END IF; RETURN value; END $$;").await.unwrap();
    let row=admin.query_one("SELECT s.system_identifier::text,d.oid::bigint,floor(extract(epoch FROM clock_timestamp())*1000)::bigint FROM pg_control_system() s,pg_database d WHERE d.datname=current_database()",&[]).await.unwrap();
    let system: String = row.get(0);
    let oid = row.get::<_, i64>(1) as u32;
    let now: i64 = row.get(2);
    let identity = DispatchDatabaseIdentity::new(system.parse().unwrap(), oid).unwrap();
    let runtime_url = format!(
        "{}{}sslmode=disable",
        url.replacen("://postgres@", "://object_dispatch_retention_runtime@", 1),
        if url.contains('?') { "&" } else { "?" }
    );
    let budget = LocalBudgetConfiguration {
        schema_revision: LOCAL_BUDGET_REVISION.into(),
        provenance: "operator-selected-local-development-limit-v1".into(),
        cell_id: "drain-test-cell".into(),
        provider_boundary_id: BOUNDARY_ID.into(),
        provider_endpoint: "http://minio:9000".into(),
        provider_bucket: "cell-alpha-fragments".into(),
        evidence_reference: "owned drain seam fixture".into(),
        system_identifier: system,
        database_oid: oid,
        allocation_revision: pin().revision,
        allocation_fence: 1,
        issued_at_unix_ms: now - 1000,
        hard_expires_at_unix_ms: now + 3600000,
        shared_units: 100,
        class_units: 50,
        list_units: 5,
        refill_interval_ms: 1000,
        predecessor: None,
    };
    local_budget_fixture::publish(&admin, &budget)
        .await
        .expect("real maintenance budget publication");
    admin.batch_execute(&format!("CREATE OR REPLACE FUNCTION object_store_retention.clock_unix_ms_v1() RETURNS bigint LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS 'SELECT {ATTEMPT_TIMESTAMP_MS}::bigint';")).await.unwrap();
    let policy = DrainPolicy {
        boundary: BOUNDARY_ID.into(),
        cell: "drain-test-cell".into(),
        service: "drain-test-service".into(),
        revision: "drain-test-policy".into(),
        quota_revision: 1,
        quotas: [[1048576, 16, 16, 0, 0, 0]; 3],
        maximum_ttl_ms: 60000,
        expires_at_ms: (DEADLINE_MS + 60000) as u64,
        metadata_max_rows: 16,
        metadata_max_bytes: 1048576,
        stage: DrainStagePolicy {
            max_bytes: 1048576,
            max_files: 16,
            max_metadata_bytes: 1048576,
            max_metadata_rows: 16,
            prepare_ttl_ms: 60000,
        },
    };
    let policy_json = serde_json::to_string(&policy).unwrap();
    let policy_bytes = policy.canonical_bytes().unwrap();
    let policy_digest = policy.digest().unwrap();
    let publish = format!(
        "SELECT object_store_retention.drain_policy_publish_v1({}::jsonb,decode('{}','hex'),decode('{}','hex'))",
        quoted(&policy_json),
        hex::encode(&policy_bytes),
        hex::encode(policy_digest)
    );
    prime(&admin, "object_dispatch_retention_maintenance", &publish).await;
    admin.batch_execute(&format!("SET SESSION AUTHORIZATION object_dispatch_retention_maintenance;BEGIN ISOLATION LEVEL SERIALIZABLE;{publish};COMMIT;RESET SESSION AUTHORIZATION;")).await.unwrap();
    let pool = Arc::new(
        DispatchRuntimePool::new(DispatchPoolConfig {
            postgres_url: runtime_url,
            role: DispatchPoolRole::Runtime,
            expected_database_identity: identity,
            pool_max: 1,
            connect_timeout: Duration::from_secs(5),
            acquire_timeout: Duration::from_secs(5),
            statement_timeout: Duration::from_secs(5),
            lock_timeout: Duration::from_secs(2),
            tls: DispatchTlsMode::Disabled,
            budget: DispatchConnectionBudget::new(1, 1, 1, 1, 1, 0).unwrap(),
        })
        .unwrap(),
    );
    let (offline, authority, port) = drain_entry(ChargeScript::Grant, narrow_put_bound());
    let Ok(mut entry) = Arc::try_unwrap(offline) else {
        panic!("fixture entry uniquely owned")
    };
    entry.pool = pool.clone();
    entry._dispatch = DispatchRuntimeClient::new(pool.clone()).unwrap();
    let entry = Arc::new(entry);
    let root = std::env::temp_dir().join(format!("lore-drain-live-{}", Uuid::now_v7()));
    std::fs::create_dir(&root).unwrap();
    let activation_pin = FragmentDrainPolicyPin {
        cell_id: policy.cell.clone(),
        revision: policy.revision.clone(),
        digest: policy_digest,
    };
    for invalid in [
        FragmentDrainPolicyPin {
            cell_id: "wrong-cell".into(),
            ..activation_pin.clone()
        },
        FragmentDrainPolicyPin {
            revision: "missing-policy".into(),
            ..activation_pin.clone()
        },
        FragmentDrainPolicyPin {
            digest: [0x55; 32],
            ..activation_pin.clone()
        },
    ] {
        assert!(
            matches!(
                entry
                    .drain_handles(
                        root.clone(),
                        invalid,
                        Duration::from_secs(1),
                        Duration::from_secs(1)
                    )
                    .await,
                Err(FragmentProviderError::DrainAuthority(_))
            ),
            "wrong cell, missing revision and wrong digest each refuse activation"
        );
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
    }
    assert!(
        matches!(
            entry
                .drain_handles(
                    root.clone(),
                    activation_pin.clone(),
                    Duration::from_secs(60),
                    Duration::from_secs(1)
                )
                .await,
            Err(FragmentProviderError::DrainAuthority(_))
        ),
        "trusted TTL must cover preparation plus send"
    );
    assert_eq!(
        std::fs::read_dir(&root).unwrap().count(),
        0,
        "rejected activation performs no spool setup"
    );
    admin.batch_execute(&format!("CREATE OR REPLACE FUNCTION object_store_retention.clock_unix_ms_v1() RETURNS bigint LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS 'SELECT {}::bigint';", policy.expires_at_ms - 500)).await.unwrap();
    assert!(
        matches!(
            entry
                .drain_handles(
                    root.clone(),
                    activation_pin,
                    Duration::from_secs(1),
                    Duration::from_secs(1)
                )
                .await,
            Err(FragmentProviderError::DrainAuthority(_))
        ),
        "policy remaining lifetime must cover both phases"
    );
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
    admin.batch_execute(&format!("CREATE OR REPLACE FUNCTION object_store_retention.clock_unix_ms_v1() RETURNS bigint LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS 'SELECT {}::bigint';", policy.expires_at_ms)).await.unwrap();
    assert!(
        matches!(
            entry
                .drain_handles(
                    root.clone(),
                    FragmentDrainPolicyPin {
                        cell_id: policy.cell.clone(),
                        revision: policy.revision.clone(),
                        digest: policy_digest
                    },
                    Duration::from_secs(1),
                    Duration::from_secs(1)
                )
                .await,
            Err(FragmentProviderError::DrainAuthority(_))
        ),
        "an expired policy cannot create spool state"
    );
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
    admin.batch_execute(&format!("CREATE OR REPLACE FUNCTION object_store_retention.clock_unix_ms_v1() RETURNS bigint LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS 'SELECT {ATTEMPT_TIMESTAMP_MS}::bigint';")).await.unwrap();
    let (capability, maintenance) = entry
        .drain_handles(
            root.clone(),
            FragmentDrainPolicyPin {
                cell_id: policy.cell.clone(),
                revision: policy.revision.clone(),
                digest: policy_digest,
            },
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
    let body = b"a fully valid drain payload".to_vec();
    let body_blake3 = *blake3::hash(&body).as_bytes();
    let input = FragmentDrainReservationInput {
        logical_request_id: REQUEST_ID.parse().unwrap(),
        attempt_id: ATTEMPT_ID.parse().unwrap(),
        upload_id: GRANT_ID.parse().unwrap(),
        spool_object_id: "018bcfe5-6800-7abc-8def-000000000004".parse().unwrap(),
        upload_fence: 1,
        source_hash: "11".repeat(32),
        source_epoch: 1,
        source_manifest: [0x22; 32],
        remote_epoch: 2,
        remote_fence: 1,
        object_key: "objects/fragment.bin".into(),
        body_digest: body_blake3,
        body_size: body.len() as u64,
        send_not_after_ms: DEADLINE_MS,
        hard_not_after_ms: DEADLINE_MS + 1000,
    };
    let layout = SpoolLayout::new(root.clone()).unwrap();
    let key = SpoolObjectKey {
        provider_boundary_id: BOUNDARY_ID.into(),
        logical_request_id: REQUEST_ID.into(),
        attempt_id: ATTEMPT_ID.into(),
        kind: SpoolObjectKind::Put,
    };
    let paths = layout.derive_paths(&key).unwrap();
    let expected = DrainDescriptor {
        policy_revision: policy.revision.clone(),
        policy_digest: hex::encode(policy_digest),
        boundary: BOUNDARY_ID.into(),
        cell: policy.cell.clone(),
        service: policy.service.clone(),
        logical_request_id: input.logical_request_id,
        attempt_id: input.attempt_id,
        upload_id: input.upload_id,
        spool_object_id: input.spool_object_id,
        upload_fence: 1,
        source_hash: input.source_hash.clone(),
        source_epoch: 1,
        source_manifest: hex::encode(input.source_manifest),
        remote_epoch: 2,
        remote_fence: 1,
        object_key: input.object_key.clone(),
        body_digest: hex::encode(body_blake3),
        body_size: body.len() as u64,
        send_not_after_ms: DEADLINE_MS as u64,
        hard_not_after_ms: (DEADLINE_MS + 1000) as u64,
        prepared_ttl_ms: 60000,
        max_chunk_bytes: FRAGMENT_PROVIDER_INGRESS_CAP_BYTES,
        allocation_revision: budget.allocation_revision.clone(),
        allocation_fence: 1,
        allocation_expiry_ms: budget.hard_expires_at_unix_ms as u64,
        boundary_digest: hex::encode(paths.boundary_binding().boundary_blake3()),
        boundary_token: paths.boundary_binding().boundary_token().into(),
        observation_digest: hex::encode(paths.observation_binding_blake3()),
    };
    let canonical = expected.canonical_bytes().unwrap();
    let reserve = format!(
        "SELECT object_store_retention.drain_reserve_v1({}::jsonb,decode('{}','hex'),decode('{}','hex'))",
        quoted(&serde_json::to_string(&expected).unwrap()),
        hex::encode(&canonical),
        blake3::hash(&canonical).to_hex()
    );
    prime(&admin, "object_dispatch_retention_runtime", &reserve).await;
    let mut plan = FragmentDrainReservationPlan::new(input.clone());
    let reservation = capability
        .reserve_spool(&mut plan)
        .await
        .expect("real guarded reservation");
    let reservation = Arc::new(reservation);
    capability
        .reserve_spool(&mut plan)
        .await
        .expect("same descriptor replay charges once");
    // Changed identities carry their genuine canonical digest, so refusal
    // proves reservation binding rather than the finite hash fixture gate.
    let mut changed_body = expected.clone();
    changed_body.body_digest = "ab".repeat(32);
    let mut changed_source = expected.clone();
    changed_source.source_epoch += 1;
    let mut changed_policy = expected.clone();
    changed_policy.policy_digest = "cd".repeat(32);
    let mut changed_fingerprint = expected.clone();
    changed_fingerprint.object_key.push_str("-different");
    let identity_client = DrainClient::new(pool.clone());
    for changed in [
        changed_body,
        changed_source,
        changed_policy,
        changed_fingerprint,
    ] {
        let canonical = changed.canonical_bytes().unwrap();
        let digest = blake3::hash(&canonical);
        admin.execute("INSERT INTO public.test_drain_hashes(payload,digest) VALUES($1,$2) ON CONFLICT DO NOTHING", &[&canonical, &&digest.as_bytes()[..]]).await.unwrap();
        assert!(
            identity_client.reserve(&changed).await.is_err(),
            "changed reservation identity cannot reuse an admitted spool identity"
        );
    }
    assert_eq!(
        maintenance.observe().await.unwrap().spool_bytes,
        body.len() as u64
    );
    let rows: i64 = admin
        .query_one(
            "SELECT count(*) FROM object_store_retention.object_dispatch_spool_objects",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        rows, 1,
        "identity conflicts cannot add a reservation or quota charge"
    );
    let receipt = reservation
        .write_body(&body)
        .expect("real durable Linux placement");
    let ready_sql = format!(
        "SELECT object_store_retention.object_store_dispatch_put_spool_ready_v1('object-store-dispatch-put-spool-ready-v1','object-dispatch-v1','{BOUNDARY_ID}','drain-test-cell','drain-test-service','{REQUEST_ID}'::uuid,'{ATTEMPT_ID}'::uuid,'{GRANT_ID}'::uuid,1::object_store_retention.uint64,0::object_store_retention.uint64,{}::object_store_retention.uint64,decode('{}','hex'),{},256,256,4096,16384)",
        body.len(),
        hex::encode(body_blake3),
        quoted(receipt.0.opaque_handle())
    );
    prime(&admin, "object_dispatch_retention_runtime", &ready_sql).await;
    let wrong_protocol = ready_sql.replacen("'object-dispatch-v1'", "'object-dispatch-invalid'", 1);
    let protocol_error = admin.batch_execute(&format!("SET SESSION AUTHORIZATION object_dispatch_retention_runtime;BEGIN ISOLATION LEVEL SERIALIZABLE;{wrong_protocol};ROLLBACK;RESET SESSION AUTHORIZATION;")).await.unwrap_err();
    admin
        .batch_execute("ROLLBACK; RESET SESSION AUTHORIZATION;")
        .await
        .unwrap();
    assert_eq!(
        protocol_error.as_db_error().unwrap().message(),
        "UPLOAD_STREAM_IDENTITY_MISMATCH"
    );
    assert_eq!(
        authority.calls.load(Ordering::SeqCst),
        0,
        "protocol mismatch cannot charge or enter transport"
    );
    let ready = capability
        .mark_spool_ready(&reservation, &receipt)
        .await
        .expect("real ready transition");
    // The charge future blocks this current-thread runtime past the
    // database-derived 250ms budget, then returns a grant in the same poll.
    // A surrounding timeout alone can poll the inner future first and
    // therefore cannot prove that the transport was never entered.
    let (delayed, delayed_authority, delayed_port) = drain_entry(
        ChargeScript::GrantAfterBlocking(Duration::from_millis(400)),
        narrow_put_bound(),
    );
    let Ok(mut delayed) = Arc::try_unwrap(delayed) else {
        panic!("delayed fixture uniquely owned")
    };
    delayed.pool = pool.clone();
    delayed._dispatch = DispatchRuntimeClient::new(pool.clone()).unwrap();
    let delayed = Arc::new(delayed);
    let (delayed_capability, _) = delayed
        .drain_handles(
            root.clone(),
            FragmentDrainPolicyPin {
                cell_id: policy.cell.clone(),
                revision: policy.revision.clone(),
                digest: policy_digest,
            },
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await
        .unwrap();
    admin.batch_execute(&format!("CREATE OR REPLACE FUNCTION object_store_retention.clock_unix_ms_v1() RETURNS bigint LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS 'SELECT {}::bigint';", DEADLINE_MS - 250)).await.unwrap();
    let mut delayed_request =
        drain_attempt_fixture(REQUEST_ID, ATTEMPT_ID, body_blake3, body.len() as u64);
    delayed_request.budget_pin = reservation.budget_pin();
    let mut delayed_ledger = ledger();
    let delayed_result = delayed_capability
        .attempt_drain(&mut delayed_ledger, delayed_request, &ready, &body)
        .await;
    assert!(
        delayed_result.is_err(),
        "expired charge cannot enter transport: {delayed_result:?}"
    );
    assert_eq!(
        delayed_authority.calls.load(Ordering::SeqCst),
        1,
        "the authority returned one grant"
    );
    assert_eq!(
        delayed_port.metered_calls.load(Ordering::SeqCst),
        0,
        "post-charge expiry permits zero provider requests"
    );
    assert_eq!(delayed_ledger.committed_grant_count(), 1);
    assert_eq!(delayed_ledger.attempt_count(), 0);
    admin.batch_execute(&format!("CREATE OR REPLACE FUNCTION object_store_retention.clock_unix_ms_v1() RETURNS bigint LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS 'SELECT {ATTEMPT_TIMESTAMP_MS}::bigint';")).await.unwrap();
    let mut request = drain_attempt_fixture(REQUEST_ID, ATTEMPT_ID, body_blake3, body.len() as u64);
    request.budget_pin = reservation.budget_pin();
    let mut ledger = ledger();
    let outcome = capability
        .attempt_drain(&mut ledger, request, &ready, &body)
        .await;
    assert!(outcome.is_ok(), "real ready spool must send: {outcome:?}");
    assert_eq!(
        authority.last_seen_traffic_class(),
        Some(ProviderTrafficClass::Drain)
    );
    assert_eq!(*port.direct_body.lock().unwrap(), Some(body.clone()));
    // Start a real writer while its reservation is still live, then hold
    // its physical completion across expiry, cleanup and full-row pruning.
    let (resume_writer, held_writer) = std::sync::mpsc::channel();
    let (writer_started, started) = tokio::sync::oneshot::channel();
    let retained_reservation = reservation.clone();
    let retained_body = body.clone();
    let late_writer = lore_base::lore_spawn_blocking!("test-held-drain-writer", move || {
        writer_started.send(()).unwrap();
        held_writer.recv().unwrap();
        retained_reservation.write_body(&retained_body)
    });
    started.await.unwrap();
    let before = authority.calls.load(Ordering::SeqCst);
    admin.batch_execute(&format!("CREATE OR REPLACE FUNCTION object_store_retention.clock_unix_ms_v1() RETURNS bigint LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS 'SELECT {}::bigint';",DEADLINE_MS+1001)).await.unwrap();
    let request = drain_attempt_fixture(REQUEST_ID, ATTEMPT_ID, body_blake3, body.len() as u64);
    assert!(
        capability
            .attempt_drain(&mut ledger, request, &ready, &body)
            .await
            .is_err(),
        "fresh expiry must refuse a retained ready token"
    );
    assert!(
        capability
            .mark_spool_ready(&reservation, &receipt)
            .await
            .is_err(),
        "ready replay cannot bypass expiry"
    );
    assert_eq!(
        authority.calls.load(Ordering::SeqCst),
        before,
        "expired token must not charge"
    );
    // Full metadata remains until both the reservation and its policy expire.
    // Keep the actual writer paused across that complete compaction horizon.
    admin.batch_execute(&format!("CREATE OR REPLACE FUNCTION object_store_retention.clock_unix_ms_v1() RETURNS bigint LANGUAGE sql STABLE SECURITY DEFINER SET search_path=pg_catalog AS 'SELECT {}::bigint';", policy.expires_at_ms + 1)).await.unwrap();
    let client = DrainClient::new(pool);
    let intent = client.claim_cleanup(input.spool_object_id).await.unwrap();
    intent.unlink(&layout).unwrap();
    let release = format!(
        "SELECT object_store_retention.drain_cleanup_release_v1('{}'::uuid,1)",
        input.spool_object_id
    );
    prime(&admin, "object_dispatch_retention_runtime", &release).await;
    client.release_cleanup(&intent).await.unwrap();
    client.release_cleanup(&intent).await.unwrap();
    let full_rows: i64 = admin.query_one("SELECT count(*) FROM object_store_retention.object_dispatch_spool_objects WHERE spool_object_id=$1", &[&input.spool_object_id]).await.unwrap().get(0);
    assert_eq!(
        full_rows, 0,
        "full spool metadata is pruned while the writer remains held"
    );
    assert!(
        maintenance.observe().await.is_err(),
        "expired maintenance policy fails closed"
    );
    let sample = client.observe(BOUNDARY_ID, &policy.cell).await.unwrap();
    assert_eq!(sample.spool_bytes, 0);
    assert!(!paths.final_path().exists());
    resume_writer.send(()).unwrap();
    late_writer
        .await
        .unwrap()
        .expect("actual late physical completion after authority cleanup and compaction");
    let late = client.observe(BOUNDARY_ID, &policy.cell).await.unwrap();
    assert_eq!(late.spool_bytes, 0);
    assert!(paths.final_path().is_file());
    assert_eq!(
        std::fs::metadata(paths.final_path()).unwrap().len(),
        body.len() as u64
    );
    assert_eq!(
        maintenance.cleanup_pass(64).await.unwrap(),
        1,
        "late physical body was removed"
    );
    let purged = client.observe(BOUNDARY_ID, &policy.cell).await.unwrap();
    assert_eq!(purged.spool_bytes, 0);
    assert!(!paths.final_path().exists());
    assert_eq!(
        maintenance.cleanup_pass(64).await.unwrap(),
        0,
        "replaying the tombstone is not fresh cleanup progress"
    );
    crate::drain::assert_cleanup_recovers_after_worker_panic(&maintenance).await;
    std::fs::remove_dir_all(&root).unwrap();
}
/// Dynamic proof, not just a source reading, that the drain shares the
/// one in-flight put semaphore with the direct fallback: holding the
/// cell's only put permit through the direct path leaves a otherwise-valid
/// drain nowhere to go but the admission queue, where it times out. A
/// drain with its own semaphore would have admitted immediately instead.
#[tokio::test]
async fn attempt_drain_shares_the_one_in_flight_put_permit_with_the_direct_fallback() {
    let (entry, _authority, _port) = drain_entry(ChargeScript::Grant, narrow_put_bound());

    let holder = entry
        .admit_put(
            attempt(ProviderAttemptClass::PutObject),
            put_operation(b"held by the direct path"),
        )
        .await
        .expect("the direct path must take the only put permit");
    assert_eq!(entry.gateway.available_put_permits(), 0);

    let body = b"a drain send with nowhere to queue".to_vec();
    let body_blake3 = *blake3::hash(&body).as_bytes();
    let capability = mint_drain_capability(&entry);
    let ready = FragmentDrainReady(drain_ready_outcome(
        REQUEST_ID,
        ATTEMPT_ID,
        body.len() as u64,
        body_blake3,
    ));
    let request = drain_attempt_fixture(REQUEST_ID, ATTEMPT_ID, body_blake3, body.len() as u64);
    let mut ledger = ledger();

    let outcome = capability
        .attempt_drain(&mut ledger, request, &ready, &body)
        .await;

    assert_eq!(
        outcome,
        Err(FragmentProviderError::PutAdmissionTimedOut),
        "if the drain had its own semaphore this would admit instead of timing out; it \
             must queue behind the direct path's already-held permit",
    );
    drop(holder);
}

/// `FragmentProviderError`'s derived `PartialEq` covers the new drain
/// variants, including a source-carrying one — proof, not the assumption
/// its `#[derive(PartialEq)]` alone would otherwise be.
#[test]
fn the_new_drain_error_variants_support_partial_eq() {
    assert_eq!(
        FragmentProviderError::SpoolBindingRejected(ProviderClientError::PutBodyNotDurable),
        FragmentProviderError::SpoolBindingRejected(ProviderClientError::PutBodyNotDurable),
    );
    // The split's whole point: the binder's cause is carried, so two
    // refusals that would have compared equal as one unit variant no
    // longer do.
    assert_ne!(
        FragmentProviderError::SpoolBindingRejected(ProviderClientError::PutBodyNotDurable),
        FragmentProviderError::SpoolBindingRejected(ProviderClientError::PutBodyHandleMismatch,),
    );
    assert_ne!(
        FragmentProviderError::SpoolBindingRejected(ProviderClientError::PutBodyNotDurable),
        FragmentProviderError::SpoolBindingRequestMismatch,
    );
    assert_ne!(
        FragmentProviderError::SpoolBindingRequestMismatch,
        FragmentProviderError::ClaimBindingMismatch,
    );
    assert_ne!(
        FragmentProviderError::ClaimBindingMismatch,
        FragmentProviderError::DrainBodyMismatch,
    );
    assert_eq!(
        FragmentProviderError::SpoolReadyRefused(DispatchAuthorityError::AmbiguousCommit),
        FragmentProviderError::SpoolReadyRefused(DispatchAuthorityError::AmbiguousCommit),
    );
    assert_ne!(
        FragmentProviderError::SpoolReadyRefused(DispatchAuthorityError::AmbiguousCommit),
        FragmentProviderError::SpoolReadyRefused(DispatchAuthorityError::AuthorityUnavailable),
    );
}

/// Exhaustive over every `DispatchAuthorityError` variant, mirroring
/// `every_charge_refusal_carries_a_named_disposition`'s style for
/// `ProviderChargeError`. The production match this pins is itself
/// exhaustive with no wildcard, so a variant added upstream fails THAT
/// build; this test is what fails HERE if an existing variant's
/// classification silently changes.
#[test]
fn every_drain_spool_ready_refusal_carries_a_named_disposition() {
    let expected: [(DispatchAuthorityError, FragmentProviderDisposition); 33] = [
        (
            DispatchAuthorityError::Pool(DispatchPoolError::PoolExhausted),
            FragmentProviderDisposition::Transient,
        ),
        (
            DispatchAuthorityError::OperationTimeout,
            FragmentProviderDisposition::Transient,
        ),
        (
            DispatchAuthorityError::RetryExhausted,
            FragmentProviderDisposition::Transient,
        ),
        (
            DispatchAuthorityError::AuthorityUnavailable,
            FragmentProviderDisposition::Transient,
        ),
        (
            DispatchAuthorityError::ConnectionSlotsExhausted,
            FragmentProviderDisposition::Transient,
        ),
        (
            DispatchAuthorityError::CapacityExhausted,
            FragmentProviderDisposition::Transient,
        ),
        (
            DispatchAuthorityError::QuotaUnavailable,
            FragmentProviderDisposition::Transient,
        ),
        (
            DispatchAuthorityError::AmbiguousCommit,
            FragmentProviderDisposition::OutcomeUnknown,
        ),
        (
            DispatchAuthorityError::WrongPoolRole,
            FragmentProviderDisposition::NotReady,
        ),
        (
            DispatchAuthorityError::Unauthorized,
            FragmentProviderDisposition::NotReady,
        ),
        (
            DispatchAuthorityError::UnsupportedApiRevision,
            FragmentProviderDisposition::NotReady,
        ),
        (
            DispatchAuthorityError::SchemaUnavailable,
            FragmentProviderDisposition::NotReady,
        ),
        (
            DispatchAuthorityError::DigestProviderUnavailable,
            FragmentProviderDisposition::NotReady,
        ),
        (
            DispatchAuthorityError::SerializableTransactionRequired,
            FragmentProviderDisposition::NotReady,
        ),
        (
            DispatchAuthorityError::InvalidArgument,
            FragmentProviderDisposition::InvalidInput,
        ),
        (
            DispatchAuthorityError::CanonicalRecordInvalid,
            FragmentProviderDisposition::InvalidInput,
        ),
        (
            DispatchAuthorityError::IdentifierTimestampOutOfRange,
            FragmentProviderDisposition::InvalidInput,
        ),
        (
            DispatchAuthorityError::ExpiredOrUnknown,
            FragmentProviderDisposition::InvalidInput,
        ),
        (
            DispatchAuthorityError::ReservationExpired,
            FragmentProviderDisposition::InvalidInput,
        ),
        (
            DispatchAuthorityError::UploadClosed,
            FragmentProviderDisposition::InvalidInput,
        ),
        (
            DispatchAuthorityError::UploadStreamIdentityMismatch,
            FragmentProviderDisposition::InvalidInput,
        ),
        (
            DispatchAuthorityError::ChunkGap,
            FragmentProviderDisposition::InvalidInput,
        ),
        (
            DispatchAuthorityError::ReplayConflict,
            FragmentProviderDisposition::InvalidInput,
        ),
        (
            DispatchAuthorityError::StoredRecordMismatch,
            FragmentProviderDisposition::InvalidInput,
        ),
        (
            DispatchAuthorityError::CounterOverflow,
            FragmentProviderDisposition::Internal,
        ),
        (
            DispatchAuthorityError::TimeInvalid,
            FragmentProviderDisposition::Internal,
        ),
        (
            DispatchAuthorityError::StoredStateInvalid,
            FragmentProviderDisposition::Internal,
        ),
        (
            DispatchAuthorityError::GenerationNotMonotonic,
            FragmentProviderDisposition::Internal,
        ),
        (
            DispatchAuthorityError::ParticipantAuthenticationRequired,
            FragmentProviderDisposition::Internal,
        ),
        (
            DispatchAuthorityError::ParticipantStateInvalid,
            FragmentProviderDisposition::Internal,
        ),
        (
            DispatchAuthorityError::ParticipantKeyDigestInvalid,
            FragmentProviderDisposition::Internal,
        ),
        (
            DispatchAuthorityError::UnrecognizedResultCode,
            FragmentProviderDisposition::Internal,
        ),
        (
            DispatchAuthorityError::InvalidAuthorityResponse("unit test fixture"),
            FragmentProviderDisposition::Internal,
        ),
    ];

    for (refusal, disposition) in expected {
        let observed = FragmentProviderError::SpoolReadyRefused(refusal).disposition();
        assert_eq!(
            observed, disposition,
            "{refusal} must carry {disposition:?}"
        );
    }
}

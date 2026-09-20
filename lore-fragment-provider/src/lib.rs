// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-031/WP-118 Phase 4: the fragment lifecycle package's one provider seam.
//!
//! # What this crate is for
//!
//! Phases 2 and 3 made the lifecycle coordinator's begin/commit split
//! structural: a `FragmentIntent` owns everything and borrows nothing, so no
//! transaction, connection, or lock can be held across the I/O phase between
//! them. That left the I/O phase itself — CR-031's step 3 — unimplemented and
//! unconstrained. This module implements it, and it is the only thing in
//! `domain/fragments/` that may reach a provider.
//!
//! Phase 4's acceptance list is five properties. Each is enforced here in the
//! strongest form available, and the form is named so a reviewer can check the
//! claim rather than take it:
//!
//! 1. **Installed cell schema and typed authority client.**
//!    [`FragmentProviderGateway::new`] takes a [`CellSchemaAttestation`] by
//!    value. That type has a private field and exactly one non-test
//!    constructor, [`attest_cell_schema`], which reads 0019's runtime-callable
//!    layer identities through WP-114 CD-3's typed
//!    [`DispatchRuntimeClient`](lore_object_dispatch::dispatch_client::DispatchRuntimeClient)
//!    and requires every layer to match the artifact identity this build
//!    expects. A gateway without an attested cell schema is not constructible
//!    outside this crate's own tests. The attestation also carries the provider
//!    boundary, and the gateway takes no separate one, so the pair **cannot be
//!    re-paired after minting** — which is a narrower claim than an earlier
//!    revision of this line made. It is not a proof that the cell database and
//!    the bucket belong to the same cell: `attest_cell_schema` accepts whatever
//!    boundary its caller hands it, and 0019's readback carries no boundary
//!    identity to check it against. See [`CellSchemaAttestation`] for the full
//!    list of what the attestation does **not** cover.
//! 2. **Every provider attempt through the shared limiter and governed
//!    client.** The gateway owns a
//!    [`GovernedProviderClient`](lore_object_dispatch::GovernedProviderClient)
//!    and [`FragmentProviderGateway::execute`] is the only method that reaches
//!    it. CD-5's kernel charges CD-4's limiter before it constructs the one
//!    value a transport will accept, so "charged before sent" is inherited
//!    rather than re-implemented.
//!
//!    **This is now structural, and the mechanism is not what an earlier
//!    revision claimed.** `execute` takes a `ProviderAttemptLedger` and a
//!    `ProviderAttemptRequest`. This crate does not re-export either, and
//!    `lore-postgres` does not depend on `lore-object-dispatch`, so no caller
//!    there can **construct** those arguments. Privacy is *not* what carries
//!    this: an inherent method resolves without the caller naming, or
//!    depending on, the defining crate, which is why a
//!    `pub fn inner(&self) -> &GovernedProviderClient` plus
//!    `gateway.inner().execute(…)` compiled cleanly before the split.
//!
//!    **"Cannot construct the arguments", not "cannot write the call", and the
//!    difference is load-bearing.** An earlier revision of this paragraph said
//!    the latter, which is false: `g.inner().execute(todo!(), todo!())` still
//!    compiles from `lore-postgres`, because `todo!()` diverges and coerces to
//!    any type. What is impossible is producing a real ledger or request:
//!    naming either from `lore-postgres` is
//!    `error[E0603]: struct ProviderAttemptLedger is private`, because the
//!    import below is private to this crate. So such a call panics before it
//!    reaches the provider, and no attempt can be issued.
//!
//!    The guarantee is about the arguments and only about the arguments. Do not
//!    re-flatten it into a claim about the call expression: the flattened
//!    version is checkably wrong, and a guarantee that is checkably wrong is
//!    worse than a narrower one that holds.
//! 3. **No SDK automatic retries, and no private S3 client.**
//!    [`FragmentProviderGateway::new`] takes **no retry parameter**: it states
//!    [`ProviderRetryPolicy::disabled`] itself, so a retrying client is not
//!    expressible through this seam. That much is a signature, and
//!    `tests/seam_source_pins.rs` keeps it one.
//!
//!    The no-private-client half is structural **for this crate**: its
//!    dependency graph contains no `aws-sdk-s3`, `aws-config`, `aws-smithy-*`
//!    or `lore-aws`, so building a provider client here does not compile. It is
//!    **not** a dependency-graph fact for `coordinator.rs`, `masks.rs`,
//!    `schema.rs` and `states.rs`, which remain in `lore-postgres` beside the
//!    legacy CR-007 store's legitimate `aws-sdk-s3` dependency; for those four
//!    files it is still a source pin, over a much smaller surface than the
//!    package-wide scan it replaced.
//!
//! # What is still review-checked rather than compiler-checked
//!
//! The crate boundary alone was **not** enough, and the escalation an earlier
//! revision recorded as merely available has since been taken. The gap it left:
//! `execute`'s parameter types are public in `lore-object-dispatch`, so nothing
//! stopped this crate from re-publishing them under aliases — no privacy rule
//! can object to aliasing a public type — and an accessor could still hand out
//! the concrete client. Alias the ledger and request, hand out the client, and
//! `lore-postgres` calls `execute` while naming no dispatch type. That was a
//! working exploit, not a hypothesis, and it is what made the cost worth
//! paying.
//!
//! [`AttemptSink`] closes it: the client is boxed behind a private trait at
//! construction and never stored concretely, so there is nothing to hand back,
//! and public aliases for the parameter types buy nothing because nothing
//! yields a value to call `execute` on. An accessor returning `&dyn AttemptSink`
//! fails with *"trait `AttemptSink` is more private than the item"* under
//! `-D warnings`.
//!
//! # Where the boundary actually is
//!
//! **The seam crate is the trust boundary.** No caller outside it can reach the
//! provider: the parameter types are unnameable and no client value is
//! obtainable, and both are compiler-enforced.
//!
//! **Inside the seam, a deliberate new public API can widen it.** A forwarding
//! method — `pub async fn issue_raw(&self, ledger: &mut PublicLedger, request:
//! &PublicRequest)` over locally aliased types, calling `self.client.issue`
//! internally — would expose exactly that call. That is review-checked, not
//! compiler-checked, and **no source pin can hold it**, because it is a property
//! of a method body rather than of a declaration. The pins raise the cost of
//! doing it by accident; they do not stop it being done on purpose.
//!
//! An earlier revision said there was "nothing to call `execute` on". That is
//! not quite true and the difference is the last inch of this claim: you do not
//! need a value, you need a method, and this crate can write one. Seven rounds
//! of evasions came from claiming an inch more than was held, so the line is
//! drawn here — at the crate, not inside it.
//!
//! The same applies to a new file here constructing its own
//! `GovernedProviderClient`; the dependency is present because the seam needs
//! it. At some point "someone editing the trust boundary can widen the trust
//! boundary" stops being a defect and becomes the definition of the boundary.
//!
//! # The scope of the guarantee, stated as narrowly as it is true
//!
//! **This is a per-crate manifest fact, not a global one.** "No caller outside
//! the seam can invoke `execute`" is false as a general claim. Any crate that
//! adds `lore-object-dispatch` to its own `Cargo.toml` can name `execute`'s
//! parameters — and, more to the point, can construct its own
//! `GovernedProviderClient` and issue attempts without touching this seam at
//! all. Nothing done inside this crate prevents that, and nothing could.
//!
//! What actually holds today is narrower and checkable: **the existing
//! composition callers cannot invoke `execute` directly**. `lore-postgres`
//! does not depend on `lore-object-dispatch`, and `lore-server` activates this
//! seam without receiving the governed client's ledger, request, or client
//! value. What enforces the `lore-postgres` boundary is the manifest pin in
//! `lore-fragment-provider/tests/seam_source_pins.rs` — which fails if the AWS
//! SDK or `lore-postgres` appears in this crate's shipped dependencies — and
//! the no-re-export pin beside it. A *new* crate opting in is a manifest edit
//! that no pin here can see.
//!
//! The narrower claim is the one to carry. Six evasions of a broader one were
//! found before the erasure above; a guarantee stated wider than the property
//! is what produced every one of them.
//!
//! `tests/seam_source_pins.rs` keeps the rules a crate boundary does not
//! express: no filesystem access, no retry parameter, no publication of
//! `execute`'s two parameter types by any of three spellings, and the manifest
//! staying free of the AWS SDK. **The trait carries the property; the pin is
//! belt and braces** — it covers a seam edit that names the real types in a
//! signature directly. Its scanner is a regression detector with one known
//! limit, recorded there rather than fixed.
//! # Opt-in activation and fail-closed defaults
//!
//! [`FragmentProviderEntry::connect`] is the one composition door for the
//! shared dispatch pool, database and schema attestation, charge authority,
//! and provider transport. `lore-server` uses it only for a complete, enabled
//! Phase 5 `fragment_provider` configuration. Absent or disabled configuration
//! retains the legacy route and constructs none of these runtime objects.
//!
//! [`UnwiredChargeAuthority`] and [`UnwiredProviderTransport`] remain the
//! fail-closed defaults for a gateway built without that composition door.
//! They refuse every call, so compiling or testing the default gateway
//! authorizes no provider traffic. Bucket, region, endpoint, credential, and
//! budget values still enter only as explicit composition inputs.
//!
//! # Phase 5 direct PUT contract
//!
//! Phase 5 direct fragment PUTs are bounded synchronously rather than durably
//! spooled. Admission first acquires the one configured in-flight PUT permit;
//! the direct request then exact-binds its at-most-256-KiB body by size and
//! BLAKE3 before charge and send. The non-Clone admitted PUT token retains that
//! sole permit across validation, charge, and transport execution. Durable
//! spool vocabulary remains reserved for WP-114 dispatcher and drain work and
//! is not part of this seam's direct-write entry.
//!
//! # WP-114 CD-6's drain capability, and the one guarantee it trades away
//!
//! [`FragmentDrainCapability`] is the drain-only view of the same composition
//! door. It retains the entry — hence the one gateway, the one dispatch pool,
//! and the process's participant identity — and publishes none of them. Its
//! public surface is exactly three methods: `reserve_spool`, `mark_spool_ready`,
//! and `attempt_drain`. WP-122 reservations use a maintenance-published policy
//! and preserve an immutable descriptor before the first database mutation.
//! Cleanup and observation use a separate opaque maintenance handle.
//! Narrowness is by construction in the same order the crate
//! argues everywhere else: the dispatch pool, the dispatch request types, and
//! the ledger stay unnameable outside this crate; the capability's three fields
//! are private with no accessor; the private [`AttemptSink`] is untouched; the
//! source pins are belt and braces. Reservation values expose only bounded
//! durable placement and their budget pin, never a raw provider operation.
//!
//! **The drain shares the one limiter and adds nothing.** It reuses
//! [`FragmentProviderEntry::admit_put`], so it takes a permit from the same
//! single in-flight PUT semaphore the direct fallback uses, and it charges
//! through the same CD-5 kernel under
//! [`ProviderTrafficClass::Drain`](lore_object_dispatch::ProviderTrafficClass::Drain),
//! which is a subordinate cap inside the shared physical budget rather than a
//! second ceiling. No second semaphore, no second pool, no second limiter.
//!
//! **A caller may not declare what is sent, but must supply the independent
//! anchor the send is checked against.** `declared_size` and `declared_blake3`
//! on the wire request come from the *bound spool body* and are unnameable on
//! [`FragmentDrainAttempt`]. What the caller does supply is
//! `claim_body_blake3` / `claim_body_size`, which originate in the lifecycle
//! claim rather than in the drain worker's view of the filesystem. So the send
//! requires three-way agreement across two independent sources — the claim, the
//! dispatch database's ready row, and the actual bytes — where comparing the
//! bytes only against a digest the same caller had already spooled would let a
//! wrong file pass with both sides agreeing.
//!
//! **What this path loses, written down rather than left to be rediscovered.**
//! `ProviderDirectPutAttemptRequest` carries no durable body field, so routing
//! the drain through the direct-PUT primitive means CD-5's `validate_body` —
//! the *type gate* that refuses a body-carrying class without a
//! [`DurableProviderPutBody`] — never runs here. What runs instead is CD-5's
//! direct-PUT body check, which exact-binds the bytes to a **declaration**
//! rather than to a durable spool row. On the drain path the spool binding is
//! therefore a seam-local sequence (bind, cross-check the request, check the
//! claim anchor, check the bytes) plus the source pin that keeps that sequence
//! the only route. The trade is accepted because the claim anchor is a binding
//! the type gate never had. If it is later judged wrong, the fix is to carry a
//! durable body into the transport, which is a change to the transport port and
//! not to this capability.

use std::fmt;
mod drain;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

pub use drain::FragmentDrainMaintenanceHandle;
pub use drain::FragmentDrainObservation;
pub use drain::FragmentDrainPolicyPin;
pub use drain::FragmentDrainReservation;
pub use drain::FragmentDrainReservationInput;
pub use drain::FragmentDrainReservationPlan;
pub use drain::FragmentDrainWriteReceipt;
use lore_base::types::FRAGMENT_SIZE_THRESHOLD;
// ---------------------------------------------------------------------------
// The re-export boundary — read the rule before adding to it
// ---------------------------------------------------------------------------
use lore_object_dispatch::AuthorizedProviderAttempt;
use lore_object_dispatch::AuthorizedProviderGet;
/// Types a caller needs in order to *describe* an attempt, ask for an
/// attestation, or read an outcome.
///
/// **The rule that makes property 2 structural: [`ProviderAttemptLedger`] and
/// [`ProviderAttemptRequest`] are never re-exported.** They are exactly the two
/// parameters of
/// [`GovernedProviderClient::execute`](lore_object_dispatch::GovernedProviderClient::execute),
/// so a crate that cannot name them cannot **construct** them, and cannot make
/// a call that does anything — whatever value it is holding, and regardless of
/// any accessor this crate might grow. `lore-postgres` does not depend on
/// `lore-object-dispatch`, so these re-exports are the only dispatch vocabulary
/// it has.
///
/// The precise form matters: a call *expression* naming `execute` is still
/// writable there with divergent arguments, and it panics rather than
/// dispatching. See the crate docs for why the narrower claim is the one to
/// keep.
///
/// Everything below is safe under that rule because none of it is a parameter
/// of `execute`. Anything added here must be checked against the same rule, and
/// `tests/seam_source_pins.rs` fails if the two forbidden types appear.
///
/// # Two properties this list has that are worth stating, not leaving implicit
///
/// **The re-exported traits are nameable as bounds but unimplementable outside
/// this crate.** `ProviderTransport::issue` takes an `AuthorizedProviderAttempt`
/// and returns a `ProviderAttemptReport` or a `ProviderTransportRefusal`, and
/// none of those three is re-exported: an `impl ProviderTransport for …` in
/// `lore-postgres` is three `E0425`s through this crate's namespace, or three
/// `E0433`s reaching for `lore_object_dispatch` directly. `ProviderChargeAuthority`
/// is the same. So `lore-postgres` can hold only an **unwired** gateway — it
/// cannot inject a transport of its own, which would be a private provider
/// client under another name. That fell out of what was not re-exported rather
/// than being designed, and it is recorded here so a later edit does not
/// re-export one of the three and quietly lose it.
///
/// **[`DispatchRuntimeClient`] is a bound, not a capability.** It cannot be
/// constructed outside this crate (its pool is not re-exported and no other
/// factory returns one), cannot be obtained from elsewhere, and none of its four
/// mutations can be called because every request type is unnameable. The one
/// reachable method is the argument-free `read_dispatcher_identity_state`,
/// yielding installed schema revisions, digests and timestamps — the values
/// [`FragmentSchemaAttestationError::Mismatch`] already documents as fixed and
/// non-sensitive, and which CD-3's live suite asserts in the clear.
pub use lore_object_dispatch::BudgetPin;
pub use lore_object_dispatch::CellProviderBoundary;
use lore_object_dispatch::DispatchConnectionBudget;
use lore_object_dispatch::DispatchDatabaseIdentity;
use lore_object_dispatch::DispatchDatabaseIdentityError;
use lore_object_dispatch::DispatchPoolConfig;
use lore_object_dispatch::DispatchPoolError;
use lore_object_dispatch::DispatchPoolRole;
use lore_object_dispatch::DispatchRuntimePool;
use lore_object_dispatch::DispatchTlsMode;
pub use lore_object_dispatch::DurableProviderPutBody;
use lore_object_dispatch::GovernedProviderClient;
use lore_object_dispatch::MeteredProviderAttemptRequest;
use lore_object_dispatch::PROVIDER_ATTEMPT_DEADLINE_HORIZON_MS;
use lore_object_dispatch::PROVIDER_MIN_PART_SIZE_BYTES;
use lore_object_dispatch::PostgresProviderChargeAuthority;
pub use lore_object_dispatch::ProviderAttemptClass;
use lore_object_dispatch::ProviderAttemptExecution;
use lore_object_dispatch::ProviderAttemptLedger;
pub use lore_object_dispatch::ProviderAttemptOutcome;
use lore_object_dispatch::ProviderAttemptReport;
use lore_object_dispatch::ProviderAttemptRequest;
pub use lore_object_dispatch::ProviderCapabilities;
pub use lore_object_dispatch::ProviderChargeAuthority;
use lore_object_dispatch::ProviderChargeError;
use lore_object_dispatch::ProviderClientError;
use lore_object_dispatch::ProviderDirectPutAttemptRequest;
use lore_object_dispatch::ProviderGetAttemptRequest;
use lore_object_dispatch::ProviderGetTransport;
use lore_object_dispatch::ProviderRetryPolicy;
pub use lore_object_dispatch::ProviderTrafficClass;
pub use lore_object_dispatch::ProviderTransport;
use lore_object_dispatch::ProviderTransportRefusal;
pub use lore_object_dispatch::UnwiredChargeAuthority;
pub use lore_object_dispatch::UnwiredProviderTransport;
use lore_object_dispatch::cell_retention::CellRetentionClient;
use lore_object_dispatch::cell_schema_install::CELL_SCHEMA_LAYERS;
use lore_object_dispatch::cell_schema_install::CellSchemaLayerId;
use lore_object_dispatch::dispatch_client::DispatchAuthorityError;
pub use lore_object_dispatch::dispatch_client::DispatchRuntimeClient;
use lore_object_dispatch::dispatch_client::DispatcherIdentityState;
use lore_object_dispatch::dispatch_client::InstalledLayerIdentity;
// The 0017 ready projection and the PUT-path identity. Neither is re-exported:
// the projection travels inside `FragmentDrainReady`, whose field is private, so
// a ready receipt cannot be forged or moved between requests.
use lore_object_dispatch::dispatch_client::PutSpoolReadyOutcome;
use lore_object_dispatch::dispatch_client::PutStreamIdentity;
pub use lore_object_dispatch::drain_policy::DrainError as FragmentDrainAuthorityError;
use lore_object_dispatch::provider_client::ProviderPreTransportGuard;
use tokio::sync::Semaphore;
use tokio::sync::SemaphorePermit;
use tokio::sync::TryAcquireError;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Frozen bounds
// ---------------------------------------------------------------------------

/// The ingress cap every fragment body already obeys at every ingress path.
///
/// Deliberately an alias for `lore-base`'s existing
/// [`FRAGMENT_SIZE_THRESHOLD`], not a second number that could drift from it.
/// CR-031 adds no new cap; it applies this one at the provider seam.
pub const FRAGMENT_PROVIDER_INGRESS_CAP_BYTES: u64 = FRAGMENT_SIZE_THRESHOLD as u64;

/// Largest in-flight put count this seam will accept from configuration.
///
/// Not a tuning recommendation. It exists so a mistyped configuration value
/// cannot allocate an unbounded semaphore and call it a bound.
pub const MAX_IN_FLIGHT_PUTS: u32 = 1_024;

/// The in-flight put count a cell uses until its own configuration says
/// otherwise.
///
/// One concurrent 256 KiB put per unit, so this is a provider-pressure bound
/// rather than a memory one. Chosen to match `default_domain_pool_max`'s
/// posture: small enough that a cell that never tunes it cannot flood the
/// shared cell budget on its own.
pub const DEFAULT_IN_FLIGHT_PUTS: u32 = 4;

/// Largest accepted concurrent charge-carrying non-body attempt count.
pub const MAX_IN_FLIGHT_CHARGES: u32 = 1_024;

/// The concurrent charge-carrying non-body attempt count a cell uses until its
/// own configuration says otherwise.
///
/// A HEAD, a version list and a delete each carry a charge but no object body,
/// so [`DEFAULT_IN_FLIGHT_PUTS`] never governed them and nothing else did
/// either. Measured consequence: a 1550-fragment push issued charge attempts as
/// fast as its stream fan-out allowed, and the cell-local charge authority
/// refused 50 of them outright with `PoolExhausted` — every waiter takes a
/// dispatch-pool lease before it can charge, and the pool is at most
/// `dispatch_pool_max`. Bounding the attempts turns that stampede into a queue.
///
/// 4 rather than a larger number on purpose: the charge itself is serialized per
/// provider boundary by a session advisory lock, so concurrency above the
/// dispatch pool's width buys no throughput and only converts a Rust wait into a
/// pool refusal. Deliberately equal to [`DEFAULT_IN_FLIGHT_PUTS`] in value while
/// being a separate number, because CR-031 defines that one as a *put* bound and
/// overloading it would make the configured count mean something it does not.
pub const DEFAULT_IN_FLIGHT_CHARGES: u32 = 4;

/// Largest configured send window accepted by the fragment route.
///
/// This is derived from the governed client's request-deadline horizon rather
/// than restating five minutes in server configuration code.
pub const FRAGMENT_PROVIDER_SEND_TIMEOUT_MAX_MILLIS: u64 =
    PROVIDER_ATTEMPT_DEADLINE_HORIZON_MS as u64;

// The arithmetic behind the multipart exclusion below, checked by the compiler.
// If a later change raised the fragment ingress cap above the provider's
// minimum part size, multipart would become reachable and
// FRAGMENT_PROVIDER_ATTEMPT_CLASSES would be silently wrong. This fails the
// build at that moment instead. Deliberately a `//` comment, not a doc comment:
// a doc comment here would attach to this anonymous const and leave the public
// constant below undocumented.
const _: () = assert!(FRAGMENT_PROVIDER_INGRESS_CAP_BYTES < PROVIDER_MIN_PART_SIZE_BYTES);

/// The closed set of provider attempt classes this package may issue.
///
/// Derived from what a 256 KiB-capped body can require, and it is a **closed
/// allowlist**: [`FragmentProviderGateway::execute`] refuses every class not
/// listed here, including any class a future
/// [`ProviderAttemptClass`] variant adds.
///
/// The four multipart classes are absent on purpose.
/// `PROVIDER_MIN_PART_SIZE_BYTES` is 5 MiB, so a body bounded by
/// [`FRAGMENT_PROVIDER_INGRESS_CAP_BYTES`] can never plan as multipart, which
/// the `const` assertion above pins. Leaving those classes reachable would ship
/// four paths that cannot be exercised and cannot be tested against real
/// behavior.
pub const FRAGMENT_PROVIDER_ATTEMPT_CLASSES: [ProviderAttemptClass; 6] = [
    ProviderAttemptClass::Readiness,
    ProviderAttemptClass::HeadObject,
    ProviderAttemptClass::PutObject,
    ProviderAttemptClass::ListObjectsV2,
    ProviderAttemptClass::ListObjectVersions,
    ProviderAttemptClass::DeleteObject,
];

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why this seam refused, or how the governed client below it failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FragmentProviderError {
    /// The configured in-flight put count is outside the accepted range.
    #[error("configured in-flight put count is outside 1..={MAX_IN_FLIGHT_PUTS}")]
    InvalidInFlightPutBound,

    /// The attempt class is outside [`FRAGMENT_PROVIDER_ATTEMPT_CLASSES`].
    #[error("provider attempt class '{class}' is not permitted for fragment lifecycle I/O")]
    AttemptClassNotPermitted {
        /// [`ProviderAttemptClass::metric_label`], a fixed non-sensitive string.
        class: &'static str,
    },

    /// A put body is larger than the existing fragment ingress cap.
    #[error(
        "provider put body exceeds the {FRAGMENT_PROVIDER_INGRESS_CAP_BYTES} byte fragment ingress cap"
    )]
    IngressCapExceeded,

    #[error("wired fragment provider execution requires an explicit transport operation")]
    OperationRequired,

    #[error("fragment provider attempt class, operation, and durable body do not agree")]
    OperationMismatch,

    #[error("fragment provider object key is empty")]
    InvalidObjectKey,

    /// No in-flight put slot became free inside the configured wait.
    #[error("no in-flight put slot became available within the configured admission wait")]
    PutAdmissionTimedOut,

    /// The in-flight put admission gate was closed. Unreachable while the
    /// gateway owns its own semaphore, and fails closed rather than silently
    /// admitting if that ever changes.
    #[error("in-flight put admission is closed")]
    PutAdmissionClosed,

    /// The configured concurrent charge count is outside the accepted range.
    #[error("configured in-flight charge count is outside 1..={MAX_IN_FLIGHT_CHARGES}")]
    InvalidInFlightChargeBound,

    /// No charge-admission slot became free inside the configured wait.
    ///
    /// Named separately from [`FragmentProviderError::PutAdmissionTimedOut`]
    /// rather than reusing it: a HEAD that waited out the charge queue has
    /// nothing to do with a put bound, and an operation refused under the wrong
    /// name sends the next reader to the wrong knob.
    #[error("no charge admission slot became available within the configured admission wait")]
    ChargeAdmissionTimedOut,

    /// The charge-admission gate was closed. Unreachable while the gateway owns
    /// its own semaphore; fails closed rather than admitting unbounded.
    #[error("charge admission is closed")]
    ChargeAdmissionClosed,

    /// The drain's ready receipt could not be bound to a durable spool body.
    ///
    /// Source-preserving, and **separate from
    /// [`FragmentProviderError::SpoolBindingRequestMismatch`] on purpose**: an
    /// operator chasing a refused drain has to be able to tell a binding the
    /// dispatch layer refused — a non-ready row, a handle that is not the
    /// canonically derived one, a key that is not a PUT key — from the seam's
    /// own identity cross-check below. One variant covering both would drop
    /// this cause entirely, and the two send a reader to different places.
    #[error("fragment drain spool binding was refused: {0}")]
    SpoolBindingRejected(#[source] ProviderClientError),

    /// The bound spool body belongs to a different logical request than the
    /// attempt claims.
    ///
    /// The binding itself succeeded: the receipt is internally consistent and
    /// canonically derived. It simply describes another request, which the
    /// dispatch layer cannot see and only this seam can check.
    #[error("fragment drain spool binding names a different logical request")]
    SpoolBindingRequestMismatch,

    /// The bound spool body disagrees with the lifecycle claim's own digest or
    /// size.
    ///
    /// This is the independent anchor, and it is the only check on this path
    /// whose two sides did not both come from the drain worker's view of the
    /// filesystem. Without it, a caller that spooled the wrong file would have
    /// its bytes agree with its own spool-ready declaration and the send would
    /// proceed.
    #[error("fragment drain body does not match the lifecycle claim's digest or size")]
    ClaimBindingMismatch,

    /// The supplied bytes are not the bytes the bound spool body describes.
    #[error("fragment drain body does not match the bound durable spool body")]
    DrainBodyMismatch,

    #[error("drain reservation authority refused: {0}")]
    DrainAuthority(#[source] lore_object_dispatch::drain_policy::DrainError),
    #[error("drain spool filesystem operation failed")]
    DrainSpoolIo,

    /// The cell authority refused the 0017 `SPOOL_READY` transition.
    /// Source-preserving.
    #[error("cell authority refused the drain spool-ready transition: {0}")]
    SpoolReadyRefused(#[source] DispatchAuthorityError),

    /// The governed provider client refused, or its charge/transport kernel
    /// failed. Source-preserving.
    #[error("governed provider client refused the attempt: {0}")]
    Provider(#[source] ProviderClientError),
}

/// Why the runtime-callable schema readback could not mint an attestation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FragmentSchemaAttestationError {
    #[error("cell schema attestation could not be read: {0}")]
    Read(#[source] DispatchAuthorityError),
    #[error("cell schema layer '{layer:?}' is not installed at the expected identity")]
    Mismatch { layer: CellSchemaLayerId },
}

/// Why the one fragment-provider composition door refused activation.
///
/// Every underlying error is retained as a typed, redaction-safe source. No variant carries a URL,
/// credential, PostgreSQL diagnostic, or physical database identity value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FragmentProviderActivationError {
    #[error("fragment provider dispatch pool configuration is invalid: {0}")]
    DispatchPool(#[source] DispatchPoolError),
    #[error("fragment provider dispatch runtime client could not be constructed: {0}")]
    DispatchClient(#[source] DispatchAuthorityError),
    #[error("fragment provider dispatch database attestation failed: {0}")]
    DatabaseIdentity(#[source] DispatchDatabaseIdentityError),
    #[error("fragment provider cell schema attestation failed: {0}")]
    Schema(#[source] FragmentSchemaAttestationError),
    #[error("fragment provider charge authority could not be attached: {0}")]
    ChargeAuthority(#[source] ProviderChargeError),
}

/// How a consumer should treat a [`FragmentProviderError`], in terms that name
/// no dispatch type.
///
/// **This enum is why `lore-postgres` can classify a seam failure without
/// depending on `lore-object-dispatch`.** Mapping a refusal onto CR-029's
/// `DomainError` needs to know which of CD-5's and CD-4's ~40 error variants it
/// is looking at; doing that in `lore-postgres` would mean naming
/// `ProviderClientError` and `ProviderChargeError` there, which means depending
/// on the dispatch crate, which is exactly what property 2 rests on not
/// happening. So the seam decides severity — it is the crate that can see the
/// variants — and `lore-postgres` decides what CR-029 calls that severity.
///
/// Closed and small on purpose: a consumer matches it exhaustively, and a new
/// variant here is a compile error there rather than a silent reclassification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FragmentProviderDisposition {
    /// A caller-supplied value violated a frozen bound. Never retryable and
    /// never a partial effect.
    InvalidInput,
    /// Capacity or availability. A bounded retry is correct.
    Transient,
    /// The cell is not configured to serve this attempt. Fails closed; retrying
    /// the same request fails the same way until the cell changes.
    NotReady,
    /// A charge may have committed, or an attempt may have reached the
    /// provider, and neither can be proved. **Never retried.**
    OutcomeUnknown,
    /// A request this seam should never have built. A programming fault in the
    /// caller, not a condition to retry.
    Internal,
}

impl FragmentProviderError {
    /// A closed diagnostic for retryable refusals. Never contains request data.
    pub fn transient_diagnostic(&self) -> Option<&'static str> {
        match self {
            Self::PutAdmissionTimedOut => Some("put_admission_timeout"),
            Self::PutAdmissionClosed => Some("put_admission_closed"),
            // Without these two the `_ => None` arm below would drop them, and a
            // charge queue that timed out would be as invisible as the pool
            // exhaustion this bound exists to prevent.
            Self::ChargeAdmissionTimedOut => Some("charge_admission_timeout"),
            Self::ChargeAdmissionClosed => Some("charge_admission_closed"),
            // Derived from `disposition` rather than restated, so the two cannot
            // drift: a refusal classified retryable there is always visible
            // here. `disposition` does not call back into this method, so the
            // guard cannot recurse.
            Self::SpoolReadyRefused(_)
                if self.disposition() == FragmentProviderDisposition::Transient =>
            {
                Some("drain_spool_ready_transient")
            }
            Self::Provider(ProviderClientError::ChargeRefused(refusal)) => match refusal {
                ProviderChargeError::BudgetExhausted => Some("charge_budget_exhausted"),
                ProviderChargeError::ClassCapExhausted => Some("charge_class_cap_exhausted"),
                ProviderChargeError::AuthorityUnavailable => Some("charge_authority_unavailable"),
                ProviderChargeError::Unwired => Some("charge_unwired"),
                ProviderChargeError::DeadlineExceeded => Some("charge_deadline_exceeded"),
                ProviderChargeError::BudgetPinRejected
                | ProviderChargeError::ConfigurationUnresolved
                | ProviderChargeError::AttemptAlreadyCharged
                | ProviderChargeError::AmbiguousCommit
                | ProviderChargeError::RecoveredCommittedCharge => None,
            },
            _ => None,
        }
    }

    /// Classifies this failure for a consumer that cannot see the dispatch
    /// error vocabulary.
    ///
    /// The charge arm is exhaustive over [`ProviderChargeError`] with **no
    /// wildcard**, so a variant added upstream fails this build rather than
    /// silently landing in a catch-all.
    pub fn disposition(&self) -> FragmentProviderDisposition {
        match self {
            Self::InvalidInFlightPutBound
            | Self::InvalidInFlightChargeBound
            | Self::AttemptClassNotPermitted { .. }
            | Self::IngressCapExceeded
            | Self::OperationRequired
            | Self::OperationMismatch
            | Self::SpoolBindingRejected(_)
            | Self::SpoolBindingRequestMismatch
            | Self::ClaimBindingMismatch
            | Self::DrainBodyMismatch
            | Self::InvalidObjectKey => FragmentProviderDisposition::InvalidInput,
            // Exhaustive over `DispatchAuthorityError` with **no wildcard**, for
            // the same reason the charge arm below is: a variant added upstream
            // must fail this build rather than land silently in a catch-all and
            // be reclassified by accident.
            Self::SpoolReadyRefused(refusal) => match refusal {
                // Capacity and availability. The pool's own errors are here
                // rather than split: this pool was already built and attested at
                // activation, so a failure reaching a drain is contention or
                // loss of the database, never misconfiguration discovered late.
                DispatchAuthorityError::Pool(_)
                | DispatchAuthorityError::OperationTimeout
                | DispatchAuthorityError::RetryExhausted
                | DispatchAuthorityError::AuthorityUnavailable
                | DispatchAuthorityError::ConnectionSlotsExhausted
                | DispatchAuthorityError::CapacityExhausted
                | DispatchAuthorityError::QuotaUnavailable => {
                    FragmentProviderDisposition::Transient
                }

                // The transition may or may not have been applied and the client
                // already failed to resolve which. Same never-retried arm as an
                // ambiguous charge commit.
                DispatchAuthorityError::AmbiguousCommit => {
                    FragmentProviderDisposition::OutcomeUnknown
                }

                // The cell is not configured to serve this call. Retrying it
                // fails the same way until the cell changes.
                DispatchAuthorityError::WrongPoolRole
                | DispatchAuthorityError::Unauthorized
                | DispatchAuthorityError::UnsupportedApiRevision
                | DispatchAuthorityError::SchemaUnavailable
                | DispatchAuthorityError::DigestProviderUnavailable
                | DispatchAuthorityError::SerializableTransactionRequired => {
                    FragmentProviderDisposition::NotReady
                }

                // A value this call supplied is wrong, or the reservation it
                // names is gone. Decisive, nothing spooled, nothing sent.
                DispatchAuthorityError::InvalidArgument
                | DispatchAuthorityError::CanonicalRecordInvalid
                | DispatchAuthorityError::IdentifierTimestampOutOfRange
                | DispatchAuthorityError::ExpiredOrUnknown
                | DispatchAuthorityError::ReservationExpired
                | DispatchAuthorityError::UploadClosed
                | DispatchAuthorityError::UploadStreamIdentityMismatch
                | DispatchAuthorityError::ChunkGap
                | DispatchAuthorityError::ReplayConflict
                | DispatchAuthorityError::StoredRecordMismatch => {
                    FragmentProviderDisposition::InvalidInput
                }

                // A call this seam should never have built, or a response it
                // cannot read. A fault, not a condition to retry.
                DispatchAuthorityError::CounterOverflow
                | DispatchAuthorityError::TimeInvalid
                | DispatchAuthorityError::StoredStateInvalid
                | DispatchAuthorityError::GenerationNotMonotonic
                | DispatchAuthorityError::ParticipantAuthenticationRequired
                | DispatchAuthorityError::ParticipantStateInvalid
                | DispatchAuthorityError::ParticipantKeyDigestInvalid
                | DispatchAuthorityError::UnrecognizedResultCode
                | DispatchAuthorityError::InvalidAuthorityResponse(_) => {
                    FragmentProviderDisposition::Internal
                }
            },
            Self::DrainSpoolIo
            | Self::DrainAuthority(_)
            | Self::PutAdmissionTimedOut
            | Self::PutAdmissionClosed
            | Self::ChargeAdmissionTimedOut
            | Self::ChargeAdmissionClosed
            | Self::Provider(ProviderClientError::PreTransportGuardRefused) => {
                FragmentProviderDisposition::Transient
            }
            Self::Provider(ProviderClientError::ChargeAmbiguous)
            | Self::Provider(ProviderClientError::ChargeRecovered) => {
                FragmentProviderDisposition::OutcomeUnknown
            }
            Self::Provider(ProviderClientError::ChargeRefused(refusal)) => match refusal {
                // Capacity, not correctness. The caller backs off and re-drives.
                ProviderChargeError::BudgetExhausted
                | ProviderChargeError::ClassCapExhausted
                | ProviderChargeError::AuthorityUnavailable
                | ProviderChargeError::Unwired => FragmentProviderDisposition::Transient,

                // The attempt's own deadline elapsed before admission. Decisive,
                // and nothing was charged, so a fresh attempt may be taken.
                // Re-driving the *same* attempt identity would fail the same
                // way, and the coordinator's begin/commit split already mints a
                // new one per pass.
                ProviderChargeError::DeadlineExceeded => FragmentProviderDisposition::Transient,

                // The cell's budget configuration does not agree with the pin
                // this attempt carries, or cannot be resolved at all. Retrying
                // with the same pin fails forever.
                ProviderChargeError::BudgetPinRejected
                | ProviderChargeError::ConfigurationUnresolved => {
                    FragmentProviderDisposition::NotReady
                }

                // A durable CAS proves this exact attempt was charged before.
                // Whether it reached the provider is unknown, so this is the
                // same nonrefundable, never-retried arm as an ambiguous commit.
                ProviderChargeError::AttemptAlreadyCharged
                | ProviderChargeError::AmbiguousCommit
                | ProviderChargeError::RecoveredCommittedCharge => {
                    FragmentProviderDisposition::OutcomeUnknown
                }
            },
            // Conflicting successful grants are an authority invariant failure.
            // The grant stays counted, but no provider request was issued.
            Self::Provider(ProviderClientError::BudgetPinConflict) => {
                FragmentProviderDisposition::Internal
            }
            // Every remaining `ProviderClientError` is a request this seam
            // should never have built — a bad identity, a body that does not
            // belong to its request, a ledger naming another request.
            Self::Provider(_) => FragmentProviderDisposition::Internal,
        }
    }
}

// ---------------------------------------------------------------------------
// The two newtypes that keep the dispatch surface inside this crate
// ---------------------------------------------------------------------------

/// The attempt accounting for one logical fragment request.
///
/// Wraps CD-5's `ProviderAttemptLedger`, which is deliberately **not**
/// re-exported: it is one of the two parameters of the governed client's
/// `execute`, so a caller that could name it could call `execute` directly.
/// Callers get this instead, which exposes the counters WP-118 needs to decide
/// what happened and nothing that would let them charge or send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentAttemptLedger(ProviderAttemptLedger);

impl FragmentAttemptLedger {
    /// Opens a ledger bound to one boundary and one logical request.
    ///
    /// There is no `Default`, following CD-5: an unbound ledger is exactly the
    /// artifact the binding exists to prevent.
    pub fn new(
        provider_boundary_id: &str,
        logical_request_id: &str,
    ) -> Result<Self, FragmentProviderError> {
        ProviderAttemptLedger::new(provider_boundary_id, logical_request_id)
            .map(Self)
            .map_err(FragmentProviderError::Provider)
    }

    /// Attempts actually put on the wire.
    pub fn attempt_count(&self) -> u64 {
        self.0.attempt_count()
    }

    /// Charges committed against the cell budget. Never refunded, and counted
    /// conservatively for an ambiguous commit.
    pub fn committed_grant_count(&self) -> u64 {
        self.0.committed_grant_count()
    }

    /// Attempts that came back with a definite provider response.
    pub fn decisive_terminal_count(&self) -> u64 {
        self.0.decisive_terminal_count()
    }

    /// Attempts that reached the provider with no definite response.
    pub fn ambiguous_count(&self) -> u64 {
        self.0.ambiguous_count()
    }

    /// The error that closed this ledger, if any. A closed ledger yields no
    /// audit and accepts no further attempt.
    pub fn poisoned(&self) -> Option<ProviderClientError> {
        self.0.poisoned()
    }
}

/// The governed client, erased behind a trait private to this crate.
///
/// **This is what carries "the seam is the only route" inside the crate**, and
/// the reason it replaced a newtype is worth recording. A newtype gave the
/// compiler one check — an accessor returning it names a private type, which
/// `private_interfaces` refuses under `-D warnings` — but the raw
/// `GovernedProviderClient` stayed nameable here, so an accessor returning
/// *that* compiled. Paired with two public aliases for `execute`'s parameter
/// types, which are legitimately public upstream and so beyond any privacy
/// check, that was a working route from another crate: alias the ledger and
/// request, hand out the client, call it. Six evasions of a text-level pin were
/// found before this; the sixth is the one that made the escalation worth its
/// cost.
///
/// With the client boxed behind this trait at construction and never stored
/// concretely, there is no `GovernedProviderClient` to hand back. Public aliases
/// for the parameter types then buy nothing, because nothing yields a value to
/// call `execute` on, and an accessor returning `&dyn AttemptSink` fails with
/// *"trait `AttemptSink` is more private than the item"*.
///
/// The cost is real and was accepted deliberately: one boxed future per attempt
/// — `ProviderChargeAuthority::charge` returns `impl Future` and is not
/// object-safe, so the future has to be boxed to cross a `dyn` boundary — and
/// [`FragmentProviderGateway`] loses its type parameters. Both are cheap
/// against a network round trip.
trait AttemptSink: Send + Sync {
    /// Charges and issues one attempt. Mirrors
    /// [`GovernedProviderClient::execute`](lore_object_dispatch::GovernedProviderClient::execute)
    /// with its future boxed.
    fn issue<'a>(
        &'a self,
        ledger: &'a mut ProviderAttemptLedger,
        request: &'a MeteredProviderAttemptRequest,
        operation: &'a FragmentTransportOperation,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        ProviderAttemptExecution<FragmentTransportResponse>,
                        ProviderClientError,
                    >,
                > + Send
                + 'a,
        >,
    >;

    fn issue_get<'a>(
        &'a self,
        request: &'a ProviderGetAttemptRequest,
        operation: &'a FragmentGetOperation,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        ProviderAttemptExecution<FragmentGetResponse>,
                        ProviderClientError,
                    >,
                > + Send
                + 'a,
        >,
    >;

    fn issue_direct_put<'a>(
        &'a self,
        ledger: &'a mut ProviderAttemptLedger,
        request: &'a ProviderDirectPutAttemptRequest,
        body: &'a [u8],
        operation: &'a FragmentDirectPutOperation,
        guard: Option<&'a dyn ProviderPreTransportGuard>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        ProviderAttemptExecution<FragmentTransportResponse>,
                        ProviderClientError,
                    >,
                > + Send
                + 'a,
        >,
    >;

    fn validate(&self, request: &MeteredProviderAttemptRequest) -> Result<(), ProviderClientError>;

    fn boundary(&self) -> &CellProviderBoundary;

    fn retry_policy(&self) -> ProviderRetryPolicy;
}

struct UnitAttemptSink<C, T>(GovernedProviderClient<C, T>);

impl<C, T> AttemptSink for UnitAttemptSink<C, T>
where
    C: ProviderChargeAuthority + Send + Sync,
    T: ProviderTransport<Operation = (), Response = ()> + Send + Sync,
{
    fn issue<'a>(
        &'a self,
        ledger: &'a mut ProviderAttemptLedger,
        request: &'a MeteredProviderAttemptRequest,
        _operation: &'a FragmentTransportOperation,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        ProviderAttemptExecution<FragmentTransportResponse>,
                        ProviderClientError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let execution = self.0.execute(ledger, request, &()).await?;
            Ok(ProviderAttemptExecution {
                outcome: execution.outcome,
                response: FragmentTransportResponse::Empty,
            })
        })
    }

    fn issue_get<'a>(
        &'a self,
        _request: &'a ProviderGetAttemptRequest,
        _operation: &'a FragmentGetOperation,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        ProviderAttemptExecution<FragmentGetResponse>,
                        ProviderClientError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async {
            Err(ProviderClientError::TransportRefused(
                ProviderTransportRefusal::Unwired,
            ))
        })
    }

    fn issue_direct_put<'a>(
        &'a self,
        ledger: &'a mut ProviderAttemptLedger,
        request: &'a ProviderDirectPutAttemptRequest,
        body: &'a [u8],
        _operation: &'a FragmentDirectPutOperation,
        guard: Option<&'a dyn ProviderPreTransportGuard>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        ProviderAttemptExecution<FragmentTransportResponse>,
                        ProviderClientError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let execution = self
                .0
                .execute_direct_put_guarded(ledger, request, body, &(), guard)
                .await?;
            Ok(ProviderAttemptExecution {
                outcome: execution.outcome,
                response: FragmentTransportResponse::Empty,
            })
        })
    }

    fn validate(&self, request: &MeteredProviderAttemptRequest) -> Result<(), ProviderClientError> {
        self.0.validate_attempt(request)
    }

    fn boundary(&self) -> &CellProviderBoundary {
        self.0.boundary()
    }

    fn retry_policy(&self) -> ProviderRetryPolicy {
        self.0.retry_policy()
    }
}

struct PortAttemptSink<C, P>(GovernedProviderClient<C, FragmentTransportAdapter<P>>);

impl<C, P> AttemptSink for PortAttemptSink<C, P>
where
    C: ProviderChargeAuthority + Send + Sync,
    P: FragmentTransportPort + FragmentDirectPutPort + FragmentGetPort,
{
    fn issue<'a>(
        &'a self,
        ledger: &'a mut ProviderAttemptLedger,
        request: &'a MeteredProviderAttemptRequest,
        operation: &'a FragmentTransportOperation,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        ProviderAttemptExecution<FragmentTransportResponse>,
                        ProviderClientError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let operation = GovernedFragmentOperation::Standard(operation.clone());
            self.0.execute(ledger, request, &operation).await
        })
    }

    fn issue_get<'a>(
        &'a self,
        request: &'a ProviderGetAttemptRequest,
        operation: &'a FragmentGetOperation,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        ProviderAttemptExecution<FragmentGetResponse>,
                        ProviderClientError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(self.0.execute_get(request, operation))
    }

    fn issue_direct_put<'a>(
        &'a self,
        ledger: &'a mut ProviderAttemptLedger,
        request: &'a ProviderDirectPutAttemptRequest,
        body: &'a [u8],
        operation: &'a FragmentDirectPutOperation,
        guard: Option<&'a dyn ProviderPreTransportGuard>,
    ) -> Pin<
        Box<
            dyn Future<
                    Output = Result<
                        ProviderAttemptExecution<FragmentTransportResponse>,
                        ProviderClientError,
                    >,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let operation = GovernedFragmentOperation::DirectPut(operation.clone());
            self.0
                .execute_direct_put_guarded(ledger, request, body, &operation, guard)
                .await
        })
    }

    fn validate(&self, request: &MeteredProviderAttemptRequest) -> Result<(), ProviderClientError> {
        self.0.validate_attempt(request)
    }

    fn boundary(&self) -> &CellProviderBoundary {
        self.0.boundary()
    }

    fn retry_policy(&self) -> ProviderRetryPolicy {
        self.0.retry_policy()
    }
}

// ---------------------------------------------------------------------------
// Cell schema attestation
// ---------------------------------------------------------------------------

/// One cell's dispatch schema, read back and found to be installed at the
/// identity this build was compiled against, **paired with the provider
/// boundary that cell serves**.
///
/// The fields are private and there is exactly one non-test constructor,
/// [`attest_cell_schema`], so a [`FragmentProviderGateway`] cannot be built
/// outside this crate's tests without a real readback through the typed
/// authority client.
///
/// **The boundary travels inside the attestation, and that is the point — but
/// read the scope.** [`FragmentProviderGateway::new`] takes no separate
/// boundary argument: it uses this one. So the pair a caller declared at
/// attestation time cannot be *re-paired* afterwards, which is what an earlier
/// revision got wrong by passing the two independently. It is not a proof that
/// the pair was right in the first place: `attest_cell_schema` charges its
/// caller with naming the boundary, and nothing in the readback can check it.
///
/// **What this does not attest, stated so a later reader does not over-read
/// it.**
///
/// - 0019's readback reports four layers: `Retention`, `Authority`,
///   `PutReservation`, and `DispatcherIdentity`. `CellSchemaLayerId` has five —
///   CD-4's `BudgetLimiter` (migrations 0021/0022) has no runtime-callable
///   readback, so the layer the *charge* actually executes against is outside
///   this attestation. CD-4's own procedure checks it at charge time and fails
///   closed. This value proves "the cell database is the installed cell this
///   build expects", not "the limiter is publishable".
/// - It does not attest the live PostgreSQL catalog. That is the migrator-only
///   out-of-band attester's job.
/// - It does not prove the cell database and the provider bucket belong to the
///   same cell. 0019's readback carries no boundary identity at all, so no
///   value derived from it could. What the pairing above gives is that one
///   caller's declared pair travels as one value; proving the pair is right
///   needs a readback that names the boundary, and that is a CD-6 obligation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CellSchemaAttestation {
    boundary: CellProviderBoundary,
    /// Each attested layer's label and the install revision the cell actually
    /// reported for it, in [`ATTESTED_LAYERS`] order.
    ///
    /// The revision comes from the readback rather than from a local constant,
    /// so two cells at different install revisions produce different
    /// attestations. That is what stops
    /// [`CellSchemaAttestation::for_tests`] from comparing equal to a real one
    /// and stops a test that asserts on this from restating its own input.
    /// It names no identifier and no secret.
    attested_layers: Vec<(&'static str, u64)>,
}

impl CellSchemaAttestation {
    /// The provider boundary this attestation is paired with.
    pub fn boundary(&self) -> &CellProviderBoundary {
        &self.boundary
    }

    /// Each attested layer's label and the install revision the cell reported.
    pub fn attested_layers(&self) -> &[(&'static str, u64)] {
        &self.attested_layers
    }

    /// Test-only construction.
    ///
    /// `cfg(test)` rather than a feature flag, so no build configuration a
    /// shipped binary can select makes a fabricated attestation reachable. This
    /// is the compiler enforcing the constructor rule rather than a lint or a
    /// source scan. Integration tests do not see it either: `cfg(test)` is not
    /// set for the library when a `tests/` target links it.
    ///
    /// The sentinel revision is deliberately one a real cell cannot report, so
    /// a fabricated attestation is distinguishable from an attested one.
    #[cfg(test)]
    pub(crate) fn for_tests(boundary: CellProviderBoundary) -> Self {
        Self {
            boundary,
            attested_layers: ATTESTED_LAYERS
                .iter()
                .map(|id| (id.label(), u64::MAX))
                .collect(),
        }
    }
}

/// The layers 0019's runtime-callable readback reports, in the order
/// [`DispatcherIdentityState`] carries them.
const ATTESTED_LAYERS: [CellSchemaLayerId; 4] = [
    CellSchemaLayerId::Retention,
    CellSchemaLayerId::Authority,
    CellSchemaLayerId::PutReservation,
    CellSchemaLayerId::DispatcherIdentity,
];

/// Reads this cell's installed layer identities through WP-114 CD-3's typed
/// authority client and mints a [`CellSchemaAttestation`] only if every one
/// matches.
///
/// `boundary` is the provider boundary this cell serves. It is consumed here
/// rather than handed to [`FragmentProviderGateway::new`] separately, so the
/// readback and the bucket it authorizes cannot be paired wrongly downstream.
///
/// Needs a real cell. Opening no route and installing nothing, it is still a
/// database call, so it belongs to the caller's startup path and not to a
/// constructor.
///
/// **What is already proved, stated precisely so this is not under-claimed
/// either.** CD-3's own live suite (`lore-object-dispatch`'s
/// `dispatch_client_live.rs`) drives `read_dispatcher_identity_state` against a
/// freshly installed cell and asserts all four layers' schema revisions,
/// digests, and install revisions — so the readback's SQL, its runtime role,
/// and its decoding are proved. [`verify_installed_layers`] is proved offline.
/// What is **not** proved anywhere is this function's *composition* of the two
/// against a real cell, because no installed cell exists here to run it on.
pub async fn attest_cell_schema(
    client: &DispatchRuntimeClient,
    boundary: CellProviderBoundary,
) -> Result<CellSchemaAttestation, FragmentSchemaAttestationError> {
    let state = client
        .read_dispatcher_identity_state()
        .await
        .map_err(FragmentSchemaAttestationError::Read)?;
    verify_installed_layers(&state, boundary)
}

/// The pure half of [`attest_cell_schema`]: compares a readback against the
/// identities this build expects.
///
/// Split out so the comparison is testable without a cell. The readback itself
/// is not, and no offline test claims otherwise.
///
/// **Private, and that is the whole point.** `DispatcherIdentityState` and
/// `InstalledLayerIdentity` are public structs of public fields, and the
/// expected identities in [`CELL_SCHEMA_LAYERS`] are public too, so anything
/// that could call this with a hand-built state could mint an attestation
/// without a cell — which would make "exactly one non-test constructor" false.
/// An earlier revision of this function was `pub` and re-exported, and did make
/// it false.
fn verify_installed_layers(
    state: &DispatcherIdentityState,
    boundary: CellProviderBoundary,
) -> Result<CellSchemaAttestation, FragmentSchemaAttestationError> {
    let observed: [&InstalledLayerIdentity; 4] = [
        &state.retention,
        &state.local_authority,
        &state.put_reservation,
        &state.dispatcher_identity,
    ];
    let mut attested_layers = Vec::with_capacity(ATTESTED_LAYERS.len());
    for (id, identity) in ATTESTED_LAYERS.iter().zip(observed) {
        let expected = CELL_SCHEMA_LAYERS
            .iter()
            .find(|layer| layer.id == *id)
            .ok_or(FragmentSchemaAttestationError::Mismatch { layer: *id })?;
        if identity.schema_revision != expected.schema_revision {
            return Err(FragmentSchemaAttestationError::Mismatch { layer: *id });
        }
        if hex::encode(identity.migration_blake3) != expected.migration_blake3_hex {
            return Err(FragmentSchemaAttestationError::Mismatch { layer: *id });
        }
        if identity.install_revision == 0 {
            return Err(FragmentSchemaAttestationError::Mismatch { layer: *id });
        }
        // Record what the cell reported, not what this build expected. An
        // attestation built from local constants alone would be the same value
        // for every cell, and a test asserting on it would be restating its own
        // input.
        attested_layers.push((id.label(), identity.install_revision));
    }
    Ok(CellSchemaAttestation {
        boundary,
        attested_layers,
    })
}

// ---------------------------------------------------------------------------
// In-flight put admission
// ---------------------------------------------------------------------------

/// The configured concurrent in-flight put count, and how long a caller waits
/// for a slot.
///
/// A validated value rather than a bare `u32`, so a gateway cannot be
/// constructed from a count nobody checked. There is no `Default`: CR-031 says
/// the count is configured, and a type that supplies one silently makes
/// "configured" untrue. [`DEFAULT_IN_FLIGHT_PUTS`] exists for a configuration
/// layer to name explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InFlightPutBound {
    permits: usize,
    acquire_timeout: Duration,
}

impl InFlightPutBound {
    /// Validates a configured count and wait.
    ///
    /// The conversion to `usize` happens here rather than at the semaphore, so
    /// the gateway's constructor has no fallible conversion to fall back from
    /// and cannot silently widen a bound it failed to convert.
    pub fn new(permits: u32, acquire_timeout: Duration) -> Result<Self, FragmentProviderError> {
        if permits == 0 || permits > MAX_IN_FLIGHT_PUTS || acquire_timeout.is_zero() {
            return Err(FragmentProviderError::InvalidInFlightPutBound);
        }
        let permits =
            usize::try_from(permits).map_err(|_| FragmentProviderError::InvalidInFlightPutBound)?;
        Ok(Self {
            permits,
            acquire_timeout,
        })
    }

    /// The concurrent put count.
    pub fn permits(&self) -> usize {
        self.permits
    }

    /// How long a put waits for a slot before failing closed.
    pub fn acquire_timeout(&self) -> Duration {
        self.acquire_timeout
    }
}

/// A validated bound on concurrent charge-carrying non-body attempts.
///
/// Its own type rather than a second [`InFlightPutBound`], for the same reason
/// its error variants are their own: the two numbers govern different traffic and
/// a shared type invites a caller to pass one where the other belongs.
///
/// The wait matters more here than for puts. A large push issues one charge per
/// fragment and the charge is serialized per provider boundary, so the last
/// waiter in a 1550-fragment push queues behind every earlier one. A timeout
/// shorter than that queue converts a pool refusal into an admission refusal and
/// fixes nothing — this bound exists to apply backpressure, not to fail faster.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InFlightChargeBound {
    permits: usize,
    acquire_timeout: Duration,
}

impl InFlightChargeBound {
    /// Validates a configured count and wait.
    pub fn new(permits: u32, acquire_timeout: Duration) -> Result<Self, FragmentProviderError> {
        if permits == 0 || permits > MAX_IN_FLIGHT_CHARGES || acquire_timeout.is_zero() {
            return Err(FragmentProviderError::InvalidInFlightChargeBound);
        }
        let permits = usize::try_from(permits)
            .map_err(|_| FragmentProviderError::InvalidInFlightChargeBound)?;
        Ok(Self {
            permits,
            acquire_timeout,
        })
    }

    /// The concurrent charge-carrying non-body attempt count.
    pub fn permits(&self) -> usize {
        self.permits
    }

    /// How long a charge-carrying attempt waits for a slot before failing closed.
    pub fn acquire_timeout(&self) -> Duration {
        self.acquire_timeout
    }
}

// ---------------------------------------------------------------------------
// The attempt a caller describes
// ---------------------------------------------------------------------------

/// Provider operation carried through the policy kernel without teaching it
/// any S3 vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FragmentTransportOperation {
    Head {
        object_key: String,
    },
    ListVersions {
        object_key: String,
    },
    DeleteVersion {
        object_key: String,
        version_id: String,
    },
    /// Delete the exact key from an attested unversioned bucket.
    ///
    /// There is deliberately no version identifier: the startup typestate on
    /// the production transport proves that versioning has never been enabled,
    /// so one decisive `DeleteObject` success is proof that this key is gone.
    DeleteExact {
        object_key: String,
    },
}

impl FragmentTransportOperation {
    pub fn object_key(&self) -> &str {
        match self {
            Self::Head { object_key }
            | Self::ListVersions { object_key }
            | Self::DeleteVersion { object_key, .. }
            | Self::DeleteExact { object_key } => object_key,
        }
    }
}

/// Body-free description of one conditional direct PUT. The body itself can
/// enter the transport only through the governed authorization token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentDirectPutOperation {
    pub object_key: String,
    pub metadata: Vec<(String, String)>,
    pub declared_size: u64,
    pub declared_blake3: [u8; 32],
}

/// Operation-specific response returned through the governed execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FragmentTransportResponse {
    Empty,
    Head {
        metadata: Vec<(String, String)>,
        content_length: u64,
    },
    PutCreated,
    PutPreconditionFailed,
    Versions(Vec<FragmentObjectVersion>),
    Deleted,
    NotFound,
    DefiniteFailure,
    AmbiguousFailure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentObjectVersion {
    pub version_id: String,
    pub is_latest: bool,
}

/// One port result. The request count comes from the connector below the SDK,
/// not from the number of fluent-client calls made by the adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentTransportExchange {
    pub outcome: ProviderAttemptOutcome,
    pub provider_requests_issued: u32,
    pub response: FragmentTransportResponse,
}

/// Redaction-safe view of the target attested for this cell.
#[derive(Clone, Copy)]
pub struct FragmentTransportTarget<'a> {
    bucket: &'a str,
    region: &'a str,
    endpoint_host: &'a str,
}

impl FragmentTransportTarget<'_> {
    pub fn bucket(&self) -> &str {
        self.bucket
    }

    pub fn region(&self) -> &str {
        self.region
    }

    pub fn endpoint_host(&self) -> &str {
        self.endpoint_host
    }
}

impl std::fmt::Debug for FragmentTransportTarget<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FragmentTransportTarget")
            .field("bucket", &"[REDACTED]")
            .field("region", &"[REDACTED]")
            .field("endpoint_host", &"[REDACTED]")
            .finish()
    }
}

/// Opaque authorized request. It is publicly nameable so an adapter can
/// receive it, but its sole constructor stays inside this trust boundary.
pub struct FragmentTransportRequest<'a> {
    authorized: &'a AuthorizedProviderAttempt<'a>,
    operation: &'a FragmentTransportOperation,
}

impl<'a> FragmentTransportRequest<'a> {
    pub fn target(&self) -> FragmentTransportTarget<'_> {
        let target = self.authorized.target();
        FragmentTransportTarget {
            bucket: &target.bucket,
            region: &target.region,
            endpoint_host: &target.endpoint_host,
        }
    }

    pub fn operation(&self) -> &FragmentTransportOperation {
        self.operation
    }

    pub fn attempt_class(&self) -> ProviderAttemptClass {
        self.authorized.attempt_class()
    }

    pub fn put_body(&self) -> Option<&DurableProviderPutBody> {
        self.authorized.put_body()
    }
}

/// The only provider transport port crates outside this seam may implement.
/// They cannot mint [`FragmentTransportRequest`], so implementing the port does
/// not grant a direct-call route to a real send.
pub trait FragmentTransportPort: Send + Sync {
    fn issue<'a>(
        &'a self,
        request: FragmentTransportRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = FragmentTransportExchange> + Send + 'a>>;
}

/// Opaque authorized direct-PUT request. It is publicly nameable so an adapter
/// can receive it, but only the governed client can mint the authorization it
/// contains.
pub struct FragmentDirectPutRequest<'a> {
    authorized: &'a AuthorizedProviderAttempt<'a>,
    operation: &'a FragmentDirectPutOperation,
}

impl<'a> FragmentDirectPutRequest<'a> {
    pub fn target(&self) -> FragmentTransportTarget<'_> {
        let target = self.authorized.target();
        FragmentTransportTarget {
            bucket: &target.bucket,
            region: &target.region,
            endpoint_host: &target.endpoint_host,
        }
    }

    pub fn operation(&self) -> &FragmentDirectPutOperation {
        self.operation
    }

    /// Direct PUT bytes, available only after exact size/hash validation and
    /// a matching shared-budget grant.
    pub fn body(&self) -> Option<&[u8]> {
        self.authorized.direct_put_body()
    }

    pub fn size(&self) -> Option<u64> {
        self.authorized.direct_put_size()
    }

    pub fn blake3(&self) -> Option<&[u8; 32]> {
        self.authorized.direct_put_blake3()
    }
}

/// Direct-PUT-only provider port. A caller can implement it but cannot mint a
/// real request or invoke a send outside the governed seam.
pub trait FragmentDirectPutPort: Send + Sync {
    fn issue_direct_put<'a>(
        &'a self,
        request: FragmentDirectPutRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = FragmentTransportExchange> + Send + 'a>>;
}

/// The one unmetered provider operation. Its type carries no charge, budget,
/// deadline, traffic-class, or durable-ledger vocabulary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentGetOperation {
    pub object_key: String,
}

/// One unmetered GET attempt. The target is supplied only by the attested
/// gateway, so callers can identify the attempt but cannot redirect it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentGetAttempt {
    pub logical_request_id: String,
    pub attempt_id: String,
    pub attempt_ordinal: u32,
}

/// GET-specific response vocabulary. `Throttled` is distinct so the store can
/// map provider backpressure to `StoreError::SlowDown` without inspecting an
/// SDK error outside the adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FragmentGetResponse {
    Found {
        bytes: Vec<u8>,
        metadata: Vec<(String, String)>,
    },
    NotFound,
    Throttled,
    DefiniteFailure,
    AmbiguousFailure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentGetExchange {
    pub outcome: ProviderAttemptOutcome,
    pub provider_requests_issued: u32,
    pub response: FragmentGetResponse,
}

/// Opaque authorized GET request. Only the governed client can mint the
/// authorization token held here.
pub struct FragmentGetRequest<'a> {
    authorized: &'a AuthorizedProviderGet<'a>,
    operation: &'a FragmentGetOperation,
}

impl<'a> FragmentGetRequest<'a> {
    pub fn target(&self) -> FragmentTransportTarget<'_> {
        let target = self.authorized.target();
        FragmentTransportTarget {
            bucket: &target.bucket,
            region: &target.region,
            endpoint_host: &target.endpoint_host,
        }
    }

    pub fn operation(&self) -> &FragmentGetOperation {
        self.operation
    }
}

/// GET-only provider port. A caller can implement it but cannot construct a
/// real request, because the authorization token remains private upstream and
/// this seam exposes no constructor.
pub trait FragmentGetPort: Send + Sync {
    fn issue_get<'a>(
        &'a self,
        request: FragmentGetRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = FragmentGetExchange> + Send + 'a>>;
}

enum GovernedFragmentOperation {
    Standard(FragmentTransportOperation),
    DirectPut(FragmentDirectPutOperation),
}

struct FragmentTransportAdapter<P>(P);

impl<P: FragmentTransportPort + FragmentDirectPutPort> ProviderTransport
    for FragmentTransportAdapter<P>
{
    type Operation = GovernedFragmentOperation;
    type Response = FragmentTransportResponse;

    async fn issue<'a>(
        &'a self,
        attempt: &'a AuthorizedProviderAttempt<'a>,
        operation: &'a Self::Operation,
    ) -> Result<ProviderAttemptReport<Self::Response>, ProviderTransportRefusal> {
        let exchange = match operation {
            GovernedFragmentOperation::Standard(operation) => {
                self.0
                    .issue(FragmentTransportRequest {
                        authorized: attempt,
                        operation,
                    })
                    .await
            }
            GovernedFragmentOperation::DirectPut(operation) => {
                self.0
                    .issue_direct_put(FragmentDirectPutRequest {
                        authorized: attempt,
                        operation,
                    })
                    .await
            }
        };
        Ok(ProviderAttemptReport {
            outcome: exchange.outcome,
            provider_requests_issued: exchange.provider_requests_issued,
            response: exchange.response,
        })
    }
}

impl<P: FragmentGetPort> ProviderGetTransport for FragmentTransportAdapter<P> {
    type Operation = FragmentGetOperation;
    type Response = FragmentGetResponse;

    async fn issue_get<'a>(
        &'a self,
        attempt: &'a AuthorizedProviderGet<'a>,
        operation: &'a Self::Operation,
    ) -> Result<ProviderAttemptReport<Self::Response>, ProviderTransportRefusal> {
        let exchange = self
            .0
            .issue_get(FragmentGetRequest {
                authorized: attempt,
                operation,
            })
            .await;
        Ok(ProviderAttemptReport {
            outcome: exchange.outcome,
            provider_requests_issued: exchange.provider_requests_issued,
            response: exchange.response,
        })
    }
}

/// One provider attempt a fragment lifecycle operation asks this seam to make.
///
/// **There is deliberately no target field.** The gateway addresses its own
/// [`CellProviderBoundary`] and nothing else, which is how CR-031's
/// stay-in-the-cell's-region rule is enforced rather than checked: naming
/// another bucket, region, or endpoint is not expressible here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentProviderAttempt {
    /// Which shared-budget traffic class this attempt is charged under.
    pub traffic_class: ProviderTrafficClass,
    /// The physical attempt class. Must be in [`FRAGMENT_PROVIDER_ATTEMPT_CLASSES`].
    pub attempt_class: ProviderAttemptClass,
    /// Canonical UUIDv7 identifying the logical request.
    pub logical_request_id: String,
    /// Canonical UUIDv7 identifying this physical attempt.
    pub attempt_id: String,
    /// Positive ordinal of this attempt within its logical request.
    pub attempt_ordinal: u32,
    /// Attempt deadline, evaluated against the database admission clock.
    pub deadline_unix_ms: i64,
    /// WP-121's budget-configuration pin. Opaque here.
    pub budget_pin: BudgetPin,
    /// The durable body a `PutObject` attempt sends.
    ///
    /// Supplied by the caller. This module never mints one and never touches a
    /// filesystem, which is what keeps CR-031's "no pre-admission body spool"
    /// true of this seam. The Phase 5 direct-PUT entry supplies this bounded
    /// body only after synchronous admission and exact body binding.
    pub put_body: Option<DurableProviderPutBody>,
}

// ---------------------------------------------------------------------------
// The gateway
// ---------------------------------------------------------------------------

/// This package's one route to a provider.
///
/// Holds one governed client, erased behind the private [`AttemptSink`] trait
/// at construction, so there is no concrete client for any accessor to hand
/// back. **The type has no parameters, and that is a consequence rather than a
/// simplification** — see [`AttemptSink`] for what the erasure buys and what it
/// cost.
pub struct FragmentProviderGateway {
    client: Box<dyn AttemptSink>,
    attestation: CellSchemaAttestation,
    bound: InFlightPutBound,
    in_flight_puts: Semaphore,
    charge_bound: InFlightChargeBound,
    in_flight_charges: Semaphore,
    port_wired: bool,
}

/// TLS configuration for the one dispatch-runtime pool.
#[derive(Clone)]
pub enum FragmentDispatchTls {
    Disabled,
    PinnedRootCa(String),
}

impl fmt::Debug for FragmentDispatchTls {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => formatter.write_str("Disabled"),
            Self::PinnedRootCa(_) => formatter.write_str("PinnedRootCa([REDACTED])"),
        }
    }
}

/// Expected physical database identity supplied by the already-attested domain store.
///
/// The system identifier is accepted in the exact canonical decimal form PostgreSQL returns.
/// Database aliases, credentials, and TLS parameters are deliberately absent.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct FragmentDatabaseIdentity(DispatchDatabaseIdentity);

impl fmt::Debug for FragmentDatabaseIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FragmentDatabaseIdentity([REDACTED])")
    }
}

impl FragmentDatabaseIdentity {
    pub fn new(
        system_identifier: &str,
        database_oid: u32,
    ) -> Result<Self, FragmentDatabaseIdentityError> {
        let parsed_system_identifier = system_identifier
            .parse::<u64>()
            .map_err(|_| FragmentDatabaseIdentityError::InvalidSystemIdentifier)?;
        if parsed_system_identifier == 0
            || parsed_system_identifier.to_string() != system_identifier
        {
            return Err(FragmentDatabaseIdentityError::InvalidSystemIdentifier);
        }
        if database_oid == 0 {
            return Err(FragmentDatabaseIdentityError::InvalidDatabaseOid);
        }
        let identity = DispatchDatabaseIdentity::new(parsed_system_identifier, database_oid)
            .map_err(|_| FragmentDatabaseIdentityError::InvalidDatabaseOid)?;
        Ok(Self(identity))
    }
}

/// Why a domain-store identity cannot be used as an activation expectation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum FragmentDatabaseIdentityError {
    #[error("domain database system identifier is not canonical")]
    InvalidSystemIdentifier,
    #[error("domain database OID is invalid")]
    InvalidDatabaseOid,
}

/// Seam-owned construction input for the shared dispatch pool.
///
/// Its exact steady-state inventory names the immutable, mutable, lock, domain, and dispatch
/// maxima independently. No dispatch pool type crosses this public boundary.
#[derive(Clone)]
pub struct FragmentDispatchRuntimeConfig {
    pub postgres_url: String,
    pub expected_database_identity: FragmentDatabaseIdentity,
    pub process_pool_inventory: ValidatedFragmentProcessPoolInventory,
    pub connect_timeout: Duration,
    pub acquire_timeout: Duration,
    pub statement_timeout: Duration,
    pub lock_timeout: Duration,
    pub tls: FragmentDispatchTls,
}

impl fmt::Debug for FragmentDispatchRuntimeConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FragmentDispatchRuntimeConfig")
            .field("postgres_url", &"[REDACTED]")
            .field(
                "expected_database_identity",
                &self.expected_database_identity,
            )
            .field("process_pool_inventory", &self.process_pool_inventory)
            .field("connect_timeout", &self.connect_timeout)
            .field("acquire_timeout", &self.acquire_timeout)
            .field("statement_timeout", &self.statement_timeout)
            .field("lock_timeout", &self.lock_timeout)
            .field("tls", &self.tls)
            .finish()
    }
}

/// Exact maxima of every pool the process opens against the cell database.
///
/// Composition supplies every value from its owning configuration. The seam neither defaults nor
/// infers one pool's maximum from another pool — including `relay_pool_max`, where the caller
/// decides whether the relay is enabled and passes zero when it is not. The seam cannot read
/// `[outbox_relay]` and must not guess at it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FragmentProcessPoolInventory {
    pub immutable_pool_max: u32,
    pub mutable_pool_max: u32,
    pub lock_pool_max: u32,
    pub domain_pool_max: u32,
    pub dispatch_pool_max: u32,
    /// CR-032's event-relay pool, or zero when `[outbox_relay]` is disabled and
    /// the process opens none. The only member that may be zero, and the only
    /// one whose presence depends on configuration rather than on the process
    /// being Postgres-mode at all.
    pub relay_pool_max: u32,
}

impl FragmentProcessPoolInventory {
    /// Validate the exact six-pool process inventory before composition opens
    /// any database or object-store connection.
    pub fn validate(
        self,
    ) -> Result<ValidatedFragmentProcessPoolInventory, FragmentProviderActivationError> {
        let budget = DispatchConnectionBudget::new(
            self.immutable_pool_max,
            self.mutable_pool_max,
            self.lock_pool_max,
            self.domain_pool_max,
            self.dispatch_pool_max,
            self.relay_pool_max,
        )
        .map_err(FragmentProviderActivationError::DispatchPool)?;
        Ok(ValidatedFragmentProcessPoolInventory {
            inventory: self,
            budget,
        })
    }
}

/// Canonically validated six-pool inventory carried from server preflight to
/// the dispatch pool without repeating or reimplementing the arithmetic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedFragmentProcessPoolInventory {
    inventory: FragmentProcessPoolInventory,
    budget: DispatchConnectionBudget,
}

impl ValidatedFragmentProcessPoolInventory {
    /// The checked budget behind this inventory.
    ///
    /// Read-only, and deliberately not a way back to a pool: the budget is a
    /// `Copy` arithmetic record with no handle in it. Server composition uses it
    /// to ask `opens_dispatch_pool` when choosing its boot order, rather than
    /// re-deriving that from a raw field, and doing so costs the seam nothing —
    /// a dispatch client still cannot be constructed here.
    #[must_use]
    pub const fn budget(&self) -> DispatchConnectionBudget {
        self.budget
    }
}

/// The one composition door for attestation, charge authority, and provider
/// transport. It retains one Arc-backed pool through the typed client and
/// charge authority; no second pool or raw connection is opened.
pub struct FragmentProviderEntry {
    gateway: FragmentProviderGateway,
    _dispatch: DispatchRuntimeClient,
    /// The one pool this entry opened, retained so WP-114 CD-8's retention
    /// scheduler runs on it rather than opening a second one. Private, and
    /// reachable only through [`FragmentProviderEntry::cell_retention`], which
    /// hands out a retention client and never the pool: publishing the pool
    /// type would falsify the seam's "a dispatch client cannot be constructed"
    /// claim, which `seam_source_pins.rs` pins by name.
    pool: Arc<DispatchRuntimePool>,
}

/// A carrier for the process's cell-retention client, in a type `lore-postgres`
/// can name.
///
/// CD-8's scheduler is composed in `lore-server`, but the pool it must run on is
/// opened here and reaches `lore-server` only by passing through
/// `lore-postgres`, which may not depend on `lore-object-dispatch`. So the
/// client travels inside this opaque handle: `lore-postgres` moves it without
/// naming its contents, and `lore-server` — which may take that dependency —
/// opens it.
///
/// Holding one grants retention procedures and nothing else. 0024's procedures
/// compute their horizon, replay floor, withhold clauses and batch ceiling
/// inside `SECURITY DEFINER` bodies from the database's own clock, so a holder
/// cannot widen what a pass removes, and cannot reach any other authority
/// mutation: those request types stay unnameable outside the dispatch crate.
#[derive(Debug)]
pub struct FragmentCellRetentionHandle {
    client: CellRetentionClient,
}

impl FragmentCellRetentionHandle {
    /// Take the retention client for scheduling.
    #[must_use]
    pub fn into_client(self) -> CellRetentionClient {
        self.client
    }
}

// ---------------------------------------------------------------------------
// WP-114 CD-6: the drain capability
// ---------------------------------------------------------------------------

/// The canonical-record bounds and protocol revision the drain's spool-ready
/// call is recorded under.
///
/// **Published so the reservation side agrees, not so a caller may choose.**
/// 0016 folds all five values into the canonical record digest, so a reservation
/// recorded under different bounds and this call would not describe the same
/// record. They are constants rather than parameters for exactly the reason the
/// gateway takes no retry policy: the way to forbid a caller naming its own
/// protocol revision is to leave no way to say it.
pub const FRAGMENT_DRAIN_PROTOCOL_REVISION: &str = "object-dispatch-v1";

/// Canonical text bound for every identity column in the drain's spool-ready
/// record. Inside 0016's accepted `1..=1024`.
pub const FRAGMENT_DRAIN_MAXIMUM_IDENTITY_BYTES: i32 = 256;

/// Canonical text bound for the boundary token. Inside 0016's `1..=4096`.
pub const FRAGMENT_DRAIN_MAXIMUM_BOUNDARY_TOKEN_BYTES: i32 = 256;

/// Canonical text bound for the durable handle. Set at 0016's ceiling rather
/// than at the identity bound: the handle is a derived spool path, so it is the
/// one field whose length is a property of the deployment's staging root.
pub const FRAGMENT_DRAIN_MAXIMUM_DURABLE_HANDLE_BYTES: i32 = 4_096;

/// Canonical record bound. Inside 0016's `1..=16777216`.
pub const FRAGMENT_DRAIN_MAXIMUM_RECORD_BYTES: i32 = 16_384;

/// A drain-only view of the one composition door.
///
/// Opaque by construction: it retains the entry — and through it the process's
/// gateway, dispatch pool, and participant identity — and publishes none of
/// them. Its fields are private and it exposes no `pool`, no `dispatch`,
/// no `gateway`, and no `entry`. The public method set is exactly
/// [`Self::reserve_spool`], [`Self::mark_spool_ready`] and [`Self::attempt_drain`], which
/// `tests/seam_source_pins.rs` pins by equality rather than by containment.
///
/// **This grants no delete authority.** The drain builds a
/// [`ProviderAttemptClass::PutObject`] and nothing else, so the delete variants
/// of [`FragmentTransportOperation`] are not reachable from here. WP-114's D10
/// ruling is narrow, and this is the half of it this seam owns.
///
/// Held by value rather than borrowed: a drain worker is a background task, so
/// the capability retains an `Arc` and is `'static`.
pub struct FragmentDrainCapability {
    entry: Arc<FragmentProviderEntry>,
    dispatch: DispatchRuntimeClient,
    spool_root: PathBuf,
    policy_pin: Option<FragmentDrainPolicyPin>,
    spool_writer: Option<Arc<lore_object_dispatch::spool_writer::LinuxSpoolWriter>>,
}

/// An opaque ready receipt.
///
/// The projection inside is private with no accessor, so a receipt cannot be
/// forged, inspected for a chargeable value, or moved between requests: the only
/// thing a holder can do with one is present it to
/// [`FragmentDrainCapability::attempt_drain`], which re-derives the binding
/// rather than trusting it.
#[derive(Clone, PartialEq, Eq)]
pub struct FragmentDrainReady(PutSpoolReadyOutcome);

impl fmt::Debug for FragmentDrainReady {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FragmentDrainReady([REDACTED])")
    }
}

/// One governed drain attempt.
///
/// **Non-`Clone` on purpose**, following the admitted-PUT token: an attempt
/// identity is used once, and a `Clone` would make a second use expressible.
///
/// A caller cannot name a traffic class, an attempt class, a target, or the
/// declared size and digest. The first two the seam forces; the last two come
/// from the bound spool body. What the caller does supply is the pair below the
/// send is *checked against*, which came from the lifecycle claim rather than
/// from this worker's view of the filesystem.
#[derive(PartialEq, Eq)]
pub struct FragmentDrainAttempt {
    /// Canonical UUIDv7 identifying the logical request.
    pub logical_request_id: String,
    /// Canonical UUIDv7 identifying this physical attempt.
    pub attempt_id: String,
    /// Positive ordinal of this attempt within its logical request.
    pub attempt_ordinal: u32,
    /// Attempt deadline, evaluated against the database admission clock.
    pub deadline_unix_ms: i64,
    /// WP-121's budget-configuration pin. Opaque here, and resolving it is
    /// CD-4's obligation: this seam copies it and never inspects, compares,
    /// refreshes, or re-reads it.
    pub budget_pin: BudgetPin,
    /// The destination key for the PUT.
    pub object_key: String,
    /// Object metadata for the PUT.
    pub metadata: Vec<(String, String)>,
    /// The lifecycle claim's own digest of the body. **The independent anchor**,
    /// not a declaration: it did not come from the spool.
    pub claim_body_blake3: [u8; 32],
    /// The lifecycle claim's own size for the body.
    pub claim_body_size: u64,
}

impl fmt::Debug for FragmentDrainAttempt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FragmentDrainAttempt")
            .field("logical_request_id", &"[REDACTED]")
            .field("attempt_id", &"[REDACTED]")
            .field("attempt_ordinal", &self.attempt_ordinal)
            .field("deadline_unix_ms", &self.deadline_unix_ms)
            .field("budget_pin", &self.budget_pin)
            .field("object_key", &"[REDACTED]")
            .field("metadata", &"[REDACTED]")
            .field("claim_body_blake3", &"[REDACTED]")
            .field("claim_body_size", &self.claim_body_size)
            .finish()
    }
}

impl FragmentDrainCapability {
    /// Move this drain's spool object to `SPOOL_READY` and take the receipt a
    /// drain attempt must present.
    ///
    /// The reservation and writer receipt bind all fields. The database rechecks
    /// live custody and expiry before first publication or replay.
    ///
    /// # Errors
    ///
    /// Returns [`FragmentProviderError::SpoolReadyRefused`] when the cell
    /// authority refuses the transition.
    pub async fn mark_spool_ready(
        &self,
        reservation: &FragmentDrainReservation,
        receipt: &FragmentDrainWriteReceipt,
    ) -> Result<FragmentDrainReady, FragmentProviderError> {
        let d = &reservation.descriptor;
        if d.boundary != self.entry.boundary().provider_boundary_id()
            || self.policy_pin.as_ref().is_none_or(|pin| {
                pin.cell_id != d.cell
                    || pin.revision != d.policy_revision
                    || lore_object_dispatch::drain_policy::hex(&pin.digest) != d.policy_digest
            })
            || !reservation.matches_receipt(&receipt.0)
            || receipt.0.size() != d.body_size
            || lore_object_dispatch::drain_policy::hex(receipt.0.blake3()) != d.body_digest
        {
            return Err(FragmentProviderError::ClaimBindingMismatch);
        }
        let call = lore_object_dispatch::dispatch_client::PutSpoolReadyRequest {
            protocol_revision: FRAGMENT_DRAIN_PROTOCOL_REVISION.to_string(),
            identity: PutStreamIdentity {
                provider_boundary_id: self.entry.boundary().provider_boundary_id().to_string(),
                authenticated_cell_id: d.cell.clone(),
                authenticated_tenant_id: d.service.clone(),
                logical_request_id: d.logical_request_id,
                attempt_id: d.attempt_id,
                upload_id: d.upload_id,
                upload_fence: d.upload_fence,
            },
            final_chunk_index: 0,
            fsynced_body_size: receipt.0.size(),
            fsynced_body_blake3: *receipt.0.blake3(),
            durable_handle: receipt.0.opaque_handle().to_owned(),
            maximum_identity_bytes: FRAGMENT_DRAIN_MAXIMUM_IDENTITY_BYTES,
            maximum_boundary_token_bytes: FRAGMENT_DRAIN_MAXIMUM_BOUNDARY_TOKEN_BYTES,
            maximum_durable_handle_bytes: FRAGMENT_DRAIN_MAXIMUM_DURABLE_HANDLE_BYTES,
            maximum_record_bytes: FRAGMENT_DRAIN_MAXIMUM_RECORD_BYTES,
        };
        let accepted = self
            .dispatch
            .put_spool_ready(&call)
            .await
            .map_err(FragmentProviderError::SpoolReadyRefused)?;
        Ok(FragmentDrainReady(accepted.value))
    }

    /// One governed drain send.
    ///
    /// Each step refuses before the next costs anything, and nothing is charged
    /// or sent until all of them pass:
    ///
    /// 1. the transport port must be wired;
    /// 2. the ready receipt binds to a durable spool body, whose derived handle
    ///    must equal the one the database recorded;
    /// 3. that body must belong to this attempt's logical request;
    /// 4. **it must also equal the lifecycle claim's digest and size** — the one
    ///    check on this path whose two sides come from different sources;
    /// 5. it must be inside the existing 256 KiB ingress cap;
    /// 6. the supplied bytes must be exactly that body.
    ///
    /// Only then does it go through [`FragmentProviderEntry::admit_put`], which
    /// supplies the empty-key check, the cap check, and the one in-flight PUT
    /// permit the direct fallback also takes. CD-5 then charges CD-4's limiter
    /// before constructing the value a transport will accept, so
    /// charge-before-send is inherited rather than re-implemented, and the
    /// charge consumes the shared physical budget together with the subordinate
    /// drain cap atomically.
    ///
    /// **`Ok(FragmentTransportExecution { outcome: Ambiguous, .. })` is not
    /// success.** As on every other path through this seam, only the caller
    /// knows what an unknown provider effect means for the operation it is in
    /// the middle of, so the seam does not collapse it into an error.
    ///
    /// # Errors
    ///
    /// Returns [`FragmentProviderError::OperationRequired`],
    /// [`FragmentProviderError::SpoolBindingRejected`],
    /// [`FragmentProviderError::SpoolBindingRequestMismatch`],
    /// [`FragmentProviderError::ClaimBindingMismatch`],
    /// [`FragmentProviderError::IngressCapExceeded`],
    /// [`FragmentProviderError::DrainBodyMismatch`], or whatever admission,
    /// charge, or transport returns.
    pub async fn attempt_drain(
        &self,
        ledger: &mut FragmentAttemptLedger,
        request: FragmentDrainAttempt,
        ready: &FragmentDrainReady,
        body: &[u8],
    ) -> Result<FragmentTransportExecution, FragmentProviderError> {
        if !self.entry.gateway.port_wired {
            return Err(FragmentProviderError::OperationRequired);
        }
        let bound = lore_object_dispatch::bind_durable_put_body_from_ready(
            self.spool_root.clone(),
            self.entry.boundary().provider_boundary_id(),
            &ready.0,
        )
        .map_err(FragmentProviderError::SpoolBindingRejected)?;
        if bound.logical_request_id() != request.logical_request_id.as_str()
            || ready.0.attempt_id.to_string() != request.attempt_id
        {
            return Err(FragmentProviderError::SpoolBindingRequestMismatch);
        }
        if bound.blake3() != &request.claim_body_blake3 || bound.size() != request.claim_body_size {
            return Err(FragmentProviderError::ClaimBindingMismatch);
        }
        if bound.size() > FRAGMENT_PROVIDER_INGRESS_CAP_BYTES {
            return Err(FragmentProviderError::IngressCapExceeded);
        }
        if bound.size() == 0 {
            return Err(FragmentProviderError::Provider(
                ProviderClientError::DirectPutBodyOutOfBounds,
            ));
        }
        let body_len = u64::try_from(body.len()).unwrap_or(u64::MAX);
        if body_len != bound.size() || blake3::hash(body).as_bytes() != bound.blake3() {
            return Err(FragmentProviderError::DrainBodyMismatch);
        }
        let ready_key = request.object_key.clone();
        let ready_deadline = request.deadline_unix_ms;
        let attempt = FragmentProviderAttempt {
            traffic_class: ProviderTrafficClass::Drain,
            attempt_class: ProviderAttemptClass::PutObject,
            logical_request_id: request.logical_request_id,
            attempt_id: request.attempt_id,
            attempt_ordinal: request.attempt_ordinal,
            deadline_unix_ms: request.deadline_unix_ms,
            budget_pin: request.budget_pin,
            put_body: None,
        };
        let operation = FragmentDirectPutOperation {
            object_key: request.object_key,
            metadata: request.metadata,
            declared_size: bound.size(),
            declared_blake3: *bound.blake3(),
        };
        let mut admitted = self.entry.admit_put(attempt, operation).await?;
        // Waiting for the shared permit cannot outlive the ready authority check.
        let check_started = tokio::time::Instant::now();
        let (effective_deadline, remaining_ms) =
            lore_object_dispatch::drain_policy::DrainClient::new(self.entry.pool.clone())
                .check_ready(
                    ready.0.spool_object_id,
                    ready.0.attempt_id,
                    &ready.0.record_blake3,
                    &ready_key,
                    ready_deadline,
                )
                .await
                .map_err(FragmentProviderError::DrainAuthority)?;
        admitted.attempt.deadline_unix_ms = effective_deadline;
        let remaining = Duration::from_millis(remaining_ms)
            .checked_sub(check_started.elapsed())
            .ok_or(FragmentProviderError::DrainAuthority(
                lore_object_dispatch::drain_policy::DrainError::Refused,
            ))?;
        let guard = DrainPreTransportGuard {
            client: lore_object_dispatch::drain_policy::DrainClient::new(self.entry.pool.clone()),
            ready: &ready.0,
            object_key: &ready_key,
            deadline_unix_ms: effective_deadline,
            expires_at: check_started
                .checked_add(Duration::from_millis(remaining_ms))
                .ok_or(FragmentProviderError::DrainAuthority(
                    lore_object_dispatch::drain_policy::DrainError::Refused,
                ))?,
        };
        tokio::time::timeout(
            remaining,
            admitted.execute_direct_put_guarded(ledger, body, Some(&guard)),
        )
        .await
        .map_err(|_error| FragmentProviderError::Provider(ProviderClientError::ChargeAmbiguous))?
    }
}

/// Kept inside the seam: the caller cannot substitute ready evidence or extend
/// the database-derived window after waiting for charge authority.
struct DrainPreTransportGuard<'a> {
    client: lore_object_dispatch::drain_policy::DrainClient,
    ready: &'a PutSpoolReadyOutcome,
    object_key: &'a str,
    deadline_unix_ms: i64,
    expires_at: tokio::time::Instant,
}

impl ProviderPreTransportGuard for DrainPreTransportGuard<'_> {
    fn check(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<tokio::time::Instant, ProviderClientError>> + Send + '_>>
    {
        Box::pin(async move {
            let started = tokio::time::Instant::now();
            if started >= self.expires_at {
                return Err(ProviderClientError::PreTransportGuardRefused);
            }
            let (_, remaining_ms) = self
                .client
                .check_ready(
                    self.ready.spool_object_id,
                    self.ready.attempt_id,
                    &self.ready.record_blake3,
                    self.object_key,
                    self.deadline_unix_ms,
                )
                .await
                .map_err(|_error| ProviderClientError::PreTransportGuardRefused)?;
            // Start the lease before the database round trip, so neither query
            // latency nor a backward wall-clock change can extend admission.
            started
                .checked_add(Duration::from_millis(remaining_ms))
                .map(|expires_at| expires_at.min(self.expires_at))
                .ok_or(ProviderClientError::PreTransportGuardRefused)
        })
    }
}

impl FragmentProviderEntry {
    pub async fn connect<P>(
        config: FragmentDispatchRuntimeConfig,
        boundary: CellProviderBoundary,
        capabilities: ProviderCapabilities,
        bound: InFlightPutBound,
        charge_bound: InFlightChargeBound,
        transport: P,
    ) -> Result<Self, FragmentProviderActivationError>
    where
        P: FragmentTransportPort + FragmentDirectPutPort + FragmentGetPort + 'static,
    {
        let ValidatedFragmentProcessPoolInventory { inventory, budget } =
            config.process_pool_inventory;
        let tls = match config.tls {
            FragmentDispatchTls::Disabled => DispatchTlsMode::Disabled,
            FragmentDispatchTls::PinnedRootCa(pem) => DispatchTlsMode::PinnedRootCa(pem),
        };
        let pool = Arc::new(
            DispatchRuntimePool::new(DispatchPoolConfig {
                postgres_url: config.postgres_url,
                role: DispatchPoolRole::Runtime,
                expected_database_identity: config.expected_database_identity.0,
                pool_max: inventory.dispatch_pool_max,
                connect_timeout: config.connect_timeout,
                acquire_timeout: config.acquire_timeout,
                statement_timeout: config.statement_timeout,
                lock_timeout: config.lock_timeout,
                tls,
                budget,
            })
            .map_err(FragmentProviderActivationError::DispatchPool)?,
        );
        let dispatch = DispatchRuntimeClient::new(pool.clone())
            .map_err(FragmentProviderActivationError::DispatchClient)?;
        dispatch
            .attest_database_identity(config.expected_database_identity.0)
            .await
            .map_err(FragmentProviderActivationError::DatabaseIdentity)?;
        let attestation = attest_cell_schema(&dispatch, boundary)
            .await
            .map_err(FragmentProviderActivationError::Schema)?;
        let charge_authority = PostgresProviderChargeAuthority::new(pool.clone())
            .map_err(FragmentProviderActivationError::ChargeAuthority)?;
        let gateway = FragmentProviderGateway::with_transport_port(
            attestation,
            capabilities,
            bound,
            charge_bound,
            charge_authority,
            transport,
        );
        Ok(Self {
            gateway,
            _dispatch: dispatch,
            pool,
        })
    }

    pub fn boundary(&self) -> &CellProviderBoundary {
        self.gateway.boundary()
    }

    /// Mint WP-114 CD-8's retention client on the pool this entry already owns.
    ///
    /// Opens no connection and no second pool, so the CR-033 D8 process
    /// connection inventory is unchanged. The client's own constructor refuses a
    /// pool that does not connect as the runtime role.
    ///
    /// # Errors
    ///
    /// Returns [`FragmentProviderActivationError::DispatchClient`] when the pool
    /// is not the runtime pool.
    pub fn cell_retention(
        &self,
    ) -> Result<FragmentCellRetentionHandle, FragmentProviderActivationError> {
        let client = CellRetentionClient::new(self.pool.clone())
            .map_err(FragmentProviderActivationError::DispatchClient)?;
        Ok(FragmentCellRetentionHandle { client })
    }

    /// Mint WP-114 CD-6's drain capability on the pool this entry already owns.
    ///
    /// Opens no connection and no second pool, so the CR-033 D8 process
    /// connection inventory is unchanged and WP-119's fleet ceiling is
    /// untouched. The typed client's own constructor refuses a pool that does
    /// not connect as the runtime role.
    ///
    /// **Takes `&Arc<Self>` rather than `&self`.** A drain worker is a
    /// background task, so the capability must be `'static`; the retention
    /// handle gets away with a borrow because it hands out an owned client,
    /// while this one has to retain the gateway, which lives inside the entry.
    ///
    /// The spool root arrives as a parameter rather than as a field on
    /// [`FragmentDispatchRuntimeConfig`], so composition's construction site
    /// does not change. The seam stores it and passes it to the durable-body
    /// binder; it opens no file with it, and the pins keep that true.
    ///
    /// # Errors
    ///
    /// Returns [`FragmentProviderActivationError::DispatchClient`] when the pool
    /// is not the runtime pool.
    fn drain_capability(
        self: &Arc<Self>,
        shared_spool_root: PathBuf,
    ) -> Result<FragmentDrainCapability, FragmentProviderActivationError> {
        let dispatch = DispatchRuntimeClient::new(self.pool.clone())
            .map_err(FragmentProviderActivationError::DispatchClient)?;
        Ok(FragmentDrainCapability {
            entry: Arc::clone(self),
            dispatch,
            spool_root: shared_spool_root,
            policy_pin: None,
            spool_writer: None,
        })
    }

    pub async fn admit_operation(
        &self,
        attempt: FragmentProviderAttempt,
        operation: FragmentTransportOperation,
    ) -> Result<AdmittedFragmentAttempt<'_>, FragmentProviderError> {
        self.gateway.admit_operation(attempt, operation).await
    }

    pub async fn admit_put(
        &self,
        attempt: FragmentProviderAttempt,
        operation: FragmentDirectPutOperation,
    ) -> Result<AdmittedFragmentPutAttempt<'_>, FragmentProviderError> {
        self.gateway.admit_put(attempt, operation).await
    }

    pub async fn get(
        &self,
        attempt: &FragmentGetAttempt,
        operation: &FragmentGetOperation,
    ) -> Result<FragmentGetExecution, FragmentProviderError> {
        self.gateway.get(attempt, operation).await
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentTransportExecution {
    pub outcome: ProviderAttemptOutcome,
    pub response: FragmentTransportResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragmentGetExecution {
    pub outcome: ProviderAttemptOutcome,
    pub response: FragmentGetResponse,
}

/// One admitted body-free operation. The direct-PUT entry uses a distinct token
/// so this type cannot acquire a PUT body or invoke direct transport.
pub struct AdmittedFragmentAttempt<'a> {
    gateway: &'a FragmentProviderGateway,
    attempt: FragmentProviderAttempt,
    operation: FragmentTransportOperation,
    /// Held for the whole admission, released on drop. Named with a leading
    /// underscore for the same reason `AdmittedFragmentPutAttempt` does: it is
    /// owned for its lifetime, never read.
    _charge_permit: SemaphorePermit<'a>,
}

impl<'a> AdmittedFragmentAttempt<'a> {
    /// Consume this body-free admission for one governed charge/send.
    pub async fn execute(
        self,
        ledger: &mut FragmentAttemptLedger,
    ) -> Result<FragmentTransportExecution, FragmentProviderError> {
        self.gateway.check_ingress_cap(&self.attempt)?;
        let request =
            MeteredProviderAttemptRequest::try_from(self.gateway.build_request(&self.attempt))
                .map_err(FragmentProviderError::Provider)?;
        let execution = self
            .gateway
            .client
            .issue(&mut ledger.0, &request, &self.operation)
            .await
            .map_err(FragmentProviderError::Provider)?;
        Ok(FragmentTransportExecution {
            outcome: execution.outcome,
            response: execution.response,
        })
    }
}

/// One admitted direct PUT. It is non-Clone and retains the sole configured
/// PUT permit until validation, charge, and transport execution complete.
pub struct AdmittedFragmentPutAttempt<'a> {
    gateway: &'a FragmentProviderGateway,
    attempt: FragmentProviderAttempt,
    operation: FragmentDirectPutOperation,
    _put_permit: SemaphorePermit<'a>,
}

impl AdmittedFragmentPutAttempt<'_> {
    /// Validate and exact-bind a bounded direct PUT, then consume the sole
    /// admission permit for its one governed charge/send.
    pub async fn execute_direct_put(
        self,
        ledger: &mut FragmentAttemptLedger,
        body: &[u8],
    ) -> Result<FragmentTransportExecution, FragmentProviderError> {
        self.execute_direct_put_guarded(ledger, body, None).await
    }

    async fn execute_direct_put_guarded(
        self,
        ledger: &mut FragmentAttemptLedger,
        body: &[u8],
        guard: Option<&dyn ProviderPreTransportGuard>,
    ) -> Result<FragmentTransportExecution, FragmentProviderError> {
        let request = ProviderDirectPutAttemptRequest {
            traffic_class: self.attempt.traffic_class,
            target: self.gateway.boundary().target().clone(),
            logical_request_id: self.attempt.logical_request_id,
            attempt_id: self.attempt.attempt_id,
            attempt_ordinal: self.attempt.attempt_ordinal,
            deadline_unix_ms: self.attempt.deadline_unix_ms,
            budget_pin: self.attempt.budget_pin,
            declared_size: self.operation.declared_size,
            declared_blake3: self.operation.declared_blake3,
        };
        let execution = self
            .gateway
            .client
            .issue_direct_put(&mut ledger.0, &request, body, &self.operation, guard)
            .await
            .map_err(FragmentProviderError::Provider)?;
        Ok(FragmentTransportExecution {
            outcome: execution.outcome,
            response: execution.response,
        })
    }
}

impl FragmentProviderGateway {
    /// The shipped construction: an attested cell, its own boundary, and no
    /// ability to charge or send.
    ///
    /// Kept as a named constructor rather than left to a caller's type
    /// annotation, so "the default is unwired" is a fact about this file.
    pub fn unwired(
        attestation: CellSchemaAttestation,
        capabilities: ProviderCapabilities,
        bound: InFlightPutBound,
        charge_bound: InFlightChargeBound,
    ) -> Self {
        Self::new(
            attestation,
            capabilities,
            bound,
            charge_bound,
            UnwiredChargeAuthority,
            UnwiredProviderTransport,
        )
    }

    /// Builds the gateway.
    ///
    /// **Takes no retry policy.** CR-031 forbids SDK automatic retries, and the
    /// way to forbid something is to leave no way to say it: this constructor
    /// states [`ProviderRetryPolicy::disabled`] itself, so no caller and no
    /// configuration can widen it. CD-5's transport contract then rejects a
    /// transport that issues more than the one charged request, which is the
    /// observable half — a declaration alone would prove nothing about an SDK's
    /// internals.
    ///
    /// **Takes no boundary either.** The boundary comes out of the attestation,
    /// so this gateway addresses the cell whose schema was read back and no
    /// other. Accepting both independently left a caller free to pair them
    /// wrongly, and nothing would have said so.
    pub fn new<C, T>(
        attestation: CellSchemaAttestation,
        capabilities: ProviderCapabilities,
        bound: InFlightPutBound,
        charge_bound: InFlightChargeBound,
        charge_authority: C,
        transport: T,
    ) -> Self
    where
        C: ProviderChargeAuthority + Send + Sync + 'static,
        T: ProviderTransport<Operation = (), Response = ()> + Send + Sync + 'static,
    {
        Self {
            client: Box::new(UnitAttemptSink(GovernedProviderClient::new(
                attestation.boundary().clone(),
                capabilities,
                ProviderRetryPolicy::disabled(),
                charge_authority,
                transport,
            ))),
            attestation,
            bound,
            in_flight_puts: Semaphore::new(bound.permits()),
            charge_bound,
            in_flight_charges: Semaphore::new(charge_bound.permits()),
            port_wired: false,
        }
    }

    /// Build the wired gateway around the seam-owned opaque transport port.
    /// The adapter is private, so the authorized dispatch vocabulary remains
    /// unavailable to the port implementation.
    pub fn with_transport_port<C, P>(
        attestation: CellSchemaAttestation,
        capabilities: ProviderCapabilities,
        bound: InFlightPutBound,
        charge_bound: InFlightChargeBound,
        charge_authority: C,
        transport: P,
    ) -> Self
    where
        C: ProviderChargeAuthority + Send + Sync + 'static,
        P: FragmentTransportPort + FragmentDirectPutPort + FragmentGetPort + 'static,
    {
        Self {
            client: Box::new(PortAttemptSink(GovernedProviderClient::new(
                attestation.boundary().clone(),
                capabilities,
                ProviderRetryPolicy::disabled(),
                charge_authority,
                FragmentTransportAdapter(transport),
            ))),
            attestation,
            bound,
            in_flight_puts: Semaphore::new(bound.permits()),
            charge_bound,
            in_flight_charges: Semaphore::new(charge_bound.permits()),
            port_wired: true,
        }
    }

    /// The cell schema attestation this gateway was built against.
    pub fn attestation(&self) -> &CellSchemaAttestation {
        &self.attestation
    }

    /// The cell boundary every attempt is addressed to.
    pub fn boundary(&self) -> &CellProviderBoundary {
        self.client.boundary()
    }

    /// The retry setting handed to every authorized attempt. Always disabled.
    pub fn retry_policy(&self) -> ProviderRetryPolicy {
        self.client.retry_policy()
    }

    /// The configured in-flight put bound.
    pub fn in_flight_put_bound(&self) -> InFlightPutBound {
        self.bound
    }

    /// Put slots free right now. For tests and diagnostics.
    pub fn available_put_permits(&self) -> usize {
        self.in_flight_puts.available_permits()
    }

    /// Validate and admit one explicit body-free operation.
    pub async fn admit_operation(
        &self,
        mut attempt: FragmentProviderAttempt,
        operation: FragmentTransportOperation,
    ) -> Result<AdmittedFragmentAttempt<'_>, FragmentProviderError> {
        if !self.port_wired {
            return Err(FragmentProviderError::OperationRequired);
        }
        Self::check_attempt_class(attempt.attempt_class)?;
        if operation.object_key().is_empty() {
            return Err(FragmentProviderError::InvalidObjectKey);
        }
        let matches = matches!(
            (attempt.attempt_class, &operation),
            (
                ProviderAttemptClass::HeadObject,
                FragmentTransportOperation::Head { .. }
            ) | (
                ProviderAttemptClass::ListObjectVersions,
                FragmentTransportOperation::ListVersions { .. }
            ) | (
                ProviderAttemptClass::DeleteObject,
                FragmentTransportOperation::DeleteVersion { .. }
            ) | (
                ProviderAttemptClass::DeleteObject,
                FragmentTransportOperation::DeleteExact { .. }
            )
        );
        if !matches || attempt.put_body.is_some() {
            return Err(FragmentProviderError::OperationMismatch);
        }
        // Last, so a refusal above costs nothing — the same ordering `admit_put`
        // states. Every class this door accepts (HeadObject, ListObjectVersions,
        // DeleteObject) charges, and each charge first takes a dispatch-pool
        // lease, so without this slot a large push hands the charge authority
        // more concurrent work than its pool can hold and it refuses with
        // `PoolExhausted`.
        //
        // THE DEADLINE MUST SURVIVE THE QUEUE, and this is the half of the fix
        // that is easy to miss. Callers mint `deadline_unix_ms` while building
        // the attempt, i.e. BEFORE this wait — `lore-postgres` uses
        // `now + io_timeout`, whose default is five seconds. A queue deeper than
        // that would spend the whole budget waiting and then fail as
        // `charge_deadline_exceeded`, which is the same push failure wearing a
        // different name. Shifting the deadline by exactly the time waited makes
        // it mean "io_timeout from admission" instead of "from construction", so
        // each attempt gets the budget its caller intended. The shift is bounded
        // by the wait, so the deadline can never exceed
        // `admission + io_timeout`.
        let queued_at = tokio::time::Instant::now();
        let charge_permit = self.admit_charge_permit().await?;
        let waited_millis = i64::try_from(queued_at.elapsed().as_millis()).unwrap_or(i64::MAX);
        attempt.deadline_unix_ms = attempt.deadline_unix_ms.saturating_add(waited_millis);
        Ok(AdmittedFragmentAttempt {
            gateway: self,
            attempt,
            operation,
            _charge_permit: charge_permit,
        })
    }

    /// Validate and admit one conditional direct PUT. Admission owns the only
    /// PUT permit before the caller supplies body bytes, and execution never
    /// reacquires it.
    pub async fn admit_put(
        &self,
        attempt: FragmentProviderAttempt,
        operation: FragmentDirectPutOperation,
    ) -> Result<AdmittedFragmentPutAttempt<'_>, FragmentProviderError> {
        if !self.port_wired {
            return Err(FragmentProviderError::OperationRequired);
        }
        if attempt.attempt_class != ProviderAttemptClass::PutObject || attempt.put_body.is_some() {
            return Err(FragmentProviderError::OperationMismatch);
        }
        if operation.object_key.is_empty() {
            return Err(FragmentProviderError::InvalidObjectKey);
        }
        if operation.declared_size > FRAGMENT_PROVIDER_INGRESS_CAP_BYTES {
            return Err(FragmentProviderError::IngressCapExceeded);
        }
        let put_permit = self.admit_put_permit().await?;
        Ok(AdmittedFragmentPutAttempt {
            gateway: self,
            attempt,
            operation,
            _put_permit: put_permit,
        })
    }

    /// Charges and issues one attempt, subject to every Phase 4 property.
    ///
    /// Order matters and is deliberate. The class allowlist and the ingress cap
    /// run first, because a refusal there must cost nothing. Admission is taken
    /// **before** the charge: a permit acquired afterwards would mean holding a
    /// committed, nonrefundable grant while queueing, which manufactures the
    /// grant-without-attempt window CD-4 documents rather than bounding it. The
    /// permit's only `await` also sits ahead of CD-5's charge guard, so a caller
    /// that drops this future while queueing for admission has charged nothing.
    ///
    /// **`Ok(ProviderAttemptOutcome::Ambiguous)` is not success.** It says one
    /// charged request reached the provider and no definite response came back,
    /// so the object's state is unknown and the charge stands. A caller that
    /// treats every `Ok` alike will read an unknown provider effect as a
    /// completed one. The seam deliberately does not collapse it into an error:
    /// what an unknown effect means depends on the operation the caller is in
    /// the middle of, and only the caller knows that.
    pub async fn execute(
        &self,
        ledger: &mut FragmentAttemptLedger,
        attempt: &FragmentProviderAttempt,
    ) -> Result<ProviderAttemptOutcome, FragmentProviderError> {
        if self.port_wired {
            return Err(FragmentProviderError::OperationRequired);
        }
        Self::check_attempt_class(attempt.attempt_class)?;
        self.check_ingress_cap(attempt)?;
        let _permit = self.admit(attempt.attempt_class).await?;
        let request = MeteredProviderAttemptRequest::try_from(self.build_request(attempt))
            .map_err(FragmentProviderError::Provider)?;
        let execution = self
            .client
            .issue(
                &mut ledger.0,
                &request,
                &FragmentTransportOperation::Head {
                    object_key: String::new(),
                },
            )
            .await
            .map_err(FragmentProviderError::Provider)?;
        Ok(execution.outcome)
    }

    /// Issues the one unmetered, read-only provider operation. This path has no
    /// durable ledger, database charge authority call, budget pin, deadline,
    /// traffic class, or admission permit.
    pub async fn get(
        &self,
        attempt: &FragmentGetAttempt,
        operation: &FragmentGetOperation,
    ) -> Result<FragmentGetExecution, FragmentProviderError> {
        if !self.port_wired {
            return Err(FragmentProviderError::OperationRequired);
        }
        if operation.object_key.is_empty() {
            return Err(FragmentProviderError::InvalidObjectKey);
        }
        let request = ProviderGetAttemptRequest {
            target: self.client.boundary().target().clone(),
            logical_request_id: attempt.logical_request_id.clone(),
            attempt_id: attempt.attempt_id.clone(),
            attempt_ordinal: attempt.attempt_ordinal,
        };
        let execution = self
            .client
            .issue_get(&request, operation)
            .await
            .map_err(FragmentProviderError::Provider)?;
        Ok(FragmentGetExecution {
            outcome: execution.outcome,
            response: execution.response,
        })
    }

    /// Runs every local Phase 4 check and the governed client's own validation,
    /// charging nothing and sending nothing.
    ///
    /// Takes no admission permit, because nothing is in flight.
    pub fn validate_attempt(
        &self,
        attempt: &FragmentProviderAttempt,
    ) -> Result<(), FragmentProviderError> {
        Self::check_attempt_class(attempt.attempt_class)?;
        self.check_ingress_cap(attempt)?;
        let request = MeteredProviderAttemptRequest::try_from(self.build_request(attempt))
            .map_err(FragmentProviderError::Provider)?;
        self.client
            .validate(&request)
            .map_err(FragmentProviderError::Provider)
    }

    /// Builds the governed client's request from a caller's attempt.
    ///
    /// The target comes from this gateway's own boundary and from nowhere else.
    /// That single line is the whole of property 5.
    ///
    /// **Private.** It runs neither the class allowlist nor the ingress cap —
    /// its callers do, ahead of it — so a `pub` version handed out a request
    /// naming a multipart class and carrying an over-cap body. It was `pub`
    /// only so a test could assert on the target it fills in; the tests are in
    /// this crate and do not need it public.
    fn build_request(&self, attempt: &FragmentProviderAttempt) -> ProviderAttemptRequest {
        ProviderAttemptRequest {
            traffic_class: attempt.traffic_class,
            attempt_class: attempt.attempt_class,
            target: self.client.boundary().target().clone(),
            logical_request_id: attempt.logical_request_id.clone(),
            attempt_id: attempt.attempt_id.clone(),
            attempt_ordinal: attempt.attempt_ordinal,
            deadline_unix_ms: attempt.deadline_unix_ms,
            budget_pin: attempt.budget_pin.clone(),
            put_body: attempt.put_body.clone(),
            // Multipart is unreachable under the ingress cap, so no attempt this
            // seam builds ever carries a part range.
            put_part: None,
        }
    }

    fn check_attempt_class(class: ProviderAttemptClass) -> Result<(), FragmentProviderError> {
        if FRAGMENT_PROVIDER_ATTEMPT_CLASSES.contains(&class) {
            return Ok(());
        }
        Err(FragmentProviderError::AttemptClassNotPermitted {
            class: class.metric_label(),
        })
    }

    fn check_ingress_cap(
        &self,
        attempt: &FragmentProviderAttempt,
    ) -> Result<(), FragmentProviderError> {
        let Some(body) = attempt.put_body.as_ref() else {
            return Ok(());
        };
        if body.size() > FRAGMENT_PROVIDER_INGRESS_CAP_BYTES {
            return Err(FragmentProviderError::IngressCapExceeded);
        }
        Ok(())
    }

    /// Takes an in-flight slot for a body-carrying attempt.
    ///
    /// Non-body classes take none: a HEAD or a DELETE holds no body, so
    /// charging it against a put bound would make the configured number mean
    /// something other than what CR-031 says it means.
    async fn admit(
        &self,
        class: ProviderAttemptClass,
    ) -> Result<Option<SemaphorePermit<'_>>, FragmentProviderError> {
        if !class.carries_object_body() {
            return Ok(None);
        }
        self.admit_put_permit().await.map(Some)
    }

    /// Takes a charge-admission slot for a charge-carrying non-body attempt.
    ///
    /// Mirrors [`Self::admit_put_permit`] deliberately, including the
    /// try-then-wait shape: the fast path costs nothing when the queue is short,
    /// and a busy queue waits rather than refusing, because refusing is what the
    /// caller cannot recover from. A refused charge reaches the client as
    /// `SlowDown` and ends the push.
    async fn admit_charge_permit(&self) -> Result<SemaphorePermit<'_>, FragmentProviderError> {
        match self.in_flight_charges.try_acquire() {
            Ok(permit) => return Ok(permit),
            Err(TryAcquireError::Closed) => {
                return Err(FragmentProviderError::ChargeAdmissionClosed);
            }
            Err(TryAcquireError::NoPermits) => {}
        }
        match tokio::time::timeout(
            self.charge_bound.acquire_timeout(),
            self.in_flight_charges.acquire(),
        )
        .await
        {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_)) => Err(FragmentProviderError::ChargeAdmissionClosed),
            Err(_) => Err(FragmentProviderError::ChargeAdmissionTimedOut),
        }
    }

    async fn admit_put_permit(&self) -> Result<SemaphorePermit<'_>, FragmentProviderError> {
        match self.in_flight_puts.try_acquire() {
            Ok(permit) => return Ok(permit),
            Err(TryAcquireError::Closed) => {
                return Err(FragmentProviderError::PutAdmissionClosed);
            }
            Err(TryAcquireError::NoPermits) => {}
        }
        match tokio::time::timeout(self.bound.acquire_timeout(), self.in_flight_puts.acquire())
            .await
        {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_)) => Err(FragmentProviderError::PutAdmissionClosed),
            Err(_) => Err(FragmentProviderError::PutAdmissionTimedOut),
        }
    }
}

impl std::fmt::Debug for FragmentProviderGateway {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FragmentProviderGateway")
            .field("attestation", &self.attestation)
            .field("bound", &self.bound)
            .field(
                "available_put_permits",
                &self.in_flight_puts.available_permits(),
            )
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;

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

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

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
use lore_object_dispatch::cell_schema_install::CELL_SCHEMA_LAYERS;
use lore_object_dispatch::cell_schema_install::CellSchemaLayerId;
use lore_object_dispatch::dispatch_client::DispatchAuthorityError;
pub use lore_object_dispatch::dispatch_client::DispatchRuntimeClient;
use lore_object_dispatch::dispatch_client::DispatcherIdentityState;
use lore_object_dispatch::dispatch_client::InstalledLayerIdentity;
use tokio::sync::Semaphore;
use tokio::sync::SemaphorePermit;
use tokio::sync::TryAcquireError;

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
    /// Classifies this failure for a consumer that cannot see the dispatch
    /// error vocabulary.
    ///
    /// The charge arm is exhaustive over [`ProviderChargeError`] with **no
    /// wildcard**, so a variant added upstream fails this build rather than
    /// silently landing in a catch-all.
    pub fn disposition(&self) -> FragmentProviderDisposition {
        match self {
            Self::InvalidInFlightPutBound
            | Self::AttemptClassNotPermitted { .. }
            | Self::IngressCapExceeded
            | Self::OperationRequired
            | Self::OperationMismatch
            | Self::InvalidObjectKey => FragmentProviderDisposition::InvalidInput,
            Self::PutAdmissionTimedOut | Self::PutAdmissionClosed => {
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
                .execute_direct_put(ledger, request, body, &())
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
                .execute_direct_put(ledger, request, body, &operation)
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
}

impl FragmentTransportOperation {
    pub fn object_key(&self) -> &str {
        match self {
            Self::Head { object_key }
            | Self::ListVersions { object_key }
            | Self::DeleteVersion { object_key, .. } => object_key,
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
/// infers one pool's maximum from another pool.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FragmentProcessPoolInventory {
    pub immutable_pool_max: u32,
    pub mutable_pool_max: u32,
    pub lock_pool_max: u32,
    pub domain_pool_max: u32,
    pub dispatch_pool_max: u32,
}

impl FragmentProcessPoolInventory {
    /// Validate the exact five-pool process inventory before composition opens
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
        )
        .map_err(FragmentProviderActivationError::DispatchPool)?;
        Ok(ValidatedFragmentProcessPoolInventory {
            inventory: self,
            budget,
        })
    }
}

/// Canonically validated five-pool inventory carried from server preflight to
/// the dispatch pool without repeating or reimplementing the arithmetic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedFragmentProcessPoolInventory {
    inventory: FragmentProcessPoolInventory,
    budget: DispatchConnectionBudget,
}

/// The one composition door for attestation, charge authority, and provider
/// transport. It retains one Arc-backed pool through the typed client and
/// charge authority; no second pool or raw connection is opened.
pub struct FragmentProviderEntry {
    gateway: FragmentProviderGateway,
    _dispatch: DispatchRuntimeClient,
}

impl FragmentProviderEntry {
    pub async fn connect<P>(
        config: FragmentDispatchRuntimeConfig,
        boundary: CellProviderBoundary,
        capabilities: ProviderCapabilities,
        bound: InFlightPutBound,
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
        let charge_authority = PostgresProviderChargeAuthority::new(pool)
            .map_err(FragmentProviderActivationError::ChargeAuthority)?;
        let gateway = FragmentProviderGateway::with_transport_port(
            attestation,
            capabilities,
            bound,
            charge_authority,
            transport,
        );
        Ok(Self {
            gateway,
            _dispatch: dispatch,
        })
    }

    pub fn boundary(&self) -> &CellProviderBoundary {
        self.gateway.boundary()
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
            .issue_direct_put(&mut ledger.0, &request, body, &self.operation)
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
    ) -> Self {
        Self::new(
            attestation,
            capabilities,
            bound,
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
        attempt: FragmentProviderAttempt,
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
            )
        );
        if !matches || attempt.put_body.is_some() {
            return Err(FragmentProviderError::OperationMismatch);
        }
        Ok(AdmittedFragmentAttempt {
            gateway: self,
            attempt,
            operation,
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
mod tests {
    use std::sync::Arc;
    use std::sync::Mutex;
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
    }

    impl ScriptedChargeAuthority {
        fn new(script: ChargeScript) -> Self {
            Self {
                script,
                calls: AtomicU32::new(0),
            }
        }
    }

    impl ProviderChargeAuthority for ScriptedChargeAuthority {
        async fn charge(
            &self,
            request: &ProviderChargeRequest,
        ) -> Result<ProviderChargeGrant, ProviderChargeError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
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
            let requests_per_call = self.0.requests_per_call;
            let response = match request.operation() {
                FragmentTransportOperation::Head { .. } => FragmentTransportResponse::Head {
                    metadata: Vec::new(),
                    content_length: 1,
                },
                FragmentTransportOperation::ListVersions { .. } => {
                    FragmentTransportResponse::Versions(Vec::new())
                }
                FragmentTransportOperation::DeleteVersion { .. } => {
                    FragmentTransportResponse::Deleted
                }
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
        let authority = Arc::new(ScriptedChargeAuthority::new(script));
        let port = Arc::new(CountingGetPort {
            get_calls: AtomicUsize::new(0),
            metered_calls: AtomicUsize::new(0),
            requests_per_call,
            outcome: ProviderAttemptOutcome::Decisive,
            direct_body: Mutex::new(None),
        });
        let gateway = FragmentProviderGateway::with_transport_port(
            CellSchemaAttestation::for_tests(boundary()),
            ProviderCapabilities::none().with_listing(),
            put_bound,
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

    fn layer_slot(
        state: &mut DispatcherIdentityState,
        index: usize,
    ) -> &mut InstalledLayerIdentity {
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
    /// the five installed layers; CD-4's budget-limiter layer — the one the
    /// charge itself executes against — is not among them.
    #[test]
    fn the_attestation_does_not_cover_the_budget_limiter_layer() {
        assert_eq!(CELL_SCHEMA_LAYERS.len(), 5);
        assert!(!ATTESTED_LAYERS.contains(&CellSchemaLayerId::BudgetLimiter));
        for layer in CELL_SCHEMA_LAYERS {
            if layer.id != CellSchemaLayerId::BudgetLimiter {
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
        ];
        for (class, operation) in cases {
            let (gateway, authority, port) = port_harness(ChargeScript::Grant, 1, bound());
            let admitted = gateway
                .admit_operation(attempt(class), operation)
                .await
                .expect("metered non-GET admission");
            admitted
                .execute(&mut ledger())
                .await
                .expect("metered non-GET execution");
            assert_eq!(authority.calls.load(Ordering::SeqCst), 1, "{class:?}");
            assert_eq!(port.metered_calls.load(Ordering::SeqCst), 1, "{class:?}");
            assert_eq!(port.get_calls.load(Ordering::SeqCst), 0, "{class:?}");
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
            Ok(outcome) => panic!(
                "a bodyless attempt must not resolve while the limiter hangs, got {outcome:?}"
            ),
        }
        held.abort();
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
            let observed =
                FragmentProviderError::Provider(ProviderClientError::ChargeRefused(refusal))
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
                FragmentProviderError::Provider(ProviderClientError::ChargeRefused(
                    ProviderChargeError::BudgetPinRejected,
                )),
                FragmentProviderDisposition::NotReady,
            ),
        ] {
            assert_eq!(
                error.disposition(),
                disposition,
                "{error} must carry {disposition:?}",
            );
        }
    }
}

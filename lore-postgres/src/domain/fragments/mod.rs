// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! CR-031 server-only immutable fragment lifecycle consistency (SCHEMA-118).
//!
//! Fragment truth is currently split across association rows, one lifecycle
//! row, object metadata, a metering projection, and repair side effects, with
//! `query`, `get`, and `get_metadata` each implementing the usability predicate
//! separately. This module is the single coordinator that owns every
//! Postgres-mode fragment decision instead.
//!
//! It reuses CR-029's pool, database identity, and receipt rail, and CR-032's
//! F-032-3 lock order. It defines no receipt table, temporal constant, marker,
//! quota, or retry policy of its own, and it builds **no private provider
//! client**: WP-114's governed client is the only route to a bucket.
//!
//! **How that last claim is held changed twice, and the current wording is
//! exact.** Through Phases 2 and 3 it was "this module has no S3 dependency, so
//! a reviewer can check that by construction". Phase 4 first made it a source
//! scan, which an independent reviewer beat five times. It is now split:
//!
//! - The seam lives in its own crate, [`lore_fragment_provider`], whose
//!   dependency graph contains no `aws-sdk-s3`, `aws-config`, `aws-smithy-*` or
//!   `lore-aws`. A private provider client there is a **compile error**.
//! - `coordinator.rs`, `masks.rs`, `schema.rs` and `states.rs` stay here, in a
//!   crate that legitimately depends on `aws-sdk-s3` for the legacy CR-007
//!   store. For those four files the rule is still a **source pin**
//!   (`tests/fragment_provider_source_pins.rs`) — over four files that build no
//!   provider client at all, rather than over a whole package.
//!
//! The companion rule — that the seam is the only route to a provider — is
//! held the same way and stated the same carefully. `lore-postgres` does not
//! depend on `lore-object-dispatch`, and the seam does not re-export
//! `ProviderAttemptLedger` or `ProviderAttemptRequest`, so nothing here can
//! **construct** the arguments the governed client's `execute` takes. That is
//! deliberately narrower than "nothing here can call it": a call expression
//! with divergent arguments still compiles and panics, and the wider claim
//! would be checkably false. No provider attempt can be issued from this
//! crate, which is the property that matters. This crate also cannot supply a
//! transport of its own, because the three types `ProviderTransport::issue`
//! names are not re-exported either — so the gateway it holds can only be the
//! unwired one.
//!
//! **Scope: the seam crate is the trust boundary.** No caller outside it can
//! reach the provider, and that is compiler-enforced. Two things sit outside
//! the guarantee, both deliberately: a crate that adds `lore-object-dispatch`
//! to its own manifest can build a client without touching the seam, and inside
//! the seam a deliberate new public API — a forwarding method over locally
//! aliased types — can widen the boundary. The second is review-checked and no
//! source pin can hold it, because it is a property of a method body rather
//! than a declaration.
//!
//! Stated this narrowly on purpose. Seven rounds of evasions came from claims
//! written wider than the property they held, and at some point "someone
//! editing the trust boundary can widen the trust boundary" stops being a
//! defect and becomes the definition of the boundary.
//!
//! `domain/fragments/` is the separately owned WP-118 package, nested under
//! `domain/` so it can share that lock order and pool. WP-116 yielded it for
//! the serialized `SCHEMA-118` window and owns the final-push coordinator that
//! consumes the witness this package hands back.
//!
//! # What is here
//!
//! Phases 2 and 3: the migration-owned schema, readiness, the batched resolver,
//! and the begin/commit pairs with their witnesses and lock order.
//!
//! Phase 4: [`provider`], the adapter onto [`lore_fragment_provider`]. The seam
//! itself is that crate; this package holds only the names its consumers need
//! and the translation onto CR-029's `DomainError`. It is dark and
//! parameterized — no bucket, region, endpoint, credential, budget pin, or
//! route is named anywhere, the shipped charge authority and transport both
//! fail closed, and nothing constructs a gateway. The provider-*consuming*
//! operations (repair through the governed client, version-aware physical
//! purge, backfill) are Phases 5 onward and are still not here.
//!
//! **Why only `provider.rs` moved.** The coordinator needs `DomainError`,
//! `lock_order`, `schema::STATE_LIVE` and `pool::ensure_schema` from this
//! crate, and Phase 5 routes this crate's immutable store back into the
//! coordinator — so a whole-package split is a Cargo cycle, verified rather
//! than assumed. Breaking it would mean extracting the shared domain core,
//! which is a WP-116 seam.

pub mod coordinator;
#[cfg(feature = "failure_generator")]
pub mod failpoints;
pub mod masks;
pub mod provider;
pub mod schema;
pub mod states;

/// Whether this build carries WP-118 Phase 9's fragment failpoints.
///
/// Present in **both** configurations on purpose. Cargo cannot express that
/// `lore-server/failure_generator` and `lore-postgres/failure_generator` must
/// move together, and a forwarded feature chain in this fork has already been
/// shown to drift silently (see the `oodle` chain and the learning
/// `cargo-cannot-express-that-two-features-must-move-together-pin-it-with-a-cross-crate-guard-test.md`).
/// This is what the cross-crate guard compares against, in
/// `lore-server/src/plugins/postgres.rs`.
pub const fn failpoints_compiled() -> bool {
    cfg!(feature = "failure_generator")
}

/// Reach a WP-118 Phase 9 failpoint. Expands to nothing in a default build.
///
/// The two arms are the whole enforcement. Under `failure_generator` this calls
/// [`failpoints::hit`]; without it, that function does not exist and cannot be
/// named, so a call site that tried to reach a failpoint in a default build is
/// `E0433` rather than something a reviewer has to catch.
///
/// **That is the only property either arm holds.** The default arm binds the
/// anchor literal so it is type-checked, but it type-checks the *expression*,
/// not the *name* — every string literal passes, in both configurations. A
/// mistyped anchor is caught by nothing the compiler does; only the call-site
/// scan against [`failpoints`]'s `ANCHORS` table catches it.
///
/// Call sites write `failpoint!("anchor.name")?;` — the `?` is deliberately
/// left visible rather than hidden inside the expansion, because a `.settled`
/// anchor configured with the `unknown` action really does return an error from
/// a commit that succeeded.
#[cfg(feature = "failure_generator")]
macro_rules! failpoint {
    ($anchor:expr) => {
        $crate::domain::fragments::failpoints::hit($anchor).await
    };
}

#[cfg(not(feature = "failure_generator"))]
macro_rules! failpoint {
    ($anchor:expr) => {
        ::core::result::Result::<(), $crate::domain::errors::DomainError>::Ok({
            let _anchor: &'static str = $anchor;
        })
    };
}

pub use coordinator::BeginOutcome;
pub use coordinator::CommitVerdict;
pub use coordinator::EpochWitness;
pub use coordinator::FragmentBackfillCursorAdvance;
pub use coordinator::FragmentIntent;
pub use coordinator::FragmentLifecycleReadiness;
pub use coordinator::FragmentManifest;
pub use coordinator::FragmentObliterateBegin;
pub use coordinator::FragmentObliterateIntent;
pub use coordinator::FragmentObliterateOwnership;
pub use coordinator::FragmentObliteratePhase;
pub use coordinator::FragmentObliterateRepresentation;
pub use coordinator::FragmentPurgeProof;
pub use coordinator::FragmentPurgeTarget;
pub use coordinator::FragmentQueryMatch;
pub use coordinator::FragmentQueryRequest;
pub use coordinator::FragmentRepositoryStats;
pub use coordinator::FragmentResolution;
pub use coordinator::FragmentVerdict;
pub use coordinator::FragmentWriteCapability;
pub use coordinator::FragmentWriteCapabilityCutover;
pub use coordinator::FragmentWriteCapabilityReadiness;
pub use coordinator::FragmentWriteClaim;
pub use coordinator::FragmentWriteClaimInput;
pub use coordinator::FragmentWriteClaimPruneBatch;
pub use coordinator::FragmentWriteClaimPruneReport;
pub use coordinator::FragmentWriteSettlement;
pub use coordinator::IoObservation;
pub use coordinator::MAX_FRAGMENT_BACKFILL_CURSOR_BATCH;
pub use coordinator::MAX_FRAGMENT_WRITE_CLAIM_BODY_BYTES;
pub use coordinator::MAX_FRAGMENT_WRITE_CLAIM_PRUNE_BATCH;
pub use coordinator::MAX_LIFECYCLE_GENERATION_FANOUT;
pub use coordinator::MAX_PUSH_FRAGMENT_REVALIDATIONS;
pub use coordinator::PostgresFragmentCoordinator;
pub use coordinator::PushGenerationWitness;
pub use coordinator::PushWitnessVerdict;
pub use coordinator::REQUIRED_FRAGMENT_CHANGED;
pub use coordinator::REQUIRED_FRAGMENT_REVALIDATION_LIMIT;
pub use coordinator::RequiredFragment;
pub use coordinator::STAGED_LEASE_ALREADY_RELEASED;
pub use coordinator::STAGED_LEASE_MEMBER_NOT_STAGED;
pub use coordinator::STAGED_LEASE_MEMBER_SET_MISMATCH;
pub use coordinator::STAGED_LEASE_VANISHED;
pub use coordinator::StagedReaderLease;
pub use coordinator::read_fragment_write_capability;
pub(crate) use failpoint;
pub use masks::CONTENT_STRUCTURE_MASK;
pub use masks::DERIVED_TIER_MASK;
pub use masks::DecodeSupport;
pub use masks::ENCODING_MASK;
pub use masks::decodable_encoding;
pub use provider::BudgetPin;
pub use provider::CellProviderBoundary;
pub use provider::CellSchemaAttestation;
pub use provider::DEFAULT_IN_FLIGHT_PUTS;
pub use provider::FRAGMENT_PROVIDER_ATTEMPT_CLASSES;
pub use provider::FRAGMENT_PROVIDER_INGRESS_CAP_BYTES;
pub use provider::FRAGMENT_PROVIDER_SEND_TIMEOUT_MAX_MILLIS;
pub use provider::FragmentAttemptLedger;
pub use provider::FragmentCellRetentionHandle;
pub use provider::FragmentDatabaseIdentity;
pub use provider::FragmentDatabaseIdentityError;
pub use provider::FragmentDirectPutOperation;
pub use provider::FragmentDispatchRuntimeConfig;
pub use provider::FragmentDispatchTls;
pub use provider::FragmentGetAttempt;
pub use provider::FragmentGetExecution;
pub use provider::FragmentGetOperation;
pub use provider::FragmentGetResponse;
pub use provider::FragmentProcessPoolInventory;
pub use provider::FragmentProviderActivationError;
pub use provider::FragmentProviderAttempt;
pub use provider::FragmentProviderDisposition;
pub use provider::FragmentProviderEntry;
pub use provider::FragmentProviderError;
pub use provider::FragmentProviderGateway;
pub use provider::FragmentTransportOperation;
pub use provider::FragmentTransportResponse;
pub use provider::InFlightPutBound;
pub use provider::MAX_IN_FLIGHT_PUTS;
pub use provider::ProviderAttemptClass;
pub use provider::ProviderAttemptOutcome;
pub use provider::ProviderCapabilities;
pub use provider::ProviderTrafficClass;
pub use provider::ValidatedFragmentProcessPoolInventory;
pub use provider::attest_cell_schema;
pub use schema::FRAGMENT_SCHEMA_VERSION;
pub use states::EpochAuthority;
pub use states::FragmentLifecycleState;
pub use states::FragmentWriteClaimState;
pub use states::MissingDiagnostic;

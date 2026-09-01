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
//! crate, which is the property that matters.
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
pub mod masks;
pub mod provider;
pub mod schema;
pub mod states;

pub use coordinator::BeginOutcome;
pub use coordinator::CommitVerdict;
pub use coordinator::EpochWitness;
pub use coordinator::FragmentIntent;
pub use coordinator::FragmentLifecycleReadiness;
pub use coordinator::FragmentManifest;
pub use coordinator::FragmentResolution;
pub use coordinator::FragmentVerdict;
pub use coordinator::IoObservation;
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
pub use masks::CONTENT_STRUCTURE_MASK;
pub use masks::DERIVED_TIER_MASK;
pub use masks::DecodeSupport;
pub use masks::ENCODING_MASK;
pub use masks::decodable_encoding;
pub use provider::CellSchemaAttestation;
pub use provider::DEFAULT_IN_FLIGHT_PUTS;
pub use provider::FRAGMENT_PROVIDER_ATTEMPT_CLASSES;
pub use provider::FRAGMENT_PROVIDER_INGRESS_CAP_BYTES;
pub use provider::FragmentAttemptLedger;
pub use provider::FragmentProviderAttempt;
pub use provider::FragmentProviderDisposition;
pub use provider::FragmentProviderError;
pub use provider::FragmentProviderGateway;
pub use provider::InFlightPutBound;
pub use provider::MAX_IN_FLIGHT_PUTS;
pub use provider::attest_cell_schema;
pub use states::EpochAuthority;
pub use states::FragmentLifecycleState;
pub use states::MissingDiagnostic;

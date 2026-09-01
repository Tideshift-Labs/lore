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
//! **That last claim changed shape at Phase 4 and the wording is deliberate.**
//! Through Phases 2 and 3 it read "this module has no S3 dependency, so a
//! reviewer can check that by construction". Phase 4 gives the package one
//! provider seam ([`provider`]), which necessarily depends on WP-114's governed
//! client, so a dependency-absence argument no longer covers the package as a
//! whole. It still covers the coordinator, which has no provider dependency at
//! all; for the rest the guard is `tests/fragment_provider_source_pins.rs`.
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
//! Phase 4: [`provider`], the one seam through which this package may reach a
//! provider, built on WP-114's CD-3 typed authority client, CD-4 shared
//! limiter, and CD-5 governed provider client. It is dark and parameterized —
//! no bucket, region, endpoint, credential, budget pin, or route is named here,
//! the shipped charge authority and transport both fail closed, and no caller
//! constructs a gateway. The provider-*consuming* operations (repair through
//! the governed client, version-aware physical purge, backfill) are Phases 5
//! onward and are still not here.
//!
//! The no-second-provider-client rule stays checkable by construction for the
//! coordinator: `coordinator.rs` has no provider dependency at all, and
//! [`provider`] reaches a bucket only through WP-114's governed client. That
//! the package holds no private S3 client is pinned by
//! `tests/fragment_provider_source_pins.rs`, because `lore-postgres` as a crate
//! legitimately depends on `aws-sdk-s3` for the legacy CR-007 store and a
//! crate-level absence is therefore not available as evidence.

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
pub use provider::FragmentProviderAttempt;
pub use provider::FragmentProviderError;
pub use provider::FragmentProviderGateway;
pub use provider::InFlightPutBound;
pub use provider::MAX_IN_FLIGHT_PUTS;
pub use provider::UnwiredFragmentProviderGateway;
pub use provider::attest_cell_schema;
pub use states::EpochAuthority;
pub use states::FragmentLifecycleState;
pub use states::MissingDiagnostic;

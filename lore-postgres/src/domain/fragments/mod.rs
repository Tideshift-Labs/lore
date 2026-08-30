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
//! quota, or retry policy of its own, and it constructs **no provider client**:
//! WP-114's governed client is the only route to a bucket, and this module has
//! no S3 dependency so a reviewer can check that by construction.
//!
//! `domain/fragments/` is the separately owned WP-118 package, nested under
//! `domain/` so it can share that lock order and pool. WP-116 yielded it for
//! the serialized `SCHEMA-118` window and owns the final-push coordinator that
//! consumes the witness this package hands back.
//!
//! # What is here
//!
//! Phases 2 and 3: the migration-owned schema, readiness, the batched resolver,
//! and the begin/commit pairs with their witnesses and lock order. The
//! provider-consuming halves wait on WP-114's CD-1/CD-3/CD-4/CD-5.

pub mod coordinator;
pub mod masks;
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
pub use coordinator::StagedReaderLease;
pub use masks::CONTENT_STRUCTURE_MASK;
pub use masks::DERIVED_TIER_MASK;
pub use masks::DecodeSupport;
pub use masks::ENCODING_MASK;
pub use masks::decodable_encoding;
pub use states::EpochAuthority;
pub use states::FragmentLifecycleState;
pub use states::MissingDiagnostic;

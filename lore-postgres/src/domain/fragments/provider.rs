// Copyright 2026 Tideshift Labs
// SPDX-License-Identifier: MIT
//! The `lore-postgres` side of CR-031/WP-118's provider seam.
//!
//! The seam itself is [`lore_fragment_provider`], a separate crate. This module
//! is only the adapter: the names this crate's consumers need, and the one
//! translation from the seam's classification to CR-029's `DomainError`.
//!
//! # Why the seam is a separate crate
//!
//! Two CR-031 rules that used to be source-pinned are now facts about the
//! dependency graph:
//!
//! - **No private provider client.** `lore-fragment-provider` does not depend on
//!   `aws-sdk-s3`, `aws-config`, `aws-smithy-*` or `lore-aws`, so building one
//!   there is a compile error. It is **not** a dependency-graph fact for
//!   `coordinator.rs`, `masks.rs`, `schema.rs` and `states.rs`, which stay here
//!   beside the legacy CR-007 store's legitimate `aws-sdk-s3` dependency; for
//!   those four files it is still a source pin, over a much smaller surface.
//! - **The seam is the only route to the provider.** `lore-postgres` does not
//!   depend on `lore-object-dispatch`, and the seam crate does not re-export
//!   `ProviderAttemptLedger` or `ProviderAttemptRequest` — the two parameters of
//!   the governed client's `execute`. So no code here can **construct** those
//!   arguments, whatever value it holds and whatever accessor the seam might
//!   grow. That is the whole mechanism; gateway privacy is not carrying it.
//!
//!   **The claim is about the arguments, not the call.** An earlier revision
//!   said "no code here can call it", which is false and checkably so:
//!   `g.inner().execute(todo!(), todo!())` compiles here, because `todo!()`
//!   diverges and coerces to any type. It panics before reaching a provider,
//!   and a real ledger or request cannot be built — naming either here is
//!   `error[E0603]: struct ProviderAttemptLedger is private`. Keep the narrow
//!   wording: no provider attempt can be issued from this crate.
//!
//!   This crate can implement the seam's safe transport ports, but it cannot
//!   mint their opaque request values. The seam creates those values only
//!   after admission and authorization, so the adapter cannot invoke a real
//!   send by itself.
//!
//! **And the scope, stated as narrowly as it is true.** The seam crate is the
//! trust boundary, and the guarantee is about *crates*, not about the seam's
//! internals:
//!
//! - **No caller outside the seam can reach the provider.** The parameter types
//!   are unnameable here and no client value is obtainable; both are
//!   compiler-enforced. That covers this crate and `lore-server`.
//! - **A crate that opts in is outside the guarantee.** Anything that adds
//!   `lore-object-dispatch` to its own `Cargo.toml` can build a client and issue
//!   attempts without touching the seam. A manifest edit, which no pin sees.
//! - **Inside the seam, a deliberate new public API can widen the boundary** —
//!   a forwarding method over locally aliased types would expose the call.
//!   Review-checked, not compiler-checked, and no source pin can hold it,
//!   because it is a property of a method body rather than a declaration.
//!
//! What enforces the first bullet is this crate's dependency list plus the
//! seam's manifest, no-re-export and trait-privacy pins. The pins raise the
//! cost of widening the boundary by accident; they do not stop it being done on
//! purpose, and the record says so rather than claiming the last inch.
//!
//! Only `provider.rs` moved. The rest of `domain/fragments/` cannot follow it:
//! the coordinator needs `DomainError`, `lock_order`, `schema::STATE_LIVE` and
//! `pool::ensure_schema` from this crate, and Phase 5 routes this crate's
//! immutable store back into the coordinator, so a whole-package split is a
//! Cargo cycle. Breaking that would mean extracting the shared domain core,
//! which is a WP-116 seam rather than WP-118's.
//!
//! # Constructed and attested, but not activated by the server
//!
//! [`FragmentProviderEntry::connect`] is the seam-owned composition door. It
//! privately constructs the shared dispatch pool and typed client, attests the
//! installed cell schema, and builds the governed gateway. The Postgres S3
//! adapter implements the seam's opaque transport ports, and the immutable
//! store has the coordinated lifecycle route.
//!
//! `lore-server` constructs and activates that route only for a complete,
//! explicitly enabled deployment configuration after lifecycle readiness and
//! the exact process-wide pool inventory pass. Absent, disabled, incomplete,
//! or over-budget configurations never receive a provider entry.

pub use lore_fragment_provider::AdmittedFragmentAttempt;
pub use lore_fragment_provider::BudgetPin;
pub use lore_fragment_provider::CellProviderBoundary;
pub use lore_fragment_provider::CellSchemaAttestation;
pub use lore_fragment_provider::DEFAULT_IN_FLIGHT_PUTS;
pub use lore_fragment_provider::FRAGMENT_PROVIDER_ATTEMPT_CLASSES;
pub use lore_fragment_provider::FRAGMENT_PROVIDER_INGRESS_CAP_BYTES;
pub use lore_fragment_provider::FragmentAttemptLedger;
pub use lore_fragment_provider::FragmentDatabaseIdentity;
pub use lore_fragment_provider::FragmentDatabaseIdentityError;
pub use lore_fragment_provider::FragmentDirectPutOperation;
pub use lore_fragment_provider::FragmentDispatchRuntimeConfig;
pub use lore_fragment_provider::FragmentDispatchTls;
pub use lore_fragment_provider::FragmentGetAttempt;
pub use lore_fragment_provider::FragmentGetExecution;
pub use lore_fragment_provider::FragmentGetOperation;
pub use lore_fragment_provider::FragmentGetResponse;
pub use lore_fragment_provider::FragmentProcessPoolInventory;
pub use lore_fragment_provider::FragmentProviderActivationError;
pub use lore_fragment_provider::FragmentProviderAttempt;
pub use lore_fragment_provider::FragmentProviderDisposition;
pub use lore_fragment_provider::FragmentProviderEntry;
pub use lore_fragment_provider::FragmentProviderError;
pub use lore_fragment_provider::FragmentProviderGateway;
pub use lore_fragment_provider::FragmentTransportExecution;
pub use lore_fragment_provider::FragmentTransportOperation;
pub use lore_fragment_provider::FragmentTransportResponse;
pub use lore_fragment_provider::InFlightPutBound;
pub use lore_fragment_provider::MAX_IN_FLIGHT_PUTS;
pub use lore_fragment_provider::ProviderAttemptClass;
pub use lore_fragment_provider::ProviderAttemptOutcome;
pub use lore_fragment_provider::ProviderCapabilities;
pub use lore_fragment_provider::ProviderTrafficClass;
pub use lore_fragment_provider::ValidatedFragmentProcessPoolInventory;
pub use lore_fragment_provider::attest_cell_schema;

use crate::domain::errors::DomainError;

/// Maps a seam failure onto CR-029's classification, which is what `lore-server`
/// translates.
///
/// The match is over [`FragmentProviderDisposition`], not over the seam's error
/// variants, and that is the point: deciding which of CD-5's and CD-4's ~40
/// error variants a refusal is would mean naming `ProviderClientError` and
/// `ProviderChargeError` here, which would mean depending on
/// `lore-object-dispatch` — and that dependency's absence is what makes
/// property 2 structural. The seam decides severity because it is the crate that
/// can see the variants; this decides what CR-029 calls that severity.
///
/// Exhaustive with no wildcard, so a disposition added upstream is a compile
/// error here rather than a silent reclassification.
impl From<FragmentProviderError> for DomainError {
    fn from(error: FragmentProviderError) -> Self {
        domain_class(
            error.disposition(),
            format!("fragment provider seam: {error}"),
        )
    }
}

/// The disposition-to-`DomainError` table, split out so every arm is reachable
/// from a test.
///
/// Two of the five dispositions cannot be produced from this crate at all —
/// `OutcomeUnknown` and `Internal` both come from `ProviderClientError` variants
/// this crate cannot name, which is exactly the property the split exists for.
/// Testing the `From` impl alone would therefore leave those two arms uncovered,
/// or tempt a test into asserting a `DomainError` it built itself. Driving this
/// function over the closed disposition set covers all five honestly.
fn domain_class(disposition: FragmentProviderDisposition, message: String) -> DomainError {
    match disposition {
        FragmentProviderDisposition::InvalidInput => DomainError::InvalidInput(message),
        FragmentProviderDisposition::Transient => DomainError::Transient(message),
        FragmentProviderDisposition::NotReady => DomainError::NotReady(message),
        // Never retried, and never inferred from later state. CR-029's rule.
        FragmentProviderDisposition::OutcomeUnknown => DomainError::OutcomeUnknown(message),
        FragmentProviderDisposition::Internal => DomainError::Internal(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every disposition maps to a distinct `DomainError` class with a stated
    /// retryability, and none reaches a wildcard.
    ///
    /// Driven over the closed disposition set rather than over errors, because
    /// two dispositions are unreachable from this crate by construction — see
    /// [`domain_class`].
    #[test]
    fn every_disposition_maps_to_a_named_domain_class() {
        let expected = [
            (
                FragmentProviderDisposition::InvalidInput,
                "InvalidInput",
                false,
            ),
            (FragmentProviderDisposition::Transient, "Transient", true),
            (FragmentProviderDisposition::NotReady, "NotReady", false),
            (
                FragmentProviderDisposition::OutcomeUnknown,
                "OutcomeUnknown",
                false,
            ),
            (FragmentProviderDisposition::Internal, "Internal", false),
        ];

        for (disposition, class, retryable) in expected {
            let domain = domain_class(disposition, "probe".to_string());
            let observed = match domain {
                DomainError::InvalidInput(_) => "InvalidInput",
                DomainError::Transient(_) => "Transient",
                DomainError::NotReady(_) => "NotReady",
                DomainError::OutcomeUnknown(_) => "OutcomeUnknown",
                DomainError::Internal(_) => "Internal",
                DomainError::Contention(_) => "Contention",
                DomainError::DomainKeyBypass(_) => "DomainKeyBypass",
                DomainError::PreconditionRejected { .. } => "PreconditionRejected",
            };
            assert_eq!(observed, class, "{disposition:?} must map to {class}");
            assert_eq!(
                domain.is_retryable(),
                retryable,
                "{disposition:?} retryability must be {retryable}",
            );
        }
    }

    /// The `From` impl actually routes through the seam's classification rather
    /// than deciding for itself. Uses the two runtime errors this crate can construct
    /// without naming the private dispatch vocabulary.
    #[test]
    fn the_conversion_takes_its_class_from_the_seams_disposition() {
        for error in [
            FragmentProviderError::IngressCapExceeded,
            FragmentProviderError::PutAdmissionTimedOut,
        ] {
            let disposition = error.disposition();
            let through_conversion = DomainError::from(error.clone());
            let through_table =
                domain_class(disposition, format!("fragment provider seam: {error}"));
            assert_eq!(
                through_conversion, through_table,
                "{error} must be classified by its disposition, not independently",
            );
        }
    }
}

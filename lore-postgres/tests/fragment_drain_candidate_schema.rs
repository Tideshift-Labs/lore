// SPDX-FileCopyrightText: 2026 Tideshift Labs
// SPDX-License-Identifier: MIT

//! Offline bound control for WP-122's `staged_drain_candidates` batch newtype.
//!
//! No new schema or migration backs this query (it reads existing SCHEMA-118
//! relations), so unlike `fragment_write_claim_schema.rs` this file pins only
//! the batch constructor's bound, following the same "small offline unit test
//! for a sibling batch newtype, in its own top-level file" convention that
//! file's own `prune_batch_is_bounded_and_requires_a_positive_database_retention_window`
//! established for `FragmentWriteClaimPruneBatch`.

use lore_postgres::domain::errors::DomainError;
use lore_postgres::domain::fragments::FragmentDrainCandidateBatch;
use lore_postgres::domain::fragments::MAX_FRAGMENT_DRAIN_CANDIDATE_BATCH;

#[test]
fn drain_candidate_batch_is_bounded_between_one_and_the_maximum() {
    assert!(FragmentDrainCandidateBatch::new(1).is_ok());
    assert!(FragmentDrainCandidateBatch::new(MAX_FRAGMENT_DRAIN_CANDIDATE_BATCH).is_ok());
    for invalid in [0, MAX_FRAGMENT_DRAIN_CANDIDATE_BATCH + 1] {
        assert!(
            matches!(
                FragmentDrainCandidateBatch::new(invalid),
                Err(DomainError::InvalidInput(_))
            ),
            "batch of {invalid} must be refused as InvalidInput"
        );
    }
}
